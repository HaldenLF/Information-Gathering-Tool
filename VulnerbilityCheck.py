# written by Chris

import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import urllib


def check_open_redirect(url, domain):
  # Check if the URL contains potential open redirect parameters
  open_redirects = ["next", "url", "redirect", "redir"]
  for param in open_redirects:
    if param in url:
      return True
  return False

def check_xss(url):
  # Check for reflected XSS by injecting a script tag in a query parameter
  xss_payload = "<script>alert('XSS')</script>"
  parsed_url = urlparse(url)
  query_params = parsed_url.query
  if query_params:
    xss_url = url.replace(query_params, f"{query_params}&xss_test={xss_payload}")
  else:
    xss_url = f"{url}?xss_test={xss_payload}"
  
  response = requests.get(xss_url)
  if xss_payload in response.text:
    return True
  return False

def check_sql_injection(url):
  # Check for SQL Injection by injecting a common SQL payload in a query parameter
  sql_payload = "' OR '1'='1"
  parsed_url = urlparse(url)
  query_params = parsed_url.query
  if query_params:
    sql_url = url.replace(query_params, f"{query_params}&sql_test={sql_payload}")
  else:
    sql_url = f"{url}?sql_test={sql_payload}"
  
  response = requests.get(sql_url)
  if "error" in response.text.lower() or "sql" in response.text.lower():
    return True
  return False

def check_insecure_headers(response):
  # Check for missing or insecure HTTP headers
  insecure_headers = []
  headers = response.headers

  if "X-Frame-Options" not in headers:
    insecure_headers.append("X-Frame-Options missing")
  if "Content-Security-Policy" not in headers:
    insecure_headers.append("Content-Security-Policy missing")
  if "X-XSS-Protection" not in headers:
    insecure_headers.append("X-XSS-Protection missing or disabled")
  if "Strict-Transport-Security" not in headers:
    insecure_headers.append("Strict-Transport-Security missing")

  return insecure_headers


def perform_security_scan(url):

  parsed_url = urllib.parse.urlparse(url)
  if not parsed_url.scheme:
    url = f"https://{url}"

  open_redirect_found = check_open_redirect(url, urlparse(url).netloc)
  xss_found = check_xss(url)
  sql_injection_found = check_sql_injection(url)
  response = requests.get(url)
  insecure_headers = check_insecure_headers(response)

  results = ""
  if not open_redirect_found:
    results += f"No open redirect found at {url}\n"
  else:
    results += f"Open redirect found at {url}\n"

  if not xss_found:
    results += f"No XSS vulnerability found at {url}\n"
  else:
    results += f"XSS vulnerability suspected at {url} (further investigation recommended)\n"  

  if not sql_injection_found:
    results += f"No SQL injection vulnerability found at {url}\n"
  else:
    results += f"SQL injection vulnerability suspected at {url} (further investigation recommended)\n"

  if insecure_headers:
    results += f"Insecure headers found:\n"
    for header in insecure_headers:
      results += f"- {header}\n"
  else:
    results += "No insecure headers detected.\n"

  return results  # Return the scan results
