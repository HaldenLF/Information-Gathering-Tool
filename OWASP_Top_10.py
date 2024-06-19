import requests
from bs4 import BeautifulSoup
import re
import fpdf
from urllib.parse import urlparse, urlunparse

results =[]

url = ""

# login_url = f"{url}/login"
# admin_url = f"{url}/admin"
username = "admin"
password = "admin"

# Test Broken Access Control
def test_broken_access_control(url):
    restricted_url = url + "/admin"
    response = requests.get(restricted_url)
    if response.status_code == 200:
        results.append("Potential Broken Access Control vulnerability found.")
    else:
        results.append("No Broken Access Control vulnerability found.")


# Test Cryptographic Failures (basic)
def test_cryptographic_failures(url):
    response = requests.get(url)
    if "Set-Cookie" in response.headers:
        cookie = response.headers["Set-Cookie"]
        if "Secure" not in cookie or "HttpOnly" not in cookie:
            results.append("Potential Cryptographic Failures found: Insecure cookie attributes.")
        else:
            results.append("No Cryptographic Failures found.")


# Test Injection (e.g., SQL Injection)
def test_sql_injection(url):
    payload = "' OR '1'='1"
    params = {"username": payload, "password": payload}
    response = requests.post(url, data=params)
    if "Welcome" in response.text:
        results.append("Potential SQL Injection vulnerability found.")
    else:
        results.append("No SQL Injection vulnerability found.")


# Test Insecure Design (example check)
def test_insecure_design(url):
    response = requests.get(url)
    if "debug" in response.text or "DEBUG" in response.text:
        results.append("Potential Insecure Design vulnerability found: Debug information exposed.")
    else:
        results.append("No Insecure Design vulnerability found.")


# Test Security Misconfiguration
def test_security_misconfiguration(url):
    response = requests.get(url)
    headers = response.headers
    missing_headers = []
    required_headers = ["X-Frame-Options", "X-XSS-Protection", "Content-Security-Policy"]
    for header in required_headers:
        if header not in headers:
            missing_headers.append(header)
    if missing_headers:
        results.append(f"Potential Security Misconfiguration found: Missing headers {missing_headers}.")
    else:
        results.append("No Security Misconfiguration found.")


# Test Vulnerable and Outdated Components (requires additional tools)
def test_vulnerable_and_outdated_components():
    results.append("Manual check required for Vulnerable and Outdated Components. Consider using tools like Retire.js or OWASP Dependency-Check.")


# Test Identification and Authentication Failures
def test_identification_and_authentication_failures(url):
    common_passwords = ["password", "123456", "admin"]
    for pwd in common_passwords:
        params = {"username": username, "password": pwd}
        response = requests.post(url, data=params)
        if "Welcome" in response.text:
            results.append(f"Potential Identification and Authentication Failures found with password: {pwd}.")
            return
    results.append("No Identification and Authentication Failures found.")


# Test Software and Data Integrity Failures (basic check)
def test_software_data_integrity_failures(url):
    response = requests.get(url)
    if "integrity" not in response.text:
        results.append("Potential Software and Data Integrity Failures found: Missing SRI in scripts.")
    else:
        results.append("No Software and Data Integrity Failures found.")


# Test Security Logging and Monitoring Failures (requires log access)
def test_security_logging_monitoring_failures():
    results.append("Manual check required for Security Logging and Monitoring Failures. Ensure that appropriate logging and monitoring are in place.")


# Test Server-Side Request Forgery (SSRF)
def test_ssrf(url):
    ssrf_payload = {"url": "http://127.0.0.1:80"}
    response = requests.post(url, data=ssrf_payload)
    if "Internal Server Error" in response.text or response.status_code == 500:
        results.append("Potential Server-Side Request Forgery (SSRF) vulnerability found.")
    else:
        results.append("No Server-Side Request Forgery (SSRF) vulnerability found.")


def get_safe_filename(url):
    # Remove protocol and www (optional, adjust if needed)
    url = re.sub(r"^https?://(www\.)?", "", url)
    # Remove characters not allowed in filenames
    filename = re.sub(r"[^\w\-_. ]", "_", url)
    return filename.strip("_ ")  # Remove leading/trailing whitespace and underscores

# Run tests
def OWASP_Top_10_tests(target):
    
    global url
    if not target:
        print("Error: Target URL is empty")
        return
    
    # Ensure the target URL has a scheme (e.g. https)
    if not target.startswith("https://"):
        target = f"https://{target}"

    url = target

    login_url = url
    admin_url = f"{url}/admin"

    print(f"Testing OWASP Top 10 on: {target}")

    test_broken_access_control(target)
    test_cryptographic_failures(target)
    test_sql_injection(login_url)
    test_insecure_design(target)
    test_security_misconfiguration(target)
    test_vulnerable_and_outdated_components()
    test_identification_and_authentication_failures(login_url)
    test_software_data_integrity_failures(target)
    test_security_logging_monitoring_failures()
    test_ssrf(target)

    safe_filename = get_safe_filename(target)
    filename = f"{safe_filename}_OWASP_Test.pdf"

    pdf = fpdf.FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size = 10)

    if results:
        pdf.cell(200, 10, txt="------------- OWASP Test Results -------------", ln=1)
        for result in results:
            pdf.cell(200, 10, txt=result, ln=1)
    else:
        pdf.cell(200, 10, txt="No results found", ln=1)

    pdf.output(filename)
    print(f"OWASP Top 10 Test Complete. Report saved to {filename}\n")



