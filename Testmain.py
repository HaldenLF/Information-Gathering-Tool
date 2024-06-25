import fpdf
import re
import socket
import ping3
import dns.resolver
import requests
from whois import whois
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urlunparse

def portScan(target):
    return

def dnsScan(target):
    return

def whoisScan(target):
    return

def subDomainScan(target):
    return

def vulnerbilityScan(target):
# blend of OWASP & Vulnbilites reports
    return

def siteMap():
    return


if __name__ == "__main__":
    print("Welcome to the Network Scanner\n"
          "1. Run Port Scan\n"
          "2. Run DNS Scan\n"
          "3. Run Whois Scan\n"
          "4. Run Subdomain Scan\n"
          "5. Run Vulnerability Scan\n"
          "6. Run scans 1-5 in one report\n"
          "7. Run Sitemap Scan\n"
          "8. Exit\n")

    userChoice = input("What scan would you like to perform?\n"
                       "> \n")
    userTarget = input("What site would you like to perform the scan on?\n"
                       "> \n")
    
    if userChoice.lower() == "1" or "port scan":
        portScan(userTarget)
    if userChoice.lower() == "2" or "dns scan":
        dnsScan(userTarget)
    if userChoice.lower() == "3" or "whois scan":
        whoisScan(userTarget)
    if userChoice.lower() == "4" or "subdomain scan":
        subDomainScan(userTarget)
    if userChoice.lower() == "5" or "vulnerbility scan":
        vulnerbilityScan(userTarget)
    if userChoice.lower() == "6" or "1-5 scan" or "scan all":
        portScan(userTarget)
        dnsScan(userTarget)
        whoisScan(userTarget)
        subDomainScan(userTarget)
        vulnerbilityScan(userTarget)
    if userChoice.lower() == "7" or "sitemap" or "site map":
        siteMap(userTarget)

