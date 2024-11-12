from fpdf import FPDF
import fpdf
import re
import socket
import ping3
import dns.resolver
import requests
from whois import whois
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urlunparse, urljoin
import xml.etree.ElementTree as ET
from datetime import datetime

# # Define a custom PDF report class inheriting from FPDF
# class PDFReport(FPDF):
    
#     # Method to set the header of the PDF report
#     def header(self):
#         self.set_font('Arial', 'B', 12)  # Set the font for the header
#         self.cell(0, 10, f'Site Information Report', 0, 1, 'C')   # Add a centered title
#         self.ln(10) # Add a line break after the title

#         # Method to add a chapter title in the PDF report
#     def chapter_title(self, title): 
#         self.set_font('Arial', 'B', 14)      # Set a larger font for chapter titles
#         self.cell(0, 10, title, 0, 1, 'L')   # Add the title aligned to the left
#         self.ln(5)  # Add a smaller line break after the title

#         # Method to add the body content of a chapter in the PDF report
#     def chapter_body(self, body): 
#         self.set_font('Arial', '', 12)   # Set a regular font for the body text
#         self.multi_cell(0, 10, body)     # Add multi-line text to the cell
#         self.ln() # Add a line break after the body content

#         # Method to add a complete report section (title + body) to the PDF report
#     def add_report_section(self, title, body):
#         self.chapter_title(title)   # Add the section title
#         self.chapter_body(body)     # Add the section body


# function to check a defined list of ports to see if they are open
def tcp_connect_scan(target, ports):

    results = {}

    # Dictionary mapping commonly exploited ports to their associated services:
    service_map = {
        20: "FTP",
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        443: "HTTPS",
        137: "NetBIOS",
        139: "NetBIOS",
        445: "SMB",
        8080: "HTTP",
        8443: "HTTPS",
        1433: "SQL Server",
        1434: "SQL Server",
        3306: "MySQL",
        3389: "Remote Desktop"
    }


    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # Set a timeout for the connection attempt

        try:
            result = sock.connect_ex((target, port))
            if result == 0:
                results[port] = service_map.get(port, "Unknown Service")
        except Exception as e:
            print(f"Error scanning port {port}: {e}")
        finally:
            sock.close()

    if not results:
        print("No open vulnerable ports found.")

    return results
# function for getting port information
def portScan(Target):
    print("Checking Open Ports")
    target = Target
    vulnerable_ports = [20, 21, 22, 23, 25, 53, 137, 139, 445, 80, 443, 8080, 8443, 1433, 1434, 3306, 3389]
    
    results = tcp_connect_scan(target, vulnerable_ports)
    return results


def is_online(target):
# checks if target site is online
    try:
        ping3.ping(target)
        return True
    except Exception as e:
        return False
# function for getting DNS information
def dnsScan(Target):
    print("Gathering DNS information")
    whois_data = []
    domain = Target

    # Gathers IP information by taking the domain name as an argument
    def get_ip(domain):
        try:
            return socket.gethostbyname(domain)
        except socket.gaierror:
            return None

    # get_dns_servers retrieves the DNS servers from the provided domain
    def get_dns_servers(domain):
        try:
            answers = dns.resolver.resolve(domain, 'NS')
            return [str(rdata) for rdata in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
            return None

    if is_online(Target):
        whois_data.append(f"{Target} is online")
    else:
        whois_data.append(f"{Target} is offline")

    # Get IP address
    ip = get_ip(domain)
    if ip:
        whois_data.append(f"IP Address: {ip}\n")
    else:
        whois_data.append("IP Address: Not found\n")

    # Get DNS servers
    dns_servers = get_dns_servers(domain)
    if dns_servers:
        whois_data.append("DNS Servers: \n")
        for server in dns_servers:
            whois_data.append(f" - {server}\n")
    else:
        whois_data.append("DNS Servers: Not found\n")

    return whois_data
# function for getting whois information
def whoisScan(domain: str):
    print("Gatering whois information")
    results = []
    try:

        # Perform the WHOIS lookup using the whois module
        w = whois.whois(domain)

        # Relevant WHOIS information from given domain
        whois_info = {
            'Domain Name': w.domain_name,
            'Registrar': w.registrar,
            'Creation Date': w.creation_date,
            'Expiration Date': w.expiration_date,
            'Last Updated': w.updated_date,
            'Name Servers': w.name_servers,
            'Status': w.status,
            'Emails': w.emails,
            'DNSSEC': w.dnssec,
        }

        results.append(whois_info)

        # Return the WHOIS information
        return w, results
    except Exception as e:
        # Print an error message if an exception occurs during the lookup
        print(f"An error occurred during WHOIS lookup: {e}")

        # Return None to indicate that the lookup was unsuccessful
        return None


# Function for scanning subdomains
def subdomainScan(domain_name, subdomain_list):
    print("Scanning subdomains")

    valid_subdomains = []
    # checks subdomains against predetermined list and adds them to list if they exist
    for subdomain in subdomain_list:
        url = f"https://{subdomain}.{domain_name}"

        try:
            response = requests.get(url, timeout=5)  # Set a timeout for faster checks
            response.raise_for_status()  # Raise exception for non-2xx status codes
            valid_subdomains.append(url)
        except (requests.RequestException, requests.HTTPError) as e:
            no_connection = f"[-] Could not connect to {url}: {e}"

    return valid_subdomains if valid_subdomains else no_connection


def check_security_headers(url):
    try:
        response = requests.get(url, timeout=10)   # Send an HTTP GET request to the URL
        headers = response.headers   # Get the response headers
        
        # Define expected security headers and their respective warnings if missing
        security_headers = {
            'Content-Security-Policy': 'Content-Security-Policy header is missing',
            'Strict-Transport-Security': 'Strict-Transport-Security header is missing',
            'X-Frame-Options': 'X-Frame-Options header is missing',
            'X-Content-Type-Options': 'X-Content-Type-Options header is missing',
            'Referrer-Policy': 'Referrer-Policy header is missing',
            'Permissions-Policy': 'Permissions-Policy header is missing'
        }

        results = []
        
        # Check each security header against the actual headers received
        
        for header, warning in security_headers.items():
            if header not in headers:
                results.append(warning)   # Append the warning if header is missing
            else:
                results.append(f"{header}: {headers[header]}")  # Append the actual header value
        
        return '\n'.join(results)   # Return all results as a single string
    except requests.exceptions.RequestException as e:
        return f"Error checking security headers: {e}"   # Return error message if request fails
# Function to check for outdated software versions based on Server header
def check_outdated_software(url):
    try:
        response = requests.get(url, timeout=10)   # Send an HTTP GET request to the URL
        headers = response.headers   # Get the response headers

        results = []
        if 'Server' in headers:   # Check if Server header is present in the response
            server_header = headers['Server']   # Get the value of the Server header
            results.append(f"Server header found: {server_header}")   # Add server header info
            
            # Check for specific server types and extract their versions using regex
            if 'Apache' in server_header:
                version = re.search(r'Apache/(\d+\.\d+\.\d+)', server_header)
                if version:
                    results.append(f"Apache version detected: {version.group(1)}")
                     # Logic to check for the latest version of Apache can be added here
            elif 'nginx' in server_header:
                version = re.search(r'nginx/(\d+\.\d+\.\d+)', server_header)
                if version:
                    results.append(f"Nginx version detected: {version.group(1)}")
                    # Logic to check for the latest version of Nginx can be added here
        else:
            results.append("No Server header found")    # Add message if Server header is missing
        
        return '\n'.join(results)   # Return all results as a single string
    except requests.exceptions.RequestException as e:
        return f"Error checking outdated software: {e}"   # Return error message if request fails
# Function to check if directory listing is enabled on specified URLs
def check_directory_listing(url):
    test_urls = [url, url + '/test', url + '/test/']   # List of URLs to test for directory listing
    results = []

    for test_url in test_urls:
        try:
            response = requests.get(test_url, timeout=10)   # Send an HTTP GET request to the test URL
            if response.status_code == 200 and "Index of" in response.text:
                results.append(f"Directory listing enabled on: {test_url}")   # Add if directory listing is enabled
            else:
                results.append(f"No directory listing on: {test_url}")   # Add if directory listing is not enabled
        except requests.exceptions.RequestException as e:
            results.append(f"Error checking {test_url} for directory listing: {e}")   # Add error message if request fails
    
    return '\n'.join(results)   # Return all results as a single string
# Function to check enabled HTTP methods for a given URL
def check_http_methods(url):
    methods = ['OPTIONS', 'GET', 'POST', 'PUT', 'DELETE', 'TRACE', 'CONNECT']  # List of HTTP methods to check
    results = []
    for method in methods:
        try:
            response = requests.request(method, url, timeout=10)   # Send a request using the specified method
            if response.status_code != 405:   # Check if the method is not explicitly forbidden
                results.append(f"{method} method is enabled on {url}")   # Add if method is enabled
        except requests.exceptions.RequestException as e:
            results.append(f"Error checking {method} method: {e}")    # Add error message if request fails
    
    return '\n'.join(results)   # Return all results as a single string
# Function to check SSL/TLS versions supported by the server of a given URL
def check_ssl_tls_versions(url):
    parsed_url = urlparse(url)   # Parse the URL to get hostname and port
    hostname = parsed_url.hostname   # Extract hostname
    port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)   # Extract port, defaulting to 443 for HTTPS
    results = []

    import ssl   # Importing ssl module for SSL/TLS functionality
    import socket   # Importing socket module for network communication

    context = ssl.create_default_context()   # Create a default SSL context
    context.set_ciphers('ALL:@SECLEVEL=0')   # Set custom cipher suites (for testing purposes)
    
    try:
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                results.append(f"SSL/TLS version for {url}: {ssock.version()}")    # Add SSL/TLS version info
    except Exception as e:
        results.append(f"Failed to establish SSL/TLS connection: {e}")   # Add error message if connection fails
     
    return '\n'.join(results)   # Return all results as a single string
# Function to check cookie security attributes (Secure and HttpOnly) for a given URL
def check_cookie_security(url):
    try:
        response = requests.get(url, timeout=10)   # Send an HTTP GET request to the URL
        cookies = response.cookies   # Get the cookies from the response
        results = []

        for cookie in cookies:   # Iterate over each cookie
            if not cookie.secure:   # Check if the cookie is not marked as Secure
                results.append(f"Cookie {cookie.name} is missing the Secure attribute")    # Add if Secure attribute is missing
            if not cookie.has_nonstandard_attr('HttpOnly'):   # Check if the cookie is not marked as HttpOnly
                results.append(f"Cookie {cookie.name} is missing the HttpOnly attribute")   # Add if HttpOnly attribute is missing
        
        return '\n'.join(results)   # Return all results as a single string
    except requests.exceptions.RequestException as e:
        return f"Error checking cookie security: {e}"   # Return error message if request fails
# function to check common vulnerbilities

def vulnerbilityScan(target):
    print("Scanning for vulnerbilities")
# blend of OWASP & Vulnbilites reports
    return


# function that crawls all site specific urls and then creates an XML site map
def siteMap(url, default_protocol="https", priority=1.0):
    print("Creating site map")

    #stores visited URLs
    visited_urls = set()
    root = ET.Element("urls")


    def visit(url, priority):
        visited_urls.add(url)

        url_element = ET.SubElement(root, "url")
        url_element.text = url

        # Add priority element
        priority_element = ET.SubElement(url_element, "priority")
        priority_element.text = str(priority)

        try:
            response = requests.get(url)
            if response.status_code == 200:
                # Get the Last-Modified header, if available
                last_modified = response.headers.get('Last-Modified')
                if last_modified:
                    date_modified = datetime.strptime(last_modified, '%a, %d %b %Y %H:%M:%S %Z')
                else:
                    date_modified = datetime.now()

                # Add date modified element
                date_modified_element = ET.SubElement(url_element, "date_modified")
                date_modified_element.text = date_modified.isoformat()

                soup = BeautifulSoup(response.content, features="xml")  # Using XML parser
                all_links = soup.find_all('a')

                for link in all_links:
                    href = link.get('href')
                    if href:
                        absolute_url = urljoin(url, href)

                        if absolute_url not in visited_urls and absolute_url.startswith(url):
                            visit(absolute_url, priority)
            else:
                print("Error:", response.status_code)
        except requests.exceptions.RequestException as e:
            print("Error:", str(e))

    # Add protocol if not present
    if not url.startswith("http"):
        url = f"{default_protocol}://{url}"

    visit(url, priority)

    # function that strips characters that are not allowed in filenames
    def get_safe_filename(url):
        # Remove protocol and www
        url = re.sub(r"^https?://(www\.)?", "", url)
        # Remove characters not allowed in filenames
        filename = re.sub(r"[^\w\-_. ]", "_", url)
        return filename.strip("_ ")  # Remove leading/trailing whitespace and underscores

    
    filename = f"{get_safe_filename(url)}_site_map.xml"

    # Save to XML file
    tree = ET.ElementTree(root)
    with open(filename, "wb") as f:
        tree.write(f, encoding='utf-8', xml_declaration=True)
    
    print(f"Site Map complete. Report saved to {filename}\n")


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
    
    pdf = fpdf.FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="------------- Target Information -------------\n\n", ln=1)
    
    if userChoice.lower() == "1" or "port scan":
        port_scan_report = portScan(userTarget)
        if port_scan_report:
            pdf.cell(200, 10, txt="\n\n------------- Open Ports -------------\n\n", ln=1)
            for port, service in port_scan_report.items():
                pdf.cell(200, 10, txt=f"Port {port} ({service}) is open", ln=1)
        else:
            pdf.cell(200, 10, txt="No open ports found", ln=1)

    if userChoice.lower() == "2" or "dns scan":
        dnsScan(userTarget)

    if userChoice.lower() == "3" or "whois scan":
        whoisScan(userTarget)

    if userChoice.lower() == "4" or "subdomain scan":
        subdomainScan(userTarget)
        # check subdomain function for second function that may help
        # prbably need to combine

    if userChoice.lower() == "5" or "vulnerbility scan":
        vulnerbilityScan(userTarget)

    if userChoice.lower() == "6" or "1-5 scan" or "scan all":

        portScan(userTarget)
        dnsScan(userTarget)
        whoisScan(userTarget)
        subdomainScan(userTarget)
        vulnerbilityScan(userTarget)
    if userChoice.lower() == "7" or "sitemap" or "site map":
        siteMap(userTarget)

