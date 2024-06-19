import requests    # Importing the requests library to make HTTP requests
import re    # Importing the re library for regular expressions
from urllib.parse import urlparse    # Importing urlparse from urllib.parse to parse URLs
from fpdf import FPDF    # Importing FPDF for generating PDF reports


# Define a custom PDF report class inheriting from FPDF
class PDFReport(FPDF):
    
    # Method to set the header of the PDF report
    def header(self):
        self.set_font('Arial', 'B', 12)  # Set the font for the header
        self.cell(0, 10, 'Vulnerability Scan Report', 0, 1, 'C')   # Add a centered title
        self.ln(10) # Add a line break after the title

        # Method to add a chapter title in the PDF report
    def chapter_title(self, title): 
        self.set_font('Arial', 'B', 14)      # Set a larger font for chapter titles
        self.cell(0, 10, title, 0, 1, 'L')   # Add the title aligned to the left
        self.ln(5)  # Add a smaller line break after the title

        # Method to add the body content of a chapter in the PDF report
    def chapter_body(self, body): 
        self.set_font('Arial', '', 12)   # Set a regular font for the body text
        self.multi_cell(0, 10, body)     # Add multi-line text to the cell
        self.ln() # Add a line break after the body content

        # Method to add a complete report section (title + body) to the PDF report
    def add_report_section(self, title, body):
        self.chapter_title(title)   # Add the section title
        self.chapter_body(body)     # Add the section body


# Function to check security headers of a given URL
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
    

# # Function to check for vulnerabilities related to specific Content Management Systems (CMSs)
# def check_cms_vulnerabilities(url):
#     try:
#         response = requests.get(url, timeout=10)   # Send an HTTP GET request to the URL
#         results = []
#         if "wp-content" in response.text:   # Check if WordPress specific content is present in the response HTML
#             results.append("WordPress CMS detected")   # Add message indicating WordPress CMS detected
#             # Add logic to check for known WordPress vulnerabilities
#         elif "Joomla!" in response.text:    # Check if Joomla specific content is present in the response HTML
#             results.append("Joomla CMS detected")
#             # Add logic to check for known Joomla vulnerabilities
#         # Add checks for other CMSs as needed
        
#         return '\n'.join(results)   # Return all results as a single string
#     except requests.exceptions.RequestException as e:
#         return f"Error checking CMS vulnerabilities: {e}"   # Return error message if request fails


def get_vulnerbility_Results(target):
    print("Scanning for vulnerbilities")
    url = target
    if not url.startswith('http'):   # Check if the URL does not start with 'http'
        url = 'http://' + url

    parsed_url = urlparse(url)   # Parse the URL to extract components like hostname
    hostname = parsed_url.hostname   # Get the hostname from the parsed URL
    pdf_filename = f"{hostname}_vulnerability_scan_report.pdf"  # Construct PDF file name based on hostname

    pdf = PDFReport()   # Create an instance of the PDFReport class for generating the report
    pdf.add_page()   # Add a new page to the PDF document

    all_results = ""   # Initialize a variable to store all scan results as a single string

    # Perform various checks and collect results for each section

    headers_result = check_security_headers(url)   # Check security headers and get results
    all_results += "\nSecurity Headers:\n" + headers_result + "\n"   # Append results to the all_results variable

    software_result = check_outdated_software(url)   # Check for outdated software versions and get results
    all_results += "\nOutdated Software Versions:\n" + software_result + "\n"   # Append results to all_results

    directory_listing_result = check_directory_listing(url)   # Check for directory listing and get results
    all_results += "\nDirectory Listing:\n" + directory_listing_result + "\n"  # Append results to all_results

    http_methods_result = check_http_methods(url)   # Check enabled HTTP methods and get results
    all_results += "\nHTTP Methods:\n" + http_methods_result + "\n"   # Append results to all_results

    ssl_tls_result = check_ssl_tls_versions(url)   # Check SSL/TLS versions and get results
    all_results += "\nSSL/TLS Versions:\n" + ssl_tls_result + "\n"   # Append results to all_results

    cookie_security_result = check_cookie_security(url)   # Check cookie security attributes and get results
    all_results += "\nCookie Security:\n" + cookie_security_result + "\n"   # Append results to all_results

    # cms_vulnerabilities_result = check_cms_vulnerabilities(url)   # Check for CMS vulnerabilities and get results
    # all_results += "\nCMS Vulnerabilities:\n" + cms_vulnerabilities_result + "\n"   # Append results to all_results


    # Add each section with its title and body to the PDF report
    pdf.add_report_section("Security Headers", headers_result)
    pdf.add_report_section("Outdated Software Versions", software_result)
    pdf.add_report_section("Directory Listing", directory_listing_result)
    pdf.add_report_section("HTTP Methods", http_methods_result)
    pdf.add_report_section("SSL/TLS Versions", ssl_tls_result)
    pdf.add_report_section("Cookie Security", cookie_security_result)
    # pdf.add_report_section("CMS Vulnerabilities", cms_vulnerabilities_result)


    # Generate the PDF report with all collected sections
    pdf.output(pdf_filename)   # Output the PDF report with the specified filename
    print(f"\nVulnerbility scan complete. Report saved to {pdf_filename}")  # Print confirmation message with the filename
