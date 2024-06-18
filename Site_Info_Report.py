from TechnicalInfo import get_tech_info
from PortScan import port_scan
from SubDomains import subdomain_scan_results 
from DNS_results import DNSLookUp
from whois import whois
from fpdf import FPDF
import re


def get_safe_filename(url):
    # Remove protocol and www (optional, adjust if needed)
    url = re.sub(r"^https?://(www\.)?", "", url)
    # Remove characters not allowed in filenames
    filename = re.sub(r"[^\w\-_. ]", "_", url)
    return filename.strip("_ ")  # Remove leading/trailing whitespace and underscores

target = get_safe_filename(input("What webpage would you like to investigate?: \n"
                                  "(Use the format 'example.com')\n"
                                  "> "))

safe_filename = get_safe_filename(target)
filename = f"{safe_filename}_Summary.pdf"
with open(filename, 'w', encoding="utf-8") as f:  # Write data to file


    # Technical information scan
    tech_scan_report = get_tech_info(target)
    if tech_scan_report:
        f.write("------------- Technical Information -------------\n\n")
        for info in tech_scan_report:
            f.write(f"{info}\n")
    else:
        f.write("No technical information found\n")    


    # Port scan
    port_scan_report = port_scan(target)
    if port_scan_report:
        f.write("\n\n------------- Open Ports -------------\n\n")
        for port, service in port_scan_report.items():
            f.write(f"Port {port} ({service}) is open\n")
    else:
        f.write("No open ports found\n")


    # Subdomain scan
    subdomain_scan_report = subdomain_scan_results(target)
    if subdomain_scan_report:
        f.write("\n\n------------- Subdomains -------------\n\n")
        if "subdomains" in subdomain_scan_report:
            for subdomain in subdomain_scan_report["subdomains"]:
                f.write(f"{subdomain}\n")
        else:
            f.write("No subdomains found\n")
    else:
        f.write(f"Error: {subdomain_scan_report['message']}\n")


    # DNS scan
    dns_scan_report = DNSLookUp(target)
    if dns_scan_report:
        f.write("\n\n------------- DNS -------------\n\n")
        for dns in dns_scan_report:
            f.write(f"{dns}.\n")
    else:
        f.write("DNS information not found.\n")    # WHOIS & DNS lookup


    whois_info = whois(target)

    # Who is scan
    if whois_info:
        f.write("\n\n------------- WHOIS Information -------------\n\n")
        for key, value in whois_info.items():
            f.write(f"{key}: {value}\n")
    else:
        f.write("WHOIS information not found.\n")

