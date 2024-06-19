from TechnicalInfo import get_tech_info
from PortScan import port_scan
from SubDomains import subdomain_scan_results 
from DNS_results import DNSLookUp
from whois import whois
import fpdf
import re


def get_safe_filename(url):
    # Remove protocol and www (optional, adjust if needed)
    url = re.sub(r"^https?://(www\.)?", "", url)
    # Remove characters not allowed in filenames
    filename = re.sub(r"[^\w\-_. ]", "_", url)
    return filename.strip("_ ")  # Remove leading/trailing whitespace and underscores


def get_site_info_report(target):
    print("Gathering site information")

    safe_filename = get_safe_filename(target)
    filename = f"{safe_filename}_Summary"

        # Create a new PDF document
    pdf = fpdf.FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=10)

    # Technical information scan
    tech_scan_report = get_tech_info(target)
    if tech_scan_report:
        pdf.cell(200, 10, txt="------------- Technical Information -------------", ln=1)
        for info in tech_scan_report:
            pdf.cell(200, 10, txt=info, ln=1)
    else:
        pdf.cell(200, 10, txt="No technical information found", ln=1)

    # Port scan
    port_scan_report = port_scan(target)
    if port_scan_report:
        pdf.cell(200, 10, txt="\n\n------------- Open Ports -------------\n\n", ln=1)
        for port, service in port_scan_report.items():
            pdf.cell(200, 10, txt=f"Port {port} ({service}) is open", ln=1)
    else:
        pdf.cell(200, 10, txt="No open ports found", ln=1)


    # Subdomain scan
    subdomain_scan_report = subdomain_scan_results(target)
    if subdomain_scan_report:
        pdf.cell(200, 10, txt="\n\n------------- Subdomains -------------\n\n", ln=1)
        if "subdomains" in subdomain_scan_report:
            for subdomain in subdomain_scan_report["subdomains"]:
                pdf.cell(200, 10, txt=f"{subdomain}\n", ln=1)
        else:
            pdf.cell(200, 10, txt="No subdomains found\n", ln=1)
    else:
        pdf.cell(200, 10, txt=f"Error: {subdomain_scan_report['message']}\n", ln=1)


    # DNS scan
    dns_scan_report = DNSLookUp(target)
    if dns_scan_report:
        pdf.cell(200, 10, txt="\n\n------------- DNS -------------\n\n", ln=1)
        for dns in dns_scan_report:
            pdf.cell(200, 10, txt=f"{dns}.\n", ln=1)
    else:
        pdf.cell(200, 10, txt="DNS information not found.\n", ln=1)   # WHOIS & DNS lookup


    whois_info = whois(target)

    # Who is scan
    if whois_info:
        pdf.cell(200, 10, txt="\n\n------------- WHOIS Information -------------\n\n", ln=1)
        for key, value in whois_info.items():
            pdf.cell(200, 10, txt=f"{key}: {value}\n", ln=1)
    else:
        pdf.cell(200, 10, txt="WHOIS information not found.\n", ln=1)

    pdf.output(filename + ".pdf")
    print(f"Site information scan complete. Report saved to {filename}\n")
