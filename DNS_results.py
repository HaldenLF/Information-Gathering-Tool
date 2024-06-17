# WHOIS & DNS Lookup Script
# Developed & Modified by Danny, Daniel, Jaider, Reduan, & Tris


# Import the socket, dns resolver, and whois module
import socket
import dns.resolver
from whois import whois


whois_data = [] # varaible to store all results

def DNSLookUp(Target):

    # URL to pull DNS servers from
    # domain = Target.split("//")[1].split("/")[0]

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


    # print(f"Gathering information for: {domain}")

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

    def whois_lookup(domain: str):
        results = []
        try:
            # # Inform the user that the WHOIS lookup is being performed
            # print(f"Performing WHOIS lookup for {domain}...")

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

            # # Print the retrieved WHOIS information
            # print("WHOIS Information:")
            # print(w)
            # print(whois_info)

            # Return the WHOIS information
            return w, results
        except Exception as e:
            # Print an error message if an exception occurs during the lookup
            print(f"An error occurred during WHOIS lookup: {e}")

            # Return None to indicate that the lookup was unsuccessful
            return None
        
    return whois_data
