import whois
import dns.resolver
from ping3 import ping
import requests
import logging

# Constants
IPINFO_API_URL = "https://ipinfo.io/"

# Set up logging
logging.basicConfig(level=logging.INFO)

def get_whois_info(domain):
    try:
        whois_info = whois.whois(domain)
        return {
            "Site Name": whois_info.name or whois_info.domain_name,
            "Domain Name": whois_info.domain_name,
            "DNSSEC": whois_info.dnssec,
            "Emails": whois_info.emails,
        }
    except Exception as e:
        logging.error(f"WHOIS lookup failed: {e}")
        return {}

def get_dns_info(domain):
    try:
        answers = dns.resolver.resolve(domain, 'A')
        ip_address = answers[0].to_text()
        return {
            "IP Address": ip_address,
            "Cloud Server Host Name": domain,
            "Name Servers": [server.target.to_text() for server in dns.resolver.resolve(domain, 'NS')],
        }
    except Exception as e:
        logging.error(f"DNS lookup failed: {e}")
        return {}

def get_location_info(ip_address):
    try:
        response = requests.get(f"{IPINFO_API_URL}{ip_address}/json")
        if response.status_code == 200:
            ipinfo_data = response.json()
            return {
                "City": ipinfo_data.get("city"),
                "Region": ipinfo_data.get("region"),
                "Country": ipinfo_data.get("country"),
                # "Latitude": ipinfo_data.get("loc").split(",")[0] if ipinfo_data.get("loc") else None,
                # "Longitude": ipinfo_data.get("loc").split(",")[1] if ipinfo_data.get("loc") else None,
            }
        else:
            return "Location lookup failed"
    except Exception as e:
        logging.error(f"Location lookup failed: {e}")
        return {}

def get_ping_info(ip_address):
    try:
        response = ping(ip_address)
        if response is not None:
            return f"Server is reachable, round trip time: {response * 1000:.2f} ms"
        else:
            return "Server is not reachable"
    except Exception as e:
        logging.error(f"Ping failed: {e}")
        return ""


def main():
    domain = input("Enter a domain: ")
    whois_info = get_whois_info(domain)
    dns_info = get_dns_info(domain)
    location_info = get_location_info(dns_info.get("IP Address"))
    ping_info = get_ping_info(dns_info.get("IP Address"))

    print("WHOIS Info:")
    print(whois_info)
    print("DNS Info:")
    print(dns_info)
    print("Location Info:")
    print(location_info)
    print("Ping Info:")
    print(ping_info)

if __name__ == "__main__":
    main()