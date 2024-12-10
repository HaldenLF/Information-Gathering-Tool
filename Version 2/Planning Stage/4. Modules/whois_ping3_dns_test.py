import whois
import dns.resolver
from ping3 import ping
import requests

def get_site_info(domain):
    # Initialize the result dictionary
    site_info = {}

    # WHOIS Lookup
    try:
        w = whois.whois(domain)
        site_info["Site Name"] = w.name or w.domain_name
        site_info["Domain Name"] = w.domain_name
    except Exception as e:
        print(f"WHOIS lookup failed: {e}")

    # DNS Lookup
    try:
        # Get A record (IP address)
        answers = dns.resolver.resolve(domain, 'A')
        ip_address = answers[0].to_text()
        site_info["IP Address"] = ip_address

        # Get the cloud server host name (if available)
        site_info["Cloud Server Host Name"] = domain  # This may not be directly available
    except Exception as e:
        print(f"DNS lookup failed: {e}")

    # Ping to check if the server is reachable
    try:
        response = ping(ip_address)
        if response is not None:
            site_info["Ping"] = f"Server is reachable, round trip time: {response * 1000:.2f} ms"
        else:
            site_info["Ping"] = "Server is not reachable"
    except Exception as e:
        print(f"Ping failed: {e}")

    # Location (using IP address)
    try:
        ipinfo_api_url = f"https://ipinfo.io/{ip_address}/json"
        response = requests.get(ipinfo_api_url)
        if response.status_code == 200:
            ipinfo_data = response.json()
            site_info["Location"] = {
                "City": ipinfo_data.get("city"),
                "Region": ipinfo_data.get("region"),
                "Country": ipinfo_data.get("country"),
                "Latitude": ipinfo_data.get("loc").split(",")[0] if ipinfo_data.get("loc") else None,
                "Longitude": ipinfo_data.get("loc").split(",")[1] if ipinfo_data.get("loc") else None,
            }
        else:
            site_info["Location"] = "Location lookup failed"
    except Exception as e:
        print(f"Location lookup failed: {e}")

    return site_info

# Example usage
domain = "example.com"  # Replace with the desired domain
info = get_site_info(domain)
print(info)