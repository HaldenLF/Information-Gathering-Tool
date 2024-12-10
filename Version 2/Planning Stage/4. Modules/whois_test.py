import socket
import requests
import whois
import geoip2.database

def get_site_info(domain):
    # Get site and domain name
    w = whois.whois(domain)
    site_name = w.name if w.name else "N/A"
    domain_name = w.domain_name if w.domain_name else domain

    # Get IP address
    ip_address = socket.gethostbyname(domain)

    # Get cloud server host name
    try:
        response = requests.get(f"https://api.ipgeolocation.io/ipgeo?apiKey=YOUR_API_KEY&ip={ip_address}")
        cloud_host_name = response.json().get('isp', 'N/A')
    except Exception as e:
        cloud_host_name = "N/A"

    # Get location
    try:
        # Download the GeoLite2 City database from MaxMind
        reader = geoip2.database.Reader('GeoLite2-City.mmdb')
        response = reader.city(ip_address)
        location = f"{response.city.name}, {response.subdivisions.most_specific.name}, {response.country.name}"
    except Exception as e:
        location = "N/A"

    return {
        "Site Name": site_name,
        "Domain Name": domain_name,
        "IP Address": ip_address,
        "Cloud Server Host Name": cloud_host_name,
        "Location": location
    }

if __name__ == "__main__":
    domain = "facebook.com"  # Replace with the desired domain
    info = get_site_info(domain)
    for key, value in info.items():
        print(f"{key}: {value}")