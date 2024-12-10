# Requires user to set up API key
# Free API has limitations on amount of queries in a short space of time

import shodan
import os

shodan_API_key = os.getenv('Shodan_API_Key')

# Initialize the Shodan client
api = shodan.Shodan(shodan_API_key)

# Function to get information about a specific IP address or domain
def get_info(query):
    try:
        result = api.search(query)

        # Check for matches
        if not result['matches']:
            print("No results found for the query.")
            return

        for service in result['matches']:
            site_name = service.get('hostnames', ['N/A'])[0]  # Get hostname or 'N/A'
            domain_name = service.get('domain', 'N/A')  # Get domain or 'N/A'
            ip_address = service['ip_str']  # Get IP address
            cloud_host_name = service.get('org', 'N/A')  # Get cloud host name or 'N/A'
            location = service.get('location', {}).get('city', 'N/A') + ', ' + service.get('location', {}).get('country_name', 'N/A')  # Get location

            # Print the information
            print(f"Site Name: {site_name}")
            print(f"Domain Name: {domain_name}")
            print(f"IP Address: {ip_address}")
            print(f"Cloud Server Host Name: {cloud_host_name}")
            print(f"Location: {location}")
            print("-" * 40)

    except shodan.APIError as e:
        print(f"Error: {e}")
