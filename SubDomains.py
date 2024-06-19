# Liam and Lisa

import requests

# Function for scanning subdomains
def scan_subdomains(domain_name, subdomain_list):

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

def subdomain_scan_results(target):
    target_domain = target

    # Read subdomains from a file
    with open("subdomain_names.txt", "r") as subdomain_file:
        subdomains = subdomain_file.read().splitlines()

    # Scan for subdomains and store results
    scan_results = scan_subdomains(target_domain, subdomains)

    if isinstance(scan_results, str):
        return {"message": scan_results}  # Return error message in a dictionary
    else:
        found_subdomains = scan_results
        scan_finished = f"\nScan completed. Found {len(found_subdomains)} valid subdomains.\n"
        return {"message": scan_finished, "subdomains": found_subdomains} 