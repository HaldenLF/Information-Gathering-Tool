# Chris Sowmya

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import xml.etree.ElementTree as ET
from datetime import datetime
import re

# function that crawls all site specific urls and then creates an XML site map
def crawl_and_create_site_map(url, default_protocol="https", priority=1.0):
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
