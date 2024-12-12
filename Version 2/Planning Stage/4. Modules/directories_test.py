import requests
from bs4 import BeautifulSoup

response = requests.get('http://facebook.com')
soup = BeautifulSoup(response.text, 'html.parser')
directories = []
for link in soup.find_all('a'):
    url = link.get('href')
    if url and url.endswith('/'):
        directories.append(url)
print(directories)