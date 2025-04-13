import requests
from lxml import etree

def osint_enum(domain, verbose):
    print(f"Performing OSINT-based enumeration for {domain}...")

    # Example: crt.sh scraping
    url = f'https://crt.sh/?q=%25.{domain}'
    headers = {'User-Agent': 'Mozilla/5.0'}
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        print("Failed to fetch data from crt.sh")
        return

    # Parse subdomains from crt.sh
    root = etree.HTML(response.content)
    subdomains = root.xpath('//table/tr/td/table/tr/td[5]/text()')
    unique_subdomains = set(sub.strip() for sub in subdomains if sub.endswith(f".{domain}"))

    if verbose:
        for sub in unique_subdomains:
            print(f"Found: {sub}")

    print(f"Total subdomains found: {len(unique_subdomains)}")