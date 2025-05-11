import requests
from lxml import etree

def securitytrails_enum(domain, api_key, verbose=False):
    """
    Enumerate subdomains using the SecurityTrails API.
    """
    url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
    headers = {"APIKEY": api_key}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            subdomains = response.json().get("subdomains", [])
            if verbose:
                for sub in subdomains:
                    print(f"Found subdomain: {sub}.{domain}")
            return [f"{sub}.{domain}" for sub in subdomains]
        else:
            print(f"SecurityTrails API error: {response.status_code}")
            return []
    except Exception as e:
        print(f"Error querying SecurityTrails: {e}")
        return []
def threatcrowd_enum(domain, api_key, verbose=False):
    """
    Enumerate subdomains using the ThreatCrowd API.
    """
    url = f"https://threatcrowd.org/api/v3/domainReport/1.0/{domain}"
    headers = {"TC_APIKEY": api_key}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            subdomains = data.get("subdomains", [])
            if verbose:
                for sub in subdomains:
                    print(f"Found subdomain: {sub}.{domain}")
            return [f"{sub}.{domain}" for sub in subdomains]
        else:
            print(f"ThreatCrowd API error: {response.status_code}")
            return []
    except Exception as e:
        print(f"Error querying ThreatCrowd: {e}")
        return []

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