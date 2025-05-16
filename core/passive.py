import requests
from dns_enum.osint import securitytrails_enum, threatcrowd_enum, osint_enum
from scripts.config_loader import load_config
from dns_enum.console_output import color_print, ConsoleColors

def passive_enum(domain, output_file, verbose, all_engines):
    print(f"Performing passive enumeration for {domain}...")
    results = {}
    api_keys = load_config()['api_keys']
    
    # List of engines to query
    engines = [
        {"name": "VirusTotal", "url": f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains", "headers": {"x-apikey": "API_KEY"}},
        {"name": "AlienVault", "url": f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns", "headers": {}},
        {"name": "Shodan", "url": f"https://api.shodan.io/dns/domain/{domain}?key=API_KEY", "headers": {}},
        {"name": "SecurityTrails", "url": f"https://api.securitytrails.com/v1/domain/{domain}/subdomains?apikey={api_keys.get("securitytrails")}", "headers": {"accept": "application/json"}},
        {"name": "ThreatCrowd", "url": f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}", "headers": {}},
        {"name": "Crt.sh", "url": f"https://crt.sh/?q=%25.{domain}&output=json", "headers": {}},
        {"name": "DNSDumpster", "url": f"https://dnsdumpster.com/api/searchresult/{domain}", "headers": {}},
        {"name": "Spyse", "url": f"https://api.spyse.com/v4/data/domain/subdomains?domain={domain}&api_key=API_KEY", "headers": {}},
        {"name": "Censys", "url": f"https://search.censys.io/api/v2/hosts/{domain}/subdomains", "headers": {"Authorization": "Basic API_KEY"}},
        {"name": "PassiveTotal", "url": f"https://api.passivetotal.org/v2/enumerate/subdomains?query={domain}", "headers": {"API_KEY": "API_KEY"}},
        {"name": "DNSDB", "url": f"https://api.dnsdb.info/lookup/rrset/name/{domain}", "headers": {"API_KEY": "API_KEY"}},
        {"name": "Sublist3r", "url": f"https://api.sublist3r.com/search?domain={domain}", "headers": {}},
        {"name": "CertSpotter", "url": f"https://api.certspotter.com/v1/issuances?domain={domain}", "headers": {}},
        {"name": "HackerTarget", "url": f"https://api.hackertarget.com/hostsearch/?q={domain}", "headers": {}},
        {"name": "DNSRecon", "url": f"https://dnsrecon.com/api/v1/subdomains/{domain}", "headers": {}},
        {"name": "Subfinder", "url": f"https://api.subfinder.io/v1/domain/{domain}", "headers": {}},
        {"name": "FindSubdomains", "url": f"https://api.findsubdomains.com/subdomains/{domain}", "headers": {}},
        {"name": "ThreatMiner", "url": f"https://api.threatminer.org/v2/domain.php?q={domain}&rt=1", "headers": {}},
        {"name": "DNSlytics", "url": f"https://api.dnslytics.com/v1/subdomains/{domain}", "headers": {}},
        {"name": "Spyse", "url": f"https://api.spyse.com/v4/data/domain/subdomains?domain={domain}&api_key=API_KEY", "headers": {}},
        {"name": "SecurityTrails", "url": f"https://api.securitytrails.com/v1/domain/{domain}/subdomains", "headers": {"APIKEY": "API_KEY"}},
        {"name": "Censys", "url": f"https://search.censys.io/api/v2/hosts/{domain}/subdomains", "headers": {"Authorization": "Basic API_KEY"}},
        {"name": "PassiveTotal", "url": f"https://api.passivetotal.org/v2/enumerate/subdomains?query={domain}", "headers": {"API_KEY": "API_KEY"}},
        {"name": "DNSDB", "url": f"https://api.dnsdb.info/lookup/rrset/name/{domain}", "headers": {"API_KEY": "API_KEY"}},
        {"name": "Sublist3r", "url": f"https://api.sublist3r.com/search?domain={domain}", "headers": {}},
        {"name": "CertSpotter", "url": f"https://api.certspotter.com/v1/issuances?domain={domain}", "headers": {}},
        {"name": "HackerTarget", "url": f"https://api.hackertarget.com/hostsearch/?q={domain}", "headers": {}},
        {"name": "DNSRecon", "url": f"https://dnsrecon.com/api/v1/subdomains/{domain}", "headers": {}},
        {"name": "Subfinder", "url": f"https://api.subfinder.io/v1/domain/{domain}", "headers": {}},
        {"name": "FindSubdomains", "url": f"https://api.findsubdomains.com/subdomains/{domain}", "headers": {}},
        {"name": "ThreatMiner", "url": f"https://api.threatminer.org/v2/domain.php?q={domain}&rt=1", "headers": {}},
        {"name": "DNSlytics", "url": f"https://api.dnslytics.com/v1/subdomains/{domain}", "headers": {}}
        
    ]

    if not all_engines:
        engines = engines[:1]  # Use the first engine if --all-engines is not specified

    for engine in engines:
        if verbose:
            color_print(f"Querying {engine['name']}...",ConsoleColors.OKBLUE)
        try:
            
            response = requests.get(engine["url"], headers=engine["headers"])
            # Check if the response is valid
            if response.status_code == 403:
                color_print(f"API key for {engine['name']} is invalid or missing.",ConsoleColors.FAIL)
                continue
            elif response.status_code == 401:
                color_print(f"Unauthorized access to {engine['name']}. Check your API key.",ConsoleColors.FAIL)
                continue
            elif response.status_code == 429:
                color_print(f"Rate limit exceeded for {engine['name']}. Try again later.",ConsoleColors.FAIL)
                continue
            elif response.status_code == 404:
                color_print(f"Resource not found for {engine['name']}. Check the URL.",ConsoleColors.FAIL)
                continue
            elif response.status_code == 500:
                color_print(f"Server error for {engine['name']}. Try again later.",ConsoleColors.FAIL)
                continue
            elif response.status_code == 503:
                color_print(f"Service unavailable for {engine['name']}. Try again later.",ConsoleColors.FAIL)
                continue
            
            if response.status_code == 200:
                color_print(f"Successfully queried {engine['name']}.",ConsoleColors.OKGREEN)
                data = response.json()
                # Parse subdomains based on the engine's response structure
                if engine["name"] == "VirusTotal":
                    results["VirusTotal"] += [item["id"] for item in data.get("data", [])]
                elif engine["name"] == "AlienVault":
                    results["AlienVault"] += [entry["hostname"] for entry in data.get("passive_dns", [])]
                elif engine["name"] == "Shodan":
                    results["Shodan"] += data.get("subdomains", [])
                elif engine["name"] == "SecurityTrails":
                    results["SecurityTrails"]=[f"{sub}.{domain}" for sub in data.get("subdomains", [])]
                elif engine["name"] == "ThreatCrowd":
                    results["ThreatCrowd"] += [item["domain"] for item in data.get("subdomains", [])]
                elif engine["name"] == "Crt.sh":
                    results["Crt.sh"] += [item["name_value"] for item in data]
                elif engine["name"] == "DNSDumpster":
                    results["DNSDumpster"] += [item["domain"] for item in data.get("subdomains", [])]
                elif engine["name"] == "Spyse":
                    results["Spyse"] += [item["domain"] for item in data.get("subdomains", [])]
                elif engine["name"] == "Censys":
                    results["Censys"] += [item["subdomain"] for item in data.get("subdomains", [])]
                elif engine["name"] == "PassiveTotal":
                    results["PassiveTotal"] += [item["subdomain"] for item in data.get("subdomains", [])]
                elif engine["name"] == "DNSDB":
                    results["DNSDB"] += [item["name"] for item in data.get("rrset", [])]
                elif engine["name"] == "Sublist3r":
                    results["Sublist3r"] += [item["subdomain"] for item in data.get("subdomains", [])]
                elif engine["name"] == "CertSpotter":
                    results["CertSpotter"] += [item["common_name"] for item in data.get("issuances", [])]
                elif verbose:
                    color_print(f"{engine['name']} returned status code {response.status_code}",ConsoleColors.FAIL)
            
        except Exception as e:
            if verbose:
                color_print(f"Error querying {engine['name']}: {e}",ConsoleColors.WARNING)

    

    # Save results to file
    """with open(output_file, "w") as f:
        f.write("\n".join(results))
    print(f"Passive enumeration results saved to {output_file}")"""
    
    return results
