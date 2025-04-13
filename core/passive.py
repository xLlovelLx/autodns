import requests

def passive_enum(domain, output_file, verbose, all_engines):
    print(f"Performing passive enumeration for {domain}...")
    results = []

    # List of engines to query
    engines = [
        {"name": "VirusTotal", "url": f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains", "headers": {"x-apikey": "YOUR_API_KEY"}},
        {"name": "AlienVault", "url": f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns", "headers": {}},
        {"name": "Shodan", "url": f"https://api.shodan.io/dns/domain/{domain}?key=YOUR_API_KEY", "headers": {}},
    ]

    if not all_engines:
        engines = engines[:1]  # Use the first engine if --all-engines is not specified

    for engine in engines:
        if verbose:
            print(f"Querying {engine['name']}...")
        try:
            response = requests.get(engine["url"], headers=engine["headers"])
            if response.status_code == 200:
                data = response.json()
                # Parse subdomains based on the engine's response structure
                if engine["name"] == "VirusTotal":
                    results += [item["id"] for item in data.get("data", [])]
                elif engine["name"] == "AlienVault":
                    results += [entry["hostname"] for entry in data.get("passive_dns", [])]
                elif engine["name"] == "Shodan":
                    results += data.get("subdomains", [])
            elif verbose:
                print(f"{engine['name']} returned status code {response.status_code}")
        except Exception as e:
            if verbose:
                print(f"Error querying {engine['name']}: {e}")

    # Remove duplicates
    results = list(set(results))

    # Save results to file
    with open(output_file, "w") as f:
        f.write("\n".join(results))
    print(f"Passive enumeration results saved to {output_file}")