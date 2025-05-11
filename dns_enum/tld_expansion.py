import tldextract


def tld_expand(domain, tlds_path, verbose):
    """
    Expand the given domain across multiple TLDs (Top-Level Domains).
    """
    extracted = tldextract.extract(domain)
    stripped_domain = f"{extracted.domain}"
    
    print(f"Expanding domain {stripped_domain} across multiple TLDs...")

    try:
        with open(tlds_path, "r") as f:
            tlds = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"Error loading TLDs: {e}")
        return []
    

    expanded_domains = [f"{stripped_domain}.{tld}" for tld in tlds]

    if verbose:
        for expanded in expanded_domains:
            print(f"Expanded: {expanded}")
            

    print(f"Total TLD expansions: {len(expanded_domains)}")
    return expanded_domains

def validate_domains(domains):
    """
    Validate a list of domains to ensure they follow the correct DNS format.
    """
    valid_domains = []
    for domain in domains:
        if "." in domain and not domain.startswith("-") and not domain.endswith("-"):
            valid_domains.append(domain)
        else:
            print(f"Invalid domain: {domain}")
    return valid_domains