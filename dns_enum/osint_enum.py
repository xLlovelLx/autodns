from dns_enum.error_handling import ErrorHandler

def crtsh_enum(domain, verbose=False):
    """
    Enumerate subdomains using crt.sh (Certificate Transparency logs).
    """
    try:
        # Validate domain
        ErrorHandler.validate_domain(domain)

        print(f"Querying crt.sh for subdomains of {domain}...")

        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        response = requests.get(url, timeout=10)

        if response.status_code == 200:
            results = response.json()
            subdomains = set(entry['name_value'] for entry in results)
            if verbose:
                for subdomain in subdomains:
                    print(f"Found subdomain: {subdomain}")
            return list(subdomains)
        else:
            raise ValueError(f"crt.sh returned an error: {response.status_code}")

    except ValueError as e:
        ErrorHandler.handle_error(e, "Error in crt.sh enumeration", silent=False)
        return []
    except requests.exceptions.RequestException as e:
        ErrorHandler.handle_error(e, "Network error in crt.sh enumeration", silent=False)
        return []
    except Exception as e:
        ErrorHandler.handle_error(e, "Unexpected error in crt.sh enumeration", silent=False)
        return []