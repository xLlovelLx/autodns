import ipaddress
import dns.resolver

def ptr_lookup(ip_range, verbose):
    """
    Perform PTR (reverse DNS) record lookups for a given IP range or CIDR.
    """
    print(f"Performing PTR lookups for {ip_range}...")
    results = {}

    try:
        network = ipaddress.ip_network(ip_range)
    except ValueError as e:
        print(f"Invalid IP range or CIDR: {e}")
        return results

    for ip in network:
        try:
            reversed_ip = ip.reverse_pointer
            answers = dns.resolver.resolve(reversed_ip, "PTR")
            results[str(ip)] = [str(rdata) for rdata in answers]
            if verbose:
                print(f"{ip}: {', '.join(results[str(ip)])}")
        except Exception as e:
            if verbose:
                print(f"{ip}: No PTR record found or error: {e}")

    print(f"Total PTR records found: {len(results)}")
    return results

def validate_ip_range(ip_range):
    """
    Validate the given IP range or CIDR.
    """
    try:
        ipaddress.ip_network(ip_range)
        return True
    except ValueError:
        return False