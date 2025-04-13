import dns.query
import dns.zone
import dns.resolver

def check_zone_transfer(domain, verbose=False):
    """
    Check for DNS zone transfer vulnerabilities on the domain's nameservers.
    """
    print(f"Checking zone transfer vulnerabilities for {domain}...")
    results = {}

    try:
        ns_records = dns.resolver.resolve(domain, 'NS')
        nameservers = [str(rdata) for rdata in ns_records]

        for ns in nameservers:
            try:
                z = dns.zone.from_xfr(dns.query.xfr(ns, domain))
                results[ns] = list(z.nodes.keys())
                if verbose:
                    print(f"Zone transfer successful for {ns}:\n{results[ns]}")
            except Exception as e:
                if verbose:
                    print(f"Zone transfer failed for {ns}: {e}")
    except dns.resolver.NoAnswer:
        print("No NS records found.")
    except Exception as e:
        print(f"Error while checking zone transfer: {e}")

    return results

def zone_walk(domain, verbose=False):
    """
    Perform DNSSEC zone walking to enumerate DNS records.
    """
    print(f"Performing DNSSEC zone walk for {domain}...")
    results = []

    try:
        nsec_records = dns.resolver.resolve(domain, 'NSEC')
        for rdata in nsec_records:
            results.append(str(rdata))
            if verbose:
                print(f"NSEC Record: {rdata}")
    except dns.resolver.NoAnswer:
        print("No NSEC records found.")
    except Exception as e:
        print(f"Error while performing DNSSEC zone walk: {e}")

    return results