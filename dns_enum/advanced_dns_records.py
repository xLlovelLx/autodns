import dns.resolver

def query_advanced_dns_records(domain, verbose=False):
    """
    Query advanced DNS records for a given domain, including SPF, NSEC, NSEC3, DS, DNSKEY, and RRSIG.
    """
    print(f"Querying advanced DNS records for {domain}...")

    # List of advanced DNS record types
    advanced_record_types = ["SPF", "NSEC", "NSEC3", "DS", "DNSKEY", "RRSIG"]
    results = {}

    for record_type in advanced_record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            results[record_type] = [str(rdata) for rdata in answers]
            if verbose:
                print(f"{record_type} Records:")
                for rdata in answers:
                    print(f"  {rdata}")
        except Exception as e:
            if verbose:
                print(f"Error fetching {record_type} records: {e}")
            results[record_type] = []

    print(f"Advanced DNS record query completed for {domain}.")
    return results