import dns.resolver

def query_dns_records(domain, verbose):
    print(f"Querying DNS records for {domain}...")
    record_types = ["A", "AAAA", "MX", "TXT", "NS", "SOA"]
    results = {}

    for record in record_types:
        try:
            answers = dns.resolver.resolve(domain, record)
            results[record] = [str(rdata) for rdata in answers]
            if verbose:
                print(f"{record} Records:")
                for rdata in answers:
                    print(f"  {rdata}")
        except Exception as e:
            if verbose:
                print(f"Error fetching {record} records: {e}")
            results[record] = []

    print(f"DNS record query completed for {domain}.")
    return results