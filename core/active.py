import dns.resolver

def active_enum(domain, output_file, verbose):
    print(f"Performing active DNS probing for {domain}...")
    record_types = ["A", "AAAA", "CNAME", "MX", "TXT", "NS"]
    results = {}

    for record in record_types:
        if verbose:
            print(f"Querying {record} records...")
        try:
            answers = dns.resolver.resolve(domain, record)
            results[record] = [str(rdata) for rdata in answers]
        except Exception as e:
            if verbose:
                print(f"Error querying {record} records: {e}")
            results[record] = []

    # Save results to file
    with open(output_file, "w") as f:
        f.write(str(results))
    print(f"Active DNS probing results saved to {output_file}")