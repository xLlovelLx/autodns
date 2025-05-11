import dns.resolver
from dns_enum.console_output import color_print, ConsoleColors

def query_advanced_dns_records(domain, verbose=False):
    """
    Query advanced DNS records for a given domain, including SPF, NSEC, NSEC3, DS, DNSKEY, and RRSIG.
    """
    color_print(f"Querying advanced DNS records for {domain}...",ConsoleColors.OKBLUE)

    # List of advanced DNS record types
    advanced_record_types = ["SPF", "NSEC", "NSEC3", "DS", "DNSKEY", "RRSIG"]
    results = {}

    for record_type in advanced_record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            results[record_type] = [str(rdata) for rdata in answers]
            if verbose:
                color_print(f"{record_type} Records:",ConsoleColors.OKCYAN)
                for rdata in answers:
                    print(f"  {rdata}")
        except Exception as e:
            if verbose:
                color_print(f"Error fetching {record_type} records: {e}",ConsoleColors.FAIL)
            results[record_type] = []

    print(f"Advanced DNS record query completed for {domain}.")
    return results