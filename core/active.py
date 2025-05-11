import dns.resolver
from dns_enum import output_formats
from dns_enum.advanced_dns_records import query_advanced_dns_records
from dns_enum.output_formats import save_as_json, save_as_csv, save_as_xml
from dns_enum.console_output import color_print, ConsoleColors
from dns_enum.ptr_lookup import ptr_lookup
from dns_enum.tld_expansion import tld_expand


def active_enum(domain, output_file, verbose):
    print(f"Performing active DNS probing for {domain}...")
    record_types = ["A", "AAAA", "CNAME", "MX", "TXT", "NS"]
    results = {}

    for record in record_types:
        if verbose:
            color_print(f"Querying {record} records...",ConsoleColors.OKBLUE)
        try:
            answers = dns.resolver.resolve(domain, record)
            results[record] = [str(rdata) for rdata in answers]
            color_print(f"{record} Records:",ConsoleColors.OKCYAN)
            for rdata in answers:
                print(f"  {rdata}")
        except dns.resolver.NoNameservers:
            color_print(f"No nameservers found for {domain}.",ConsoleColors.FAIL)
            return
        except dns.resolver.NoAnswer:
            results[record] = []
        except dns.resolver.NXDOMAIN:
            color_print(f"Domain {domain} does not exist.",ConsoleColors.FAIL)
            return
        except Exception as e:
            if verbose:
                color_print(f"Error querying {record} records: {e}",ConsoleColors.WARNING)
            results[record] = []
            
    advanced_results = query_advanced_dns_records(domain, verbose)
    results.update(advanced_results)

    # Save results in the specified format
    if output_formats == "json":
        save_as_json(results, output_file)
    elif output_formats == "csv":
        save_as_csv(results, output_file)
    elif output_formats == "xml":
        save_as_xml(results, output_file)
    else:
        color_print(f"Unsupported output format: {output_formats}", ConsoleColors.FAIL)
        return
    

    # Save results to file
    with open(output_file, "w") as f:
        f.write(str(results))
    color_print(f"Active DNS probing results saved to {output_file}",ConsoleColors.OKGREEN)