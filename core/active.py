import dns.resolver
from dns_enum import output_formats
from dns_enum.advanced_dns_records import query_advanced_dns_records
from dns_enum.output_formats import save_as_json, save_as_csv, save_as_xml
from dns_enum.console_output import color_print, ConsoleColors
from dns_enum.ptr_lookup import ptr_lookup
from dns_enum.tld_expansion import tld_expand
from flask_socketio import SocketIO,emit,join_room
from scripts.utils import get_dynamic_max_workers, stop_event

def active_enum(domain, output_file=False, verbose=False):
    
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
            color_print(f"No answer for {domain} with record type {record}.",ConsoleColors.WARNING)
        except dns.resolver.NXDOMAIN:
            color_print(f"Domain {domain} does not exist.",ConsoleColors.FAIL)
            return
        except Exception as e:
            if verbose:
                color_print(f"Error querying {record} records: {e}",ConsoleColors.WARNING)
            ##results[record] = []
            
    advanced_results = query_advanced_dns_records(domain, verbose)
    results.update(advanced_results)

    
    return results

    """# Save results to file
    with open(output_file, "w") as f:
        f.write(str(results))
    color_print(f"Active DNS probing results saved to {output_file}",ConsoleColors.OKGREEN)
    """
    
def active_enum_flask(domain, output_file=None, verbose=False):
    """Perform active DNS probing for a domain in Flask context.
    """
    record_types = ["A", "AAAA","CNAME","MX", "TXT", "NS"]
    results = {}
    
    stop_event.clear()
    emit('enum_update', {'step': 'Starting active DNS probing...', 'result': None})
    for record in record_types:
        
        try:
            answers = dns.resolver.resolve(domain, record)
            results[record] = [str(rdata) for rdata in answers]
            
            emit('enum_update', {'step': f'{record}', 'result': results[record]})
            # for rdata in answers:
                # print(f"  {rdata}")
        except dns.resolver.NoNameservers:
            emit('enum_update',{'step' : f"{dns.resolver.NoNameservers}",'result' : f"No nameservers found for {domain}."})
            return
        except dns.resolver.NoAnswer:
            emit('enum_update',{'step' : f"{dns.resolver.NoAnswer}",'result' : f"No answer for {domain} with record type {record}."})
        except dns.resolver.NXDOMAIN:
            emit('enum_update',{'step' : f"{dns.resolver.NXDOMAIN}",'result' : f"Domain {domain} does not exist."})
            return
        except Exception as e:
            # if verbose:
            emit('enum_update',{'step' : f"{e}",'result' : f"Error querying {record} records: {e}"})
            ##results[record] = []
            
    advanced_results = query_advanced_dns_records(domain, verbose)
    results.update(advanced_results)
    
    
    return results