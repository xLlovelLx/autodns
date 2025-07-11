from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress
import dns.resolver
from flask_socketio import emit
from scripts.utils import get_dynamic_max_workers,stop_event

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

def ptr_lookup_flask(ip_range, verbose):
    """
     Perform PTR (reverse DNS) record lookups for a given IP range or CIDR.
    Emits each result to enum_update. Uses threading for speed.
    """
    results = {}
    stop_event.clear()
    try:
        network = ipaddress.ip_network(ip_range)
    except ValueError as e:
        msg = f"Invalid IP range or CIDR: {e}"
        emit('enum_update', {'step': 'PTR', 'result': msg})
        return results

    def resolve_ptr(ip):
        try:
            if stop_event.is_set():
                return None, None
            
            reversed_ip = ip.reverse_pointer
            answers = dns.resolver.resolve(reversed_ip, "PTR")
            return str(ip), [str(rdata) for rdata in answers]
        except Exception as e:
            return str(ip), None

    max_workers = get_dynamic_max_workers(len(list(network)))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {executor.submit(resolve_ptr, ip): ip for ip in network}
        for future in as_completed(future_to_ip):
            if stop_event.is_set():
                break
            ip_str, ptrs = future.result()
            if ptrs is None:
                continue # Skip if stopped
            if ptrs:
                results[ip_str] = ptrs
                emit('enum_update', {'step': 'PTR', 'result': {ip_str: ptrs}})
                # if verbose:
                    # print(f"{ip_str}: {', '.join(ptrs)}")
            else:
                emit('enum_update', {'step': 'PTR', 'result': {ip_str: None}})
                # if verbose:
                    # print(f"{ip_str}: No PTR record found or error.")

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