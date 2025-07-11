import asyncio
import socket
import dns.asyncresolver
import dns.resolver
from flask_socketio import SocketIO,emit,join_room
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import socketio
from dns_enum.console_output import color_print, ConsoleColors
from scripts.utils import get_dynamic_max_workers, stop_event


def query_subdomain(subdomain, resolver, verbose):
    if stop_event.is_set():
        return subdomain, []
    
    if verbose:
        color_print(f"Querying {subdomain}...",ConsoleColors.OKBLUE)
    try:
        answers = dns.resolver.resolve(subdomain, "A")
        #answers = await resolver.resolve(subdomain, "A")
        return subdomain, [str(rdata) for rdata in answers]
    except Exception as e:
        if verbose:
            color_print(f"Error querying {subdomain}: {e}", ConsoleColors.WARNING)
        return subdomain, []
    
    
def check_subdomain(subdomain, domain, resolver_ip):
    if stop_event.is_set():
        return None
    
    fqdn = f"{subdomain}.{domain}"
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [resolver_ip]
    try:
        resolver.resolve(fqdn, 'A', lifetime=2)
        return fqdn
    except Exception:
        return None

def brute_force_flask(domain, wordlist_path, resolver_file_path):
    found = []
    with open(resolver_file_path, 'r') as f:
        RESOLVERS = [line.strip() for line in f if line.strip()]
    with open(wordlist_path, 'r') as f:
        SUBDOMAINS = [line.strip() for line in f if line.strip()]
        
    max_workers = get_dynamic_max_workers(len(SUBDOMAINS))
    stop_event.clear()
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = []
        for i, sub in enumerate(SUBDOMAINS):
            if stop_event.is_set():
                break
            resolver_ip = RESOLVERS[i % len(RESOLVERS)]
            futures.append(executor.submit(check_subdomain, sub, domain, resolver_ip))
        for future in futures:
            if stop_event.is_set():
                break
            result = future.result()
            if result:
                found.append(result)
                print(f"Found subdomain: {result}")
                # if socketio:
                emit('enum_update', {'step' : 'Brute-Force','result': f"found {result}" })
    # if sid:
    emit('enum_complete', {'step':'Brute-Force', 'result': f"found {found}" })

    return found


"""def query_subdomain_flask(subdomain, resolver, verbose, sid=None):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    if verbose:
        print(f"Querying {subdomain}...")
    try:
        answers = loop.run_until_complete(resolver.resolve(subdomain, "A"))
        #return subdomain, [str(rdata) for rdata in answers]
        if sid:
            SocketIO.emit('enum_update', {'step':'Brute-Force','subdomain': subdomain, 'ips': [str(rdata) for rdata in answers]}, room=sid)
        else:
            print(f"Subdomain: {subdomain}, IPs: {[str(rdata) for rdata in answers]}")
    except Exception as e:
        if verbose:
            print(f"Error querying {subdomain}: {e}")
"""
def brute_force(domain, wordlist_path, resolver_file_path, output_file, verbose):
    color_print(f"Performing brute-force enumeration for {domain}...",ConsoleColors.OKGREEN)

    # Load the wordlist from file
    with open(wordlist_path, "r") as f:
        words = [word.strip() for word in f]

    # Load the resolvers from file
    resolver = dns.resolver.Resolver()
    with open(resolver_file_path, "r") as f:
        resolvers = [resolver_ip.strip() for resolver_ip in f]
        
    resolver.nameservers = resolvers  # Set custom resolvers for DNS queries

    # Start brute-forcing
    #tasks = []
    found = {}
    max_workers = get_dynamic_max_workers(len(words))
    stop_event.clear()
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(query_subdomain, f"{word}.{domain}", resolver, verbose) for word in words]
        for future in as_completed(futures):
            if stop_event.is_set():
                color_print("Brute-force enumeration stopped by user.", ConsoleColors.WARNING)
                break
            sub, ips = future.result()
            if ips:
                found[sub] = ips
        #tasks.append(query_subdomain(subdomain, resolver, verbose))

    #results = await asyncio.gather(*tasks)
    #found = {sub: ips for sub, ips in results if ips}

    if output_file:
        with open(output_file, "w") as f:
            f.write(str(found))
    color_print(f"Brute-force results saved to {output_file}",ConsoleColors.OKYELLOW)
    
    return found



"""async def brute_force_flask(param, wordlist_path, resolver_file_path, sid=None, verbose= True):
    domain = param
    if isinstance(param, dict):
        domain = param.get("domain", "")
    if not domain:
        raise ValueError("Domain parameter is required for brute-force enumeration.")
    if verbose:
        print(f"Performing brute-force enumeration for {param["domain"]}...")

    # Load the wordlist from file
    with open(wordlist_path, "r") as f:
        words = [word.strip() for word in f]

    # Load the resolvers from file
    resolver = dns.asyncresolver.Resolver()
    with open(resolver_file_path, "r") as f:
        resolvers = [resolver_ip.strip() for resolver_ip in f]

    resolver.nameservers = resolvers  # Set custom resolvers for DNS queries

    # Start brute-forcing
    tasks = []
    for word in words:
        subdomain = f"{word}.{domain}"
        tasks.append(query_subdomain(subdomain, resolver, verbose))

    #results = await asyncio.gather(*tasks)
    #found = {sub: ips for sub, ips in results if ips}

    # Save results to file
    with open(output_file, "w") as f:
        f.write(str(found))
    #print(f"Brute-force results saved to {output_file}")
    
    #return found"""