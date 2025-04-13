import asyncio
import dns.asyncresolver

async def query_subdomain(subdomain, resolver, verbose):
    try:
        answers = await resolver.resolve(subdomain, "A")
        if verbose:
            print(f"{subdomain}: {', '.join([str(ip) for ip in answers])}")
        return subdomain, [str(ip) for ip in answers]
    except Exception:
        return subdomain, []

async def brute_force(domain, wordlist_path, resolvers_path, verbose):
    resolver = dns.asyncresolver.Resolver()
    if resolvers_path:
        with open(resolvers_path, "r") as f:
            resolver.nameservers = [line.strip() for line in f]

    with open(wordlist_path, "r") as f:
        subdomains = [f"{line.strip()}.{domain}" for line in f]

    tasks = [query_subdomain(sub, resolver, verbose) for sub in subdomains]
    results = await asyncio.gather(*tasks)
    found = {sub: ips for sub, ips in results if ips}

    print(f"Brute-force results:")
    for sub, ips in found.items():
        print(f"{sub}: {', '.join(ips)}")