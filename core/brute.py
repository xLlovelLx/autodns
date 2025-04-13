import asyncio
import dns.asyncresolver

async def query_subdomain(subdomain, resolver, verbose):
    if verbose:
        print(f"Querying {subdomain}...")
    try:
        answers = await resolver.resolve(subdomain, "A")
        return subdomain, [str(rdata) for rdata in answers]
    except Exception as e:
        if verbose:
            print(f"Error querying {subdomain}: {e}")
        return subdomain, []

async def brute_force(domain, wordlist_path, resolver_file_path, output_file, verbose):
    print(f"Performing brute-force enumeration for {domain}...")

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

    results = await asyncio.gather(*tasks)
    found = {sub: ips for sub, ips in results if ips}

    # Save results to file
    with open(output_file, "w") as f:
        f.write(str(found))
    print(f"Brute-force results saved to {output_file}")