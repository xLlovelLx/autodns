import json
import os
from core.passive import passive_enum
from core.active import active_enum
from core.brute import brute_force
from dns_enum.advanced_dns_records import dns_over_https,dns_over_tls
from dns_enum.output_formats import save_as_csv, save_as_json, save_as_xml
from scripts.utils import validate_file_path, stop_event
from dns_enum.tld_expansion import tld_expand

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_SUBDOMAINS = os.path.join(BASE_DIR, "data", "subdomains2.txt")
DEFAULT_RESOLVERS = os.path.join(BASE_DIR, "data", "resolvers.txt")
DEFAULT_TLDS = os.path.join(BASE_DIR, "data", "tlds.txt")

def interactive_mode():
    import readline  # For better input experience on Unix
    import time
    
    print("="*50)
    print("Welcome to the Interactive DNS Enumeration Tool")
    print("="*50)

    while True:
        print("\nPlease enter the enumeration options:")

        # Prompt for domain
        while True:
            domain = input("Target domain (e.g., example.com): ").strip()
            if domain:
                break
            print("Domain cannot be empty.")

        # Prompt for enumeration types
        print("\nSelect enumeration types (y/n):")
        active = input("  Active DNS probing? [y/N]: ").strip().lower() == "y"
        passive = input("  Passive enumeration? [y/N]: ").strip().lower() == "y"
        bruteforce = input("  Brute-force subdomains? [y/N]: ").strip().lower() == "y"
        zone_transfer = input("  Check for zone transfer? [y/N]: ").strip().lower() == "y"
        tld_exp = input("  TLD expansion? [y/N]: ").strip().lower() == "y"
        verbose = input("  Verbose output? [y/N]: ").strip().lower() == "y"

        # Protocols
        protocol = []
        if active:
            print("  DNS protocol options:")
            doh = input("    Use DNS over HTTPS (DoH)? [y/N]: ").strip().lower() == "y"
            dot = input("    Use DNS over TLS (DoT)? [y/N]: ").strip().lower() == "y"
            if doh: protocol.append("doh")
            if dot: protocol.append("dot")

        # Wordlist and resolver files
        wordlist = input("Path to subdomain wordlist [default: data/subdomains2.txt]: ").strip()
        if not wordlist:
            wordlist = DEFAULT_SUBDOMAINS
        resolver_file = input("Path to resolver file [default: data/resolvers.txt]: ").strip()
        if not resolver_file:
            resolver_file = DEFAULT_RESOLVERS

        # Output format
        print("\nOutput format options:")
        output_format = input("  Output format (json/csv/xml) [json]: ").strip().lower()
        if output_format not in ("json", "csv", "xml"):
            output_format = "json"
        output_file = input("  Output file [results.json]: ").strip()
        if not output_file:
            output_file = "results.json"

        # Graph
        graph = input("Generate DNS graph visualization? [y/N]: ").strip().lower() == "y"

        # Confirm options
        print("\nSummary of your choices:")
        print(f"  Domain: {domain}")
        print(f"  Active: {active}, Passive: {passive}, Brute-force: {bruteforce}, Zone Transfer: {zone_transfer}, TLD Expansion: {tld_exp}, Verbose: {verbose}")
        print(f"  Protocols: {protocol if protocol else 'Default'}")
        print(f"  Wordlist: {wordlist}")
        print(f"  Resolver file: {resolver_file}")
        print(f"  Output: {output_file} ({output_format})")
        print(f"  Graph: {graph}")
        proceed = input("Proceed with these settings? [Y/n]: ").strip().lower()
        if proceed == "n":
            print("Restarting option selection...\n")
            continue

        # Build args-like object
        class Args:
            pass
        args = Args()
        args.domain = domain
        args.active = active
        args.passive = passive
        args.bruteforce = bruteforce
        args.zone_transfer = zone_transfer
        args.tlds = None
        args.tld = tld_exp
        args.protocol = protocol
        args.wordlist = wordlist
        args.resolver_file = resolver_file
        args.verbose = verbose
        args.output = output_file
        args.output_format = output_format
        args.graph = graph
        args.all_engines = True  # You can prompt for this if needed

        # Run the enumeration (reuse your main logic)
        results = {}
        try:
            if args.active:
                results["Active"] = active_enum(args.domain, args.output, args.verbose)
            if args.protocol:
                if args.protocol == ["doh"]:
                    print("Using DNS over HTTPS for active probing.")
                    results["DoH"]=dns_over_https(args.domain, output_file=args.output, verbose=args.verbose)
                elif args.protocol == ["dot"]:
                    print("Using DNS over TLS for active probing.")
                    results["DoT"]=dns_over_tls(args.domain, output_file=args.output, verbose=args.verbose)
            if args.passive:
                results["Passive"] = passive_enum(args.domain, args.output, args.verbose, args.all_engines)
            if args.bruteforce:
                results["BruteForce"] = brute_force(args.domain, args.wordlist, args.resolver_file, args.output, args.verbose)
            if args.zone_transfer:
                from dns_enum.zone_transfer import check_zone_transfer
                zone_results = check_zone_transfer(args.domain, args.verbose)
                results["ZoneTransfer"] = zone_results
                print(f"Zone transfer results: {zone_results}")
            if args.tld:
                expanded_domains = tld_expand(args.domain, DEFAULT_TLDS, args.tlds)
                results["ExpandedDomains"] = expanded_domains
                print(f"Expanded domains: {expanded_domains}")
            if args.output_format:
                if args.output_format == "json":
                    save_as_json(results, args.output)
                elif args.output_format == "csv":
                    save_as_csv(results, args.output)
                elif args.output_format == "xml":
                    save_as_xml(results, args.output)
                else:
                    print(f"Unsupported output format: {args.output_format}")
                print(f"Results saved to {args.output}")
            if args.graph:
                from dns_enum.graph import visualize_dns_graph
                visualize_dns_graph(results, output_file="dns_graph.png")
        except KeyboardInterrupt:
            print("\nEnumeration interrupted by user.")
            stop_event.set()

        # Show results summary
        print("\n=== Enumeration Complete ===")
        print(json.dumps(results, indent=2))

        # Ask if the user wants to run another enumeration
        again = input("\nRun another enumeration? [y/N]: ").strip().lower()
        if again != "y":
            print("Exiting interactive mode. Goodbye!")
            break