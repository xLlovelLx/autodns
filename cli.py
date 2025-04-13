import argparse
import os
from core.passive import passive_enum
from core.active import active_enum
from core.brute import brute_force

# Get the default paths for subdomains and resolvers
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_SUBDOMAINS = os.path.join(BASE_DIR, "data", "subdomains.txt")
DEFAULT_RESOLVERS = os.path.join(BASE_DIR, "data", "resolvers.txt")

def main():
    parser = argparse.ArgumentParser(description="DNS Enumeration Tool")
    parser.add_argument("--domain", required=True, help="Target domain for enumeration")
    parser.add_argument("--passive", action="store_true", help="Perform passive enumeration")
    parser.add_argument("--active", action="store_true", help="Perform active DNS probing")
    parser.add_argument("--bruteforce", action="store_true", help="Perform subdomain brute-forcing")
    parser.add_argument("--wordlist", help="Path to custom subdomain wordlist", default=DEFAULT_SUBDOMAINS)
    parser.add_argument("--resolver-file", help="Path to custom DNS resolver list", default=DEFAULT_RESOLVERS)
    parser.add_argument("--all-engines", action="store_true", help="Use all available engines for enumeration")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--output", help="Output file to save results", default="results.json")
    args = parser.parse_args()

    if args.passive:
        passive_enum(args.domain, args.output, args.verbose, args.all_engines)
    if args.active:
        active_enum(args.domain, args.output, args.verbose)
    if args.bruteforce:
        brute_force(args.domain, args.wordlist, args.resolver_file, args.output, args.verbose)

if __name__ == "__main__":
    main()