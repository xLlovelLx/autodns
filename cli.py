#!/usr/bin/env python

import argparse
import sys
import os
import logging
from core.passive import passive_enum
from core.active import active_enum
from core.brute import brute_force
from dns_enum.advanced_dns_records import dns_over_https,dns_over_tls
import asyncio
from dns_enum.output_formats import save_as_csv, save_as_json, save_as_xml
from scripts.utils import validate_file_path, stop_event
from dns_enum.tld_expansion import tld_expand
from dns_enum.interactive_mode import interactive_mode

# Setup audit logger
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
audit_logger = logging.getLogger('audit')
audit_logger.setLevel(logging.INFO)
audit_handler = logging.FileHandler(os.path.join(BASE_DIR, 'audit.log'))
audit_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
audit_handler.setFormatter(audit_formatter)
audit_logger.addHandler(audit_handler)

# Get the default paths for subdomains and resolvers
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_SUBDOMAINS = os.path.join(BASE_DIR, "data", "subdomains.txt")
DEFAULT_RESOLVERS = os.path.join(BASE_DIR, "data", "resolvers.txt")
DEFAULT_TLDS = os.path.join(BASE_DIR, "data", "tlds.txt")


def main():
    parser = argparse.ArgumentParser(description="DNS Enumeration Tool")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--domain", help="Target domain(s) for enumeration, comma separated")
    group.add_argument("--domain-file", help="Path to file containing domains, one per line")
    group.add_argument("--gui", choices=["pyqt","flask"], help="Launch the GUI (pyqt or flask)")
    group.add_argument("--ip-range", help="IP range or CIDR for PTR lookups")
    group.add_argument("--ptr", action="store_true", help="Perform PTR lookups for the given IP range or CIDR")
    
    parser.add_argument("--active", action="store_true", help="Perform active DNS probing, including A, AAAA, CNAME, MX, TXT, and NS records, as well as advanced records like SPF, NSEC, NSEC3, DS, DNSKEY, and RRSIG.\nit uses DNS over UDP by default, it will automatically retry using DNS over TCP if UDP fails.")
    parser.add_argument("--doh", action="store_true", help="Use DNS over HTTPS for active probing")
    parser.add_argument("--dot", action="store_true", help="Use DNS over TLS for" "active probing")
    
    parser.add_argument("--passive", action="store_true", help="Perform passive enumeration")
    parser.add_argument("--bruteforce", action="store_true", help="Perform subdomain brute-forcing")
    parser.add_argument("--wordlist", help="Path to custom subdomain wordlist", default=DEFAULT_SUBDOMAINS)
    parser.add_argument("--resolver-file", help="Path to custom DNS resolver list", default=DEFAULT_RESOLVERS)
    parser.add_argument("--zone-transfer", action="store_true", help="Check for DNS zone transfer vulnerabilities")
    parser.add_argument("--ports", help="Comma-separated list of ports to scan")
    parser.add_argument("--tlds", help="Path to TLDs file for domain expansion" , default=None)
    parser.add_argument("--all-engines", action="store_true", help="Use all available engines for enumeration")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--output", help="Path to save the results", default="results.json")
    parser.add_argument("--output-format", choices=["json", "csv", "xml"], default="json",help="Format to save the results (json, csv, xml)")
    parser.add_argument("--graph", action="store_true", help="Generate a graph visualization of DNS relationships.")
    parser.add_argument("--interactive", action="store_true", help="Run in interactive mode (prompts for input).")
    
    
    args = parser.parse_args()
    
    tlds_file = validate_file_path(args.tlds, DEFAULT_TLDS)
    
    
    results = {}
    
    domains = []
    if args.domain:
        if args.domain == '-':
            if not sys.stdin.isatty():
                stdin_data = sys.stdin.read().strip()
                if stdin_data:
                    domains = [d.strip() for d in stdin_data.split(',') if d.strip()]
            else:
                print("Error: No piped input detected for --domain -")
                return
        else:
            domains = [d.strip() for d in args.domain.split(',') if d.strip()]
    elif args.domain_file:
        if os.path.exists(args.domain_file):
            with open(args.domain_file, 'r') as f:
                domains = [line.strip() for line in f if line.strip()]
        else:
            print(f"Domain file {args.domain_file} not found.")
            return
    
    if not domains and not args.gui and not args.interactive:
        print("Error: Please provide at least one domain for enumeration or use the --gui option to launch the GUI.")
        return
    
    for domain in domains:
        import logging
        audit_logger.info(f"CLI enumeration started for domain: {domain} with options: {args}")
        domain_results = {}
        if args.active:
            domain_results["Active"] = active_enum(domain, args.output, args.verbose)
        if args.doh:
            print(f"Using DNS over HTTPS for active probing on {domain}.")
            domain_results["DoH"] = dns_over_https(domain, output_file=args.output, verbose=args.verbose)
        if args.dot:
            print(f"Using DNS over TLS for active probing on {domain}.")
            domain_results["DoT"] = dns_over_tls(domain, output_file=args.output, verbose=args.verbose)
        if args.passive:
            domain_results["Passive"] = passive_enum(domain, args.output, args.verbose, args.all_engines)
        if args.bruteforce:
            try:
                domain_results["BruteForce"] = brute_force(domain, args.wordlist, args.resolver_file, args.output, args.verbose)
            except KeyboardInterrupt:
                print("\nBrute-force enumeration interrupted by user.")
                stop_event.set()
                    
        if args.zone_transfer:
            from dns_enum.zone_transfer import check_zone_transfer
            zone_results = check_zone_transfer(domain, args.verbose)
            domain_results["ZoneTransfer"] = zone_results
            print(f"Zone transfer results for {domain}: {zone_results}")

        if args.ports:
            if tlds_file:
                from dns_enum.port_scanner import scan_ports
                ports = list(map(int, args.ports.split(',')))
                port_results = scan_ports(domain, ports, verbose=args.verbose)
                domain_results["PortScan"] = port_results
                print(f"Port scan results for {domain}: {port_results}")
    
        if args.tlds:
            expanded_domains = tld_expand(domain, tlds_file, args.tlds)
            domain_results["ExpandedDomains"] = expanded_domains
            print(f"Expanded domains for {domain}: {expanded_domains}")
        
        results[domain] = domain_results

    # Save results based on the specified output format after processing all domains
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
    
    if args.gui:
        if args.gui == "pyqt":
            print("Launching PyQt GUI...")
            from gui_pyqt import launch_pyqt_gui
            launch_pyqt_gui()
        elif args.gui == "flask":
            from gui_flask import app
            print("Launching the AutoDNS web GUI at http://127.0.0.1:5000/")
            app.run(debug=True)
            sys.exit(0)
        return  # Exit after launching the GUI
    
    if args.interactive:
        interactive_mode()
        return
    
if __name__ == "__main__":
    main()
