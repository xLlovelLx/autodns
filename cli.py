#!/usr/bin/env python

import argparse
import sys
import os
from core.passive import passive_enum
from core.active import active_enum
from core.brute import brute_force
import asyncio
from dns_enum.output_formats import save_as_csv, save_as_json, save_as_xml
from scripts.utils import validate_file_path
from dns_enum.tld_expansion import tld_expand


# Get the default paths for subdomains and resolvers
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_SUBDOMAINS = os.path.join(BASE_DIR, "data", "subdomains.txt")
DEFAULT_RESOLVERS = os.path.join(BASE_DIR, "data", "resolvers.txt")
DEFAULT_TLDS = os.path.join(BASE_DIR, "data", "tlds.txt")


def main():
    parser = argparse.ArgumentParser(description="DNS Enumeration Tool")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--domain", help="Target domain for enumeration")
    group.add_argument("--gui", choices=["pyqt","flask"], help="Launch the GUI (pyqt or flask)")
    
    parser.add_argument("--active", action="store_true", help="Perform active DNS probing")
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
    
    
    args = parser.parse_args()
    
    tlds_file = validate_file_path(args.tlds, DEFAULT_TLDS)

    results = {}
    
    if args.domain:
        
        if args.active:
            results["Active"] = active_enum(args.domain, args.output, args.verbose)
        if args.passive:
            results["Passive"] = passive_enum(args.domain, args.output, args.verbose, args.all_engines)
        if args.bruteforce:
            results["BruteForce"] = asyncio.run(brute_force(args.domain, args.wordlist, args.resolver_file, args.output, args.verbose))
        if args.zone_transfer:
            from dns_enum.zone_transfer import check_zone_transfer
            zone_results = check_zone_transfer(args.domain, args.verbose)
            results["ZoneTransfer"] = zone_results
            print(f"Zone transfer results: {zone_results}")

        if args.ports:
            if tlds_file:
            
                from dns_enum.port_scanner import scan_ports
                ports = list(map(int, args.ports.split(',')))
                port_results = scan_ports(args.domain, ports, verbose=args.verbose)
                results["PortScan"] = port_results
                print(f"Port scan results: {port_results}")
    
        if args.tlds:
            expanded_domains = tld_expand(args.domain, tlds_file, args.tlds)
            results["ExpandedDomains"] = expanded_domains
            print(f"Expanded domains: {expanded_domains}")
        
        if args.output_format:
            # Save results based on the specified output format
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
        
        
    else:
        print("Error: Please provide a domain for enumeration or use the --gui option to launch the GUI.")
    
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

    
    
            

if __name__ == "__main__":
    main()