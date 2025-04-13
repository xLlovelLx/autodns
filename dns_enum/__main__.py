import argparse
from dns_enum.advanced_dns_records import query_advanced_dns_records
from dns_enum.zone_transfer import check_zone_transfer, zone_walk
from dns_enum.osint_enum import crtsh_enum, virustotal_enum, threatcrowd_enum
from dns_enum.port_scanner import scan_ports
from dns_enum.output_formats import save_as_json, save_as_csv, save_as_xml

def main():
    parser = argparse.ArgumentParser(description="DNS Enumeration Tool")
    parser.add_argument("-d", "--domain", required=True, help="Target domain for enumeration.")
    parser.add_argument("--dns-records", action="store_true", help="Query advanced DNS records.")
    parser.add_argument("--zone-transfer", action="store_true", help="Check for zone transfer vulnerabilities.")
    parser.add_argument("--osint", action="store_true", help="Perform OSINT-based subdomain enumeration.")
    parser.add_argument("--ports", help="Comma-separated list of ports to scan.")
    parser.add_argument("--output", help="Save results to a file (supports .json, .csv, .xml).")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output.")
    parser.add_argument("--silent", action="store_true", help="Suppress all output except critical errors.")
    args = parser.parse_args()

    results = {}

    if args.dns_records:
        results['AdvancedDNSRecords'] = query_advanced_dns_records(args.domain, args.verbose)

    if args.zone_transfer:
        results['ZoneTransfer'] = check_zone_transfer(args.domain, args.verbose)
        results['ZoneWalk'] = zone_walk(args.domain, args.verbose)

    if args.osint:
        results['Subdomains'] = crtsh_enum(args.domain, args.verbose)

    if args.ports:
        ports_to_scan = list(map(int, args.ports.split(',')))
        results['OpenPorts'] = scan_ports(args.domain, ports_to_scan, verbose=args.verbose, silent=args.silent)

    if args.output:
        if args.output.endswith(".json"):
            save_as_json(results, args.output)
        elif args.output.endswith(".csv"):
            save_as_csv(results, args.output)
        elif args.output.endswith(".xml"):
            save_as_xml(results, args.output)
        else:
            print("Unsupported output format. Please use .json, .csv, or .xml.")

if __name__ == "__main__":
    main()