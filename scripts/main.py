from dns_enum.error_handling import ErrorHandler
import argparse
import json
import os
from dns_enum.config import config
from dns_enum.output_formats import save_as_json, save_as_csv, save_as_xml
from dns_enum.zone_transfer import check_zone_transfer
from dns_enum.port_scanner import scan_ports
from dns_enum.graph import visualize_dns_graph


# Parse command-line arguments
parser = argparse.ArgumentParser(description="DNS Enumeration Script")
parser.add_argument("--output", help="Specify the output file format (.json, .csv, .xml)")
parser.add_argument("--osint", action="store_true", help="Enable OSINT features")
args = parser.parse_args()

# Placeholder for results
results = []  # Initialize results as an empty list or populate it with actual data

# Update output handling
if args.output:
    try:
        if args.output.endswith(".json"):
            save_as_json(results, args.output)
        elif args.output.endswith(".csv"):
            save_as_csv(results, args.output)
        elif args.output.endswith(".xml"):
            save_as_xml(results, args.output)
        else:
            raise ValueError("Unsupported output format. Please use .json, .csv, or .xml.")
    except ValueError as e:
        ErrorHandler.handle_error(e, "Output format error", silent=False)
    except Exception as e:
        ErrorHandler.handle_error(e, "Unexpected error in output handling", silent=False)
if args.zone_transfer:
    results["ZoneTransfer"] = check_zone_transfer(args.domain, args.verbose)

if args.ports:
    ports = list(map(int, args.ports.split(',')))
    results["PortScan"] = scan_ports(args.domain, ports, verbose=args.verbose)

if args.graph:
    visualize_dns_graph(results, output_file="dns_graph.png")
# Check for missing API keys
if args.osint and not config["api_keys"].get("virustotal"):
    ErrorHandler.handle_error(ValueError("Missing VirusTotal API key"), "API key error", silent=False)