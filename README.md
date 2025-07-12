# Advanced DNS Enumeration Tool

## Overview

This tool is designed for advanced DNS enumeration, combining the best features of Sublist3r and DNSRecon. It includes OSINT-based subdomain enumeration, brute-force techniques, DNS record queries, and more.

## Features
- OSINT Subdomain Enumeration using search engines and APIs like `crt.sh`.
- Brute-force DNS enumeration with customizable wordlists and resolvers.
- DNS record queries for A, AAAA, MX, TXT, NS, SOA, and more.
- Zone transfer vulnerability checks.
- PTR (reverse DNS) record lookups.
- TLD expansion for subdomains.
- Cached record snooping.
- Real-time verbose output.
- Default wordlists and resolvers included.
- Docker support for containerized deployment.

## Installation

### Prerequisites
- Python 3.13+
- Docker (optional)

## Install
1. Clone the repository:

## Usage

### Command Line Interface (CLI)

Run the tool with the `--domain` option to specify the target domain for DNS enumeration. You can combine various flags to customize the scan:

- Active DNS probing (A, AAAA, MX, TXT, NS, SPF, DNSSEC, etc.):
  ```
  python cli.py --domain example.com --active
  ```

- Passive enumeration using OSINT sources:
  ```
  python cli.py --domain example.com --passive
  ```

- Subdomain brute-forcing with default or custom wordlist:
  ```
  python cli.py --domain example.com --bruteforce
  python cli.py --domain example.com --bruteforce --wordlist path/to/wordlist.txt
  ```

- Check for DNS zone transfer vulnerabilities:
  ```
  python cli.py --domain example.com --zone-transfer
  ```

- Perform PTR lookups for an IP range or CIDR:
  ```
  python cli.py --ip-range 192.168.1.0/24 --ptr
  ```

- Use DNS over HTTPS or DNS over TLS protocols for active probing:
  ```
  python cli.py --domain example.com --protocol doh
  python cli.py --domain example.com --protocol dot
  ```

- Generate a graph visualization of DNS relationships:
  ```
  python cli.py --domain example.com --graph
  ```

- Save results in different formats (json, csv, xml):
  ```
  python cli.py --domain example.com --output results.json --output-format json
  python cli.py --domain example.com --output results.csv --output-format csv
  ```

- Enable verbose output for detailed logs:
  ```
  python cli.py --domain example.com --verbose
  ```

- Run in interactive mode (prompts for input):
  ```
  python cli.py --interactive
  ```

### Graphical User Interface (GUI)

Launch the GUI using one of the following options:

- PyQt GUI:
  ```
  python cli.py --gui pyqt
  ```

- Flask web GUI (accessible at http://127.0.0.1:5000/):
  ```
  python cli.py --gui flask
  ```

### Notes

- Default wordlists and resolver files are included in the `data/` directory.
- You can customize wordlists, resolvers, and TLD files using the respective command line options.
- Use `--help` to see all available options and usage details:
  ```
