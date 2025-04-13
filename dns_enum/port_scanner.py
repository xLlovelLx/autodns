from dns_enum.error_handling import ErrorHandler

def scan_ports(domain, ports, max_threads=10, verbose=False, silent=False):
    """
    Scan specified TCP ports on a domain or subdomain.
    """
    try:
        # Validate domain
        ErrorHandler.validate_domain(domain)

        if not silent:
            print(f"Scanning ports {ports} on {domain} with {max_threads} threads...")

        open_ports = []

        def scan_port(port):
            try:
                with socket.create_connection((domain, port), timeout=3):
                    if verbose and not silent:
                        print(f"Port {port} is open on {domain}.")
                    return port
            except (socket.timeout, ConnectionRefusedError) as e:
                ErrorHandler.handle_error(e, f"Port {port} on {domain} failed", silent)
            return None

        task_args_list = [(port,) for port in ports]
        open_ports = execute_with_threads(scan_port, task_args_list, max_threads, verbose)

        if not silent:
            print(f"Open ports on {domain}: {open_ports}")

        return [port for port in open_ports if port]

    except ValueError as e:
        ErrorHandler.handle_error(e, "Invalid domain name", silent)
        return []
    except Exception as e:
        ErrorHandler.handle_error(e, "Unexpected error during port scanning", silent)
        return []