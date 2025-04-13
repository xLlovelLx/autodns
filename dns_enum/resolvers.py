import dns.asyncresolver

def load_resolvers(resolvers_path):
    """
    Load a list of custom resolvers from a file.
    If the file is not provided or invalid, the system defaults are used.
    """
    try:
        with open(resolvers_path, "r") as f:
            resolvers = [line.strip() for line in f if line.strip()]
        return resolvers
    except Exception as e:
        print(f"Error loading resolvers: {e}")
        return []

def set_custom_resolvers(resolver, resolvers_path):
    """
    Set custom DNS resolvers for the asyncresolver instance.
    """
    custom_resolvers = load_resolvers(resolvers_path)
    if custom_resolvers:
        resolver.nameservers = custom_resolvers
        print(f"Using custom resolvers: {custom_resolvers}")
    else:
        print("Using default system resolvers.")

def test_resolvers(resolvers):
    """
    Test a list of resolvers to ensure they are functional.
    Returns a list of working resolvers.
    """
    working_resolvers = []
    for resolver_ip in resolvers:
        try:
            resolver = dns.asyncresolver.Resolver()
            resolver.nameservers = [resolver_ip]
            resolver.resolve("www.google.com", "A")
            working_resolvers.append(resolver_ip)
        except Exception as e:
            print(f"Resolver {resolver_ip} failed: {e}")
    return working_resolvers