from dns_enum.error_handling import ErrorHandler

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

# Check for missing API keys
if args.osint and not config["api_keys"].get("virustotal"):
    ErrorHandler.handle_error(ValueError("Missing VirusTotal API key"), "API key error", silent=False)