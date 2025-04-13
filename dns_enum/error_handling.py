class ErrorHandler:
    @staticmethod
    def handle_error(error, context="", silent=False):
        """
        Centralized error handler to log or suppress errors.

        Args:
            error (Exception): The error to handle.
            context (str): Contextual information about where the error occurred.
            silent (bool): If True, suppress error messages.
        """
        if not silent:
            print(f"[ERROR] {context}: {error}")

    @staticmethod
    def validate_domain(domain):
        """
        Validate that the input is a valid domain name.

        Args:
            domain (str): The domain name to validate.

        Returns:
            bool: True if valid, False otherwise.
        """
        import re
        domain_regex = r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.[A-Za-z]{2,6}$"
        if not re.match(domain_regex, domain):
            raise ValueError(f"{domain} is not a valid domain name.")
        return True