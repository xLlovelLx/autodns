import yaml
from dns_enum.console_output import color_print, ConsoleColors

def load_config(config_path="config.yaml"):
    """
    Load configuration from a YAML file.
    """
    try:
        with open(config_path, "r") as file:
            config = yaml.safe_load(file)
        return config
    except Exception as e:
        print(f"Error loading configuration file: {e}")
        return {}
