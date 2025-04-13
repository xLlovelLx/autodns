import logging
import logging.config
import yaml

def setup_logging(config_path="config.yaml"):
    """
    Set up logging configuration from a YAML file.
    """
    try:
        with open(config_path, "r") as file:
            config = yaml.safe_load(file)
            logging_config = {
                "version": 1,
                "formatters": {
                    "default": {
                        "format": config["logging"]["format"]
                    }
                },
                "handlers": {
                    "file": {
                        "class": "logging.FileHandler",
                        "level": config["logging"]["level"],
                        "formatter": "default",
                        "filename": config["logging"]["file"]
                    },
                    "console": {
                        "class": "logging.StreamHandler",
                        "level": config["logging"]["level"],
                        "formatter": "default"
                    }
                },
                "root": {
                    "level": config["logging"]["level"],
                    "handlers": ["file", "console"]
                }
            }
            logging.config.dictConfig(logging_config)
            logging.info("Logging is successfully configured.")
    except Exception as e:
        print(f"Error setting up logging: {e}")
        logging.basicConfig(level=logging.INFO)
        logging.warning("Falling back to basic logging configuration.")