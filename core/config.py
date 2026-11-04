import os
import json
from core.logger import setup_logger

logger = setup_logger("PySecT-Config")
DEFAULT_CONFIG ={
  "app": {
  "name": "PySecT",
  "version": "0.1.0",
  "reports_dir": "reports"
},
"log_analyzer":{
  "max_failed_attempts":"5"
},

"network_scanner ":{
  "default_timeout": "2.0"

}
}
def load_config(config_path="config\settings.json"):
    """
        Loads configuration settings from a JSON file.
        Falls back to DEFAULT_CONFIG if the file is missing or corrupted.
    """
    try:
        with open (config_path,"r" ) as file:
            data = json.load(file)
            logger.info(f"Loaded configuration settings from {config_path}")
            return data
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logger.warning(f"Failed to load configuration settings from {config_path}: {e}")
        return DEFAULT_CONFIG



