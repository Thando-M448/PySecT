import ipaddress
import os
from core.logger import setup_logger

logger = setup_logger("PySecT-Validator")


def validate_ip(ip_str: str) -> bool:
    """
    Validates whether a given string is a valid IPv4 or IPv6 address.
    Returns True if valid, False otherwise.
    """
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        logger.warning(f"Invalid IP address format provided: '{ip_str}'")
        return False


def validate_file_path(file_path: str) -> bool:
    """
    Validates whether a given file path exists and is a readable file.
    Returns True if valid, False otherwise.
    """
    if not file_path:
        logger.warning("Empty file path provided.")
        return False

    if os.path.exists(file_path) and os.path.isfile(file_path):
        return True
    else:
        logger.warning(f"File path does not exist or is not a valid file: '{file_path}'")
        return False
