from core.logger import setup_logger
from core.validator import validate_ip, validate_file_path
# Initialize logger for the main application
logger = setup_logger("PySecT-Main")
from core.config import load_config

def main(ip , file):


    is_valid = validate_ip(ip)
    print(f"IP: {ip} -> Valid? {is_valid}")

    # Test File Path validation

    is_valid = validate_file_path(file)
    print(f"File: {file} -> Valid? {is_valid}")
    load_config()
if __name__ == "__main__":
    ipaddr = input("Enter ip address ").strip()
    filename = str(input("Enter file path ").strip())
    main(ipaddr, filename)
