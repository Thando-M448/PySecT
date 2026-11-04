from core.logger import setup_logger
from core.validator import validate_ip, validate_file_path
# Initialize logger for the main application
logger = setup_logger("PySecT-Main")

def main():
    logger.info("PySecT framework initialized successfully.")
    logger.debug("This is a debug message for testing purposes.")
    logger.warning("This is a warning test message.")

    test_ips = ["192.168.1.1", "999.999.999.999", "not_an_ip"]
    for ip in test_ips:
        is_valid = validate_ip(ip)
        print(f"IP: {ip} -> Valid? {is_valid}")

    # Test File Path validation
    test_files = ["logs/pysect.log", "nonexistent_file.txt"]
    for fpath in test_files:
        is_valid = validate_file_path(fpath)
        print(f"File: {fpath} -> Valid? {is_valid}")
if __name__ == "__main__":
    main()