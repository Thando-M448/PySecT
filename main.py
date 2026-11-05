from core.logger import setup_logger
from core.validator import validate_ip, validate_file_path
# Initialize logger for the main application
logger = setup_logger("PySecT-Main")
from core.config import load_config
import pyfiglet
from colorama import Fore, Style, init

init(autoreset=True)
standard_banner = pyfiglet.figlet_format("PySecT", font="slant")

print(Fore.GREEN + Style.BRIGHT + standard_banner)

menu = """
                 PySecT v0.1.0
       Python Cybersecurity Toolkit
==================================================
[1] Log File Analyzer & Suspicious Activity Detector
[2] Network Security Scanner
[3] Network Traffic Analyzer & Visualizer
[4] Secure File Encryption & Decryption
[5] Social Engineering Awareness & Simulation
[6] Exit PySecT
==================================================
"""
Disclaimer = """
==================================================
                Disclaimer!!!!!
Authorized Defensive Testing & Security Toolkit!!!
==================================================
"""
print(Fore.RED + Disclaimer )
print(Fore.GREEN + menu)
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
