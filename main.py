from core.logger import setup_logger
from core.validator import validate_ip, validate_file_path
from core.config import load_config
import pyfiglet
from colorama import Fore, Style, init
import os, sys
from modules.file_encryption.crypto import *
# Initialize logger for the main application
logger = setup_logger("PySecT-Main")

init(autoreset=True)
standard_banner = pyfiglet.figlet_format("PySecT", font="slant")

def banner():
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

def error_handler(value):
    print(Fore.RED + f"Error number {value} not defined")
    print(Fore.RED + "Please enter a number between 1 and 6")
def main():
    #load conf on startup
    config = load_config()
    logger.info(f"Loaded configurations. Active reports directory: {config['app']["reports_dir"]} ")
    while True:
        banner()
        try:
            choice = input(Fore.GREEN + "Select an option> " + Style.RESET_ALL).strip()
            if not choice.isdigit():
                error_handler(choice)
                continue
            num = int(choice)
            if num == 1:
                logger.info(f"User Selected Log File analyser")
                print(Fore.YELLOW + "[*] Initializing Log analyser .......( Coming..)")

            elif num == 2:
                logger.info("User selected: Network Security Scanner")
                print(Fore.YELLOW + "[*] Initializing Network Security Scanner... (Coming Soon)" + Style.RESET_ALL)

            elif num == 3:
                logger.info("User selected: Network Traffic Analyzer")
                print(Fore.YELLOW + "[*] Initializing Network Traffic Analyzer... (Coming Soon)" + Style.RESET_ALL)

            elif num == 4:
                logger.info("User selected: Secure File Encryption & Decryption")
                print(Fore.YELLOW + "[*] Initializing File Encryption/Decryption Module... " + Style.RESET_ALL)
                sleep(2)
                decider()


            elif num == 5:
                logger.info("User selected: Social Engineering Awareness")
                print(Fore.YELLOW + "[*] Initializing Social Engineering Module... (Coming Soon)" + Style.RESET_ALL)

            elif num == 6:
                logger.info("User exited PySecT framework safely.")
                print(Fore.GREEN + "\n[+] Thank you for using PySecT. Stay secure!\n Regards Thandooooo" + Style.RESET_ALL)

                sys.exit(0)

        except KeyboardInterrupt:
            print(Fore.RED + "Keyboard interrupt. Exiting PySecT ")
            sys.exit(0)

        input(Fore.CYAN + "Press Neter to return to amin menu")

if __name__ == "__main__":

    main()
