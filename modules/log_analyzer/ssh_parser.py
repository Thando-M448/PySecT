import os
import re
from os import linesep
import json
from datetime import datetime, timedelta
from time import sleep

#import datetime
from core.logger import setup_logger
from core.validator import validate_file_path
#from pygments.styles.dracula import foreground
from colorama import Fore
from config import *
from core.config import load_config
from modules.log_analyzer.WebServer_parser import parser
logger = setup_logger('PySecT')
def file_validator():
    file = input("Enter log file name: ")
    logger.info(f"File : {file}")
    validate_file_path(file)
    if validate_file_path(file):
        web_pattern = re.compile(r'"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+.*HTTP\/[\d.]+"')
        is_web_log = False
        with open(file, "r", encoding='utf-8', errors= 'ignore ') as log_file:
            for _ in range(10):
                line= log_file.readline()
                if not line:
                    break
                if web_pattern.search(line):
                    is_web_log = True
                    break

        if is_web_log:
            print(Fore.MAGENTA+ f'[*] Web Server logs detected , Trying ot analyse logs.....')
            sleep(2)
            parser(file)
        else:
            print(Fore.MAGENTA + f" SHH Logs detected , trying to analyse logs.....")
            sleep(2)
            extractor(file)

    else:
        print(Fore.RED + f" File does not exist : {file}")

def extractor(file_path):
    config= load_config()
    with open(file_path, "r") as file:
        file_content = file.readlines()

    pattern = r"Failed password for (?:invalid user )?(\w+) from (\d+\.\d+\.\d+\.\d+)"
    failed_attempt = {}
    for line in file_content:
        match = re.search(pattern, line)
        if match:
            ip = match.group(2)

            if ip in failed_attempt:
                failed_attempt[ip] += 1
            else:
                failed_attempt[ip] = 1
    print(Fore.BLUE+ '\n [+]Analysing Ip threat level...........')
    threshold = int(config["log_analyzer"]['max_failed_attempts'])
    alerts = []
    for ip , count in failed_attempt.items():
        if count>= (threshold * 10) :
            print(Fore.RED+ f'[ALERT (CRITICAL)] Ip {ip} has {count} failed attempts (POSSIBLE BRUTEFORCE ATTACK )')
            alerts.append({
                "severity": "CRITICAL",
                "ip": ip,
                "failed_attempts": count
            })

        elif count >= threshold*4:
            print(Fore.CYAN+ f'[ALERT] Ip {ip} has {count} failed attempts (ATTENTION NEEDED TO MONITOR THIS ADDRESS) )')
            alerts.append({
                'severity': 'HIGH',
                'ip': ip,
                'failed_attempts': count
            })
        elif count >= threshold:
            print(Fore.YELLOW + f'[ALERT] Ip {ip} has {count} failed attempts (YOU MIGHT NEED TO MONITOR THIS ADDRESS)')
            alerts.append({
                'severity': 'WARNING',
                'ip': ip,
                'failed_attempts': count
            })

    file_saver(alerts)

def file_saver(alerts):
    config = load_config()
    reports = config["app"]["reports_dir"]
    os.makedirs(reports, exist_ok=True)
    timestamps = datetime.now().strftime("%Y%m%d-%H%M%S")

    report_file = os.path.join(
        reports,
        f"Analyzed_logs{timestamps}.json"

        )
    with open(report_file, 'w') as report:
        json.dump(alerts, report, indent=4)


    print(Fore.BLUE + f'Reports saved to {report_file}')






