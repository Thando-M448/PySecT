import os
import re
import json
from modules.log_analyzer import ssh_parser
from core.config import load_config
from core.logger import setup_logger
from colorama import Fore
from datetime import datetime
logger = setup_logger('PySecT')

def parser(file_path):
    config = load_config()
    with open(file_path, 'r') as file:
        file_content  = file.readlines()
    log_line_pattern = r'^(\d+\.\d+\.\d+\.\d+)\s+\S+\s+\S+\s+\[.*?\]\s+"[A-Z]+\s+(.+?)\s+HTTP\/[\d\.]+"\s+(\d{3})'
    bruteforce_status_pattern = r'(\d{3})\s+\d+$'
    dictionary_pattern = [
        r'/admin',
        r'/wp-admin'
        r'/phpmyadmin',
        r'/dashboard',
        r'/config',
        r'/backup'
    ]
    sql_pattern = [
    r"union\s+select",
    r"or\s+1=1",
    r"drop\s+table",
    r"information_schema",
    r"select\s+\*",
    r"'--"
    ]
    XSS_PATTERNS = [
        r"<script",
        r"javascript:",
        r"alert\(",
        r"onerror="
    ]
    TRAVERSAL_PATTERNS = [
        r"\.\./",
        r"\.\.\\",
        r"%2e%2e"
    ]
    alerts =[]
    threat_ip={}
    threshold = config['log_analyzer']['max_failed_attempts']
    for line in file_content:
        #match first the standard web access log structure (log line pattern)
        match = re.search(log_line_pattern, line)
        if not match:
            continue

        ip = match.group(1)
        request_url = match.group(2)
        status_code=match.group(3)

        # Bruteforce
        if ('login' in request_url.lower() or 'signin' in request_url.lower() and status_code['401', '403']):
            threat_ip[ip] = threat_ip.get(ip, 0)+ 1
        #Dictionary
        for pattern in dictionary_pattern:
            if re.search(pattern, request_url, re.IGNORECASE):
                print(Fore.RED + f'Suspected Dictionary attack from {ip} and {dictionary_pattern}')
                alerts.append({
                    'type': 'dictionary probing',
                    'ip': ip,
                    'payload': pattern,
                    'url': request_url,
                })
                break
        # Sql
        for pattern in sql_pattern:
            if re.search(pattern, line, re.IGNORECASE):
                print(Fore.RED +f'Suspected Sql injection from ip {ip} with payload {sql_pattern} line {line.strip()}' )
                alerts.append({
                    'type': 'sql injection',
                    'ip': ip,
                    'payload': pattern,
                    'line': line.strip(),
                })
                break
        # XXS
        for pattern in XSS_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                print(Fore.RED+ f'Suspected XSS injection from ip: {ip} using payload: {pattern} line: {line.strip()}' )
                alerts.append({
                    type: 'XSS injection',
                    'ip': ip,
                    'payload': pattern,
                    line: line.strip(),
                })
                break
        #Transversal
        for pattern in TRAVERSAL_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                print(Fore.RED+f'Suspected Traversal from ip: {ip} using payload: {pattern} line: {line.strip()}' )
                alerts.append({
                    'type': 'Traversal injection',
                    'ip': ip,
                    'payload': pattern,
                    'line': line.strip(),
                })
                break
     #brutefoce ip counter counter
    for ip, count in threat_ip.items():
        if count > int(threshold):
            print(Fore.RED +f' [+] ALERT: Suspected brute-force attack from IP {ip} {count} failed attempts')
            alerts.append({
                'type': 'Brute-Force Attack',
                'ip': ip,
                'count': count,
            })
    saver(alerts)

def saver(alerts):
    config = load_config()
    web_reports = config['app']['reports_dir']
    os.makedirs(web_reports, exist_ok=True)
    timestamps = datetime.now().strftime('%Y%m%d%H%M%S')

    web_report_file = os.path.join(web_reports, f'Analyzed_web_logs-{timestamps}.json')
    with open(web_report_file, 'w', encoding="utf-8") as file:
        json.dump(alerts, file, indent=4)
    print(Fore.BLUE+ f'Report saved to {web_report_file}')
