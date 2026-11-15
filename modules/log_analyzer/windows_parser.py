import os
from datetime import datetime
from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET
from colorama import *
from core.config import load_config
from core.logger import setup_logger
import json
from time import perf_counter
logger = setup_logger('PySecT')

failed_attempts= {}
alerts = []
alerted_accounts = set()
def extract_event(file):
    root = ET.fromstring(file.xml())
    events = {}
    for element in root.iter():
        tag = element.tag.split('}')[1]
        if tag == 'EventID':
            events['EventID'] = int(element.text)
        elif tag == 'TimeCreated':
            events['TimeStamp'] = element.attrib.get('SystemTime')
        elif tag == 'Computer':
            events['Computer'] = element.text
        elif tag == 'EventRecordID':
            events['EventRecordID'] = element.text
        elif tag == 'Data':
            name = element.attrib.get('Name')
            if name:
                events[name] = element.text
    return events

def detect_failed_logins(events):
    config = load_config()
    ip = events.get('IpAddress')
    username = events.get('TargetUserName')
    timestamp = events.get('TimeStamp')

    ip = ip if ip and ip != '-' else ('Unknown')
    username = username if username and username != '-' else ('Unknown')
    account = (ip , username)
    print(Fore.RED + '[!]FAILED LOGIN DETECTED')

    print(Fore.RED+f'[!]Username : {username}')
    print(Fore.RED + f'[!]Ip : {ip}')
    print(Fore.RED + f'[!]Timestamp : {timestamp}')

    failed_attempts[account] = failed_attempts.get(account, 0) + 1
    attempts= failed_attempts[account]
    threshold = int(config['log_analyzer']['max_failed_attempts'])
    if attempts > threshold and account not in alerted_accounts:
        print(Fore.RED+f'[!]ALERT: POSSIBLE BRUTE FORCE ATTACK')
        print(Fore.CYAN+f'Username : {username}\n IP : {ip}\n Failed Attempts : {attempts}')

        alerts.append({
            'event.id' : events['EventID'],
            'type' : 'POSSIBLE BRUTE FORCE',
            'username' : username,
            'ip' : ip,
            'failed_attempts' : attempts,
            'severity': 'HIGH',
            'timestamp' : timestamp,
            'computer' : events.get('Computer'),
        })
        alerted_accounts.add(account)

def detect_acc_lockout(events):
    username = events.get('TargetUsername', 'Unknown')
    caller = events.get('CallerComputer', 'Unknown')
    timestamp = events.get('TimeStamp')
    print(Fore.RED +f'[!] ACCOUNT LOCKOUT DETECTED')
    print(Fore.CYAN +f'Username : {username}\n Caller Computer : {caller}\n Timestamp : {timestamp}')
    alerts.append({
        'event.id' : events['EventID'],
        'type' : 'ACCOUNT LOCKOUT',
        'username' : username,
        'caller_computer' : caller,
        'timestamp' : timestamp,
        'computer' : events.get('Computer'),

    })

def analyze_events(events):
    event_id = events.get('EventID')
    if event_id == 4625:
        detect_failed_logins(events)
    elif event_id == 4740:
        detect_acc_lockout(events)


def report_generator():
    config = load_config()
    reports= config['app']['reports_dir']
    os.makedirs(reports, exist_ok=True)
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')

    report_file =os.path.join(reports,f'Windows_Analyzed_Report-{timestamp}.json')
    with open(report_file, 'w') as f:
        json.dump(alerts, f , indent=4)

    print(Fore.MAGENTA +f'[*] Report file : {report_file} saved in reports folder/directory')

def windows_parser(file):
    start = perf_counter()
    with Evtx(file) as log:
        print(Fore.CYAN + f'[*] {file} decoded trying to parse log')
        for record in log.records():
            event = extract_event(record)
            analyze_events(event)
    end = perf_counter()
    report_generator()
    print(f'Completed in {end - start:.2f} seconds')