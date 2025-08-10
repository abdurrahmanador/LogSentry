#!/usr/bin/env python3
"""
LogSentry v2.0 – Real-Time Security Log Monitor & Alerter
Author: Abdur Rahman
"""

import argparse
import time
import re
import csv
import os
from datetime import datetime
from colorama import init, Fore, Style

# Initialize Colorama
init(autoreset=True)

# ====== Default Config ======
DEFAULT_LOG = "sample.log"
DEFAULT_ALERT_CSV = "sample.csv"
DEFAULT_DEDUPE_SECONDS = 60
DEFAULT_POLL_INTERVAL = 0.5

# ====== Regex Patterns ======
PAT_FAILED_LOGIN = re.compile(r"Failed password for .* from (\d{1,3}(?:\.\d{1,3}){3})")
PAT_SQLI = re.compile(r"(%27|\'|--|%23|#|\bunion\b|\bselect\b)", re.IGNORECASE)
PAT_ADMIN_PANEL = re.compile(r"(\/wp-admin|\/wp-login\.php|\/admin\b)", re.IGNORECASE)
PAT_IP = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")

# ====== Blacklisted IPs ======
BLACKLISTED_IP = {"192.168.0.1", "45.33.32.156"}

# ====== Alert Deduplication ======
_last_alert_times = {}

# ====== Helper Functions ======
def now_ts():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def ensure_csv_header(csv_path):
    if not os.path.exists(csv_path):
        with open(csv_path, "w", newline='', encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["TimeStamp", "Alert Type", "IP Address", "Details"])

def should_emit(alert_key, dedupe_seconds):
    ts = time.time()
    last = _last_alert_times.get(alert_key)
    if last is None or (ts - last) >= dedupe_seconds:
        _last_alert_times[alert_key] = ts
        return True
    return False

def emit_alert(alert_type, ip, details, csv_path, dedupe_seconds):
    signature = (alert_type, ip, details)
    if not should_emit(signature, dedupe_seconds):
        return
    timestamp = now_ts()

    print(Fore.GREEN + "──────────────────────────────────────────────" + Style.RESET_ALL)
    print(Fore.RED + f"[ALERT] {alert_type}" + Style.RESET_ALL)
    print(Fore.WHITE + f"  Time: {timestamp}")
    print(Fore.WHITE + f"  IP:   {ip or 'Unknown'}")
    print(Fore.WHITE + f"  Info: {details}")
    print(Fore.GREEN + "──────────────────────────────────────────────\n" + Style.RESET_ALL)

    with open(csv_path, 'a', newline='', encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([timestamp, alert_type, ip or "", details])

# ====== Core Monitor ======
def monitor_log_file(log_path, csv_path, dedupe_seconds, poll_interval):
    ensure_csv_header(csv_path)

    print(Fore.LIGHTBLUE_EX+ """
 _                         _____        _                
| |                       |  ___|      | |               
| |      ___    __ _  ___ | |__  _ __  | |_  _ __  _   _ 
| |     / _ \  / _` |/ __||  __|| '_ \ | __|| '__|| | | |
| |____| (_) || (_| |\__ \| |___| | | || |_ | |   | |_| |
\_____/ \___/  \__, ||___/\____/|_| |_| \__||_|    \__, |
                __/ |                               __/ |
               |___/                               |___/                                                                                      
""" + Style.RESET_ALL)
    print(Fore.CYAN + "🚨 LogSentry v1.0 – Real-Time Security Log Monitoring" + Style.RESET_ALL)
    print(Fore.CYAN + "Author: Abdur Rahman" + Style.RESET_ALL)
    print(Fore.YELLOW + "⚠ For authorized use only. Do not monitor systems without permission.\n" + Style.RESET_ALL)
    print(Fore.CYAN + f"🔍 Monitoring '{log_path}' — Alerts saved to '{csv_path}'" + Style.RESET_ALL)

    try:
        with open(log_path, 'r', encoding="utf-8", errors="replace") as logFile:
            logFile.seek(0, os.SEEK_END)

            while True:
                line = logFile.readline()
                if not line:
                    time.sleep(poll_interval)
                    continue
                line = line.strip()

                # Detection Rules
                if (m := PAT_FAILED_LOGIN.search(line)):
                    emit_alert("Failed SSH Login", m.group(1), "Multiple failed SSH logins detected", csv_path, dedupe_seconds)
                    continue

                for bad in BLACKLISTED_IP:
                    if bad in line:
                        emit_alert("Blacklisted IP Access", bad, "Blacklisted IP detected in logs", csv_path, dedupe_seconds)
                        break

                if PAT_ADMIN_PANEL.search(line):
                    ip_match = PAT_IP.search(line)
                    ip = ip_match.group(1) if ip_match else None
                    emit_alert("Admin Panel Probe", ip, "Attempt to access admin endpoint", csv_path, dedupe_seconds)

                if PAT_SQLI.search(line):
                    ip_match = PAT_IP.search(line)
                    ip = ip_match.group(1) if ip_match else None
                    emit_alert("SQL Injection Attempt", ip, "Suspicious SQL-like pattern detected", csv_path, dedupe_seconds)

    except FileNotFoundError:
        print(Fore.RED + f"[!] Log file not found: {log_path}" + Style.RESET_ALL)
    except KeyboardInterrupt:
        print("\n" + Fore.CYAN + "Stopping LogSentry (user interrupt)." + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"[!] Unexpected error: {e}" + Style.RESET_ALL)

# ====== CLI ======
def parse_args():
    p = argparse.ArgumentParser(description="LogSentry - real-time log monitor & alerter")
    p.add_argument("--log-file", "-l", default=DEFAULT_LOG, help="Path to log file to monitor")
    p.add_argument("--alert-csv", "-o", default=DEFAULT_ALERT_CSV, help="CSV file to append alerts to")
    p.add_argument("--dedupe", "-d", type=int, default=DEFAULT_DEDUPE_SECONDS, help="Duplicate suppression (seconds)")
    p.add_argument("--poll", "-p", type=float, default=DEFAULT_POLL_INTERVAL, help="File polling interval (seconds)")
    return p.parse_args()

def main():
    args = parse_args()
    monitor_log_file(args.log_file, args.alert_csv, args.dedupe, args.poll)

if __name__ == "__main__":
    main()


#__example entry
#


