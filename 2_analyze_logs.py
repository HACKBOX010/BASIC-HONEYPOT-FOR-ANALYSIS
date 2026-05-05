import json
import argparse
from collections import Counter
from datetime import datetime
import os
import random
import sys
import io

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')


def analyze_logs(log_file):
    if not os.path.exists(log_file):
        print(f"Error: {log_file} not found.")
        return None
        
    data = []
    with open(log_file, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line: continue
            try:
                data.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    if not data:
        return None

    stats = {
        "total_events": len(data),
        "unique_ips": Counter(),
        "usernames": Counter(),
        "passwords": Counter(),
        "commands": Counter(),
        "hourly_dist": Counter(),
        "login_success": 0,
        "login_failed": 0,
        "connections": 0
    }

    for event in data:
        src_ip = event.get("src_ip", "Unknown")
        stats["unique_ips"][src_ip] += 1
        
        ts = event.get("timestamp")
        if ts:
            try:
                clean_ts = ts.replace("Z", "").split(".")[0]
                hour = datetime.fromisoformat(clean_ts).hour
                stats["hourly_dist"][hour] += 1
            except (ValueError, TypeError):
                pass
        
        eid = event.get("eventid", "")
        if eid == "cowrie.session.connect":
            stats["connections"] += 1
        elif eid == "cowrie.login.success":
            stats["login_success"] += 1
            stats["usernames"][event.get("username", "Unknown")] += 1
            stats["passwords"][event.get("password", "Unknown")] += 1
        elif eid == "cowrie.login.failed":
            stats["login_failed"] += 1
            stats["usernames"][event.get("username", "Unknown")] += 1
            stats["passwords"][event.get("password", "Unknown")] += 1
        elif eid == "cowrie.command.input":
            stats["commands"][event.get("input", "Unknown")] += 1

    return stats

def print_report(stats):
    if not stats:
        print("No data to report.")
        return

    report = []
    report.append("="*40)
    report.append("HONEYPOT SECURITY ANALYSIS REPORT")
    report.append("="*40)
    report.append(f"Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report.append(f"Total Events: {stats['total_events']}")
    report.append(f"Connections: {stats['connections']}")
    report.append(f"Login Attempts: {stats['login_success'] + stats['login_failed']} (Success: {stats['login_success']}, Failed: {stats['login_failed']})")
    report.append(f"Unique Attacking IPs: {len(stats['unique_ips'])}")
    
    report.append("\nTop 5 Attacking IPs:")
    for ip, count in stats['unique_ips'].most_common(5):
        report.append(f"  {ip}: {count}")
    
    report.append("\nTop 5 Usernames Used:")
    for user, count in stats['usernames'].most_common(5):
        report.append(f"  {user}: {count}")
        
    report.append("\nTop 5 Commands Executed:")
    for cmd, count in stats['commands'].most_common(5):
        report.append(f"  {cmd}: {count}")
        
    report_text = "\n".join(report)
    print(report_text)
    
    with open("honeypot_report.txt", "w", encoding='utf-8') as f:
        f.write(report_text)
    print("\nReport saved to honeypot_report.txt")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze Cowrie Honeypot Logs")
    parser.add_argument("--log", default="cowrie.json", help="Path to cowrie.json log file")
    args = parser.parse_args()
    
    analysis_stats = analyze_logs(args.log)
    if analysis_stats:
        print_report(analysis_stats)
