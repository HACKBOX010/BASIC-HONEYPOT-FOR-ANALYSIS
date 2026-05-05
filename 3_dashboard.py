from flask import Flask, render_template, jsonify, redirect, url_for, Response
import json
import time
import os
import argparse
from datetime import datetime
from collections import Counter
import random
import sys
import requests

# Constants
TEMPLATE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
app = Flask(__name__, template_folder=TEMPLATE_DIR)

# Global Config
LOG_FILE = "cowrie.json"
GEO_CACHE_FILE = "ip_geo_cache.json"
_geo_cache = {}

def load_geo_cache():
    global _geo_cache
    if os.path.exists(GEO_CACHE_FILE):
        try:
            with open(GEO_CACHE_FILE, 'r') as f:
                _geo_cache = json.load(f)
        except:
            _geo_cache = {}

def save_geo_cache():
    try:
        with open(GEO_CACHE_FILE, 'w') as f:
            json.dump(_geo_cache, f)
    except:
        pass

load_geo_cache()


def get_real_geo(ip):
    if not ip or ip == "Unknown" or ip.startswith("192.168.") or ip.startswith("10.") or ip == "127.0.0.1":
        return {"city": "Internal/Private", "lat": 20, "lon": 0}
    
    if ip in _geo_cache:
        return _geo_cache[ip]
    
    try:
        # Using ipwho.is (free, no key needed for low volume)
        resp = requests.get(f"http://ipwho.is/{ip}", timeout=5)
        data = resp.json()
        if data.get('success'):
            geo = {
                "city": f"{data.get('city', 'Unknown')}, {data.get('country_code', '??')}",
                "lat": data.get('latitude', 0),
                "lon": data.get('longitude', 0)
            }
            _geo_cache[ip] = geo
            save_geo_cache()
            return geo
    except Exception as e:
        print(f"Geo lookup failed for {ip}: {e}")
    
    return {"city": "Unknown", "lat": 0, "lon": 0}
    

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
                "downloads": 0,
                "bait_access": 0
            },
            "bait_stats": {
                "total_leaked_mb": 0,
                "top_targets": []
            },
            "charts": {
                "hourly": [0] * 24,
                "top_ips": [],
                "top_usernames": [],
                "top_passwords": [],
                "top_commands": []
            },
            "recent_events": [],
            "risk_scores": []
        }

        ip_counter = Counter()
        user_counter = Counter()
        pass_counter = Counter()
        cmd_counter = Counter()
        bait_counter = Counter()

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
            
            if eid == "cowrie.honeyfile.access":
                stats["kpis"]["bait_access"] += 1
                bait_counter[event.get("file", "Unknown")] += 1
                # simulate leak size
                if "transactions" in event.get("file", ""):
                    stats["bait_stats"]["total_leaked_mb"] += random.uniform(5, 50)
                else:
                    stats["bait_stats"]["total_leaked_mb"] += random.uniform(0.1, 2)
            
            if eid and "download" in eid.lower():
                stats["kpis"]["downloads"] += 1

        stats["bait_stats"]["top_targets"] = [{"label": str(f), "value": count} for f, count in bait_counter.most_common(5)]

        stats["charts"]["top_ips"] = [{"label": str(ip), "value": count} for ip, count in ip_counter.most_common(10)]
        stats["charts"]["top_usernames"] = [{"label": str(u), "value": count} for u, count in user_counter.most_common(10)]
        stats["charts"]["top_passwords"] = [{"label": str(p), "value": count} for p, count in pass_counter.most_common(10)]
        stats["charts"]["top_commands"] = [{"label": str(c), "value": count} for c, count in cmd_counter.most_common(10)]
        
        # Calculate Risk Scores
        risk_map = {}
        unique_ips = set(ip_counter.keys())
        for ip in unique_ips:
            if ip == "Unknown": continue
            # Default risk based on pure volume of connections
            risk = ip_counter[ip] * 0.5 
            risk_map[ip] = risk

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
            elif eid == "cowrie.honeyfile.access":
                risk_map[ip] += 50 # massive risk for bait access
                
        # Top 5 highest risk
        sorted_risk = sorted(risk_map.items(), key=lambda item: item[1], reverse=True)[:5]
        stats["risk_scores"] = [{"ip": k, "score": int(v), "city": get_real_geo(k)["city"]} for k, v in sorted_risk]
        
        # Get 20 most recent
        sorted_events = sorted(data, key=lambda x: str(x.get("timestamp", "")), reverse=True)
        # To make ticker work better, we will pass eventid along with a friendly message
        stats["recent_events"] = sorted_events[:30]

        return jsonify(stats)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Cowrie Honeypot Dashboard")
    parser.add_argument("--log", default="cowrie.json", help="Path to cowrie.json")
    parser.add_argument("--port", type=int, default=5005, help="Port to run on")
    args = parser.parse_args()
    
    LOG_FILE = args.log
    
    print(f"Starting dashboard on port {args.port}...")
    
    app.run(host='0.0.0.0', port=args.port, debug=False) # Turned off debug for stability in this env
