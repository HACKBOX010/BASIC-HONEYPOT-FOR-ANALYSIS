# Project Technology Report: Cyber Honeypot & Threat Intelligence Dashboard

This report provides a comprehensive breakdown of the components, libraries, and architectural choices used in the **Cyber Honeypot** project.

## 1. System Architecture Overview
The project is a multi-process security application consisting of a **Simulated SSH Honeypot** and a **Real-time Threat Intelligence Dashboard**. It is designed to attract, log, and analyze malicious network activity.

---

## 2. Backend Technology Stack (Python)
The core logic is implemented in **Python 3**, leveraging several specialized libraries for networking and web services.

### Core Frameworks & Libraries
| Component | Technology | Purpose |
| :--- | :--- | :--- |
| **Web Server** | [Flask](https://flask.palletsprojects.com/) | Provides the REST API and serves the dashboard UI. |
| **SSH Protocol** | [Paramiko](https://www.paramiko.org/) | Handles SSH connections, authentication simulation, and command logging. |
| **Security** | [Cryptography](https://cryptography.io/) | Manages SSH host keys and secure communication layers. |
| **API Client** | [Requests](https://requests.readthedocs.io/) | Performs external HTTP calls for real-time Geo-IP lookups. |
| **WSGI Server** | [Gunicorn](https://gunicorn.org/) | High-performance Python HTTP server for production deployment. |

### Data Management
- **Logging**: Uses a JSON-based event stream (`cowrie.json`) compatible with the Cowrie honeypot ecosystem.
- **Caching**: Local JSON cache (`ip_geo_cache.json`) to minimize API calls and improve dashboard performance.
- **State Management**: Real-time calculation of "Risk Scores" based on attacker behavior (e.g., successful logins vs. failed attempts).

---

## 3. Frontend Technology Stack (Web UI)
The dashboard uses a modern, high-performance frontend stack designed for low-latency updates.

### Visual & Interactive Components
- **Framework**: Vanilla JavaScript (ES6+) for maximum performance and zero dependency overhead.
- **Visualizations**: [Chart.js](https://www.chartjs.org/) is used for:
    - Attack distribution timelines (24h).
    - Top attacking IP addresses (Horizontal Bar Charts).
    - Common password/username frequency analysis.
- **Styling**: Vanilla CSS3 with a custom "Cyber" design system:
    - **Color Palette**: Slate/Zinc dark mode with semantic accents (Danger Red, Success Green, Accent Blue).
    - **Typography**: [Inter](https://fonts.google.com/specimen/Inter) via Google Fonts.
    - **Animations**: CSS keyframes for "Critical Breach" tickers and "Bait Access" pulsing alerts.

---

## 4. Security & Honeypot Features
- **Bait System**: Simulated file system access tracking (`cowrie.honeyfile.access`) to detect data exfiltration attempts.
    - **Decoy Files**: High-value targets like `transactions.csv` and `user_bank_details.csv` are used to monitor deep attacker engagement.
- **IP Intelligence**: Integration with `ipwho.is` for real-time attribution of attack sources.
- **Dynamic Risk Engine**: A custom backend algorithm that assigns scores to IPs based on:
    - Login success (Critical Risk)
    - Command execution (High Risk)
    - File downloads (High Risk)
    - Connection volume (Baseline Risk)

---

## 5. Deployment & DevOps
- **Process Orchestration**: `run_all.py` manages the concurrent execution of the honeypot listener and the web dashboard.
- **Startup Automation**: `START.bat` for one-click initialization on Windows environments.
- **Cloud Readiness**: `Procfile` included for seamless deployment to platforms like Heroku or Render.
- **Environment Isolation**: Configured for Python Virtual Environments (`.venv`) to ensure dependency consistency.

---

## 6. Summary of Dependencies
As listed in `requirements.txt`:
- `flask`: Web Framework
- `paramiko`: SSH Library
- `cryptography`: Security Primitives
- `requests`: HTTP Client
- `gunicorn`: Production Server
