import subprocess
import os
import sys
import time
import signal
import webbrowser
import io
from concurrent.futures import ThreadPoolExecutor

# Force UTF-8 encoding for terminal output
if sys.stdout.encoding != 'utf-8':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

# Colors for terminal output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def print_banner():
    banner = f"""
{Colors.CYAN}{Colors.BOLD}
    ╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║   🛡️  CYBER HONEYPOT ALL-IN-ONE STARTER                   ║
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝
{Colors.ENDC}
    """
    print(banner)

def run_process(command, label, color):
    """Runs a subprocess and streams its output with a label."""
    print(f"{color}[STARTING]{Colors.ENDC} {label}...")
    process = subprocess.Popen(
        [sys.executable, command],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        universal_newlines=True
    )
    
    # Prefix every line with the label
    for line in iter(process.stdout.readline, ""):
        if line:
            print(f"{color}[{label}]{Colors.ENDC} {line.strip()}")
    
    process.wait()
    return process.returncode

def main():
    print_banner()
    
    # Paths to the scripts
    honeypot_script = "ssh_honeypot.py"
    dashboard_script = "3_dashboard.py"
    
    # Check if files exist
    if not os.path.exists(honeypot_script) or not os.path.exists(dashboard_script):
        print(f"{Colors.FAIL}[ERROR]{Colors.ENDC} Could not find required scripts.")
        sys.exit(1)

    processes = []
    
    try:
        # Start Honeypot
        hp_proc = subprocess.Popen([sys.executable, honeypot_script], 
                                  stdout=None, 
                                  stderr=None)
        processes.append(hp_proc)
        print(f"{Colors.GREEN}[SUCCESS]{Colors.ENDC} SSH Honeypot is running on port 2222")

        # Start Dashboard
        db_proc = subprocess.Popen([sys.executable, dashboard_script],
                                  stdout=None,
                                  stderr=None)
        processes.append(db_proc)
        print(f"{Colors.GREEN}[SUCCESS]{Colors.ENDC} Main Dashboard is running on http://localhost:5005")

        # Wait another moment then open browser
        time.sleep(2)
        print(f"{Colors.CYAN}[INFO]{Colors.ENDC} Opening dashboard...")
        webbrowser.open("http://localhost:5005")

        print(f"\n{Colors.WARNING}{Colors.BOLD}>>> System is fully active. Press Ctrl+C to stop all services.{Colors.ENDC}\n")

        # Keep the main thread alive while subprocesses are running
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}[TERMINATING]{Colors.ENDC} Stopping all services...")
        for p in processes:
            p.terminate()
        
        # Give them a moment to shut down gracefully
        time.sleep(1)
        
        # Kill if they haven't stopped
        for p in processes:
            if p.poll() is None:
                p.kill()
        
        print(f"{Colors.GREEN}[DONE]{Colors.ENDC} All services stopped.")

if __name__ == "__main__":
    main()
