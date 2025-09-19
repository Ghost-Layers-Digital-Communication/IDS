import os
import json
import threading
import datetime
import time
from collections import defaultdict
import platform
from scapy.all import sniff, TCP, IP

# ==================== CONFIG ====================
CONFIG = {
    "threshold_attempts": 5,
    "threshold_seconds": 10,
    "auto_unblock_minutes": 5,
    "log_file": os.path.join(os.path.expanduser("~"), "Desktop", "IDS_log.txt"),
    "db_file": os.path.join(os.path.expanduser("~"), "Desktop", "IDS_db.json"),
    "ports_to_monitor": [22, 80, 443],
    "dry_run": False, # True = detect only, False = actually block
    "monitor_ip": None # IP will be set dynamically from GUI
}

OS = platform.system() # 'Windows', 'Linux', 'Darwin'

# ==================== DATA STRUCTURES ====================
connection_attempts = defaultdict(lambda: defaultdict(list))
blocked_ips = {}
lock = threading.Lock()

# ==================== HELPER FUNCTIONS ====================
def log_event(message):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"{timestamp} | {message}"
    print(line)
    # GUI callback will be injected from Part 2 if available
    try:
        gui_callback(line)
    except:
        pass
    with open(CONFIG["log_file"], "a") as f:
        f.write(line + "\n")
    return line

def save_db():
    with lock:
        with open(CONFIG["db_file"], "w") as f:
            json.dump(blocked_ips, f, indent=2)

def load_db():
    global blocked_ips
    if os.path.exists(CONFIG["db_file"]):
        with open(CONFIG["db_file"], "r") as f:
            blocked_ips = json.load(f)

def add_attempt(ip, port):
    with lock:
        now = time.time()
        connection_attempts[ip][port].append(now)

def check_threshold(ip, port):
    with lock:
        attempts = connection_attempts[ip][port]
        window_start = time.time() - CONFIG["threshold_seconds"]
        connection_attempts[ip][port] = [t for t in attempts if t >= window_start]
        return len(connection_attempts[ip][port]) >= CONFIG["threshold_attempts"]

def block_ip(ip, ports):
    if CONFIG["dry_run"]:
        log_event(f"DRY RUN: Would block {ip} on ports {ports}")
        return

    with lock:
        blocked_ips[ip] = {"ports": ports, "blocked_at": time.time()}
        save_db()
        log_event(f"BLOCKED {ip} on ports {ports}")

        if OS == "Windows":
            for port in ports:
                cmd = f'netsh advfirewall firewall add rule name="GhostLayer-{ip}-{port}" dir=in action=block remoteip={ip}'
                os.system(cmd)
        elif OS == "Linux":
            for port in ports:
                cmd = f'sudo iptables -A INPUT -p tcp --dport {port} -s {ip} -j DROP'
                os.system(cmd)

def unblock_ip(ip):
    with lock:
        if ip in blocked_ips:
            ports = blocked_ips[ip]["ports"]
            if not CONFIG["dry_run"]:
                if OS == "Windows":
                    for port in ports:
                        cmd = f'netsh advfirewall firewall delete rule name="GhostLayer-{ip}-{port}"'
                        os.system(cmd)
                elif OS == "Linux":
                    for port in ports:
                        cmd = f'sudo iptables -D INPUT -p tcp --dport {port} -s {ip} -j DROP'
                        os.system(cmd)
            del blocked_ips[ip]
            save_db()
            log_event(f"UNBLOCKED {ip}")

def auto_unblock_loop():
    while True:
        with lock:
            now = time.time()
            for ip, info in list(blocked_ips.items()):
                if now - info["blocked_at"] >= CONFIG["auto_unblock_minutes"] * 60:
                    unblock_ip(ip)
        time.sleep(30)

# ==================== SCAPY PACKET MONITORING ====================
def packet_callback(pkt):
    if IP in pkt and TCP in pkt:
        ip_src = pkt[IP].src
        port = pkt[TCP].dport
        tcp_flags = pkt[TCP].flags

        # Only monitor specified ports
        if port not in CONFIG["ports_to_monitor"]:
            return
        # Only monitor specified IP if set
        if CONFIG["monitor_ip"] and ip_src != CONFIG["monitor_ip"]:
            return

        if tcp_flags & 0x02: # SYN flag
            add_attempt(ip_src, port)
            if check_threshold(ip_src, port):
                if ip_src not in blocked_ips:
                    block_ip(ip_src, [port])
                    try:
                        gui_callback(f"ALERT: {ip_src} exceeded threshold on port {port}")
                    except:
                        pass
            else:
                try:
                    gui_callback(f"Connection attempt from {ip_src} on port {port}")
                except:
                    pass

def start_sniffing():
    log_event(f"Starting Scapy packet sniffing on ports: {CONFIG['ports_to_monitor']}")
    sniff(filter="tcp", prn=packet_callback, store=0)

def start_monitor_thread():
    t = threading.Thread(target=start_sniffing, daemon=True)
    t.start()
    log_event("Packet sniffing thread started")

# ==================== LOAD PREVIOUS DB ====================
load_db()
threading.Thread(target=auto_unblock_loop, daemon=True).start()

import tkinter as tk
from tkinter import scrolledtext, messagebox
import threading

# ==================== GUI CONFIG ====================
FG_COLOR = "#00FF00"
BG_COLOR = "#000000"
FONT = ("Courier", 12)

# Reference to backend functions
# Part 1 must have been imported with: from part1_backend import start_monitor_thread, CONFIG

root = tk.Tk()
root.title("===[Ghost-Layer IDS Firewall]=== coded by: sacred G")
root.configure(bg=BG_COLOR)
root.geometry("700x500")

# ==================== LOG DISPLAY ====================
log_text = scrolledtext.ScrolledText(root, width=80, height=25, bg=BG_COLOR, fg=FG_COLOR, font=FONT)
log_text.pack(fill="both", expand=True, padx=10, pady=10)

def append_log(message):
    log_text.configure(state="normal")
    log_text.insert(tk.END, message + "\n")
    log_text.see(tk.END)
    log_text.configure(state="disabled")

# ==================== GUI CALLBACK ====================
def gui_callback(message):
    append_log(message)

# Inject callback into backend namespace
globals()["gui_callback"] = gui_callback

# ==================== BUTTON COMMANDS ====================
def start_monitoring():
    start_monitor_thread()
    append_log("Monitoring started.")

def stop_monitoring():
    # Currently backend thread is daemon; stopping means just disabling GUI alerts
    append_log("Monitoring stopped (backend still running in daemon thread).")

def add_port():
    port = port_entry.get()
    try:
        port_num = int(port)
        if port_num not in CONFIG["ports_to_monitor"]:
            CONFIG["ports_to_monitor"].append(port_num)
            append_log(f"Added port {port_num} to monitoring list.")
        else:
            append_log(f"Port {port_num} is already being monitored.")
    except ValueError:
        append_log("Invalid port number.")

# ==================== CONTROL FRAME ====================
control_frame = tk.Frame(root, bg=BG_COLOR)
control_frame.pack(fill="x", padx=10, pady=5)

start_btn = tk.Button(control_frame, text="Connect / Start", command=start_monitoring, bg=BG_COLOR, fg=FG_COLOR, font=FONT)
start_btn.pack(side="left", padx=5, pady=5)

stop_btn = tk.Button(control_frame, text="Disconnect / Stop", command=stop_monitoring, bg=BG_COLOR, fg=FG_COLOR, font=FONT)
stop_btn.pack(side="left", padx=5, pady=5)

port_entry = tk.Entry(control_frame, bg=BG_COLOR, fg=FG_COLOR, font=FONT, width=10)
port_entry.pack(side="left", padx=5, pady=5)
port_entry.insert(0, "Enter port")

add_port_btn = tk.Button(control_frame, text="Add Port", command=add_port, bg=BG_COLOR, fg=FG_COLOR, font=FONT)
add_port_btn.pack(side="left", padx=5, pady=5)

# ==================== RUN GUI ====================
root.mainloop()
