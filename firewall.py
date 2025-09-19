import socket
import threading
import json
import os
import datetime
import time

# ==================== CONFIG ====================
CONFIG = {
    "threshold_attempts": 5, # Attempts per time window
    "threshold_seconds": 10, # Time window in seconds
    "auto_unblock_minutes": 5, # Auto unblock after X minutes
    "log_file": os.path.join(os.path.expanduser("~"), "Desktop", "IDS_log.txt"),
    "db_file": os.path.join(os.path.expanduser("~"), "Desktop", "IDS_db.json")
}

# ==================== DATA STRUCTURES ====================
connection_attempts = {} # {ip: {port: [timestamps]}}
blocked_ips = {} # {ip: {"ports": [], "blocked_at": timestamp}}

lock = threading.Lock()

# ==================== HELPER FUNCTIONS ====================
def log_event(message):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"{timestamp} | {message}"
    print(line)
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
        if ip not in connection_attempts:
            connection_attempts[ip] = {}
        if port not in connection_attempts[ip]:
            connection_attempts[ip][port] = []
        connection_attempts[ip][port].append(now)

def check_threshold(ip, port):
    with lock:
        attempts = connection_attempts[ip][port]
        window_start = time.time() - CONFIG["threshold_seconds"]
        # Keep only recent attempts
        connection_attempts[ip][port] = [t for t in attempts if t >= window_start]
        return len(connection_attempts[ip][port]) >= CONFIG["threshold_attempts"]

def block_ip(ip, ports):
    with lock:
        blocked_ips[ip] = {
            "ports": ports,
            "blocked_at": time.time()
        }
        save_db()
        log_event(f"BLOCKED {ip} on ports {ports}")

def unblock_ip(ip):
    with lock:
        if ip in blocked_ips:
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

# Start auto-unblock thread
threading.Thread(target=auto_unblock_loop, daemon=True).start()

# ==================== MONITORING LOGIC ====================
def monitor_port(ip_to_monitor, port_to_monitor, callback=None):
    """
    Monitor a single port on localhost
    ip_to_monitor: string (e.g., '127.0.0.1' or '')
    port_to_monitor: integer port
    callback: optional function to notify GUI/log
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind((ip_to_monitor, port_to_monitor))
        s.listen()
    except OSError:
        log_event(f"Port {port_to_monitor} unavailable (in use?)")
        return
    log_event(f"Monitoring port {port_to_monitor} on {ip_to_monitor}")

    while True:
        try:
            conn, addr = s.accept()
            ip = addr[0]
            add_attempt(ip, port_to_monitor)
            if check_threshold(ip, port_to_monitor):
                if ip not in blocked_ips:
                    block_ip(ip, [port_to_monitor])
                    if callback:
                        callback(f"ALERT: {ip} exceeded threshold on port {port_to_monitor}")
            else:
                if callback:
                    callback(f"Connection from {ip} on port {port_to_monitor}")
            conn.close()
        except Exception as e:
            log_event(f"Error monitoring port {port_to_monitor}: {e}")

import tkinter as tk
from tkinter import scrolledtext, messagebox
import threading

# ==================== GUI CONFIG ====================
FG_COLOR = "#00FF00"
BG_COLOR = "#000000"
FONT = ("Courier", 12)

monitor_threads = []

# ==================== GUI WINDOW ====================
root = tk.Tk()
root.title("Ghost-Layer IDS Firewall")
root.configure(bg=BG_COLOR)
root.geometry("900x600")
root.minsize(800, 500)

# ==================== TOP FRAME (Buttons & Input) ====================
top_frame = tk.Frame(root, bg=BG_COLOR)
top_frame.pack(side=tk.TOP, fill=tk.X, padx=10, pady=5)

# IP Label & Entry
tk.Label(top_frame, text="Monitor IP:", bg=BG_COLOR, fg=FG_COLOR, font=FONT).grid(row=0, column=0, padx=5, sticky="w")
ip_entry = tk.Entry(top_frame, bg=BG_COLOR, fg=FG_COLOR, font=FONT, insertbackground=FG_COLOR)
ip_entry.grid(row=0, column=1, padx=5, sticky="we")
ip_entry.insert(0, "127.0.0.1")

# Ports Label & Entry
tk.Label(top_frame, text="Ports (comma-separated):", bg=BG_COLOR, fg=FG_COLOR, font=FONT).grid(row=0, column=2, padx=5, sticky="w")
port_entry = tk.Entry(top_frame, bg=BG_COLOR, fg=FG_COLOR, font=FONT, insertbackground=FG_COLOR)
port_entry.grid(row=0, column=3, padx=5, sticky="we")
port_entry.insert(0, "22,80,443")

# Configure grid columns to expand
for i in range(4):
    top_frame.columnconfigure(i, weight=1)

# Buttons
def connect_action():
    append_log("Monitoring started", color="#00FF00")
    start_monitoring()

def disconnect_action():
    append_log("Monitoring stopped", color="#FF0000")
    stop_monitoring()

connect_button = tk.Button(top_frame, text="Connect", bg=BG_COLOR, fg=FG_COLOR, font=FONT, command=connect_action)
connect_button.grid(row=0, column=4, padx=5, sticky="we")

disconnect_button = tk.Button(top_frame, text="Disconnect", bg=BG_COLOR, fg=FG_COLOR, font=FONT, command=disconnect_action)
disconnect_button.grid(row=0, column=5, padx=5, sticky="we")

top_frame.columnconfigure(4, weight=0)
top_frame.columnconfigure(5, weight=0)

# ==================== LOG AREA ====================
log_area = scrolledtext.ScrolledText(root, bg=BG_COLOR, fg=FG_COLOR, font=FONT)
log_area.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=10, pady=5)

def append_log(text, color=FG_COLOR):
    log_area.configure(state=tk.NORMAL)
    log_area.insert(tk.END, text + "\n", color)
    log_area.tag_config(color, foreground=color)
    log_area.see(tk.END)
    log_area.configure(state=tk.DISABLED)

# ==================== MONITORING LOGIC ====================
def gui_callback(msg):
    append_log(msg, color="#00FF00")
    if msg.startswith("ALERT:"):
        messagebox.showinfo("Alert", msg)

def monitor_loop(ip, port):
    from __main__ import monitor_port
    monitor_port(ip, port, callback=gui_callback)

def start_monitoring():
    stop_monitoring()
    ip = ip_entry.get().strip()
    ports = port_entry.get().strip().split(",")
    for p in ports:
        try:
            port = int(p.strip())
        except ValueError:
            append_log(f"Invalid port: {p}", color="#FF0000")
            continue
        t = threading.Thread(target=monitor_loop, args=(ip, port), daemon=True)
        monitor_threads.append(t)
        t.start()

def stop_monitoring():
    global monitor_threads
    monitor_threads = []

# ==================== START GUI ====================
root.mainloop()
