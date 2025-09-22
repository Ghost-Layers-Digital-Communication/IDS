import os
import json
import threading
import datetime
import time
from collections import defaultdict
import platform
from scapy.all import sniff, TCP, IP, get_if_list
import tkinter as tk
from tkinter import scrolledtext
import subprocess

# ==================== CONFIG ====================
CONFIG = {
    "threshold_attempts": 5,
    "threshold_seconds": 10,
    "auto_unblock_minutes": 5,
    "log_file": os.path.join(os.path.expanduser("~"), "Desktop", "IDS_log.txt"),
    "db_file": os.path.join(os.path.expanduser("~"), "Desktop", "IDS_db.json"),
    "ports_to_monitor": [22, 80, 443],
    "dry_run": False,
    "monitor_ip": None,
    "iface": None
}

OS = platform.system()

# ==================== DATA STRUCTURES ====================
connection_attempts = defaultdict(lambda: defaultdict(list))
blocked_ips = {}
lock = threading.Lock()

# ==================== GUI ====================
FG_COLOR = "#00FF00"
BG_COLOR = "#000000"
FONT = ("Courier", 12)

root = tk.Tk()
root.title("===[Ghost-Layers IDS Firewall]=== coded by: sacred G")
root.configure(bg=BG_COLOR)
root.geometry("1250x550")

log_text = scrolledtext.ScrolledText(root, width=90, height=25, bg=BG_COLOR, fg=FG_COLOR, font=FONT)
log_text.pack(fill="both", expand=True, padx=10, pady=10)

def append_log(message):
    log_text.configure(state="normal")
    log_text.insert(tk.END, message + "\n")
    log_text.see(tk.END)
    log_text.configure(state="disabled")

def gui_callback(message):
    append_log(message)

globals()["gui_callback"] = gui_callback

# ==================== HELPER FUNCTIONS ====================
def log_event(message):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"{timestamp} | {message}"
    print(line)
    try:
        root.after(0, lambda: gui_callback(line))
    except Exception as e:
        print(f"[GUI CALLBACK ERROR] {e}")
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
                os.system(f'netsh advfirewall firewall add rule name="GhostLayer-{ip}-{port}" dir=in action=block remoteip={ip}')
        elif OS == "Linux":
            for port in ports:
                os.system(f'sudo iptables -A INPUT -p tcp --dport {port} -s {ip} -j DROP')

def unblock_ip(ip):
    with lock:
        if ip in blocked_ips:
            ports = blocked_ips[ip]["ports"]
            if not CONFIG["dry_run"]:
                if OS == "Windows":
                    for port in ports:
                        os.system(f'netsh advfirewall firewall delete rule name="GhostLayer-{ip}-{port}"')
                elif OS == "Linux":
                    for port in ports:
                        os.system(f'sudo iptables -D INPUT -p tcp --dport {port} -s {ip} -j DROP')
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

# ==================== PACKET MONITORING ====================
def packet_callback(pkt):
    if IP in pkt and TCP in pkt:
        ip_src = pkt[IP].src
        port = pkt[TCP].dport
        tcp_flags = pkt[TCP].flags

        if port not in CONFIG["ports_to_monitor"]:
            return
        if CONFIG["monitor_ip"] and ip_src != CONFIG["monitor_ip"]:
            return

        if tcp_flags & 0x02:  # SYN flag
            add_attempt(ip_src, port)
            log_event(f"Attempt from {ip_src} on port {port}")
            if check_threshold(ip_src, port):
                if ip_src not in blocked_ips:
                    block_ip(ip_src, [port])
                    log_event(f"ALERT: {ip_src} exceeded threshold on port {port}")

def start_sniffing():
    iface = CONFIG["iface"]
    if not iface:
        log_event("No interface selected. Cannot start sniffing.")
        return
    log_event(f"Starting sniffing on interface {iface} for ports {CONFIG['ports_to_monitor']}")
    sniff(filter="tcp", prn=packet_callback, store=0, iface=iface)

def start_monitor_thread():
    t = threading.Thread(target=start_sniffing, daemon=True)
    t.start()
    log_event("Packet sniffing thread started")

# ==================== LOAD DB AND START AUTO-UNBLOCK ====================
load_db()
threading.Thread(target=auto_unblock_loop, daemon=True).start()

# ==================== INTERFACE & ESSID FUNCTIONS ====================
def get_current_essid(iface_name):
    """Return the connected ESSID for a given interface (Windows/Linux)."""
    try:
        if OS == "Windows":
            output = subprocess.check_output("netsh wlan show interfaces", shell=True, text=True)
            for line in output.splitlines():
                if "SSID" in line and "BSSID" not in line:
                    return line.split(":", 1)[1].strip()
        elif OS == "Linux":
            output = subprocess.check_output(f"iwgetid {iface_name} -r", shell=True, text=True).strip()
            return output if output else "N/A"
    except Exception:
        return "N/A"
    return "N/A"

def get_interfaces_with_essid():
    lst = []
    for iface in get_if_list():
        essid = get_current_essid(iface)
        lst.append(f"{iface} ({essid})")
    return lst

# ==================== CONTROL FRAME ====================
control_frame = tk.Frame(root, bg=BG_COLOR)
control_frame.pack(fill="x", padx=10, pady=5)

# Start / Stop buttons
start_btn = tk.Button(control_frame, text="Start Monitoring", command=start_monitor_thread, bg=BG_COLOR, fg=FG_COLOR, font=FONT)
start_btn.pack(side="left", padx=5, pady=5)

stop_btn = tk.Button(control_frame, text="Stop Monitoring", command=lambda: append_log("Monitoring stopped (backend still running)."), bg=BG_COLOR, fg=FG_COLOR, font=FONT)
stop_btn.pack(side="left", padx=5, pady=5)

# Port entry
port_entry = tk.Entry(control_frame, bg=BG_COLOR, fg=FG_COLOR, font=FONT, width=10)
port_entry.pack(side="left", padx=5, pady=5)
port_entry.insert(0, "Enter port")

def add_port():
    try:
        port_num = int(port_entry.get())
        if port_num not in CONFIG["ports_to_monitor"]:
            CONFIG["ports_to_monitor"].append(port_num)
            append_log(f"Added port {port_num} to monitoring list.")
        else:
            append_log(f"Port {port_num} is already monitored.")
    except ValueError:
        append_log("Invalid port number.")

add_port_btn = tk.Button(control_frame, text="Add Port", command=add_port, bg=BG_COLOR, fg=FG_COLOR, font=FONT)
add_port_btn.pack(side="left", padx=5, pady=5)

# Interface selection with ESSID
iface_label = tk.Label(control_frame, text="Interface:", bg=BG_COLOR, fg=FG_COLOR, font=FONT)
iface_label.pack(side="left", padx=5)

iface_var = tk.StringVar()
interfaces_with_essid = get_interfaces_with_essid()
iface_var.set(interfaces_with_essid[0] if interfaces_with_essid else "None")

iface_dropdown = tk.OptionMenu(control_frame, iface_var, *interfaces_with_essid)
iface_dropdown.config(bg=BG_COLOR, fg=FG_COLOR, font=FONT, width=30, anchor="w")
iface_dropdown.pack(side="left", padx=5)

def set_iface():
    # Extract the interface name from the dropdown string "iface (ESSID)"
    selected = iface_var.get()
    iface_name = selected.split("(", 1)[0].strip()
    CONFIG["iface"] = iface_name
    append_log(f"Selected interface: {CONFIG['iface']}")

iface_set_btn = tk.Button(control_frame, text="Set Interface", command=set_iface, bg=BG_COLOR, fg=FG_COLOR, font=FONT)
iface_set_btn.pack(side="left", padx=5, pady=5)

# Refresh interfaces button
def refresh_interfaces():
    new_list = get_interfaces_with_essid()
    iface_var.set(new_list[0] if new_list else "None")
    menu = iface_dropdown["menu"]
    menu.delete(0, "end")
    for item in new_list:
        menu.add_command(label=item, command=lambda v=item: iface_var.set(v))
    append_log("Interface list refreshed.")

refresh_btn = tk.Button(control_frame, text="Refresh Interfaces", command=refresh_interfaces, bg=BG_COLOR, fg=FG_COLOR, font=FONT)
refresh_btn.pack(side="left", padx=5, pady=5)

root.mainloop()
