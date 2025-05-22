import tkinter as tk
from tkinter import filedialog, messagebox
import ipaddress
import socket
import subprocess
import threading
import os
import re
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import pandas as pd
import csv
import ttkbootstrap as tb
from ttkbootstrap.toast import ToastNotification

# OUI dictionary for vendors
OUI_DICT = {
    "00:1A:79": "Cisco Systems",
    "00:1B:44": "Dell Inc",
    "00:1E:C2": "Hewlett-Packard",
    "00:21:5A": "Lenovo ThinkCentre",
    "00:13:72": "Wyse Technology",
    "00:50:56": "VMware, Inc.",
    "00:1C:23": "Lenovo",
    "00:17:F2": "Hewlett Packard",
}

def get_vendor_from_mac(mac):
    prefix = mac.upper()[0:8]
    return OUI_DICT.get(prefix, "Unknown")

def get_mac_address(ip):
    try:
        pid = subprocess.Popen(
            ["arp", "-a", ip],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
        )
        out, _ = pid.communicate(timeout=3)
        out = out.decode(errors="ignore")
        regex = re.compile(r"([0-9a-f]{2}[:-]){5}([0-9a-f]{2})", re.I)
        mac = regex.search(out)
        return mac.group(0) if mac else "N/A"
    except Exception:
        return "N/A"

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "N/A"

def get_last_login_windows(host, username, password):
    if not username:
        return "N/A"
    try:
        ps_command = f"""
        $secpasswd = ConvertTo-SecureString \"{password}\" -AsPlainText -Force
        $cred = New-Object System.Management.Automation.PSCredential(\"{username}\", $secpasswd)
        $user = Get-WmiObject -Class Win32_NetworkLoginProfile -ComputerName {host} -Credential $cred -ErrorAction SilentlyContinue |
            Where-Object {{ $_.LastLogon -ne $null }} |
            Sort-Object -Property LastLogon -Descending |
            Select-Object -First 1 @{{
                Name = 'Info';
                Expression = {{
                    '{{0}} at {1}' -f $_.Name, ([DateTime]::FromFileTime($_.LastLogon).ToString('yyyy-MM-dd HH:mm:ss'))
                }}
            }}
        }}
        $user.Info
        """
        completed = subprocess.run(
            ["powershell", "-Command", ps_command],
            capture_output=True,
            text=True,
            timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
        )
        result = completed.stdout.strip()
        return result if result else "N/A"
    except Exception:
        return "N/A"

def get_serial_number_windows(host, username, password):
    if not username:
        return "N/A"
    try:
        ps_command = f"""
        $secpasswd = ConvertTo-SecureString \"{password}\" -AsPlainText -Force
        $cred = New-Object System.Management.Automation.PSCredential(\"{username}\", $secpasswd)
        (Get-WmiObject -Class Win32_BIOS -ComputerName {host} -Credential $cred -ErrorAction SilentlyContinue).SerialNumber
        """
        completed = subprocess.run(
            ["powershell", "-Command", ps_command],
            capture_output=True,
            text=True,
            timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
        )
        serial = completed.stdout.strip()
        return serial if serial and serial != "System Serial Number" else "N/A"
    except Exception:
        return "N/A"

def ping_host(ip):
    param = "-n" if os.name == "nt" else "-c"
    timeout_param = "-w" if os.name == "nt" else "-W"
    timeout_val = "1000" if os.name == "nt" else "1"
    command = ["ping", param, "1", timeout_param, timeout_val, ip]
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
        )
        if result.returncode == 0:
            match = re.search(r"time[=<]\s*(\d+\.?\d*)\s*ms", result.stdout)
            return float(match.group(1)) if match else 0
        return None
    except Exception:
        return None

def center_window(win, width, height):
    win.update_idletasks()
    screen_width = win.winfo_screenwidth()
    screen_height = win.winfo_screenheight()
    x = (screen_width // 2) - (width // 2)
    y = (screen_height // 2) - (height // 2)
    win.geometry(f"{width}x{height}+{x}+{y}")

def get_local_ip_and_subnet():
    try:
        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)
        # default subnet /24
        subnet_cidr = ip.rsplit('.', 1)[0] + '.0/24'
        return f"{ip}", subnet_cidr
    except Exception:
        return "192.168.1.100", "192.168.1.0/24"

def scan_subnet(subnet, status_var, tree, results, progress_var, stop_event, btn_scan, btn_stop, username, password):
    try:
        network = ipaddress.ip_network(subnet, strict=False)
    except ValueError as e:
        ToastNotification(title="Error", message=f"Invalid subnet: {e}", duration=3000, bootstyle="danger").show()
        btn_scan.config(state=tk.NORMAL)
        btn_stop.config(state=tk.DISABLED)
        status_var.set("Idle")
        return

    results.clear()
    for item in tree.get_children():
        tree.delete(item)

    status_var.set(f"Scanning {subnet} ...")
    ips = list(network.hosts())
    total_ips = len(ips)

    progress_var.set(0)
    max_threads = 30
    thread_lock = threading.Lock()
    scanned_count = 0

    log_filename = os.path.join(os.path.dirname(os.path.abspath(__file__)), datetime.now().strftime("%d%m%Y_log.csv"))
    if not os.path.exists(log_filename):
        with open(log_filename, "w", newline='', encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["IP Address", "Hostname", "MAC Address", "Vendor", "Last Login", "Serial Number"])

    def scan_ip(ip):
        nonlocal scanned_count
        if stop_event.is_set():
            return
        ip_str = str(ip)
        ping_time = ping_host(ip_str)
        if ping_time is not None:
            mac = get_mac_address(ip_str)
            vendor = get_vendor_from_mac(mac) if mac != "N/A" else "Unknown"
            last_login = get_last_login_windows(ip_str, username, password) if username else "N/A"
            hostname = get_hostname(ip_str)
            serial = get_serial_number_windows(ip_str, username, password) if username else "N/A"
            with thread_lock:
                tree.insert("", "end", values=(ip_str, hostname, mac, vendor, last_login, serial))
                results.append({
                    "IP": ip_str,
                    "Hostname": hostname,
                    "MAC Address": mac,
                    "Vendor": vendor,
                    "Last Login": last_login,
                    "Serial Number": serial,
                })
                with open(log_filename, "a", newline='', encoding="utf-8") as f:
                    writer = csv.writer(f)
                    writer.writerow([ip_str, hostname, mac, vendor, last_login, serial])

        with thread_lock:
            scanned_count += 1
            progress_var.set(int((scanned_count / total_ips) * 100))
            status_var.set(f"Scanned {scanned_count} of {total_ips} hosts")

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = [executor.submit(scan_ip, ip) for ip in ips]
        for future in futures:
            if stop_event.is_set():
                break

    status_var.set("Scan stopped by user." if stop_event.is_set() else "Scan completed.")
    btn_scan.config(state=tk.NORMAL)
    btn_stop.config(state=tk.DISABLED)
    stop_event.clear()

def export_log_to_csv():
    if not results:
        messagebox.showwarning("No Data", "No scan results to save.")
        return
    file_path = filedialog.asksaveasfilename(
        defaultextension=".csv",
        filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")],
        title="Save log as..."
    )
    if not file_path:
        return
    try:
        with open(file_path, "w", newline='', encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["IP", "Hostname", "MAC Address", "Vendor", "Last Login", "Serial Number"])
            writer.writeheader()
            writer.writerows(results)
        messagebox.showinfo("Export Successful", f"Log exported to:\n{file_path}")
    except Exception as e:
        messagebox.showerror("Export Failed", str(e))

def ping_ip_action(ip, status_var, progress_var, btn):
    if not ip:
        ToastNotification(title="Error", message="Please enter an IP address to ping.", duration=2500, bootstyle="danger").show()
        return

    def run_ping():
        btn.config(state=tk.DISABLED)
        status_var.set(f"Pinging {ip} ...")
        progress_var.set(10)
        ping_result = ping_host(ip)
        if ping_result is not None:
            status_var.set(f"Ping to {ip} successful: {ping_result} ms")
        else:
            status_var.set(f"Ping to {ip} failed or host unreachable.")
        progress_var.set(100)
        btn.config(state=tk.NORMAL)

    threading.Thread(target=run_ping, daemon=True).start()

def ping_hostname(hostname, status_var, progress_var, btn):
    if not hostname:
        ToastNotification(title="Error", message="Please enter a hostname to ping.", duration=2500, bootstyle="danger").show()
        return

    def run_ping():
        btn.config(state=tk.DISABLED)
        status_var.set(f"Resolving {hostname} ...")
        progress_var.set(0)
        try:
            ip = socket.gethostbyname(hostname)
            status_var.set(f"Pinging {hostname} ({ip}) ...")
            progress_var.set(10)
            ping_result = ping_host(ip)
            if ping_result is not None:
                status_var.set(f"Ping to {hostname} successful: {ping_result} ms")
            else:
                status_var.set(f"Ping to {hostname} failed or host unreachable.")
            progress_var.set(100)
        except Exception:
            status_var.set(f"Failed to resolve hostname: {hostname}")
            progress_var.set(0)
        btn.config(state=tk.NORMAL)

    threading.Thread(target=run_ping, daemon=True).start()

# --- Main GUI ---

root = tb.Window(themename="cosmo")
root.title("Device Scanner v1.1")
center_window(root, 900, 680)
root.resizable(True, True) 

is_fullscreen = tk.BooleanVar(value=False)

def toggle_fullscreen(event=None):
    is_fullscreen.set(not is_fullscreen.get())
    root.attributes("-fullscreen", is_fullscreen.get())

def end_fullscreen(event=None):
    is_fullscreen.set(False)
    root.attributes("-fullscreen", False)

# Bind F11 to toggle fullscreen, and Escape to exit fullscreen
root.bind("<F11>", toggle_fullscreen)
root.bind("<Escape>", end_fullscreen)

results = []
stop_event = threading.Event()

# Top frame for subnet input and scan controls
frm_top = tb.Frame(root)
frm_top.pack(fill=tk.X, padx=15, pady=10)

lbl_subnet = tb.Label(frm_top, text="IP Address / Subnet CIDR:", font=("Segoe UI", 11))
lbl_subnet.grid(row=0, column=0, sticky="w")

ip, subnet = get_local_ip_and_subnet()
entry_subnet = tb.Entry(frm_top, font=("Segoe UI", 11))
entry_subnet.grid(row=0, column=1, sticky="ew", padx=10)
entry_subnet.insert(0, subnet)
frm_top.columnconfigure(1, weight=1)

btn_scan = tb.Button(frm_top, text="Start Scan", width=12)
btn_scan.grid(row=0, column=2, padx=5)

btn_stop = tb.Button(frm_top, text="Stop Scan", width=12, state=tk.DISABLED)
btn_stop.grid(row=0, column=3, padx=5)

btn_export = tb.Button(frm_top, text="Export Log", width=12)
btn_export.grid(row=0, column=4, padx=5)

# Treeview for scan results
columns = ("IP Address", "Hostname", "MAC Address", "Vendor", "Last Login", "Serial Number")
tree = tb.Treeview(root, columns=columns, show="headings", selectmode="browse")
for col in columns:
    tree.heading(col, text=col)
    tree.column(col, anchor="w", width=130)
tree.pack(fill=tk.BOTH, expand=True, padx=15, pady=10)

# Status bar and progress bar
frm_status = tb.Frame(root)
frm_status.pack(fill=tk.X, padx=15)

status_var = tk.StringVar(value="Idle")
lbl_status = tb.Label(frm_status, textvariable=status_var, font=("Segoe UI", 10, "italic"))
lbl_status.pack(side=tk.LEFT, padx=5)

progress_var = tk.IntVar(value=0)
progress_bar = tb.Progressbar(frm_status, maximum=100, variable=progress_var)
progress_bar.pack(side=tk.RIGHT, fill=tk.X, expand=True, padx=5, pady=2)

# Ping Test frame (existing IP ping)
frm_ping = tb.LabelFrame(root, text="IP Ping Test", padding=10)
frm_ping.pack(fill=tk.X, padx=15, pady=(0,10))
frm_ping.columnconfigure(1, weight=1)

lbl_ping = tb.Label(frm_ping, text="IP to ping:", font=("Segoe UI", 11))
lbl_ping.grid(row=0, column=0, padx=5, pady=5, sticky="w")

entry_ping = tb.Entry(frm_ping, font=("Segoe UI", 11))
entry_ping.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

btn_ping = tb.Button(frm_ping, text="Ping IP", width=15)
btn_ping.grid(row=0, column=2, padx=10, pady=5)

ping_status_var = tk.StringVar(value="Idle")
lbl_ping_status = tb.Label(frm_ping, textvariable=ping_status_var, font=("Segoe UI", 10, "italic"), foreground="gray")
lbl_ping_status.grid(row=1, column=0, columnspan=3, sticky="w", padx=5)

ping_progress_var = tk.IntVar(value=0)
ping_progress = tb.Progressbar(frm_ping, maximum=100, variable=ping_progress_var)
ping_progress.grid(row=2, column=0, columnspan=3, sticky="ew", padx=5, pady=5)

btn_ping.config(command=lambda: ping_ip_action(entry_ping.get().strip(), ping_status_var, ping_progress_var, btn_ping))

# Hostname Ping Test frame (NEW)
frm_host_ping = tb.LabelFrame(root, text="Hostname Ping Test", padding=10)
frm_host_ping.pack(fill=tk.X, padx=15, pady=(0,15))
frm_host_ping.columnconfigure(1, weight=1)

lbl_host_ping = tb.Label(frm_host_ping, text="Hostname to ping:", font=("Segoe UI", 11))
lbl_host_ping.grid(row=0, column=0, padx=5, pady=5, sticky="w")

entry_host_ping = tb.Entry(frm_host_ping, font=("Segoe UI", 11))
entry_host_ping.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

btn_host_ping = tb.Button(frm_host_ping, text="Ping Hostname", width=15)
btn_host_ping.grid(row=0, column=2, padx=10, pady=5)

host_ping_status_var = tk.StringVar(value="Idle")
lbl_host_ping_status = tb.Label(frm_host_ping, textvariable=host_ping_status_var, font=("Segoe UI", 10, "italic"), foreground="gray")
lbl_host_ping_status.grid(row=1, column=0, columnspan=3, sticky="w", padx=5)

host_ping_progress_var = tk.IntVar(value=0)
host_ping_progress = tb.Progressbar(frm_host_ping, maximum=100, variable=host_ping_progress_var)
host_ping_progress.grid(row=2, column=0, columnspan=3, sticky="ew", padx=5, pady=5)

btn_host_ping.config(command=lambda: ping_hostname(entry_host_ping.get().strip(), host_ping_status_var, host_ping_progress_var, btn_host_ping))

# Button commands
def on_start_scan():
    subnet_cidr = entry_subnet.get().strip()
    if not subnet_cidr:
        ToastNotification(title="Error", message="Please enter a subnet CIDR to scan.", duration=2500, bootstyle="danger").show()
        return
    btn_scan.config(state=tk.DISABLED)
    btn_stop.config(state=tk.NORMAL)
    stop_event.clear()
    threading.Thread(target=scan_subnet, args=(subnet_cidr, status_var, tree, results, progress_var, stop_event, btn_scan, btn_stop, entry_username.get().strip(), entry_password.get().strip()), daemon=True).start()

def on_stop_scan():
    stop_event.set()
    btn_stop.config(state=tk.DISABLED)
    status_var.set("Stopping scan...")

btn_scan.config(command=on_start_scan)
btn_stop.config(command=on_stop_scan)
btn_export.config(command=export_log_to_csv)

# Optional fields for Windows creds (username, password) for WMI
frm_creds = tb.LabelFrame(root, text="Windows Credentials (Optional for extra info)", padding=10)
frm_creds.pack(fill=tk.X, padx=15, pady=5)
frm_creds.columnconfigure(1, weight=1)

lbl_username = tb.Label(frm_creds, text="Username:", font=("Segoe UI", 11))
lbl_username.grid(row=0, column=0, sticky="w", padx=5, pady=3)
entry_username = tb.Entry(frm_creds, font=("Segoe UI", 11))
entry_username.grid(row=0, column=1, sticky="ew", padx=5, pady=3)

lbl_password = tb.Label(frm_creds, text="Password:", font=("Segoe UI", 11))
lbl_password.grid(row=1, column=0, sticky="w", padx=5, pady=3)
entry_password = tb.Entry(frm_creds, font=("Segoe UI", 11), show="*")
entry_password.grid(row=1, column=1, sticky="ew", padx=5, pady=3)

# Copyright label at the bottom
lbl_copyright = tb.Label(
    root,
    text="© Created by Nico Ardian SOW 7 - 2025",
    font=("Segoe UI", 9, "italic"),
    foreground="gray"
)
lbl_copyright.pack(side=tk.BOTTOM, pady=5)




root.mainloop()
