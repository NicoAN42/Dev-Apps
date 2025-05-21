import tkinter as tk
from tkinter import filedialog, messagebox
import ipaddress
import socket
import subprocess
import threading
import os
import re
from concurrent.futures import ThreadPoolExecutor
import pandas as pd
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
    try:
        # PowerShell command to get last login from remote host
        ps_command = f"""
        $secpasswd = ConvertTo-SecureString "{password}" -AsPlainText -Force
        $cred = New-Object System.Management.Automation.PSCredential("{username}", $secpasswd)
        $user = Get-WmiObject -Class Win32_NetworkLoginProfile -ComputerName {host} -Credential $cred -ErrorAction SilentlyContinue |
            Sort-Object -Property LastLogon -Descending | Select-Object -First 1
        if ($user -and $user.LastLogon) {{
            [DateTime]::FromFileTime($user.LastLogon).ToString("yyyy-MM-dd HH:mm:ss")
        }} else {{
            "Never"
        }}
        """
        completed = subprocess.run(
            ["powershell", "-Command", ps_command],
            capture_output=True,
            text=True,
            timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
        )
        login = completed.stdout.strip()
        return login if login else "N/A"
    except Exception:
        return "N/A"

def get_serial_number_windows(host, username, password):
    try:
        ps_command = f"""
        $secpasswd = ConvertTo-SecureString "{password}" -AsPlainText -Force
        $cred = New-Object System.Management.Automation.PSCredential("{username}", $secpasswd)
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
            # Regex to extract ping time in ms
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

    def scan_ip(ip):
        nonlocal scanned_count
        if stop_event.is_set():
            return
        ip_str = str(ip)
        ping_time = ping_host(ip_str)
        if ping_time is not None:
            mac = get_mac_address(ip_str)
            vendor = get_vendor_from_mac(mac) if mac != "N/A" else "Unknown"
            last_login = get_last_login_windows(ip_str, username, password)
            hostname = get_hostname(ip_str)
            serial = get_serial_number_windows(ip_str, username, password)
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

def ping_test(ip, ping_status_var, ping_progress_var, btn_ping):
    if not ip:
        ToastNotification(title="Error", message="Please enter an IP address to ping.", duration=2500, bootstyle="danger").show()
        return

    def run_ping():
        btn_ping.config(state=tk.DISABLED)
        ping_status_var.set(f"Pinging {ip} ...")
        ping_progress_var.set(0)
        result = ping_host(ip)
        ping_status_var.set(f"Ping successful: {result} ms" if result is not None else "Ping failed or host unreachable.")
        ping_progress_var.set(100)
        btn_ping.config(state=tk.NORMAL)

    threading.Thread(target=run_ping, daemon=True).start()

def export_to_excel(results):
    if not results:
        messagebox.showwarning("No Data", "No scan results to export.")
        return
    file_path = filedialog.asksaveasfilename(
        defaultextension=".xlsx",
        filetypes=[("Excel Files", "*.xlsx"), ("All Files", "*.*")],
        title="Save scan results as..."
    )
    if not file_path:
        return
    try:
        df = pd.DataFrame(results)
        df.to_excel(file_path, index=False)
        messagebox.showinfo("Export Successful", f"Results exported to:\n{file_path}")
    except Exception as e:
        messagebox.showerror("Export Failed", f"Failed to export results:\n{e}")

def main():
    root = tb.Window(themename="flatly")
    root.title("Device Scanner")
    center_window(root, 1200, 750)
    root.minsize(1000, 650)

    # Fullscreen toggle variables and functions
    root.fullscreen = False
    def toggle_fullscreen(event=None):
        root.fullscreen = not root.fullscreen
        root.attributes("-fullscreen", root.fullscreen)

    def exit_fullscreen(event=None):
        if root.fullscreen:
            root.fullscreen = False
            root.attributes("-fullscreen", False)

    root.bind("<F11>", toggle_fullscreen)
    root.bind("<Escape>", exit_fullscreen)

    results = []
    stop_event = threading.Event()

    frm_top = tb.LabelFrame(root, text="Subnet Scan", padding=15)
    frm_top.pack(fill=tk.X, padx=10, pady=10)

    lbl_subnet = tb.Label(frm_top, text="Subnet (CIDR):", font=("Segoe UI", 11))
    lbl_subnet.grid(row=0, column=0, padx=5, pady=5, sticky="w")

    entry_subnet = tb.Entry(frm_top, width=25, font=("Segoe UI", 11))
    entry_subnet.insert(0, "192.168.1.0/24")
    entry_subnet.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

    # Username and Password side by side
    lbl_username = tb.Label(frm_top, text="Admin Username:", font=("Segoe UI", 11))
    lbl_username.grid(row=0, column=2, padx=(15,5), pady=5, sticky="w")

    entry_username = tb.Entry(frm_top, width=15, font=("Segoe UI", 11))
    entry_username.grid(row=0, column=3, padx=5, pady=5, sticky="ew")

    lbl_password = tb.Label(frm_top, text="Password:", font=("Segoe UI", 11))
    lbl_password.grid(row=0, column=4, padx=(15,5), pady=5, sticky="w")

    entry_password = tb.Entry(frm_top, width=15, font=("Segoe UI", 11), show="*")
    entry_password.grid(row=0, column=5, padx=5, pady=5, sticky="ew")

    btn_scan = tb.Button(frm_top, text="Start Scan", width=12)
    btn_scan.grid(row=0, column=6, padx=15, pady=5)

    btn_stop = tb.Button(frm_top, text="Stop Scan", state=tk.DISABLED, width=12)
    btn_stop.grid(row=0, column=7, padx=5, pady=5)

    btn_export = tb.Button(frm_top, text="Export Results to Excel", width=20)
    btn_export.grid(row=0, column=8, padx=15, pady=5)

    frm_top.columnconfigure(1, weight=1)
    frm_top.columnconfigure(3, weight=1)
    frm_top.columnconfigure(5, weight=1)

    progress_var = tk.IntVar()
    progress = tb.Progressbar(frm_top, maximum=100, variable=progress_var, bootstyle="info-striped")
    progress.grid(row=1, column=0, columnspan=9, sticky="ew", pady=(0,10))

    status_var = tk.StringVar(value="Idle")
    lbl_status = tb.Label(frm_top, textvariable=status_var, font=("Segoe UI", 10, "italic"))
    lbl_status.grid(row=2, column=0, columnspan=9, sticky="w")

    # Treeview for results
    columns = ("IP Address", "Hostname", "MAC Address", "Vendor", "Last Login", "Serial Number")
    tree = tb.Treeview(root, columns=columns, show="headings", selectmode="browse")
    tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

    for col in columns:
        tree.heading(col, text=col)
        tree.column(col, anchor=tk.CENTER, width=120)

    # Ping test frame
    frm_ping = tb.LabelFrame(root, text="Ping Test", padding=15)
    frm_ping.pack(fill=tk.X, padx=10, pady=10)

    lbl_ping_ip = tb.Label(frm_ping, text="IP to Ping:", font=("Segoe UI", 11))
    lbl_ping_ip.grid(row=0, column=0, padx=5, pady=5, sticky="w")

    entry_ping_ip = tb.Entry(frm_ping, width=25, font=("Segoe UI", 11))
    entry_ping_ip.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

    btn_ping = tb.Button(frm_ping, text="Ping", width=12)
    btn_ping.grid(row=0, column=2, padx=10, pady=5)

    ping_status_var = tk.StringVar(value="Idle")
    lbl_ping_status = tb.Label(frm_ping, textvariable=ping_status_var, font=("Segoe UI", 10, "italic"))
    lbl_ping_status.grid(row=1, column=0, columnspan=3, sticky="w")

    ping_progress_var = tk.IntVar()
    ping_progress = tb.Progressbar(frm_ping, maximum=100, variable=ping_progress_var, bootstyle="success")
    ping_progress.grid(row=2, column=0, columnspan=3, sticky="ew", pady=(5,0))

    frm_ping.columnconfigure(1, weight=1)

    # Footer label copyright
    copyright_lbl = tb.Label(root, text="© Created by Nico Ardian SOW 7 - 2025", font=("Segoe UI", 9), foreground="#666666")
    copyright_lbl.pack(side=tk.BOTTOM, pady=5)

    def start_scan():
        subnet = entry_subnet.get().strip()
        user = entry_username.get().strip()
        pwd = entry_password.get().strip()
        if not subnet:
            ToastNotification(title="Error", message="Please enter a subnet to scan.", duration=2500, bootstyle="danger").show()
            return
        if not user or not pwd:
            ToastNotification(title="Error", message="Please enter admin username and password.", duration=2500, bootstyle="danger").show()
            return
        btn_scan.config(state=tk.DISABLED)
        btn_stop.config(state=tk.NORMAL)
        stop_event.clear()
        threading.Thread(
            target=scan_subnet,
            args=(subnet, status_var, tree, results, progress_var, stop_event, btn_scan, btn_stop, user, pwd),
            daemon=True
        ).start()

    def stop_scan():
        stop_event.set()
        status_var.set("Stopping scan...")

    def start_ping():
        ip = entry_ping_ip.get().strip()
        ping_test(ip, ping_status_var, ping_progress_var, btn_ping)

    btn_scan.config(command=start_scan)
    btn_stop.config(command=stop_scan)
    btn_export.config(command=lambda: export_to_excel(results))
    btn_ping.config(command=start_ping)

    root.mainloop()

if __name__ == "__main__":
    main()
