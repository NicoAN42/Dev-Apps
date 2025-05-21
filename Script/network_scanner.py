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

# OUI dictionary including Lenovo ThinkCentre, Wyse, HP, Cisco, Dell, etc.
OUI_DICT = {
    "00:1A:79": "Cisco Systems",
    "00:1B:44": "Dell Inc",
    "00:1E:C2": "Hewlett-Packard",
    "00:21:5A": "Lenovo ThinkCentre",
    "00:13:72": "Wyse Technology",
    "00:50:56": "VMware, Inc.",
    "00:1C:23": "Lenovo",
    "00:17:F2": "Hewlett Packard",
    # Add more OUI prefixes as needed
}

def get_vendor_from_mac(mac):
    prefix = mac.upper()[0:8]
    return OUI_DICT.get(prefix, "Unknown")

def get_mac_address(ip):
    try:
        pid = subprocess.Popen(["arp", "-a", ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, _ = pid.communicate(timeout=3)
        out = out.decode(errors="ignore")
        regex = re.compile(r"([0-9a-f]{2}[:-]){5}([0-9a-f]{2})", re.I)
        mac = regex.search(out)
        if mac:
            return mac.group(0)
        else:
            return "N/A"
    except Exception:
        return "N/A"

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "N/A"

def get_last_login_windows(host):
    try:
        ps_command = f"""
        $user = Get-WmiObject -Class Win32_NetworkLoginProfile -ComputerName {host} -ErrorAction SilentlyContinue | 
                Sort-Object -Property LastLogon -Descending | Select-Object -First 1
        if ($user -and $user.LastLogon) {{
            [DateTime]::FromFileTime($user.LastLogon).ToString("yyyy-MM-dd HH:mm:ss")
        }} else {{
            "Never"
        }}
        """
        completed = subprocess.run(["powershell", "-Command", ps_command], capture_output=True, text=True, timeout=10)
        login = completed.stdout.strip()
        return login if login else "N/A"
    except Exception:
        return "N/A"

def get_serial_number_windows(host):
    try:
        # Attempt to get BIOS serial number via WMI
        ps_command = f"""
        (Get-WmiObject -Class Win32_BIOS -ComputerName {host} -ErrorAction SilentlyContinue).SerialNumber
        """
        completed = subprocess.run(["powershell", "-Command", ps_command], capture_output=True, text=True, timeout=10)
        serial = completed.stdout.strip()
        if serial and serial != "System Serial Number":
            return serial
        else:
            return "N/A"
    except Exception:
        return "N/A"

def ping_host(ip):
    param = "-n" if os.name == "nt" else "-c"
    timeout_param = "-w" if os.name == "nt" else "-W"
    timeout_val = "1000" if os.name == "nt" else "1"
    command = ["ping", param, "1", timeout_param, timeout_val, ip]
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode == 0:
            match = re.search(r'time[=<]\s*(\d+\.?\d*)\s*ms', result.stdout)
            if match:
                return float(match.group(1))
            return 0
        else:
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

def scan_subnet(subnet, status_var, tree, results, progress_var, stop_event, btn_scan, btn_stop):
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
            return None
        ip_str = str(ip)
        ping_time = ping_host(ip_str)
        if ping_time is not None:
            mac = get_mac_address(ip_str)
            vendor = get_vendor_from_mac(mac) if mac != "N/A" else "Unknown"
            last_login = get_last_login_windows(ip_str)
            hostname = get_hostname(ip_str)
            serial = get_serial_number_windows(ip_str)
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
                scanned_count += 1
                progress_var.set(int((scanned_count / total_ips) * 100))
                status_var.set(f"Scanned {scanned_count} of {total_ips} hosts")
        else:
            with thread_lock:
                scanned_count += 1
                progress_var.set(int((scanned_count / total_ips) * 100))

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = [executor.submit(scan_ip, ip) for ip in ips]
        try:
            for future in futures:
                if stop_event.is_set():
                    break
        except Exception as e:
            print("Scan error:", e)

    if stop_event.is_set():
        status_var.set("Scan stopped by user.")
    else:
        status_var.set("Scan completed.")
    btn_scan.config(state=tk.NORMAL)
    btn_stop.config(state=tk.DISABLED)

def ping_test(ip, ping_status_var, ping_progress_var, btn_ping):
    if not ip:
        ToastNotification(title="Error", message="Please enter an IP address to ping.", duration=2500, bootstyle="danger").show()
        return

    def run_ping():
        btn_ping.config(state=tk.DISABLED)
        ping_status_var.set(f"Pinging {ip} ...")
        ping_progress_var.set(0)
        result = ping_host(ip)
        if result is not None:
            ping_status_var.set(f"Ping successful: {result} ms")
        else:
            ping_status_var.set("Ping failed or host unreachable.")
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
    win_width, win_height = 1200, 750
    root.minsize(1000, 650)
    center_window(root, win_width, win_height)

    results = []
    stop_event = threading.Event()

    # --- Top Frame: Subnet Scan ---
    frm_top = tb.LabelFrame(root, text="Subnet Scan", padding=15)
    frm_top.pack(fill=tk.X, padx=10, pady=10)

    lbl_subnet = tb.Label(frm_top, text="Subnet (CIDR):", font=("Segoe UI", 11))
    lbl_subnet.grid(row=0, column=0, sticky="w", padx=5, pady=5)

    entry_subnet = tb.Entry(frm_top, width=25, font=("Segoe UI", 11))
    entry_subnet.insert(0, "192.168.1.0/24")
    entry_subnet.grid(row=0, column=1, sticky="ew", padx=5, pady=5)
    frm_top.columnconfigure(1, weight=1)

    btn_scan = tb.Button(frm_top, text="Start Scan", width=12)
    btn_scan.grid(row=0, column=2, sticky="e", padx=5, pady=5)

    btn_stop = tb.Button(frm_top, text="Stop Scan", state=tk.DISABLED, width=12)
    btn_stop.grid(row=0, column=3, sticky="e", padx=5, pady=5)

    btn_export = tb.Button(frm_top, text="Export Results to Excel", width=20)
    btn_export.grid(row=0, column=4, sticky="e", padx=5, pady=5)

    progress_var = tk.IntVar()
    progress = tb.Progressbar(frm_top, maximum=100, variable=progress_var, bootstyle="info-striped")
    progress.grid(row=1, column=0, columnspan=5, sticky="ew", padx=5, pady=(0,10))

    status_var = tk.StringVar(value="Idle")
    lbl_status = tb.Label(frm_top, textvariable=status_var, font=("Segoe UI", 10, "italic"))
    lbl_status.grid(row=2, column=0, columnspan=5, sticky="w", padx=5, pady=5)

    # --- Middle Frame: Scan Results ---
    frm_results = tb.LabelFrame(root, text="Scan Results", padding=15)
    frm_results.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    columns = ("IP", "Hostname", "MAC Address", "Vendor", "Last Login", "Serial Number")
    tree = tb.Treeview(frm_results, columns=columns, show="headings", selectmode="browse")
    for col in columns:
        tree.heading(col, text=col)
        tree.column(col, anchor="center", width=150)
    tree.pack(fill=tk.BOTH, expand=True)

    # --- Bottom Frame: Ping Test ---
    frm_ping = tb.LabelFrame(root, text="Ping Test", padding=15)
    frm_ping.pack(fill=tk.X, padx=10, pady=10)

    lbl_ip = tb.Label(frm_ping, text="IP Address:", font=("Segoe UI", 11))
    lbl_ip.grid(row=0, column=0, sticky="w", padx=5, pady=5)

    entry_ip = tb.Entry(frm_ping, width=25, font=("Segoe UI", 11))
    entry_ip.grid(row=0, column=1, sticky="ew", padx=5, pady=5)
    frm_ping.columnconfigure(1, weight=1)

    btn_ping = tb.Button(frm_ping, text="Ping", width=12)
    btn_ping.grid(row=0, column=2, sticky="e", padx=5, pady=5)

    ping_status_var = tk.StringVar(value="Idle")
    lbl_ping_status = tb.Label(frm_ping, textvariable=ping_status_var, font=("Segoe UI", 10, "italic"))
    lbl_ping_status.grid(row=1, column=0, columnspan=3, sticky="w", padx=5, pady=5)

    ping_progress_var = tk.IntVar()
    ping_progress = tb.Progressbar(frm_ping, maximum=100, variable=ping_progress_var, bootstyle="success-striped")
    ping_progress.grid(row=2, column=0, columnspan=3, sticky="ew", padx=5, pady=(0,10))

    # --- Footer Frame ---
    frm_footer = tb.Frame(root)
    frm_footer.pack(fill=tk.X, padx=10, pady=5)
    lbl_footer = tb.Label(frm_footer, text="© Created by Nico Ardian SOW 7 - 2025", anchor="center", font=("Segoe UI", 9, "italic"))
    lbl_footer.pack(fill=tk.X)

    # Button commands
    def on_scan():
        subnet = entry_subnet.get().strip()
        if not subnet:
            ToastNotification(title="Error", message="Please enter a subnet to scan.", duration=2500, bootstyle="danger").show()
            return
        stop_event.clear()
        btn_scan.config(state=tk.DISABLED)
        btn_stop.config(state=tk.NORMAL)
        threading.Thread(target=scan_subnet, args=(subnet, status_var, tree, results, progress_var, stop_event, btn_scan, btn_stop), daemon=True).start()

    def on_stop():
        stop_event.set()
        btn_stop.config(state=tk.DISABLED)

    def on_ping():
        ip = entry_ip.get().strip()
        ping_test(ip, ping_status_var, ping_progress_var, btn_ping)

    def on_export():
        export_to_excel(results)

    btn_scan.config(command=on_scan)
    btn_stop.config(command=on_stop)
    btn_ping.config(command=on_ping)
    btn_export.config(command=on_export)

    root.mainloop()

if __name__ == "__main__":
    main()
