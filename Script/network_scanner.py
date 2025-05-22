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

# Optional: netifaces to get subnet mask (pip install netifaces)
try:
    import netifaces
except ImportError:
    netifaces = None

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
    if not username or not password:
        return "N/A"
    try:
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
    if not username or not password:
        return "N/A"
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

def get_local_network_cidr():
    """
    Attempts to get the current local network IP and subnet mask in CIDR format.
    Uses netifaces if available, else defaults to 192.168.x.0/24 based on local IP.
    """
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
    except Exception:
        return "192.168.1.0/24"  # fallback

    if netifaces:
        try:
            for iface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    for link in addrs[netifaces.AF_INET]:
                        ip = link.get('addr')
                        netmask = link.get('netmask')
                        if ip == local_ip and netmask:
                            # Convert netmask to prefix length
                            prefix_len = sum(bin(int(x)).count('1') for x in netmask.split('.'))
                            network = ipaddress.IPv4Network(f"{ip}/{prefix_len}", strict=False)
                            return str(network)
        except Exception:
            pass

    # fallback: assume /24 subnet and network address
    try:
        ip_parts = local_ip.split('.')
        ip_parts[-1] = '0'
        network = ".".join(ip_parts) + "/24"
        return network
    except Exception:
        return "192.168.1.0/24"

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
            # Only query last login and serial if username and password provided
            last_login = get_last_login_windows(ip_str, username, password) if username != "" and password != "" else "N/A"
            hostname = get_hostname(ip_str)
            serial = get_serial_number_windows(ip_str, username, password) if username != "" and password != "" else "N/A"
            with thread_lock:
                tree.insert("", "end", values=(ip_str, hostname, mac, vendor, last_login, serial, f"{ping_time} ms"), tags=('online',))
                results.append({
                    "IP Address": ip_str,
                    "Hostname": hostname,
                    "MAC Address": mac,
                    "Vendor": vendor,
                    "Last Login": last_login,
                    "Serial Number": serial,
                    "Ping Time": ping_time,
                })
        else:
            with thread_lock:
                tree.insert("", "end", values=(ip_str, "N/A", "N/A", "N/A", "N/A", "N/A", "Timeout"), tags=('offline',))
                results.append({
                    "IP Address": ip_str,
                    "Hostname": "N/A",
                    "MAC Address": "N/A",
                    "Vendor": "N/A",
                    "Last Login": "N/A",
                    "Serial Number": "N/A",
                    "Ping Time": None,
                })

        with thread_lock:
            nonlocal scanned_count
            scanned_count += 1
            progress = int(scanned_count / total_ips * 100)
            progress_var.set(progress)
            status_var.set(f"Scanning {scanned_count}/{total_ips} IPs...")

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = [executor.submit(scan_ip, ip) for ip in ips]
        for future in futures:
            if stop_event.is_set():
                break
            future.result()

    status_var.set("Scan complete")
    btn_scan.config(state=tk.NORMAL)
    btn_stop.config(state=tk.DISABLED)

class NetworkScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Scanner")
        center_window(self.root, 900, 600)

        # Style
        self.style = tb.Style(theme="superhero")

        # Variables
        self.status_var = tk.StringVar(value="Idle")
        self.progress_var = tk.IntVar(value=0)
        self.results = []
        self.stop_event = threading.Event()

        # Username and password for remote queries
        self.username_var = tk.StringVar()
        self.password_var = tk.StringVar()

        # Frame for inputs (uses pack on frame)
        frame_inputs = tb.Frame(root)
        frame_inputs.pack(pady=10, padx=10, fill="x")

        # Username label and entry (grid inside frame)
        tb.Label(frame_inputs, text="Admin Username:").grid(row=0, column=0, sticky="w", padx=5)
        tb.Entry(frame_inputs, textvariable=self.username_var, width=25).grid(row=0, column=1, padx=5)

        tb.Label(frame_inputs, text="Admin Password:").grid(row=0, column=2, sticky="w", padx=5)
        tb.Entry(frame_inputs, textvariable=self.password_var, width=25, show="*").grid(row=0, column=3, padx=5)

        # Subnet entry
        self.subnet_var = tk.StringVar(value=get_local_network_cidr())
        tb.Label(frame_inputs, text="Subnet (CIDR):").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.entry_subnet = tb.Entry(frame_inputs, textvariable=self.subnet_var, width=30)
        self.entry_subnet.grid(row=1, column=1, padx=5, pady=5, sticky="w")

        # Buttons frame (packed)
        frame_buttons = tb.Frame(root)
        frame_buttons.pack(pady=5)

        self.btn_scan = tb.Button(frame_buttons, text="Start Scan", command=self.start_scan, bootstyle="success")
        self.btn_scan.pack(side="left", padx=10)

        self.btn_stop = tb.Button(frame_buttons, text="Stop Scan", command=self.stop_scan, bootstyle="danger", state=tk.DISABLED)
        self.btn_stop.pack(side="left", padx=10)

        self.btn_export = tb.Button(frame_buttons, text="Export to Excel", command=self.export_results, bootstyle="info")
        self.btn_export.pack(side="left", padx=10)

        # Status and progress bar (packed)
        self.status_label = tb.Label(root, textvariable=self.status_var, anchor="w")
        self.status_label.pack(fill="x", padx=10, pady=5)

        self.progress = tb.Progressbar(root, maximum=100, variable=self.progress_var)
        self.progress.pack(fill="x", padx=10, pady=5)

        # Treeview for results (packed)
        columns = ("IP Address", "Hostname", "MAC Address", "Vendor", "Last Login", "Serial Number", "Ping Time")
        self.tree = tb.Treeview(root, columns=columns, show="headings", height=20)
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, anchor="center", width=110 if col != "Hostname" else 150)

        self.tree.tag_configure('online', background='#d1f7d1')
        self.tree.tag_configure('offline', background='#f7d1d1')

        self.tree.pack(fill="both", expand=True, padx=10, pady=10)

    def start_scan(self):
        subnet = self.subnet_var.get()
        username = self.username_var.get()
        password = self.password_var.get()

        if not subnet:
            messagebox.showerror("Error", "Please enter a subnet.")
            return

        # Disable buttons
        self.btn_scan.config(state=tk.DISABLED)
        self.btn_stop.config(state=tk.NORMAL)
        self.stop_event.clear()

        # Start scan in thread to avoid blocking GUI
        threading.Thread(target=scan_subnet, args=(
            subnet, self.status_var, self.tree, self.results,
            self.progress_var, self.stop_event, self.btn_scan, self.btn_stop, username, password
        ), daemon=True).start()

    def stop_scan(self):
        self.stop_event.set()
        self.status_var.set("Stopping scan...")

    def export_results(self):
        if not self.results:
            messagebox.showinfo("Info", "No data to export.")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".xlsx",
            filetypes=[("Excel Files", "*.xlsx")],
            title="Save scan results"
        )
        if not file_path:
            return

        try:
            df = pd.DataFrame(self.results)
            df.to_excel(file_path, index=False)
            ToastNotification(title="Success", message="Export completed.", duration=3000, bootstyle="success").show()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export:\n{e}")

if __name__ == "__main__":
    root = tb.Window(themename="superhero")
    app = NetworkScannerApp(root)
    root.mainloop()
