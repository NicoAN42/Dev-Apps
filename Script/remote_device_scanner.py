import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import ttkbootstrap as tb
from ttkbootstrap.toast import ToastNotification
import subprocess
import threading
import socket
import ipaddress
import time
import platform
import os
import datetime

class RemoteDeviceApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Remote App Launcher @ Nico Ardian SOW 7 - 2025")
        self.root.geometry("720x820")
        self.center_window()
        self.root.minsize(720, 820)

        # Fullscreen toggle on F11
        self.fullscreen = False
        self.root.bind("<F11>", self.toggle_fullscreen)
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        # Themes
        self.style = tb.Style()
        self.current_theme = tk.StringVar(value="superhero")
        self.style.theme_use(self.current_theme.get())

        # App data
        self.devices = {}  # hostname: IP
        self.device_ping_status = {}  # IP: bool (True=ping success)
        self.scanning = False
        self.auto_refresh = False
        self.auto_refresh_thread = None
        self.scan_thread = None
        self.app_scan_thread = None
        self.scheduled_tasks = []

        # Predefined apps
        self.app_paths = {
            "amcfg.exe": r'"C:\Program Files\YourApp\amcfg.exe"',
            "notepad.exe": "notepad.exe",
            "calc.exe": "calc.exe",
            "chrome.exe": r'"C:\Program Files\Google\Chrome\Application\chrome.exe"',
        }
        self.selected_app = tk.StringVar(value="amcfg.exe")
        self.scheduled_time = tk.StringVar()

        # Selected device
        self.selected_device = None

        # Installed apps (dummy) for selected device
        self.installed_apps = []

        self.build_ui()

    def center_window(self):
        self.root.update_idletasks()
        w = self.root.winfo_width()
        h = self.root.winfo_height()
        ws = self.root.winfo_screenwidth()
        hs = self.root.winfo_screenheight()
        x = (ws // 2) - (w // 2)
        y = (hs // 2) - (h // 2)
        self.root.geometry(f'{w}x{h}+{x}+{y}')

    def toggle_fullscreen(self, event=None):
        self.fullscreen = not self.fullscreen
        self.root.attributes("-fullscreen", self.fullscreen)

    def on_closing(self):
        if self.scanning:
            if not messagebox.askokcancel("Quit", "Scan is running, do you want to quit?"):
                return
        self.scanning = False
        self.auto_refresh = False
        self.root.destroy()

    def build_ui(self):
        # Top frame: Theme switch and Auto refresh controls
        top_frame = tb.Frame(self.root, padding=10)
        top_frame.pack(fill="x")

        tb.Label(top_frame, text="Theme:", font=("Segoe UI", 10)).pack(side="left")
        theme_menu = ttk.OptionMenu(top_frame, self.current_theme, self.current_theme.get(),
                                    "superhero", "darkly", "cosmo", "flatly", "litera", "pulse", "minty",
                                    command=self.change_theme)
        theme_menu.pack(side="left", padx=(5, 15))

        self.auto_refresh_var = tk.BooleanVar(value=False)
        auto_refresh_cb = tb.Checkbutton(top_frame, text="Auto Refresh Devices", variable=self.auto_refresh_var,
                                        bootstyle="success-round-toggle", command=self.toggle_auto_refresh)
        auto_refresh_cb.pack(side="left", padx=5)

        tb.Label(top_frame, text="Interval (sec):", font=("Segoe UI", 10)).pack(side="left", padx=(15, 5))
        self.auto_refresh_interval = tk.IntVar(value=60)
        interval_entry = tb.Entry(top_frame, width=6, textvariable=self.auto_refresh_interval, justify="center")
        interval_entry.pack(side="left")

        # Main content frame with padding
        main_frame = tb.Frame(self.root, padding=10)
        main_frame.pack(fill="both", expand=True)

        # Left side: Device discovery and list + search
        left_frame = tb.Labelframe(main_frame, text="Discovered Devices", padding=10)
        left_frame.pack(side="left", fill="both", expand=True, padx=(0, 10))

        search_frame = tb.Frame(left_frame)
        search_frame.pack(fill="x", pady=(0, 5))

        tb.Label(search_frame, text="Search:", font=("Segoe UI", 10)).pack(side="left")
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", self.filter_devices)
        search_entry = tb.Entry(search_frame, textvariable=self.search_var)
        search_entry.pack(side="left", fill="x", expand=True, padx=(5, 0))

        self.device_listbox = tk.Listbox(left_frame, height=15, font=("Segoe UI", 10))
        self.device_listbox.pack(fill="both", expand=True)
        self.device_listbox.bind("<<ListboxSelect>>", self.on_device_select)

        # Scrollbar for device list
        device_scroll = ttk.Scrollbar(left_frame, orient="vertical", command=self.device_listbox.yview)
        self.device_listbox.config(yscrollcommand=device_scroll.set)
        device_scroll.pack(side="right", fill="y")

        # Buttons for device scanning
        btn_frame = tb.Frame(left_frame)
        btn_frame.pack(fill="x", pady=5)

        self.scan_btn = tb.Button(btn_frame, text="Discover Devices", bootstyle="info", command=self.start_scan)
        self.scan_btn.pack(side="left", fill="x", expand=True, padx=(0, 5))

        self.stop_scan_btn = tb.Button(btn_frame, text="Stop Scan", bootstyle="danger-outline",
                                       command=self.stop_scan, state="disabled")
        self.stop_scan_btn.pack(side="left", fill="x", expand=True, padx=(5, 0))

        # Middle frame: Installed apps on selected device
        mid_frame = tb.Labelframe(main_frame, text="Installed Apps on Selected Device", padding=10)
        mid_frame.pack(side="left", fill="both", expand=True, padx=(0, 10))

        self.installed_apps_listbox = tk.Listbox(mid_frame, height=15, font=("Segoe UI", 10))
        self.installed_apps_listbox.pack(fill="both", expand=True)

        # Scrollbar
        installed_scroll = ttk.Scrollbar(mid_frame, orient="vertical", command=self.installed_apps_listbox.yview)
        self.installed_apps_listbox.config(yscrollcommand=installed_scroll.set)
        installed_scroll.pack(side="right", fill="y")

        btn_apps_frame = tb.Frame(mid_frame)
        btn_apps_frame.pack(fill="x", pady=5)

        self.launch_selected_app_btn = tb.Button(btn_apps_frame, text="Launch Selected App", bootstyle="success",
                                                command=self.launch_selected_app)
        self.launch_selected_app_btn.pack(side="left", fill="x", expand=True)

        # Right frame: Controls for apps & schedule + logs
        right_frame = tb.Labelframe(main_frame, text="App Launcher & Logs", padding=10)
        right_frame.pack(side="left", fill="both", expand=True)

        # App selection dropdown
        tb.Label(right_frame, text="Select App to Launch", font=("Segoe UI", 10)).pack(anchor="w")
        self.app_menu = ttk.OptionMenu(right_frame, self.selected_app, self.selected_app.get(), *self.app_paths.keys())
        self.app_menu.pack(fill="x", pady=(0, 10))

        tb.Button(right_frame, text="Add Custom .exe", bootstyle="secondary-outline", command=self.add_custom_exe).pack(fill="x", pady=(0, 10))

        # Schedule section
        tb.Label(right_frame, text="Schedule Time (HH:MM 24hr)", font=("Segoe UI", 10)).pack(anchor="w")
        self.schedule_entry = tb.Entry(right_frame, textvariable=self.scheduled_time)
        self.schedule_entry.pack(fill="x", pady=(0, 10))

        tb.Button(right_frame, text="Schedule App Launch", bootstyle="primary", command=self.schedule_app).pack(fill="x", pady=(0, 10))

        # Command buttons
        cmd_btn_frame = tb.Frame(right_frame)
        cmd_btn_frame.pack(fill="x", pady=(0, 10))

        tb.Button(cmd_btn_frame, text="Check App Status", bootstyle="warning", command=self.check_app_status).pack(fill="x", pady=2)
        tb.Button(cmd_btn_frame, text="Restart Device", bootstyle="warning-outline", command=lambda: self.send_command("restart")).pack(fill="x", pady=2)
        tb.Button(cmd_btn_frame, text="Shutdown Device", bootstyle="danger", command=lambda: self.send_command("shutdown")).pack(fill="x", pady=2)

        # Log box
        tb.Label(right_frame, text="Activity Log", font=("Segoe UI", 10)).pack(anchor="w", pady=(10, 0))
        self.log_text = tk.Text(right_frame, height=12, font=("Segoe UI", 9), state="disabled", wrap="word")
        self.log_text.pack(fill="both", expand=True)

        log_scroll = ttk.Scrollbar(right_frame, orient="vertical", command=self.log_text.yview)
        self.log_text.config(yscrollcommand=log_scroll.set)
        log_scroll.pack(side="right", fill="y")

        # Clear Log button below log
        self.clear_log_btn = tb.Button(right_frame, text="Clear Log", bootstyle="secondary", command=self.clear_log)
        self.clear_log_btn.pack(fill="x", pady=(5, 0))

        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = tb.Label(self.root, textvariable=self.status_var, bootstyle="secondary", anchor="w")
        status_bar.pack(side="bottom", fill="x")

    def change_theme(self, theme_name):
        self.style.theme_use(theme_name)
        self.status_var.set(f"Theme changed to {theme_name}")

    def log(self, msg):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.log_text.configure(state="normal")
        self.log_text.insert("end", f"[{timestamp}] {msg}\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def clear_log(self):
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")
        self.status_var.set("Activity log cleared")

    def toggle_auto_refresh(self):
        if self.auto_refresh_var.get():
            interval = self.auto_refresh_interval.get()
            if interval < 10:
                messagebox.showwarning("Interval Too Short", "Please set an interval of at least 10 seconds.")
                self.auto_refresh_var.set(False)
                return
            self.auto_refresh = True
            self.status_var.set("Auto-refresh enabled")
            self.auto_refresh_thread = threading.Thread(target=self.auto_refresh_loop, daemon=True)
            self.auto_refresh_thread.start()
        else:
            self.auto_refresh = False
            self.status_var.set("Auto-refresh disabled")

    def auto_refresh_loop(self):
        while self.auto_refresh:
            self.start_scan()
            for _ in range(self.auto_refresh_interval.get()):
                if not self.auto_refresh:
                    break
                time.sleep(1)

    def start_scan(self):
        if self.scanning:
            self.log("Scan is already running...")
            return
        self.scanning = True
        self.scan_btn.config(state="disabled")
        self.stop_scan_btn.config(state="normal")
        self.log("Starting device discovery...")
        self.device_listbox.delete(0, "end")
        self.devices.clear()
        self.device_ping_status.clear()
        self.selected_device = None
        self.installed_apps_listbox.delete(0, "end")

        self.scan_thread = threading.Thread(target=self.scan_network, daemon=True)
        self.scan_thread.start()

    def stop_scan(self):
        if not self.scanning:
            self.log("No scan is running.")
            return
        self.scanning = False
        self.scan_btn.config(state="normal")
        self.stop_scan_btn.config(state="disabled")
        self.status_var.set("Scan stopped")
        self.log("Device discovery stopped by user.")

    def scan_network(self):
        # We'll scan the local subnet of the main network interface
        try:
            local_ip = self.get_local_ip()
            if local_ip is None:
                self.log("Failed to determine local IP.")
                self.scanning = False
                self.scan_btn.config(state="normal")
                self.stop_scan_btn.config(state="disabled")
                return
            network = ipaddress.ip_network(local_ip + "/24", strict=False)
            self.log(f"Scanning subnet: {network}")

            for ip in network.hosts():
                if not self.scanning:
                    break
                ip_str = str(ip)
                if self.ping(ip_str):
                    try:
                        hostname = socket.gethostbyaddr(ip_str)[0]
                    except socket.herror:
                        hostname = ip_str
                    self.devices[hostname] = ip_str
                    self.device_ping_status[ip_str] = True
                    self.add_device_to_list(hostname, ip_str)
                else:
                    self.device_ping_status[str(ip)] = False

            self.scanning = False
            self.scan_btn.config(state="normal")
            self.stop_scan_btn.config(state="disabled")
            self.status_var.set("Device discovery complete")
            self.log("Device discovery complete.")

        except Exception as e:
            self.log(f"Error during scan: {e}")
            self.scanning = False
            self.scan_btn.config(state="normal")
            self.stop_scan_btn.config(state="disabled")

    def get_local_ip(self):
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            # Check if local_ip is in private range, else try other methods
            if local_ip.startswith("127."):
                # Try to get external interface IP by connecting to a public IP
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(2)
                try:
                    s.connect(("8.8.8.8", 80))
                    local_ip = s.getsockname()[0]
                finally:
                    s.close()
            return local_ip
        except Exception as e:
            self.log(f"Failed to get local IP: {e}")
            return None

    def ping(self, ip):
        param = "-n" if platform.system().lower() == "windows" else "-c"
        command = ["ping", param, "1", "-w", "1000", ip]
        try:
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return result.returncode == 0
        except Exception as e:
            return False

    def add_device_to_list(self, hostname, ip):
        display_text = f"{hostname} ({ip})"
        # UI update must be in main thread
        self.root.after(0, lambda: self.device_listbox.insert("end", display_text))
        self.log(f"Discovered device: {display_text}")

    def filter_devices(self, *args):
        filter_text = self.search_var.get().lower()
        self.device_listbox.delete(0, "end")
        for hostname, ip in self.devices.items():
            display_text = f"{hostname} ({ip})"
            if filter_text in display_text.lower():
                self.device_listbox.insert("end", display_text)

    def on_device_select(self, event):
        if not self.device_listbox.curselection():
            return
        index = self.device_listbox.curselection()[0]
        device_text = self.device_listbox.get(index)
        # Extract hostname and IP
        try:
            hostname = device_text.split(" (")[0]
            ip = self.devices.get(hostname, None)
            if ip is None:
                self.log("Selected device not found in devices list.")
                return
            self.selected_device = (hostname, ip)
            self.status_var.set(f"Selected device: {hostname} ({ip})")
            self.log(f"Selected device: {hostname} ({ip})")
            self.refresh_installed_apps()
        except Exception as e:
            self.log(f"Error selecting device: {e}")

    def refresh_installed_apps(self):
        self.installed_apps_listbox.delete(0, "end")
        if self.selected_device is None:
            return
        hostname, ip = self.selected_device
        # For demo: list apps as keys from app_paths + some dummy apps
        self.installed_apps = list(self.app_paths.keys()) + ["example_app.exe", "dummy_app.exe"]
        for app in self.installed_apps:
            self.installed_apps_listbox.insert("end", app)

    def launch_selected_app(self):
        if self.selected_device is None:
            messagebox.showwarning("No Device Selected", "Please select a device first.")
            return
        if not self.installed_apps_listbox.curselection():
            messagebox.showwarning("No App Selected", "Please select an app to launch.")
            return
        index = self.installed_apps_listbox.curselection()[0]
        app_name = self.installed_apps_listbox.get(index)
        self.log(f"Launching {app_name} on {self.selected_device[0]} ({self.selected_device[1]})...")
        # Here, execute the remote launch command (dummy simulation)
        self.log(f"App {app_name} launch command sent (simulation).")

    def add_custom_exe(self):
        file_path = filedialog.askopenfilename(title="Select .exe file",
                                               filetypes=[("Executable files", "*.exe")])
        if file_path:
            exe_name = os.path.basename(file_path)
            self.app_paths[exe_name] = f'"{file_path}"'
            menu = self.app_menu["menu"]
            menu.add_command(label=exe_name, command=tk._setit(self.selected_app, exe_name))
            self.selected_app.set(exe_name)
            self.log(f"Custom app added: {exe_name}")

    def schedule_app(self):
        if self.selected_device is None:
            messagebox.showwarning("No Device Selected", "Please select a device first.")
            return
        app = self.selected_app.get()
        time_str = self.scheduled_time.get()
        if not time_str:
            messagebox.showwarning("No Schedule Time", "Please enter a schedule time in HH:MM format.")
            return
        try:
            sched_time = datetime.datetime.strptime(time_str, "%H:%M").time()
            now = datetime.datetime.now()
            sched_datetime = datetime.datetime.combine(now.date(), sched_time)
            if sched_datetime < now:
                sched_datetime += datetime.timedelta(days=1)  # Schedule for next day
            delay = (sched_datetime - now).total_seconds()
            self.log(f"Scheduling launch of {app} on {self.selected_device[0]} at {sched_datetime.strftime('%Y-%m-%d %H:%M:%S')}")
            threading.Timer(delay, self.launch_scheduled_app).start()
            messagebox.showinfo("Scheduled", f"App '{app}' scheduled to launch at {time_str} on device {self.selected_device[0]}.")
        except ValueError:
            messagebox.showerror("Invalid Time Format", "Please enter time as HH:MM (24-hour format).")

    def launch_scheduled_app(self):
        # This runs in background thread, update UI thread for log
        if self.selected_device is None:
            return
        app = self.selected_app.get()
        hostname, ip = self.selected_device
        self.root.after(0, lambda: self.log(f"Scheduled launch: Starting {app} on {hostname} ({ip})..."))
        # Simulate launch
        time.sleep(1)
        self.root.after(0, lambda: self.log(f"Scheduled launch: {app} launched on {hostname}."))

    def check_app_status(self):
        if self.selected_device is None:
            messagebox.showwarning("No Device Selected", "Please select a device first.")
            return
        app = self.selected_app.get()
        self.log(f"Checking status of {app} on {self.selected_device[0]} ({self.selected_device[1]})...")
        # Simulated status check
        time.sleep(1)
        self.log(f"App {app} is currently running on {self.selected_device[0]} (simulated).")

    def send_command(self, cmd):
        if self.selected_device is None:
            messagebox.showwarning("No Device Selected", "Please select a device first.")
            return
        hostname, ip = self.selected_device
        if cmd == "shutdown":
            confirm = messagebox.askyesno("Confirm Shutdown",
                                          f"Are you sure you want to shutdown {hostname} ({ip})?")
            if not confirm:
                return
            self.log(f"Sending shutdown command to {hostname} ({ip})...")
        elif cmd == "restart":
            confirm = messagebox.askyesno("Confirm Restart",
                                          f"Are you sure you want to restart {hostname} ({ip})?")
            if not confirm:
                return
            self.log(f"Sending restart command to {hostname} ({ip})...")
        # Simulate sending command
        threading.Thread(target=self.simulate_remote_command, args=(hostname, ip, cmd), daemon=True).start()

    def simulate_remote_command(self, hostname, ip, cmd):
        time.sleep(2)
        self.root.after(0, lambda: self.log(f"Remote command '{cmd}' executed on {hostname} ({ip}) (simulated)."))
        self.root.after(0, lambda: ToastNotification(self.root, f"{cmd.capitalize()} executed on {hostname}", duration=3000).show())

def main():
    root = tb.Window(themename="superhero")
    app = RemoteDeviceApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
