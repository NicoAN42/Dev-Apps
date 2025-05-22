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

    def change_theme(self, theme_name):
        self.style.theme_use(theme_name)

    def log(self, message, color="black"):
        self.log_text.configure(state="normal")
        self.log_text.insert("end", f"{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {message}\n")
        self.log_text.tag_add(color, "end-2l", "end-1l")
        self.log_text.tag_config(color, foreground=color)
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def toggle_auto_refresh(self):
        if self.auto_refresh_var.get():
            interval = self.auto_refresh_interval.get()
            if interval < 10:
                messagebox.showwarning("Interval too low", "Minimum auto-refresh interval is 10 seconds.")
                self.auto_refresh_var.set(False)
                return
            self.auto_refresh = True
            self.log("Auto refresh enabled.")
            self.auto_refresh_thread = threading.Thread(target=self.auto_refresh_loop, daemon=True)
            self.auto_refresh_thread.start()
        else:
            self.auto_refresh = False
            self.log("Auto refresh disabled.")

    def auto_refresh_loop(self):
        while self.auto_refresh:
            self.log("Auto-refresh: Discovering devices...")
            self.start_scan()
            interval = self.auto_refresh_interval.get()
            for _ in range(interval):
                if not self.auto_refresh:
                    break
                time.sleep(1)

    def start_scan(self):
        if self.scanning:
            self.log("Scan already in progress.", "red")
            return
        self.scanning = True
        self.scan_btn.config(state="disabled")
        self.stop_scan_btn.config(state="normal")
        self.device_listbox.delete(0, "end")
        self.devices.clear()
        self.device_ping_status.clear()
        self.log("Starting device discovery...")

        self.scan_thread = threading.Thread(target=self.scan_network, daemon=True)
        self.scan_thread.start()

    def stop_scan(self):
        if self.scanning:
            self.scanning = False
            self.log("Stopping device discovery...")
            self.scan_btn.config(state="normal")
            self.stop_scan_btn.config(state="disabled")

    def scan_network(self):
        # Get local IP and subnet mask
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
        except Exception as e:
            self.log(f"Failed to get local IP: {e}", "red")
            self.scanning = False
            self.scan_btn.config(state="normal")
            self.stop_scan_btn.config(state="disabled")
            return

        self.log(f"Local IP: {local_ip}")

        # Assume /24 subnet for scanning
        network = ipaddress.IPv4Network(local_ip + '/24', strict=False)
        ips = list(network.hosts())

        for ip in ips:
            if not self.scanning:
                break
            ip_str = str(ip)
            reachable = self.ping(ip_str)
            self.device_ping_status[ip_str] = reachable
            if reachable:
                try:
                    host = socket.gethostbyaddr(ip_str)[0]
                except socket.herror:
                    host = ip_str
                self.devices[host] = ip_str
                self.root.after(0, self.add_device_to_listbox, host, ip_str, reachable)
            else:
                # Optionally, can add unreachable devices with different color
                pass

        self.scanning = False
        self.root.after(0, self.scan_finished_ui)

    def scan_finished_ui(self):
        self.scan_btn.config(state="normal")
        self.stop_scan_btn.config(state="disabled")
        self.log("Device discovery finished.")

    def add_device_to_listbox(self, hostname, ip, reachable):
        # Add device with coloring based on ping
        display_text = f"{hostname} | {ip} | {'Online' if reachable else 'Offline'}"
        self.device_listbox.insert("end", display_text)
        idx = self.device_listbox.size() - 1
        color = "green" if reachable else "red"
        self.device_listbox.itemconfig(idx, fg=color)

    def ping(self, ip):
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = ['ping', param, '1', '-w', '1000', ip] if platform.system().lower() == 'windows' else ['ping', param, '1', '-W', '1', ip]
        try:
            output = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)
            return True if "TTL=" in output.upper() or "ttl=" in output else False
        except subprocess.CalledProcessError:
            return False

    def filter_devices(self, *args):
        search_term = self.search_var.get().lower()
        self.device_listbox.delete(0, "end")
        for host, ip in self.devices.items():
            display_text = f"{host} | {ip} | {'Online' if self.device_ping_status.get(ip, False) else 'Offline'}"
            if search_term in host.lower() or search_term in ip:
                idx = self.device_listbox.size()
                self.device_listbox.insert("end", display_text)
                color = "green" if self.device_ping_status.get(ip, False) else "red"
                self.device_listbox.itemconfig(idx, fg=color)

    def on_device_select(self, event):
        if not self.device_listbox.curselection():
            return
        idx = self.device_listbox.curselection()[0]
        selection = self.device_listbox.get(idx)
        hostname = selection.split("|")[0].strip()
        ip = selection.split("|")[1].strip()
        self.selected_device = (hostname, ip)
        self.log(f"Selected device: {hostname} ({ip})")
        self.load_installed_apps(ip)

    def load_installed_apps(self, ip):
        # For demo, simulate installed apps
        # In real scenario, this should query remote device for installed apps
        dummy_apps = ["amcfg.exe", "notepad.exe", "calc.exe", "chrome.exe"]
        # Randomize to simulate different apps
        import random
        self.installed_apps = random.sample(dummy_apps, k=random.randint(1, len(dummy_apps)))

        self.installed_apps_listbox.delete(0, "end")
        for app in self.installed_apps:
            self.installed_apps_listbox.insert("end", app)

    def launch_selected_app(self):
        if not self.selected_device:
            messagebox.showwarning("No device selected", "Please select a device first.")
            return
        selection = self.installed_apps_listbox.curselection()
        if not selection:
            messagebox.showwarning("No app selected", "Please select an app to launch.")
            return
        app = self.installed_apps_listbox.get(selection[0])
        hostname, ip = self.selected_device
        self.log(f"Launching {app} on {hostname} ({ip})...")
        threading.Thread(target=self.remote_launch_app, args=(ip, app), daemon=True).start()

    def remote_launch_app(self, ip, app):
        # Placeholder: simulate remote launch
        # Replace with your remote command logic (e.g., PSExec, SSH, etc.)
        time.sleep(2)
        self.log(f"App '{app}' launched successfully on {ip}", "green")

    def send_command(self, cmd):
        if not self.selected_device:
            messagebox.showwarning("No device selected", "Please select a device first.")
            return
        hostname, ip = self.selected_device
        self.log(f"Sending '{cmd}' command to {hostname} ({ip})...")
        threading.Thread(target=self.remote_send_command, args=(ip, cmd), daemon=True).start()

    def remote_send_command(self, ip, cmd):
        # Placeholder: simulate remote commands (restart, shutdown)
        time.sleep(2)
        self.log(f"Command '{cmd}' executed successfully on {ip}", "green")

    def check_app_status(self):
        if not self.selected_device:
            messagebox.showwarning("No device selected", "Please select a device first.")
            return
        hostname, ip = self.selected_device
        app = self.selected_app.get()
        self.log(f"Checking status of '{app}' on {hostname} ({ip})...")
        threading.Thread(target=self.remote_check_status, args=(ip, app), daemon=True).start()

    def remote_check_status(self, ip, app):
        # Placeholder: simulate status check
        time.sleep(2)
        # Randomly say running or not
        import random
        status = random.choice(["running", "not running"])
        self.log(f"App '{app}' is currently {status} on {ip}", "blue")

    def add_custom_exe(self):
        file_path = filedialog.askopenfilename(title="Select Executable", filetypes=[("Executables", "*.exe")])
        if file_path:
            exe_name = os.path.basename(file_path)
            self.app_paths[exe_name] = file_path
            menu = self.app_menu["menu"]
            menu.add_command(label=exe_name, command=tk._setit(self.selected_app, exe_name))
            self.selected_app.set(exe_name)
            self.log(f"Added custom executable: {exe_name}", "purple")

    def schedule_app(self):
        if not self.selected_device:
            messagebox.showwarning("No device selected", "Please select a device first.")
            return
        schedule_time = self.scheduled_time.get().strip()
        if not schedule_time:
            messagebox.showwarning("Schedule Time Missing", "Please enter a schedule time in HH:MM format.")
            return
        try:
            schedule_dt = datetime.datetime.strptime(schedule_time, "%H:%M").time()
        except ValueError:
            messagebox.showerror("Invalid Time Format", "Please enter time as HH:MM in 24-hour format.")
            return

        now = datetime.datetime.now()
        today_schedule = datetime.datetime.combine(now.date(), schedule_dt)
        if today_schedule < now:
            today_schedule += datetime.timedelta(days=1)

        delta_seconds = (today_schedule - now).total_seconds()

        hostname, ip = self.selected_device
        app = self.selected_app.get()
        self.log(f"Scheduling app '{app}' on {hostname} ({ip}) at {schedule_time}...")

        # Start a thread to wait and launch
        threading.Thread(target=self.schedule_launch, args=(delta_seconds, ip, app, schedule_time), daemon=True).start()

    def schedule_launch(self, delay_seconds, ip, app, sched_time):
        time.sleep(delay_seconds)
        self.log(f"Scheduled time reached: Launching '{app}' on {ip}...", "orange")
        self.remote_launch_app(ip, app)

def main():
    root = tb.Window(themename="superhero")
    app = RemoteDeviceApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
