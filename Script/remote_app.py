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
        device_scroll = ttk.Scrollbar(self.device_listbox, orient="vertical", command=self.device_listbox.yview)
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
        installed_scroll = ttk.Scrollbar(self.installed_apps_listbox, orient="vertical",
                                        command=self.installed_apps_listbox.yview)
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

        log_btn_frame = tb.Frame(right_frame)
        log_btn_frame.pack(fill="x", pady=5)
        tb.Button(log_btn_frame, text="Clear Log", bootstyle="secondary-outline", command=self.clear_log).pack(side="left", fill="x", expand=True, padx=(0,5))
        tb.Button(log_btn_frame, text="Download Log", bootstyle="secondary-outline", command=self.download_log).pack(side="left", fill="x", expand=True, padx=(5,0))

        # Footer
        footer = tb.Label(self.root, text="© Nico Ardian SOW 7 - 2025", font=("Segoe UI", 9), bootstyle="muted")
        footer.pack(side="bottom", pady=5)

    def add_log(self, text, color="black"):
        self.log_text.configure(state="normal")
        self.log_text.insert(tk.END, text + "\n")
        self.log_text.tag_add("lastline", "end-2l", "end-1l")
        self.log_text.tag_config("lastline", foreground=color)
        self.log_text.see(tk.END)
        self.log_text.configure(state="disabled")

    def clear_log(self):
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", tk.END)
        self.log_text.configure(state="disabled")
        self.add_log("Log cleared.", "gray")

    def download_log(self):
        log_content = self.log_text.get("1.0", tk.END)
        if not log_content.strip():
            messagebox.showinfo("Download Log", "Log is empty.")
            return
        f = filedialog.asksaveasfile(mode='w', defaultextension=".txt",
                                     filetypes=[("Text files", "*.txt")],
                                     title="Save Log As")
        if f:
            f.write(log_content)
            f.close()
            messagebox.showinfo("Download Log", "Log saved successfully.")

    def change_theme(self, theme_name):
        self.style.theme_use(theme_name)

    def toggle_auto_refresh(self):
        if self.auto_refresh_var.get():
            try:
                interval = int(self.auto_refresh_interval.get())
                if interval < 10:
                    messagebox.showwarning("Interval too short", "Minimum interval is 10 seconds.")
                    self.auto_refresh_var.set(False)
                    return
            except:
                messagebox.showwarning("Invalid interval", "Please enter a valid number.")
                self.auto_refresh_var.set(False)
                return
            self.auto_refresh = True
            self.add_log(f"Auto-refresh enabled every {interval} seconds.", "green")
            self.auto_refresh_thread = threading.Thread(target=self.auto_refresh_devices, daemon=True)
            self.auto_refresh_thread.start()
        else:
            self.auto_refresh = False
            self.add_log("Auto-refresh disabled.", "red")

    def auto_refresh_devices(self):
        while self.auto_refresh:
            self.scan_devices()
            interval = int(self.auto_refresh_interval.get())
            for _ in range(interval):
                if not self.auto_refresh:
                    break
                time.sleep(1)

    def start_scan(self):
        if self.scanning:
            self.add_log("Scan already running.", "orange")
            return
        self.scanning = True
        self.scan_btn.config(state="disabled")
        self.stop_scan_btn.config(state="normal")
        self.add_log("Starting device scan...", "blue")
        self.device_listbox.delete(0, tk.END)
        self.devices.clear()
        self.device_ping_status.clear()
        self.scan_thread = threading.Thread(target=self.scan_devices, daemon=True)
        self.scan_thread.start()

    def stop_scan(self):
        if not self.scanning:
            self.add_log("No scan running.", "orange")
            return
        self.scanning = False
        self.scan_btn.config(state="normal")
        self.stop_scan_btn.config(state="disabled")
        self.add_log("Scan stopped.", "red")

    def scan_devices(self):
        try:
            local_ip = self.get_local_ip()
            subnet = ipaddress.ip_network(local_ip + "/24", strict=False)
        except Exception as e:
            self.add_log(f"Error getting local IP or subnet: {e}", "red")
            self.scanning = False
            self.scan_btn.config(state="normal")
            self.stop_scan_btn.config(state="disabled")
            return

        found = 0
        all_ips = list(subnet.hosts())

        for ip in all_ips:
            if not self.scanning:
                self.add_log("Scan aborted by user.", "red")
                break

            ip_str = str(ip)
            # Ping test
            ping_success = self.ping_ip(ip_str)
            self.device_ping_status[ip_str] = ping_success

            if ping_success:
                try:
                    hostname = socket.gethostbyaddr(ip_str)[0]
                except:
                    hostname = ip_str
                self.devices[hostname] = ip_str
                self.add_log(f"Device found: {hostname} ({ip_str})", "green")
                found += 1

            self.update_device_list()

        self.scanning = False
        self.scan_btn.config(state="normal")
        self.stop_scan_btn.config(state="disabled")
        self.add_log(f"Device scan complete. Found {found} device(s).", "blue")

    def get_local_ip(self):
        # Try a better way to get local IP (cross-platform)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # Doesn't have to be reachable
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            # fallback to hostname resolution
            return socket.gethostbyname(socket.gethostname())

    def ping_ip(self, ip):
        param = "-n" if platform.system().lower() == "windows" else "-c"
        # Timeout in milliseconds for Windows ping: -w, for Unix -W (in seconds)
        timeout_param = "-w" if platform.system().lower() == "windows" else "-W"
        timeout_val = "150" if platform.system().lower() == "windows" else "1"

        cmd = ["ping", param, "1", timeout_param, timeout_val, ip]
        result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return result.returncode == 0

    def update_device_list(self):
        filter_text = self.search_var.get().lower()
        self.device_listbox.delete(0, tk.END)

        for hostname, ip in sorted(self.devices.items()):
            if filter_text in hostname.lower() or filter_text in ip:
                ping_status = self.device_ping_status.get(ip, False)
                display_text = f"{hostname} ({ip})"
                self.device_listbox.insert(tk.END, display_text)
                # Color row by ping success
                if ping_status:
                    self.device_listbox.itemconfig(tk.END, fg="green")
                else:
                    self.device_listbox.itemconfig(tk.END, fg="red")

    def filter_devices(self, *args):
        self.update_device_list()

    def on_device_select(self, event=None):
        selection = self.device_listbox.curselection()
        if not selection:
            self.selected_device = None
            self.installed_apps_listbox.delete(0, tk.END)
            return
        idx = selection[0]
        val = self.device_listbox.get(idx)
        # Extract IP from string (hostname (IP))
        if "(" in val and ")" in val:
            ip = val[val.find("(")+1:val.find(")")]
        else:
            ip = val
        self.selected_device = ip
        self.add_log(f"Selected device: {val}", "blue")
        self.installed_apps_listbox.delete(0, tk.END)
        self.installed_apps = []
        # Start thread to simulate app scan
        if self.app_scan_thread and self.app_scan_thread.is_alive():
            return  # Don't scan twice
        self.app_scan_thread = threading.Thread(target=self.scan_installed_apps, args=(ip,), daemon=True)
        self.app_scan_thread.start()

    def scan_installed_apps(self, ip):
        self.add_log(f"Scanning installed apps on {ip}...", "blue")
        # Dummy delay + dummy apps for demo
        time.sleep(2)
        # Dummy installed apps (random subset)
        apps = ["amcfg.exe", "notepad.exe", "calc.exe", "chrome.exe"]
        # Just pretend all installed for demo
        self.installed_apps = apps
        self.installed_apps_listbox.delete(0, tk.END)
        for app in self.installed_apps:
            self.installed_apps_listbox.insert(tk.END, app)
        self.add_log(f"Installed apps on {ip} loaded.", "green")

    def launch_selected_app(self):
        if not self.selected_device:
            messagebox.showwarning("No Device Selected", "Please select a device first.")
            return
        sel = self.installed_apps_listbox.curselection()
        if not sel:
            messagebox.showwarning("No App Selected", "Please select an app to launch.")
            return
        app_name = self.installed_apps_listbox.get(sel[0])
        # Launch app remotely (dummy)
        self.add_log(f"Launching {app_name} on {self.selected_device}...", "blue")
        # Simulate remote launch delay
        threading.Thread(target=self.simulate_remote_launch, args=(app_name,), daemon=True).start()

    def simulate_remote_launch(self, app_name):
        time.sleep(2)
        self.add_log(f"{app_name} launched successfully.", "green")
        ToastNotification(self.root, title="App Launch", message=f"{app_name} launched on device.", duration=3000).show()

    def add_custom_exe(self):
        path = filedialog.askopenfilename(filetypes=[("Executable files", "*.exe")])
        if not path:
            return
        name = os.path.basename(path)
        if name in self.app_paths:
            messagebox.showinfo("App Exists", "This executable is already in the list.")
            return
        self.app_paths[name] = f'"{path}"'
        menu = self.app_menu["menu"]
        menu.add_command(label=name, command=tk._setit(self.selected_app, name))
        self.add_log(f"Custom executable added: {name}", "green")
        self.selected_app.set(name)

    def schedule_app(self):
        if not self.selected_device:
            messagebox.showwarning("No Device Selected", "Please select a device first.")
            return
        app_name = self.selected_app.get()
        schedule_time = self.scheduled_time.get().strip()
        if not schedule_time:
            messagebox.showwarning("Schedule Time Missing", "Please enter a schedule time in HH:MM 24hr format.")
            return
        if not self.validate_time_format(schedule_time):
            messagebox.showwarning("Invalid Time Format", "Please enter time as HH:MM in 24-hour format.")
            return
        self.add_log(f"Scheduled {app_name} to launch on {self.selected_device} at {schedule_time}.", "blue")
        # Simulate scheduling (dummy)
        ToastNotification(self.root, title="Schedule Set", message=f"{app_name} scheduled at {schedule_time}", duration=3000).show()

    def validate_time_format(self, t):
        try:
            hh, mm = t.split(":")
            hh = int(hh)
            mm = int(mm)
            return 0 <= hh < 24 and 0 <= mm < 60
        except:
            return False

    def check_app_status(self):
        if not self.selected_device:
            messagebox.showwarning("No Device Selected", "Please select a device first.")
            return
        self.add_log(f"Checking app status on {self.selected_device}...", "blue")
        # Dummy check
        time.sleep(1)
        self.add_log("App is running normally.", "green")
        ToastNotification(self.root, title="App Status", message="App is running normally.", duration=3000).show()

    def send_command(self, cmd):
        if not self.selected_device:
            messagebox.showwarning("No Device Selected", "Please select a device first.")
            return
        if cmd == "shutdown":
            confirm = messagebox.askyesno("Confirm Shutdown", f"Are you sure you want to shutdown {self.selected_device}?")
            if not confirm:
                return
            self.add_log(f"Sending shutdown command to {self.selected_device}...", "red")
        elif cmd == "restart":
            confirm = messagebox.askyesno("Confirm Restart", f"Are you sure you want to restart {self.selected_device}?")
            if not confirm:
                return
            self.add_log(f"Sending restart command to {self.selected_device}...", "orange")
        else:
            self.add_log(f"Unknown command: {cmd}", "red")
            return
        # Dummy command execution delay
        threading.Thread(target=self.simulate_command_exec, args=(cmd,), daemon=True).start()

    def simulate_command_exec(self, cmd):
        time.sleep(3)
        if cmd == "shutdown":
            self.add_log(f"{self.selected_device} shutdown command sent successfully.", "red")
            ToastNotification(self.root, title="Shutdown", message="Shutdown command sent.", duration=3000).show()
        elif cmd == "restart":
            self.add_log(f"{self.selected_device} restart command sent successfully.", "orange")
            ToastNotification(self.root, title="Restart", message="Restart command sent.", duration=3000).show()

def main():
    root = tb.Window(themename="superhero")
    app = RemoteDeviceApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
