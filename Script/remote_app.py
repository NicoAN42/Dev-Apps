import tkinter as tk
from tkinter import filedialog
import ttkbootstrap as tb
from ttkbootstrap.toast import ToastNotification
import subprocess
import threading
import socket
import ipaddress
import time

# === Setup ===
app = tb.Window(themename="superhero")
app.title("Remote App Launcher")
app.geometry("700x780")
app.resizable(False, False)

devices = {}
app_paths = {
    "AMCFG": r'"C:\Program Files\YourApp\amcfg.exe"',
    "Notepad": r'"C:\Windows\System32\notepad.exe"',
    "Calculator": r'"C:\Windows\System32\calc.exe"',
}
selected_app = tk.StringVar(value="AMCFG")
scheduled_time = tk.StringVar()


# === Toast Helper ===
def show_toast(title, message, duration=4000):
    ToastNotification(title=title, message=message, duration=duration).show_toast()


# === Device Discovery ===
def discover_devices():
    discover_btn.config(state="disabled", text="Scanning...")    
    devices.clear()
    device_listbox.delete(0, tk.END)

    def scan():
        try:
            local_ip = socket.gethostbyname(socket.gethostname())
        except:
            show_toast("Error", "Could not get local IP.")
            discover_btn.config(state="normal", text="Discover Devices")
            return

        subnet = ipaddress.ip_network(local_ip + "/24", strict=False)
        found = 0
        for ip in subnet.hosts():
            ip = str(ip)
            result = subprocess.run(["ping", "-n", "1", "-w", "150", ip], stdout=subprocess.DEVNULL)
            if result.returncode == 0:
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except:
                    hostname = ip
                devices[hostname] = ip
                device_listbox.insert(tk.END, f"{hostname} ({ip})")
                found += 1

        discover_btn.config(state="normal", text=f"Scan Devices ({found} found)")
        show_toast("Scan Complete", f"{found} devices discovered.")

    threading.Thread(target=scan, daemon=True).start()


# === Send Remote Command ===
def send_command(action):
    try:
        selected = device_listbox.get(device_listbox.curselection())
        hostname = selected.split(" (")[0]
        ip = devices[hostname]
    except:
        show_toast("Error", "Please select a device.")
        return

    if action in ["shutdown", "restart"]:
        cmd = f"powershell -Command \"{('Stop' if action=='shutdown' else 'Restart')}-Computer -ComputerName '{ip}' -Force\""
    elif action == "start_app":
        exe_path = app_paths[selected_app.get()]
        cmd = f"powershell -Command \"Invoke-Command -ComputerName {ip} -ScriptBlock {{ Start-Process -FilePath {exe_path} -WindowStyle Hidden }}\""
    elif action == "check_status":
        exe_name = app_paths[selected_app.get()].strip('\"').split("\\")[-1].replace(".exe", "")
        cmd = f"powershell -Command \"Invoke-Command -ComputerName {ip} -ScriptBlock {{ Get-Process -Name '{exe_name}' -ErrorAction SilentlyContinue }}\""
    elif action == "schedule_app":
        time_str = scheduled_time.get()
        if not time_str or ":" not in time_str:
            show_toast("Invalid Time", "Use format HH:MM (24hr)")
            return
        exe_path = app_paths[selected_app.get()]
        task_name = f"Launch_{selected_app.get()}"
        cmd = f"powershell -Command \"Invoke-Command -ComputerName {ip} -ScriptBlock {{ schtasks /Create /TN '{task_name}' /TR {exe_path} /SC ONCE /ST {time_str} /F }}\""
    else:
        return

    def run():
        retries = 3
        for _ in range(retries):
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if result.returncode == 0:
                if action == "check_status":
                    status = "RUNNING" if result.stdout.strip() else "NOT running"
                    show_toast("App Status", f"{selected_app.get()} is {status} on {hostname}")
                elif action == "schedule_app":
                    show_toast("Scheduled", f"{selected_app.get()} will run at {scheduled_time.get()} on {hostname}")
                else:
                    show_toast("Success", f"{action.replace('_', ' ').title()} command sent to {hostname}")
                return
            time.sleep(1)
        show_toast("Failed", f"Command failed:\n{result.stderr.strip()}")

    threading.Thread(target=run, daemon=True).start()


# === Add Custom EXE ===
def add_custom_exe():
    filepath = filedialog.askopenfilename(filetypes=[("Executable Files", "*.exe")])
    if filepath:
        name = filepath.split("\\")[-1].replace(".exe", "")
        app_paths[name] = f'"{filepath}"'
        app_menu["menu"].add_command(label=name, command=tk._setit(selected_app, name))
        selected_app.set(name)
        show_toast("App Added", f"{name} added to launcher.")


# === Layout ===

# -- Devices --
device_frame = tb.Labelframe(app, text="Discovered Devices", padding=10)
device_frame.pack(fill="both", padx=10, pady=10)

device_listbox = tk.Listbox(device_frame, height=10)
device_listbox.pack(fill="both", expand=True, padx=5, pady=5)

discover_btn = tb.Button(device_frame, text="Discover Devices", command=discover_devices, bootstyle="info")
discover_btn.pack(pady=5)

# -- App Selection --
app_frame = tb.Labelframe(app, text="App Launcher", padding=10)
app_frame.pack(fill="x", padx=10, pady=5)

tk.Label(app_frame, text="Select Application:").pack(anchor="w")
app_menu = tk.OptionMenu(app_frame, selected_app, *app_paths.keys())
app_menu.pack(fill="x", padx=5, pady=5)

tb.Button(app_frame, text="Launch App", command=lambda: send_command("start_app"), bootstyle="success").pack(fill="x", pady=3)
tb.Button(app_frame, text="Check App Status", command=lambda: send_command("check_status"), bootstyle="warning").pack(fill="x", pady=3)
tb.Button(app_frame, text="Add Custom .exe", command=add_custom_exe, bootstyle="light").pack(fill="x", pady=3)

# -- Schedule --
schedule_frame = tb.Labelframe(app, text="Schedule App Launch", padding=10)
schedule_frame.pack(fill="x", padx=10, pady=5)

tk.Label(schedule_frame, text="Schedule Time (HH:MM):").pack(anchor="w")
tk.Entry(schedule_frame, textvariable=scheduled_time).pack(fill="x", padx=5, pady=5)
tb.Button(schedule_frame, text="Schedule App", command=lambda: send_command("schedule_app"), bootstyle="primary").pack(fill="x", pady=5)

# -- Device Control --
control_frame = tb.Labelframe(app, text="Device Control", padding=10)
control_frame.pack(fill="x", padx=10, pady=10)

tb.Button(control_frame, text="Restart Device", command=lambda: send_command("restart"), bootstyle="warning").pack(fill="x", pady=5)
tb.Button(control_frame, text="Shutdown Device", command=lambda: send_command("shutdown"), bootstyle="danger").pack(fill="x", pady=5)

app.mainloop()
