import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import ttkbootstrap as tb
from ttkbootstrap.constants import *
import paramiko
import threading
import openpyxl


class RemoteAppManager(tb.Window):
    def __init__(self):
        super().__init__(themename="superhero")
        self.title("Remote App Manager via SSH")
        self.geometry("720x520")
        self.resizable(False, False)

        # Variables
        self.ip_var = tk.StringVar()
        self.user_var = tk.StringVar()
        self.pass_var = tk.StringVar()
        self.status_var = tk.StringVar(value="Idle")
        self.app_list = []

        # Build UI
        self.create_widgets()

    def create_widgets(self):
        # Input Frame with border and padding
        frm_input = tb.Frame(self, padding=(15, 10), bootstyle="secondary")
        frm_input.pack(fill=X, padx=15, pady=10)

        tb.Label(frm_input, text="Remote IP Address:", font=("Segoe UI", 11, "bold")).grid(row=0, column=0, sticky=W, pady=6)
        ip_entry = tb.Entry(frm_input, textvariable=self.ip_var, width=30, font=("Segoe UI", 10))
        ip_entry.grid(row=0, column=1, sticky=W, pady=6, padx=8)
        ip_entry.insert(0, "e.g. 192.168.1.100")

        tb.Label(frm_input, text="SSH Username:", font=("Segoe UI", 11, "bold")).grid(row=1, column=0, sticky=W, pady=6)
        user_entry = tb.Entry(frm_input, textvariable=self.user_var, width=30, font=("Segoe UI", 10))
        user_entry.grid(row=1, column=1, sticky=W, pady=6, padx=8)
        user_entry.insert(0, "e.g. Administrator")

        tb.Label(frm_input, text="SSH Password:", font=("Segoe UI", 11, "bold")).grid(row=2, column=0, sticky=W, pady=6)
        pass_entry = tb.Entry(frm_input, textvariable=self.pass_var, show="*", width=30, font=("Segoe UI", 10))
        pass_entry.grid(row=2, column=1, sticky=W, pady=6, padx=8)

        # Buttons Frame
        frm_buttons = tb.Frame(self, padding=10)
        frm_buttons.pack(fill=X, padx=15)

        self.btn_scan = tb.Button(frm_buttons, text="Start Scan", bootstyle=SUCCESS, width=12, command=self.start_scan)
        self.btn_scan.grid(row=0, column=0, padx=6)

        self.btn_clear_log = tb.Button(frm_buttons, text="Clear Log", bootstyle=WARNING, width=12, command=self.clear_log)
        self.btn_clear_log.grid(row=0, column=1, padx=6)

        self.btn_export = tb.Button(frm_buttons, text="Export to Excel", bootstyle=INFO, width=14, command=self.export_to_excel)
        self.btn_export.grid(row=0, column=2, padx=6)

        self.btn_reset = tb.Button(frm_buttons, text="Reset Fields", bootstyle=SECONDARY, width=12, command=self.reset_fields)
        self.btn_reset.grid(row=0, column=3, padx=6)

        # Progress bar and label frame
        frm_progress = tb.Frame(self, padding=(15, 5))
        frm_progress.pack(fill=X, padx=15, pady=(5,10))

        self.progress = tb.Progressbar(frm_progress, mode='indeterminate')
        self.progress.pack(side=LEFT, fill=X, expand=True)

        self.lbl_progress = tb.Label(frm_progress, text="Idle", font=("Segoe UI", 10, "italic"))
        self.lbl_progress.pack(side=LEFT, padx=12)

        # Log Frame with border and scrollbar
        frm_log = tb.Frame(self, padding=10, bootstyle="dark")
        frm_log.pack(fill=BOTH, expand=True, padx=15, pady=(0,15))

        tb.Label(frm_log, text="Scan Log", font=("Segoe UI", 12, "bold"), foreground="white").pack(anchor=W, pady=(0,5))

        self.txt_log = tk.Text(frm_log, height=15, bg='#222222', fg='white', font=("Consolas", 10), state='disabled', wrap='word')
        self.txt_log.pack(side=LEFT, fill=BOTH, expand=True)

        scrollbar = ttk.Scrollbar(frm_log, command=self.txt_log.yview)
        scrollbar.pack(side=RIGHT, fill=Y)
        self.txt_log.config(yscrollcommand=scrollbar.set)

        # Status bar at bottom
        self.status_bar = tb.Label(self, textvariable=self.status_var, relief=SUNKEN, anchor=W, font=("Segoe UI", 10, "bold"))
        self.status_bar.pack(fill=X, side=BOTTOM)

        # Initialize status color
        self.update_status_color("idle")

    def update_status_color(self, status_type):
        # Change status bar color based on status
        if status_type == "success":
            self.status_bar.configure(foreground="limegreen")
        elif status_type == "error":
            self.status_bar.configure(foreground="tomato")
        else:
            self.status_bar.configure(foreground="white")

    def log(self, message):
        self.txt_log.config(state='normal')
        self.txt_log.insert(END, message + "\n")
        self.txt_log.see(END)
        self.txt_log.config(state='disabled')

    def clear_log(self):
        if messagebox.askyesno("Confirm", "Are you sure you want to clear the log?"):
            self.txt_log.config(state='normal')
            self.txt_log.delete('1.0', END)
            self.txt_log.config(state='disabled')
            self.app_list.clear()
            self.status_var.set("Log cleared")
            self.update_status_color("idle")

    def reset_fields(self):
        if messagebox.askyesno("Confirm", "Reset all input fields and clear log?"):
            self.ip_var.set("")
            self.user_var.set("")
            self.pass_var.set("")
            self.clear_log()
            self.status_var.set("Fields reset")
            self.update_status_color("idle")

    def export_to_excel(self):
        if not self.app_list:
            messagebox.showwarning("Warning", "No data to export. Please run a scan first.")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".xlsx",
            filetypes=[("Excel files", "*.xlsx"), ("All files", "*.*")]
        )
        if not file_path:
            return

        wb = openpyxl.Workbook()
        ws = wb.active
        ws.title = "Installed Apps"
        ws.append(["App Name"])

        for app in self.app_list:
            ws.append([app])

        try:
            wb.save(file_path)
            messagebox.showinfo("Success", f"Data exported to {file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save Excel file:\n{e}")

    def start_scan(self):
        ip = self.ip_var.get().strip()
        user = self.user_var.get().strip()
        passwd = self.pass_var.get().strip()

        if not ip or not user or not passwd:
            messagebox.showerror("Error", "Please fill in all fields")
            return

        # Disable buttons during scanning
        self.btn_scan.config(state=DISABLED)
        self.btn_clear_log.config(state=DISABLED)
        self.btn_export.config(state=DISABLED)
        self.btn_reset.config(state=DISABLED)

        self.status_var.set(f"Connecting to {ip}...")
        self.update_status_color("idle")

        # Start progress bar animation
        self.progress.start(10)
        self.lbl_progress.config(text="Scanning installed apps...")

        # Run scan in thread to avoid freezing UI
        thread = threading.Thread(target=self.scan_apps_ssh, args=(ip, user, passwd), daemon=True)
        thread.start()

    def scan_apps_ssh(self, ip, username, password):
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(ip, username=username, password=password, timeout=10)
            self.log(f"Connected to {ip}")

            # Command to list installed apps (powershell) - retrieving DisplayName from registry
            ps_command = (
                "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | "
                "Select-Object DisplayName | Where-Object { $_.DisplayName } | ForEach-Object { $_.DisplayName }"
            )

            stdin, stdout, stderr = client.exec_command(f"powershell -Command \"{ps_command}\"")
            output = stdout.read().decode('utf-8', errors='ignore')
            error = stderr.read().decode('utf-8', errors='ignore')

            if error.strip():
                self.log(f"Error: {error.strip()}")
                self.status_var.set("Error during scanning")
                self.update_status_color("error")
            else:
                apps = output.strip().split('\n')
                self.app_list = [app.strip() for app in apps if app.strip()]
                self.log(f"Found {len(self.app_list)} installed apps:")
                for app in self.app_list:
                    self.log(f"- {app}")
                self.status_var.set(f"Scan completed: {len(self.app_list)} apps found")
                self.update_status_color("success")

            client.close()
        except Exception as e:
            self.log(f"Connection failed: {str(e)}")
            self.status_var.set("Scan failed")
            self.update_status_color("error")

        # Stop progress bar and enable buttons
        self.progress.stop()
        self.lbl_progress.config(text="Idle")

        self.btn_scan.config(state=NORMAL)
        self.btn_clear_log.config(state=NORMAL)
        self.btn_export.config(state=NORMAL)
        self.btn_reset.config(state=NORMAL)


if __name__ == "__main__":
    app = RemoteAppManager()
    app.mainloop()
