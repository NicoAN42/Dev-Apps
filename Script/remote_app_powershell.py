import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import ttkbootstrap as tb
from ttkbootstrap.constants import *
import threading
import subprocess
import queue
import time
import openpyxl


def run_powershell_silent(remote_computer, command, username=None, password=None):
    CREATE_NO_WINDOW = 0x08000000

    cred_part = ""
    if username and password:
        cred_part = (
            f"$secpasswd = ConvertTo-SecureString '{password}' -AsPlainText -Force;"
            f"$mycreds = New-Object System.Management.Automation.PSCredential('{username}', $secpasswd);"
        ) + " "

    ps_script = (
        cred_part +
        f"Invoke-Command -ComputerName {remote_computer} "
        + ("-Credential $mycreds " if username and password else "")
        + f"-ScriptBlock {{ {command} }}"
    )

    ps_command = [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        ps_script
    ]

    proc = subprocess.Popen(
        ps_command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        creationflags=CREATE_NO_WINDOW
    )

    stdout, stderr = proc.communicate()

    return stdout.decode("utf-8", errors="ignore"), stderr.decode("utf-8", errors="ignore")


class RemoteAppManager(tb.Window):
    def __init__(self):
        super().__init__(themename="darkly")
        self.title("Remote App Manager with Scan Progress & Clear Reset")
        self.geometry("900x700")
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

        self.device_list = []
        self.installed_apps = {}
        self.queue = queue.Queue()
        self.scan_thread = None
        self.scan_stop_flag = threading.Event()

        self._build_ui()
        self.after(100, self.process_queue)

    def _build_ui(self):
        main_frame = tb.Frame(self, padding=10)
        main_frame.pack(fill=BOTH, expand=YES)

        # Connection input frame
        input_frame = tb.Labelframe(main_frame, text="Connection Settings", padding=10)
        input_frame.pack(fill=X, pady=5)

        tb.Label(input_frame, text="Remote Computer IP/Name:").grid(row=0, column=0, sticky=W, padx=5, pady=5)
        self.entry_subnet = tb.Entry(input_frame, width=35)
        self.entry_subnet.grid(row=0, column=1, sticky=W, padx=5, pady=5)

        tb.Label(input_frame, text="Username (optional):").grid(row=1, column=0, sticky=W, padx=5, pady=5)
        self.entry_username = tb.Entry(input_frame, width=35)
        self.entry_username.grid(row=1, column=1, sticky=W, padx=5, pady=5)

        tb.Label(input_frame, text="Password (optional):").grid(row=2, column=0, sticky=W, padx=5, pady=5)
        self.entry_password = tb.Entry(input_frame, width=35, show="*")
        self.entry_password.grid(row=2, column=1, sticky=W, padx=5, pady=5)

        # Buttons frame
        btn_frame = tb.Frame(main_frame)
        btn_frame.pack(fill=X, pady=10)

        self.btn_scan = tb.Button(btn_frame, text="Scan Device & Get Apps", bootstyle=PRIMARY, command=self.start_scan)
        self.btn_scan.pack(side=LEFT, padx=5)

        self.btn_stop = tb.Button(btn_frame, text="Stop Scan", bootstyle=DANGER, command=self.stop_scan, state=DISABLED)
        self.btn_stop.pack(side=LEFT, padx=5)

        self.btn_export = tb.Button(btn_frame, text="Export App List to Excel", bootstyle=SUCCESS, command=self.export_to_excel, state=DISABLED)
        self.btn_export.pack(side=LEFT, padx=5)

        self.btn_clear_log = tb.Button(btn_frame, text="Clear Log & Reset", bootstyle=SECONDARY, command=self.clear_all)
        self.btn_clear_log.pack(side=RIGHT, padx=5)

        # Progress bar
        self.progress = ttk.Progressbar(main_frame, orient='horizontal', mode='indeterminate')
        self.progress.pack(fill=X, pady=(0, 10))

        # Treeview for app list
        tree_frame = tb.Labelframe(main_frame, text="Installed Applications", padding=10)
        tree_frame.pack(fill=BOTH, expand=YES)

        columns = ("AppName",)
        self.tree = ttk.Treeview(tree_frame, columns=columns, show='headings')
        self.tree.heading("AppName", text="Application Name")
        self.tree.pack(fill=BOTH, expand=YES, side=LEFT)

        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.configure(yscrollcommand=scrollbar.set)

        # Log output frame
        log_frame = tb.Labelframe(main_frame, text="Log Output", padding=10)
        log_frame.pack(fill=BOTH, expand=YES, pady=(10, 0))

        self.log_text = tk.Text(log_frame, height=12, font=("Consolas", 11), state=tk.NORMAL)
        self.log_text.pack(side=LEFT, fill=BOTH, expand=YES)

        log_scroll = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self.log_text.yview)
        log_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text.configure(yscrollcommand=log_scroll.set)

    def start_scan(self):
        remote = self.entry_subnet.get().strip()
        if not remote:
            messagebox.showerror("Input Error", "Please enter a remote computer IP or name.")
            return

        self.device_list = [remote]
        self.installed_apps = {}

        self.log(f"Starting scan on remote device: {remote}\n")
        self.progress.start(10)  # Start progress animation

        self.btn_scan.config(state=DISABLED)
        self.btn_stop.config(state=NORMAL)
        self.btn_export.config(state=DISABLED)
        self.tree.delete(*self.tree.get_children())
        self.log_text.delete('1.0', tk.END)

        self.scan_stop_flag.clear()
        self.scan_thread = threading.Thread(target=self.scan_device_apps, args=(remote,), daemon=True)
        self.scan_thread.start()

    def stop_scan(self):
        if self.scan_thread and self.scan_thread.is_alive():
            self.scan_stop_flag.set()
            self.log("Stopping scan... Please wait.\n")
            self.btn_stop.config(state=DISABLED)

    def scan_device_apps(self, remote):
        try:
            # Command to get installed apps from registry (both 32 and 64 bit)
            ps_command = r"""
$paths = @(
  'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
  'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
$appNames = foreach ($path in $paths) {
    Get-ItemProperty $path -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } | Select-Object -ExpandProperty DisplayName
}
$appNames = $appNames | Sort-Object -Unique
$appNames -join "`n"
"""

            out, err = run_powershell_silent(remote, ps_command, self.entry_username.get().strip() or None, self.entry_password.get() or None)

            if self.scan_stop_flag.is_set():
                self.queue.put(("log", "Scan stopped by user.\n"))
                self.queue.put(("done", None))
                return

            if err.strip():
                self.queue.put(("log", f"Error during scan:\n{err}\n"))
            else:
                apps = [line.strip() for line in out.splitlines() if line.strip()]
                self.installed_apps[remote] = apps
                self.queue.put(("log", f"Found {len(apps)} installed applications.\n"))
                self.queue.put(("apps", apps))

            self.queue.put(("done", None))

        except Exception as e:
            self.queue.put(("log", f"Exception during scan: {e}\n"))
            self.queue.put(("done", None))

    def process_queue(self):
        try:
            while True:
                msg_type, data = self.queue.get_nowait()
                if msg_type == "log":
                    self.log(data)
                elif msg_type == "apps":
                    self.tree.delete(*self.tree.get_children())
                    for app in data:
                        self.tree.insert("", tk.END, values=(app,))
                elif msg_type == "done":
                    self.progress.stop()
                    self.btn_scan.config(state=NORMAL)
                    self.btn_stop.config(state=DISABLED)
                    if self.installed_apps:
                        self.btn_export.config(state=NORMAL)
                self.queue.task_done()
        except queue.Empty:
            pass
        self.after(100, self.process_queue)

    def log(self, text):
        self.log_text.insert(tk.END, text)
        self.log_text.see(tk.END)

    def export_to_excel(self):
        if not self.installed_apps:
            messagebox.showinfo("No Data", "No application data to export.")
            return

        save_path = filedialog.asksaveasfilename(
            defaultextension=".xlsx",
            filetypes=[("Excel files", "*.xlsx")],
            title="Save application list to Excel"
        )
        if not save_path:
            return

        try:
            wb = openpyxl.Workbook()
            ws = wb.active
            ws.title = "Installed Applications"

            ws.append(["Remote Computer", "Application Name"])

            for remote, apps in self.installed_apps.items():
                for app in apps:
                    ws.append([remote, app])

            wb.save(save_path)
            messagebox.showinfo("Export Success", f"Application list saved to:\n{save_path}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to save Excel file:\n{e}")

    def clear_all(self):
        # Clear log
        self.log_text.delete('1.0', tk.END)

        # Clear input fields
        self.entry_subnet.delete(0, tk.END)
        self.entry_username.delete(0, tk.END)
        self.entry_password.delete(0, tk.END)

        # Reset progress bar
        self.progress.stop()
        self.progress['value'] = 0

        # Clear device list and treeview
        self.device_list.clear()
        self.installed_apps.clear()
        self.tree.delete(*self.tree.get_children())

        # Enable scan button and disable stop button and export button
        self.btn_scan.config(state=tk.NORMAL)
        self.btn_stop.config(state=tk.DISABLED)
        self.btn_export.config(state=tk.DISABLED)

    def on_closing(self):
        if self.scan_thread and self.scan_thread.is_alive():
            if not messagebox.askokcancel("Quit", "Scan is running. Do you want to quit?"):
                return
        self.destroy()


if __name__ == "__main__":
    app = RemoteAppManager()
    app.mainloop()
