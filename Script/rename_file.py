import os
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from datetime import datetime
from threading import Thread
import time
from ttkbootstrap import Style
from ttkbootstrap.widgets import Button, Progressbar, Checkbutton
from tkinter import Toplevel

# Global variables
stop_flag = False
start_time = None
timer_running = False
total_folders_global = 0
folders_done_global = 0
dark_mode = False  # Dark mode state

# Select folder
def select_folder():
    folder = filedialog.askdirectory(title="Select Root Folder")
    if folder:
        folder_var.set(folder)
        log_textbox.delete(1.0, tk.END)
        start_button["state"] = "normal"
        stop_button["state"] = "disabled"

# Start process
def start_processing():
    global start_time, timer_running
    start_time = time.time()
    timer_running = True
    time_label_var.set("Elapsed Time: 00:00")
    eta_label_var.set("Estimated Time Left: calculating...")
    update_timer()
    thread = Thread(target=process_folder)
    thread.start()

# Stop process
def stop_processing():
    global stop_flag, timer_running
    stop_flag = True
    timer_running = False
    eta_label_var.set("Estimated Time Left: stopped")

# Update timer & ETA
def update_timer():
    if timer_running:
        elapsed = int(time.time() - start_time)
        minutes, seconds = divmod(elapsed, 60)
        time_label_var.set(f"Elapsed Time: {minutes:02}:{seconds:02}")

        if total_folders_global > 0 and folders_done_global > 0:
            avg_time_per_folder = elapsed / folders_done_global
            remaining = total_folders_global - folders_done_global
            eta = int(avg_time_per_folder * remaining)
            eta_m, eta_s = divmod(eta, 60)
            eta_label_var.set(f"Estimated Time Left: {eta_m:02}:{eta_s:02}")
        else:
            eta_label_var.set("Estimated Time Left: calculating...")

        root.after(1000, update_timer)

# Process folders
def process_folder():
    global stop_flag, total_folders_global, folders_done_global, timer_running
    stop_flag = False
    root_folder = folder_var.get()
    if not os.path.isdir(root_folder):
        return

    start_button["state"] = "disabled"
    stop_button["state"] = "normal"
    log_textbox.delete(1.0, tk.END)
    log("Starting process...")

    renamed_files = 0
    skipped_folders = 0
    log_lines = []

    folder_list = [d for d in os.walk(root_folder)]
    total_folders_global = len(folder_list)
    folders_done_global = 0

    progress["maximum"] = total_folders_global
    progress["value"] = 0

    for i, (dirpath, dirnames, filenames) in enumerate(folder_list, start=1):
        if stop_flag:
            log("\n❌ Process stopped by user.")
            messagebox.showwarning("Stopped", "Process was manually stopped.")
            return

        excel_files = [f for f in filenames if f.lower().endswith(('.xlsx', '.xls'))]
        file_count = len(excel_files)
        renamed_in_this_folder = 0

        if file_count == 0:
            skipped_folders += 1
            log_lines.append(f"Skipped: {dirpath} (no Excel files)")
        else:
            log_lines.append(f"{dirpath} - Excel files found: {file_count}")
            for filename in excel_files:
                old_path = os.path.join(dirpath, filename)

                if "CSO" in filename or "Teller" in filename:
                    log_lines.append(f"[Skipped - Contains CSO or Teller] {filename}")
                    continue

                if "Tabel" in filename:
                    new_filename = "Act.xlsx"
                else:
                    new_filename = "Trx.xlsx"

                new_path = os.path.join(dirpath, new_filename)

                if not os.path.exists(old_path):
                    continue

                try:
                    if os.path.exists(new_path):
                        log_lines.append(f"[Skipped - File Already Exists] {new_path}")
                        continue

                    os.rename(old_path, new_path)
                    log_lines.append(f"Renamed: {old_path} -> {new_path}")
                    renamed_files += 1
                    renamed_in_this_folder += 1

                except FileNotFoundError:
                    log_lines.append(f"[Skipped - Not Found] {old_path}")
                    continue
                except Exception as e:
                    log_lines.append(f"[Error] Could not rename {old_path}: {str(e)}")
                    continue

        progress["value"] = i
        percentage = int((i / total_folders_global) * 100)
        percent_label_var.set(f"Progress: {percentage}%")
        folders_done_global += 1
        root.update_idletasks()

    elapsed = int(time.time() - start_time)
    minutes, seconds = divmod(elapsed, 60)
    elapsed_str = f"{minutes}m {seconds}s" if minutes else f"{seconds}s"

    # Save log as .txt
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    log_txt = os.path.join(root_folder, f"rename_log_{timestamp}.txt")

    with open(log_txt, 'w') as f:
        f.write("Excel File Rename Log\n======================\n")
        f.write(f"Root folder: {root_folder}\n")
        f.write(f"Total folders: {total_folders_global}\n")
        f.write(f"Files renamed: {renamed_files}\n")
        f.write(f"Folders skipped: {skipped_folders}\n")
        f.write(f"Elapsed time: {elapsed_str}\n\nDetails:\n")
        f.write("\n".join(log_lines))

    log(f"\n✅ Process complete in {elapsed_str}.")
    log(f"Text log: {log_txt}")

    show_toast("✅ Process Complete", f"{renamed_files} file(s) renamed.\nElapsed time: {elapsed_str}")

    messagebox.showinfo("Success", f"✅ {renamed_files} file(s) renamed.\nElapsed time: {elapsed_str}\nProcess FINISHED.")
    root.after(1000, root.quit)

    start_button["state"] = "normal"
    stop_button["state"] = "disabled"
    timer_running = False
    eta_label_var.set("Estimated Time Left: 00:00")

# Logging
def log(message):
    log_textbox.insert(tk.END, message + "\n")
    log_textbox.see(tk.END)

# Animated toast (bottom-right)
def show_toast(title, message):
    toast = Toplevel(root)
    toast.overrideredirect(True)
    toast.attributes("-topmost", True)

    width, height = 300, 100
    screen_width = toast.winfo_screenwidth()
    screen_height = toast.winfo_screenheight()
    x = screen_width - width - 20
    y = screen_height

    toast.geometry(f"{width}x{height}+{x}+{y}")
    bg_color = "#222222" if dark_mode else "#ffffff"
    fg_color = "white" if dark_mode else "#222222"

    toast.configure(bg=bg_color)

    icon = tk.Label(toast, text="✅", font=("Segoe UI Emoji", 36), bg=bg_color, fg=fg_color)
    icon.pack(pady=(5, 0))

    title_lbl = tk.Label(toast, text=title, font=("Segoe UI", 12, "bold"), bg=bg_color, fg=fg_color)
    title_lbl.pack()

    msg_lbl = tk.Label(toast, text=message, font=("Segoe UI", 10), bg=bg_color, fg=fg_color, wraplength=280, justify="center")
    msg_lbl.pack(padx=10)

    # Animate sliding up
    def animate_slide(current_y):
        if current_y > screen_height - height - 50:
            current_y -= 10
            toast.geometry(f"{width}x{height}+{x}+{current_y}")
            toast.after(10, lambda: animate_slide(current_y))

    animate_slide(screen_height)

    toast.after(3000, toast.destroy)

# Dark Mode Toggle
def toggle_dark_mode():
    global dark_mode
    dark_mode = not dark_mode
    style.theme_use("darkly" if dark_mode else "minty")
    root.configure(bg="#444444" if dark_mode else "#f4f4f4")

# Center window
def center_window(win, width=None, height=None):
    win.update_idletasks()
    if not width or not height:
        width = win.winfo_width()
        height = win.winfo_height()
    screen_width = win.winfo_screenwidth()
    screen_height = win.winfo_screenheight()
    x = (screen_width // 2) - (width // 2)
    y = (screen_height // 2) - (height // 2)
    win.geometry(f'{width}x{height}+{x}+{y}')

# GUI setup
style = Style("minty")
root = style.master
root.title("Rename File Cabang")

folder_var = tk.StringVar()
percent_label_var = tk.StringVar(value="Progress: 0%")
time_label_var = tk.StringVar(value="Elapsed Time: 00:00")
eta_label_var = tk.StringVar(value="Estimated Time Left: calculating...")

frame = tk.Frame(root, padx=10, pady=10)
frame.pack(fill=tk.BOTH, expand=True)

# Title
tk.Label(frame, text="Rename File Cabang", font=("Segoe UI", 16, "bold")).pack(pady=10)

# Folder chooser
tk.Label(frame, text="Selected Folder:").pack(anchor="w")
tk.Entry(frame, textvariable=folder_var, width=80, state="readonly").pack(fill=tk.X, pady=2)
Button(frame, text="Choose Folder", command=select_folder, bootstyle="success").pack(pady=5)

# Buttons
button_frame = tk.Frame(frame)
button_frame.pack(pady=5)

start_button = Button(button_frame, text="Start Renaming", command=start_processing, bootstyle="primary", state="disabled")
start_button.pack(side=tk.LEFT, padx=5)

stop_button = Button(button_frame, text="Stop", command=stop_processing, bootstyle="danger", state="disabled")
stop_button.pack(side=tk.LEFT, padx=5)

# Dark Mode Toggle Checkbox
dark_mode_checkbox = Checkbutton(frame, text="Dark Mode", bootstyle="info", command=toggle_dark_mode)
dark_mode_checkbox.pack(pady=5)

# Progress bar
progress = Progressbar(frame, bootstyle="success-striped", length=300)
progress.pack(pady=5)
tk.Label(frame, textvariable=percent_label_var).pack()
tk.Label(frame, textvariable=time_label_var, font=("Segoe UI", 10)).pack()
tk.Label(frame, textvariable=eta_label_var, font=("Segoe UI", 10)).pack()

# Log output
log_textbox = scrolledtext.ScrolledText(frame, height=15)
log_textbox.pack(fill=tk.BOTH, expand=True, pady=5)

# Center the window and run the app
center_window(root, 800, 600)
root.mainloop()
