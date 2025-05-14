import ttkbootstrap as tb
from ttkbootstrap.constants import *
import tkinter as tk
import subprocess
import os
from tkinter import messagebox

def run_and_wait(exe_name):
    if not os.path.isfile(exe_name):
        print(f"❌ File not found: {exe_name}")
        return False

    try:
        print(f"▶ Running: {exe_name}")
        subprocess.run([exe_name], check=True)
        print(f"✅ Completed: {exe_name}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Error running {exe_name}: {e}")
        return False

def on_start():
    btn_start.config(state=tk.DISABLED)
    root.update()

    success = False
    if run_and_wait("rename_file.exe"):
        if run_and_wait("data_combine.exe"):
            if run_and_wait("data_processing.exe"):
                success = True
            else:
                messagebox.showerror("Error", "data_processing.exe failed.")
        else:
            messagebox.showerror("Error", "data_combine.exe failed.")
    else:
        messagebox.showerror("Error", "rename_file.exe not found or failed.")

    if success:
        messagebox.showinfo("Success", "🎉 All apps ran successfully!")
        messagebox.showinfo("Thank You", "🙏 Thanks for using this tool!\n- SOW 7")
    
    btn_start.config(state=tk.NORMAL)

def on_close():
    root.destroy()

# Create main window
root = tb.Window(themename="litera")
root.title("Run Apps for Mission Digital Tools")
root.resizable(False, False)

# Set size and center the window
window_width = 400
window_height = 250
screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()
x = int((screen_width - window_width) / 2)
y = int((screen_height - window_height) / 2)
root.geometry(f"{window_width}x{window_height}+{x}+{y}")

# Center frame
frame = tb.Frame(root, padding=20)
frame.place(relx=0.5, rely=0.5, anchor=CENTER)

# Welcome label
label_title = tb.Label(frame, text="🚀 Run Apps for Mission Digital Tools", font=("Segoe UI", 14, "bold"), bootstyle=INFO)
label_title.pack(pady=(0, 10))

label_subtitle = tb.Label(frame, text="Created by SOW 7", font=("Segoe UI", 11), bootstyle=SECONDARY)
label_subtitle.pack(pady=(0, 20))

# Buttons
btn_start = tb.Button(frame, text="Start", bootstyle=SUCCESS, width=15, command=on_start)
btn_start.pack(pady=5)

btn_close = tb.Button(frame, text="Close", bootstyle=DANGER, width=15, command=on_close)
btn_close.pack(pady=5)

root.mainloop()
