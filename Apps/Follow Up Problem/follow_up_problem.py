import tkinter as tk
from tkinter import messagebox, ttk
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from ttkbootstrap.toast import ToastNotification
from datetime import datetime
import smtplib
import csv
import os
import socket
import requests
from email.message import EmailMessage
from dotenv import load_dotenv

# -----------------------------

# Load Environment Variables

# -----------------------------

load_dotenv()  # Load variables from .env file

SENDER_EMAIL = 'nicoardian17th@gmail.com'  # Replace with your Gmail sender
SENDER_PASSWORD = os.getenv("EMAIL_APP_PASSWORD")  # Load app password from env var
RECIPIENT_EMAIL = 'nugrohonicoardian@gmail.com'
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587
LOG_FILE = "notifications_log.csv"

# -----------------------------

# Data

# -----------------------------

obstacle_options = [
    "Peripheral PC", "BDS Web", "BDS IBS", "Fingerscan", "Tablet Monica",
    "Wifi", "Online Meeting", "Internal Website", "CS Digital",
    "E Service", "Antrian SARI", "Caller Antrian", "User Locked"
]

work_locations = [
    "CSO Regular", "CSO Prioritas", "Teller Regular", "Teller Prioritas",
    "PO", "APK", "PBC", "PIC", "Credit Admin"
]

# -----------------------------

# Functions

# -----------------------------

def center_window(win, width, height):
    screen_width = win.winfo_screenwidth()
    screen_height = win.winfo_screenheight()
    x = int((screen_width / 2) - (width / 2))
    y = int((screen_height / 2) - (height / 2))
    win.geometry(f'{width}x{height}+{x}+{y}')

def save_to_log(name, user_id, location, obstacles, timestamp, ticket_number, additional_comment):
    file_exists = os.path.isfile(LOG_FILE)
    with open(LOG_FILE, mode='a', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(["Ticket Number", "Name", "User ID", "Work Location", "Problems", "Timestamp", "Additional Comment"])
        writer.writerow([ticket_number, name, user_id, location, obstacles, timestamp, additional_comment])

def show_toast():
    toast = ToastNotification(
        title="Notification Sent",
        message="Support request has been sent and logged.",
        duration=3000,
        bootstyle="success"
    )
    toast.show_toast()

def send_email(subject, body):
    if not SENDER_PASSWORD:
        messagebox.showerror("Missing App Password", "EMAIL_APP_PASSWORD is not set.")
        return False
    try:
        msg = EmailMessage()
        msg['Subject'] = subject
        msg['From'] = SENDER_EMAIL
        msg['To'] = RECIPIENT_EMAIL
        msg.set_content(body)

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as smtp:
            smtp.starttls()
            smtp.login(SENDER_EMAIL, SENDER_PASSWORD)
            smtp.send_message(msg)

        return True
    except Exception as e:
        messagebox.showerror("Email Error", f"Failed to send email:\n{e}")
        return False

def disable_ui():
    """Disables all the widgets in the window."""
    entry_name.config(state='disabled')
    entry_id.config(state='disabled')
    work_location.config(state='disabled')
    entry_comment.config(state='disabled')
    send_button.config(state='disabled')
    for var in obstacle_vars.values():
        var.set(False)

def enable_ui():
    """Enables all the widgets in the window."""
    entry_name.config(state='normal')
    entry_id.config(state='normal')
    work_location.config(state='normal')
    entry_comment.config(state='normal')
    send_button.config(state='normal')

def reset_fields():
    """Reset all the fields after the process."""
    entry_name.delete(0, tk.END)
    entry_id.delete(0, tk.END)
    work_location.set('')
    entry_comment.delete(0, tk.END)
    for var in obstacle_vars.values():
        var.set(False)

def get_ip_and_hostname():
    """Fetches the device's public IP and hostname."""
    try:
        ip_address = requests.get('https://api.ipify.org').text  # Get public IP address
    except requests.exceptions.RequestException:
        ip_address = 'Unavailable'

    hostname = socket.gethostname()  # Get the hostname of the machine
    return ip_address, hostname

def send_notification():
    name = entry_name.get().strip()
    user_id = entry_id.get().strip()
    location = work_location.get()
    selected_obstacles = [key for key, var in obstacle_vars.items() if var.get()]
    additional_comment = entry_comment.get().strip()

    if not name or not user_id or not location or not selected_obstacles:
        messagebox.showerror("Missing Info", "Please complete all fields and select at least one problem.")
        return

    obstacle_str = ", ".join(selected_obstacles)
    time_now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Generate Incident Ticket Number (e.g., TICKET-20230507-123456)
    ticket_number = f"TICKET-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{user_id}"

    # Get IP address and Hostname
    ip_address, hostname = get_ip_and_hostname()

    message = (
        f"Ticket Number: {ticket_number}\n\n"
        f"Please support the problem(s) ({obstacle_str}) in {location} submitted by "
        f"{name} ({user_id}) created at {time_now}. Thank you.\n\n"
        f"Additional Comments:\n{additional_comment}\n\n"
        f"Device Info:\n"
        f"IP Address: {ip_address}\n"
        f"Hostname: {hostname}"
    )

    # Disable UI while sending the email
    disable_ui()

    # Start the email sending process
    if send_email(f"REQUEST - {ticket_number}", message):
        save_to_log(name, user_id, location, obstacle_str, time_now, ticket_number, additional_comment)
        show_toast()

        # Reset fields after sending
        reset_fields()

    # Re-enable the UI elements
    enable_ui()

# -----------------------------

# UI Setup

# -----------------------------

# Use ttkbootstrap Window class
app = ttk.Window(title="Support Notification App", themename="flatly")
center_window(app, 600, 700)

ttk.Label(app, text="Full Name:").pack(pady=5)
entry_name = ttk.Entry(app, width=40)
entry_name.pack()

ttk.Label(app, text="NIP:").pack(pady=5)
entry_id = ttk.Entry(app, width=40)
entry_id.pack()

ttk.Label(app, text="Work Location:").pack(pady=5)
work_location = ttk.Combobox(app, values=work_locations, width=40, state="readonly")
work_location.pack()

ttk.Label(app, text="Select Problems:").pack(pady=10)
obstacle_frame = ttk.Frame(app)
obstacle_frame.pack(pady=5)

obstacle_vars = {}
for option in obstacle_options:
    var = tk.BooleanVar()
    ttk.Checkbutton(obstacle_frame, text=option, variable=var).pack(anchor="w")
    obstacle_vars[option] = var

ttk.Label(app, text="Additional Comment:").pack(pady=5)
entry_comment = ttk.Entry(app, width=40)
entry_comment.pack(pady=5)

send_button = ttk.Button(app, text="Send Notification", bootstyle="success", command=send_notification)
send_button.pack(pady=20)

ttk.Label(app, text="© Created by SOW 7", font=("Arial", 10, "italic")).pack(side="bottom", pady=10)

app.mainloop()
