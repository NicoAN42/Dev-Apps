import os
import time
import json
import ttkbootstrap as tb
from ttkbootstrap.constants import *
from tkinter import filedialog, messagebox, simpledialog, scrolledtext
import threading

# Initialize the app window first
app = tb.Window(themename="minty")
app.title("📁 Folder Creator")

# Center the window on the screen with larger size
def center_window(window):
    window.update_idletasks()
    window_width = 1000  # Set the window width
    window_height = 700  # Set the window height
    screen_width = window.winfo_screenwidth()
    screen_height = window.winfo_screenheight()
    x = (screen_width // 2) - (window_width // 2)
    y = (screen_height // 2) - (window_height // 2)
    window.geometry(f'{window_width}x{window_height}+{x}+{y}')

# Call center_window to center the windoww
center_window(app)

# Variables (initialized after app)
parent_folder_var = tb.StringVar()
top_folders_var = tb.StringVar()
status_var = tb.StringVar()
created_folders = []
folder_structure = {}

# Browse Folder
def browse_folder():
    folder = filedialog.askdirectory()
    if folder:
        parent_folder_var.set(folder)

# Save current folder structure as template
def save_template():
    if not folder_structure:
        messagebox.showinfo("No Structure", "No folder structure to save.")
        return
    file = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON Files", "*.json")])
    if file:
        try:
            with open(file, "w") as f:
                json.dump(folder_structure, f, indent=2)
            messagebox.showinfo("Saved", f"Template saved to {file}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

# Load a saved template
def load_template():
    file = filedialog.askopenfilename(filetypes=[("JSON Files", "*.json")])
    if file:
        try:
            with open(file, "r") as f:
                data = json.load(f)
            if not isinstance(data, dict):
                raise ValueError("Invalid template format.")
            folder_structure.clear()
            folder_structure.update(data)
            top_folders_var.set(", ".join(folder_structure.keys()))
            log_area.insert("end", f"📂 Loaded template: {file}\n")
            log_area.see("end")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load template: {str(e)}")

# Folder creation logic with animation
def create_folders():
    parent = parent_folder_var.get().strip()
    top_names = top_folders_var.get().strip()

    if not parent:
        messagebox.showwarning("Missing", "Select parent folder.")
        return
    if not top_names:
        messagebox.showwarning("Missing", "Enter top-level folders.")
        return

    top_folders = [f.strip() for f in top_names.split(",") if f.strip()]

    # If structure was loaded from template, use it directly
    if set(folder_structure.keys()) != set(top_folders):
        folder_structure.clear()
        for top in top_folders:
            full_path = os.path.join(parent, top)
            subs = []
            if messagebox.askyesno("Add Subfolders?", f"Add subfolders to '{top}'?"):
                input_str = simpledialog.askstring("Subfolders", f"Enter subfolders for {top} (comma-separated):")  # Corrected here
                if input_str:
                    subs = [s.strip() for s in input_str.split(",") if s.strip()]
            folder_structure[top] = subs

    confirm = messagebox.askyesno("Confirm", "Ready to create folders?")
    if not confirm:
        return

    all_paths = []
    for top, subs in folder_structure.items():
        top_path = os.path.join(parent, top)
        all_paths.append(top_path)
        for sub in subs:
            all_paths.append(os.path.join(top_path, sub))

    created_folders.clear()
    status_var.set("Creating folders...")

    def folder_thread():
        for path in all_paths:
            try:
                os.makedirs(path, exist_ok=True)
                created_folders.append(path)
                log_area.insert("end", f"✅ Created: {path}\n")
                log_area.see("end")
                time.sleep(0.1)
                app.after(50, lambda p=path: show_toast(f"Folder Created: {p}"))
            except Exception as e:
                messagebox.showerror("Error", str(e))
        status_var.set("✅ Folder creation completed")

    t = threading.Thread(target=folder_thread)
    t.start()

# Show toast notification in the bottom right corner
def show_toast(message):
    toast = tb.Label(app, text=message, bootstyle=INFO, font=("Segoe UI", 10))
    toast.place(relx=1.0, rely=1.0, anchor="se", x=-10, y=-10)
    toast.after(3000, toast.destroy)  # Remove after 3 seconds

# Layout
header = tb.Label(app, text="📁 Folder Creator", font=("Segoe UI", 20, "bold"))
header.pack(pady=10)

btn_toggle = tb.Button(app, text="🌙 Toggle Dark Mode", command=lambda: app.style.theme_use("darkly" if app.style.theme.name != "darkly" else "minty"), bootstyle=INFO)
btn_toggle.pack(pady=5)

tabs = tb.Notebook(app)
main_frame = tb.Frame(tabs)
tabs.add(main_frame, text="Folder Creation")

walkthrough_frame = tb.Frame(tabs)
tabs.add(walkthrough_frame, text="Walkthrough")

walkthrough_text = """
📘 How to Use Folder Creator

1. **Select a Parent Folder**
   Click 'Browse' and select the base directory where your folder structure will be created.

2. **Define Top-Level Folders**
   Enter folder names separated by commas (e.g., `ProjectA, ProjectB`).

3. **Add Optional Subfolders**
   You’ll be prompted to add subfolders to each top-level folder.

4. **Save/Load Templates**
   You can save or reuse structures using the template buttons.

5. **Click 'Create Folders'**
   The app will create folders with animated updates in the tree view.

6. **View Results**
   Logs will show folder creation results.

💡 Tip: Toggle Dark Mode for a different visual style.
"""

walkthrough_label = tb.Label(walkthrough_frame, text=walkthrough_text, justify=LEFT, font=("Segoe UI", 10), anchor=NW)
walkthrough_label.pack(padx=20, pady=20, fill=BOTH, expand=True)

# Input Section
frame_parent = tb.Frame(main_frame)
frame_parent.pack(fill=X, padx=20, pady=5)
tb.Label(frame_parent, text="Parent Folder:").pack(anchor=W)
tb.Entry(frame_parent, textvariable=parent_folder_var).pack(side=LEFT, fill=X, expand=True, padx=(0, 5))
tb.Button(frame_parent, text="Browse", command=browse_folder, bootstyle=PRIMARY).pack(side=RIGHT)

frame_top = tb.Frame(main_frame)
frame_top.pack(fill=X, padx=20, pady=5)
tb.Label(frame_top, text="Top-Level Folder(s): (comma-separated)").pack(anchor=W)
tb.Entry(frame_top, textvariable=top_folders_var).pack(fill=X)

btn_frame = tb.Frame(main_frame)
btn_frame.pack(pady=10)
tb.Button(btn_frame, text="📥 Load Template", command=load_template, bootstyle=INFO).pack(side=LEFT, padx=5)
tb.Button(btn_frame, text="💾 Save Template", command=save_template, bootstyle=SECONDARY).pack(side=LEFT, padx=5)
tb.Button(btn_frame, text="🚀 Create Folders", command=create_folders, bootstyle=SUCCESS).pack(side=LEFT, padx=5)

# Status + Logs
frame_status = tb.Frame(main_frame)
frame_status.pack(pady=5)
tb.Label(frame_status, textvariable=status_var, foreground="green").pack()

frame_log = tb.Frame(main_frame)
frame_log.pack(fill=BOTH, padx=20, pady=10, expand=True)
tb.Label(frame_log, text="Log:").pack(anchor=W)
log_area = scrolledtext.ScrolledText(frame_log, height=10)
log_area.pack(fill=BOTH, expand=True)

# Footer
tb.Label(app, text="© 2025 Created by SOW 7", font=("Segoe UI", 9)).pack(pady=10)
tabs.pack(expand=1, fill=BOTH)

app.mainloop()
