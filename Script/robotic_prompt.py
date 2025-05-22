import tkinter as tk
from tkinter import messagebox
import threading
import time
import pygetwindow as gw
import pyautogui
from PIL import ImageGrab, Image
from transformers import BlipProcessor, BlipForConditionalGeneration
import torch

# --- Load the BLIP model ---
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
processor = BlipProcessor.from_pretrained("Salesforce/blip-image-captioning-base")
model = BlipForConditionalGeneration.from_pretrained("Salesforce/blip-image-captioning-base").to(device)

# --- Global Variables ---
capture_region = None
running = True

# --- Functions ---

def is_youtube_open():
    for window in gw.getWindowsWithTitle("YouTube"):
        if window.isVisible:
            return True
    return False

def select_video_area():
    messagebox.showinfo("Select Area", "Drag your mouse to select the YouTube video area.")
    box = pyautogui.selectRegion()
    return box  # (left, top, width, height)

def describe_image_blip(pil_image):
    inputs = processor(images=pil_image, return_tensors="pt").to(device)
    out = model.generate(**inputs)
    caption = processor.decode(out[0], skip_special_tokens=True)
    return caption

def capture_loop():
    global capture_region, running
    while running:
        if is_youtube_open() and capture_region:
            left, top, width, height = capture_region
            bbox = (left, top, left + width, top + height)
            screenshot = ImageGrab.grab(bbox)
            try:
                caption = describe_image_blip(screenshot)
                desc_var.set(f"📝 {caption}")
            except Exception as e:
                desc_var.set(f"❌ Error: {str(e)}")
        else:
            desc_var.set("🕵️ Waiting for YouTube...")
        time.sleep(30)

def on_close():
    global running
    running = False
    root.destroy()

# --- GUI Setup ---
root = tk.Tk()
root.title("AI YouTube Reporter")
root.geometry("350x180")
root.attributes('-topmost', True)
root.protocol("WM_DELETE_WINDOW", on_close)

desc_var = tk.StringVar()
desc_var.set("🔍 Waiting for YouTube...")

label = tk.Label(root, textvariable=desc_var, wraplength=320, justify="left")
label.pack(padx=10, pady=15)

def start_reporting():
    global capture_region
    if not is_youtube_open():
        messagebox.showwarning("YouTube Not Found", "Open a YouTube video first.")
        return
    capture_region = select_video_area()
    threading.Thread(target=capture_loop, daemon=True).start()
    start_btn.config(state="disabled")

start_btn = tk.Button(root, text="Start Reporter", command=start_reporting)
start_btn.pack(pady=5)

root.mainloop()
