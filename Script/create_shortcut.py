import os
import tkinter as tk
from tkinter import messagebox
from ttkbootstrap import Style
from ttkbootstrap.widgets import Checkbutton, Button
import ctypes.wintypes
import math

WEB_APPS = {
    "ARI": "https://bca-ari.intra.bca.co.id:58066/lbu/#/login",
    "BC Portal": "https://mybcaportal/sites/mr/BusinessContinuityCrisis/Business%20Continuity/BC%20Portal/index.html",
    "BDS Web": "https://bdsweb8.intra.bca.co.id/login.jsp",
    "BDS Web GEN 2": "https://bdswebg2.intra.bca.co.id/#/auth/login",
    "Bank Trade": "https://btradeappl.intra.bca.co.id/ucgps/_banktrade.html",
    "CAMS": "https://cams:50024/LoginAction.do;jsessionid=60jSBsAsBc55SbGw561e5IhiIL2Hw_WxOdAXuACkjJI4h9w4xzs-!-1691658497",
    "CCMS": "https://ccms:55044/ccms/index.do",
    "CCOS": "https://ccos:50014/icos-cl/index.do",
    "CCOS BCA-PL": "https://ccos:50014/icos-cl/indexpl.do",
    "CRM Cabang": "https://bcacrmcabang.intra.bca.co.id:15312/Login/Index",
    "DEA": "https://dea.intra.bca.co.id/#/",
    "DIAN Dashboard": "https://mydashboard.intra.bca.co.id/extensions/homepage/homepage.html?qlikTicket=BZp4NfTVUcLuHoz.",
    "Dukcapil" : "https://192.168.94.251/",
    "EBI": "https://kpportebi.intra.bca.co.id/",
    "ET Client": "https://et.bca.co.id/BCAclient.html",
    "FIRE": "https://bcaremit.klikbca.com:8008/LoginAction.do;jsessionid=op3SB324AAj6FIajI6WAZ8En2mAkXoW611o6e6OBzskOWUiT0U7O!55461711",
    "Formulir": "https://mybcaportal/sites/FORMULIR/Pages/All-Formulir.aspx",
    "GPOL": "https://mybcaportal/sites/op/Pages/home.aspx",
    "GISTA": "https://gista.bca.co.id/auth/realms/gista/protocol/openid-connect/auth?client_id=gista-fe&redirect_uri=https%3A%2F%2Fgista.bca.co.id%2F&state=163d80a8-5f3b-480e-b755-c35a2cf8e714&response_mode=fragment&response_type=code&scope=openid&nonce=6bacf969-2442-4dbe-85cf-6b3960e0ff84",
    "HC Inspire": "https://hcinspire.bca.co.id/auth/realms/zrea_hcinspire/protocol/openid-connect/auth?client_id=zcli_portal&redirect_uri=https%3A%2F%2Fhcinspire.bca.co.id%2F%23%2F&state=33a8fa3e-0bfc-41a8-91a2-4ced3920ca65&response_mode=fragment&response_type=code&scope=openid&nonce=dce897c7-d70a-47c0-8b4c-a64506b10903",
    "ID Gov": "https://idgovernance/login.jsf?prompt=true",
    "JIRA": "https://jira.bca.co.id/",
    "JUPO": "https://jupo:51114/JupoCoreWeb/",
    "Kirana": "https://digitalab.bca.co.id/Kirana/",
    "Klik BCA" : "www.klikbca.com",
    "KPMSS ESS": "https://kpmssess.intra.bca.co.id/",
    "KM Center": "https://mybcaportal/sites/kmc/pages/homepage.aspx",
    "Magenta": "https://magenta.intra.bca.co.id:55204/magenta/login",
    "MC2": "https://mc2.bca.co.id/",
    "Monica": "https://monica.bca.co.id/momo/#/login?navigate=%2Fhome",
    "Monita": "https://monita.intra.bca.co.id/auth/login?client_id=monita-public&redirect_uri=https://monita.intra.bca.co.id/callback&response_type=code&scope=openid%20profile%20offline_access&nonce=c1fab988ede6fc677ac297ec986d33ec280d96U8E&state=7957f3e029ea58887aa6c4b065686818d2neaA0U3&code_challenge=eS8G1bv3xw43gH2QTO0gFPXd-Vi6M2_A7mFYFZvq3Qw&code_challenge_method=S256",
    "MyBCA Portal": "https://mybcaportal/",
    "My Development" : "https://mydevelopment.bca.co.id/",
    "My Experience" : "https://myxperience.bca.co.id/login/email",
    "My Growth" : "https://mygrowth.bca.co.id/login/email",
    "MyVideo": "https://myvideo.bca.co.id/",
    "My Solution" : "https://hcinspire.bca.co.id/auth/realms/zrea_hcinspire/protocol/openid-connect/auth?client_id=zcli_frontend&redirect_uri=https%3A%2F%2Fmysolution.bca.co.id%2F%23%2F&state=e0b65e12-cb74-407f-89a7-12ee80f9d27b&response_mode=fragment&response_type=code&scope=openid&nonce=064a4a74-7918-42ac-8667-1715fb3682bb",
    "Opticash": "https://opticash/opticash/#/",
    "Optinet Opticash": "https://opticash/optinet/#/",
    "Optinet Valas": "https://optivalas/optinet/",
    "Optivalas Cash": "https://optivalas/opticash/",
    "ORMIS": "https://newormis.intra.bca.co.id/login",
    "PAKAR": "https://pakar.intra.bca.co.id/auth/login?redirect=%2Fhomepage",
    "POL Branch2020": "https://mybcaportal/Pages/landingpageprojects.aspx",
    "RONA": "https://ronaadm.intra.bca.co.id/landing",
    "SEAL": "https://digitalab.bca.co.id/SEAL/",
    "SK Suku Bunga": "https://mybcaportal/sites/mybcasites/SK%20Suku%20Bunga/Forms/AllItems.aspx",
    "SK/SE": "https://mybcaportal/sites/skse/Pages/All-SKSE.aspx",
    "SPECTA": "https://specta.intra.bca.co.id/login",
    "Tracking EDC QRIS": "https://mybcaportal/sites/trackingedc/Pages/Homepage.aspx",
    "Tracking System": "https://mybcaportal/sites/tracking/Pages/Homepage.aspx"
}

def get_desktop_path():
    CSIDL_DESKTOP = 0
    SHGFP_TYPE_CURRENT = 0
    buf = ctypes.create_unicode_buffer(ctypes.wintypes.MAX_PATH)
    ctypes.windll.shell32.SHGetFolderPathW(None, CSIDL_DESKTOP, None, SHGFP_TYPE_CURRENT, buf)
    return buf.value

def create_edge_shortcut(name, url):
    desktop = get_desktop_path()
    shortcut_path = os.path.join(desktop, f"{name}.url")
    try:
        with open(shortcut_path, 'w', encoding='utf-8') as f:
            f.write("[InternetShortcut]\n")
            f.write(f"URL=microsoft-edge:{url}\n")
            f.write("IconFile=msedge.exe\n")
            f.write("IconIndex=0\n")
        return True
    except Exception as e:
        print(f"Error creating shortcut for {name}: {e}")
        return False

def create_selected_shortcuts():
    selected = [app for app, var in app_vars.items() if var.get()]
    if not selected:
        messagebox.showwarning("No Selection", "Please select at least one web app.")
        return
    failures = []
    for app in selected:
        if not create_edge_shortcut(app, WEB_APPS[app]):
            failures.append(app)
    if failures:
        messagebox.showerror("Error", f"Failed to create shortcut(s): {', '.join(failures)}")
    else:
        messagebox.showinfo("Success", f"Shortcut(s) created on Desktop:\n{', '.join(selected)}")

def center_window(win, width=640, height=560):
    win.update_idletasks()
    x = (win.winfo_screenwidth() // 2) - (width // 2)
    y = (win.winfo_screenheight() // 2) - (height // 2)
    win.geometry(f"{width}x{height}+{x}+{y}")

style = Style(theme="superhero")  # Cooler dark theme
style.configure("TCheckbutton", font=("Segoe UI", 11, "bold"))
style.configure("TLabel", font=("Segoe UI", 16, "bold"))
style.configure("TButton", font=("Segoe UI", 12, "bold"), padding=10)

root = style.master
root.title("BCA Web App Shortcut Creator v1.0.1")
center_window(root)

root.configure(bg=style.colors.bg)  # use theme background

title_label = tk.Label(root, text="Select Web Apps :", bg=style.colors.bg, foreground=style.colors.info, font=("Segoe UI", 18, "bold"))
title_label.pack(pady=(20, 15))

frame_container = tk.Frame(root, bg=style.colors.bg)
frame_container.pack(expand=True, fill="both", padx=20, pady=(0,10))

canvas = tk.Canvas(frame_container, bg=style.colors.bg, highlightthickness=0)
scrollbar = tk.Scrollbar(frame_container, orient="vertical", command=canvas.yview)
scrollable_frame = tk.Frame(canvas, bg=style.colors.bg)

scrollable_frame.bind(
    "<Configure>",
    lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
)

canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
canvas.configure(yscrollcommand=scrollbar.set)

canvas.pack(side="left", fill="both", expand=True)
scrollbar.pack(side="right", fill="y")

app_vars = {}
apps_sorted = sorted(WEB_APPS.keys())
total_apps = len(apps_sorted)
rows = math.ceil(total_apps / 3)

for index, app in enumerate(apps_sorted):
    var = tk.BooleanVar()
    chk = Checkbutton(scrollable_frame, text=app, variable=var, bootstyle="info")  # use "info" bootstyle only
    row = index % rows
    col = index // rows
    chk.grid(row=row, column=col, sticky="w", padx=20, pady=6)
    app_vars[app] = var

btn_create = Button(root, text="Create Shortcuts", bootstyle="success", command=create_selected_shortcuts)
btn_create.pack(pady=15, ipadx=12, ipady=7)

copyright_label = tk.Label(root, text="© Created by Nico Ardian SOW 7 - 2025", bg=style.colors.bg, fg=style.colors.secondary, font=("Segoe UI", 10, "italic"))
copyright_label.pack(side="bottom", pady=10)

root.mainloop()
