import tkinter as tk
from tkinter import ttk
from ttkbootstrap import Style
from ttkbootstrap.toast import ToastNotification
from datetime import datetime
import locale

locale.setlocale(locale.LC_ALL, 'id_ID.UTF-8')

class CashDepositApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Cash Deposit v1.0.0")
        self.style = Style("flatly")

        # Adjust window size based on content
        w, h = 1000, 700
        sw = root.winfo_screenwidth()
        sh = root.winfo_screenheight()
        x = (sw - w) // 2
        y = (sh - h) // 2
        root.geometry(f"{w}x{h}+{x}+{y}")

        # Toast Notification - Welcome
        self.toast = ToastNotification(title="Welcome", message="Selamat datang di Cash Deposit",
                                       duration=3000, bootstyle="info")
        self.toast.show_toast()

        self.build_ui()

    def build_ui(self):
        # Top frame with current date
        date_frame = ttk.Frame(self.root, padding=10)
        date_frame.pack(fill='x')
        self.date_label = ttk.Label(date_frame, text=datetime.now().strftime("%d-%m-%Y %H:%M:%S"), font=("Helvetica", 12))
        self.date_label.pack(anchor='center')

        # User Data input section
        user_frame = ttk.Labelframe(self.root, text="User Data", padding=10)
        user_frame.pack(fill='x', padx=10, pady=10)

        ttk.Label(user_frame, text="User ID:").grid(row=0, column=0, padx=5, pady=5, sticky='e')
        self.user_id_entry = ttk.Entry(user_frame)
        self.user_id_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(user_frame, text="Seal Number:").grid(row=0, column=2, padx=5, pady=5, sticky='e')
        self.seal_number_entry = ttk.Entry(user_frame)
        self.seal_number_entry.grid(row=0, column=3, padx=5, pady=5)

        # Denomination Input section
        denom_frame = ttk.Labelframe(self.root, text="Table Input Denom", padding=10)
        denom_frame.pack(fill='x', padx=10, pady=10)

        self.denom_fields = {}
        denom_labels = ["100", "75", "50", "20", "10", "5", "2", "1", "STAR"]
        for i, label in enumerate(denom_labels):
            ttk.Label(denom_frame, text=label).grid(row=0, column=i, padx=5, pady=5)
            entry = ttk.Entry(denom_frame, width=10)
            entry.grid(row=1, column=i, padx=5, pady=5)
            self.denom_fields[label] = entry

        # Submit button
        submit_button = ttk.Button(self.root, text="Submit", command=self.submit_data)
        submit_button.pack(pady=10)

        # Table section with scrollbar
        table_frame = ttk.Labelframe(self.root, text="Show Table Data", padding=10)
        table_frame.pack(fill='both', expand=True, padx=10, pady=10)

        columns = ("USER-SEAL", "100", "75", "50", "20", "10", "5", "2", "1", "STAR", "Total")
        self.tree = ttk.Treeview(table_frame, columns=columns, show='headings')

        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, anchor='center', width=100)

        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(table_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscroll=vsb.set, xscroll=hsb.set)
        self.tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')

        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)

        # Footer
        footer = ttk.Label(self.root, text="@ Nico Ardian Nugroho SOW 7 - 2025", font=("Helvetica", 9))
        footer.pack(side='bottom', pady=5)

    def submit_data(self):
        user_id = self.user_id_entry.get()
        seal_number = self.seal_number_entry.get()
        user_seal = f"{user_id}/{seal_number}"

        try:
            values = [int(self.denom_fields[key].get() or 0) for key in self.denom_fields]
        except ValueError:
            self.toast = ToastNotification(title="Input Error", message="Please enter valid numbers", bootstyle="danger")
            self.toast.show_toast()
            return

        nominal_values = []
        total = 0
        for k, v in zip(self.denom_fields.keys(), values):
            multiplier = int(k) if k.isdigit() else 1
            amount = v * multiplier
            nominal_values.append(locale.currency(amount, grouping=True))
            total += amount

        total_formatted = locale.currency(total, grouping=True)
        self.tree.insert("", "end", values=[user_seal] + nominal_values + [total_formatted])

        self.toast = ToastNotification(title="Success", message="Data successfully added", bootstyle="success")
        self.toast.show_toast()

if __name__ == '__main__':
    root = tk.Tk()
    app = CashDepositApp(root)
    root.mainloop()
