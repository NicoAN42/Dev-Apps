import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from ttkbootstrap import Style
from ttkbootstrap.toast import ToastNotification
from datetime import datetime
import locale
import openpyxl
from openpyxl.utils import get_column_letter
from openpyxl.styles import Font, Border, Side

locale.setlocale(locale.LC_ALL, 'id_ID.UTF-8')

class CashDepositApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Cash Deposit v1.0.0")
        self.style = Style("flatly")

        w, h = 1000, 700
        sw = root.winfo_screenwidth()
        sh = root.winfo_screenheight()
        x = (sw - w) // 2
        y = (sh - h) // 2
        root.geometry(f"{w}x{h}+{x}+{y}")

        self.toast = ToastNotification(title="Welcome", message="Selamat datang di Cash Deposit",
                                       duration=3000, bootstyle="info")
        self.toast.show_toast()

        self.deleted_row = None
        self.build_ui()
        self.update_clock()

    def build_ui(self):
        date_frame = ttk.Frame(self.root, padding=10)
        date_frame.pack(fill='x')
        self.date_label = ttk.Label(date_frame, font=("Helvetica", 12, "bold"))
        self.date_label.pack(anchor='center')

        user_frame = ttk.Labelframe(self.root, text="User Data", padding=10)
        user_frame.configure(labelwidget=ttk.Label(user_frame, text="User Data", font=("Helvetica", 10, "bold")))
        user_frame.pack(fill='x', padx=10, pady=10)

        ttk.Label(user_frame, text="User ID:").grid(row=0, column=0, padx=5, pady=5, sticky='e')
        self.user_id_entry = ttk.Entry(user_frame)
        self.user_id_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(user_frame, text="Seal Number:").grid(row=0, column=2, padx=5, pady=5, sticky='e')
        self.seal_number_entry = ttk.Entry(user_frame)
        self.seal_number_entry.grid(row=0, column=3, padx=5, pady=5)

        denom_frame = ttk.Labelframe(self.root, text="Table Input Denom", padding=10)
        denom_frame.configure(labelwidget=ttk.Label(denom_frame, text="Table Input Denom", font=("Helvetica", 10, "bold")))
        denom_frame.pack(fill='x', padx=10, pady=10)

        self.denom_fields = {}
        self.denom_labels = ["100", "75", "50", "20", "10", "5", "2", "1", "STAR"]
        for i, label in enumerate(self.denom_labels):
            ttk.Label(denom_frame, text=label).grid(row=0, column=i, padx=5, pady=5)
            entry = ttk.Entry(denom_frame, width=10, justify='right')
            entry.grid(row=1, column=i, padx=5, pady=5)
            entry.bind('<KeyRelease>', self.format_currency_input)
            self.denom_fields[label] = entry

        action_frame = ttk.Frame(self.root)
        action_frame.pack(pady=10)

        ttk.Button(action_frame, text="Submit", command=self.submit_data).pack(side='left', padx=10)

        table_frame = ttk.Labelframe(self.root, text="Show Table Data", padding=10)
        table_frame.configure(labelwidget=ttk.Label(table_frame, text="Show Table Data", font=("Helvetica", 10, "bold")))
        table_frame.pack(fill='both', expand=True, padx=10, pady=10)

        self.columns = ["USER-SEAL"] + self.denom_labels + ["Total"]
        self.tree = ttk.Treeview(table_frame, columns=self.columns, show='headings', selectmode="browse")

        for col in self.columns:
            self.tree.heading(col, text=col, command=lambda c=col: self.sort_column(c, False))
            self.tree.column(col, anchor='center', width=100)

        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(table_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscroll=vsb.set, xscroll=hsb.set)
        self.tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')

        button_frame = ttk.Frame(table_frame)
        button_frame.grid(row=2, column=0, pady=10, sticky='e')

        ttk.Button(button_frame, text="Delete Selected", command=self.delete_selected_row).pack(side='left', padx=5)
        ttk.Button(button_frame, text="Clear All", command=self.clear_all).pack(side='left', padx=5)
        ttk.Button(button_frame, text="Undo Delete", command=self.undo_delete).pack(side='left', padx=5)
        ttk.Button(button_frame, text="Export to Excel", command=self.export_to_excel).pack(side='left', padx=5)

        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)

        footer = ttk.Label(self.root, text="@ Nico Ardian Nugroho SOW 7 - 2025", font=("Helvetica", 9))
        footer.pack(side='bottom', pady=5)

    def update_clock(self):
        days = ["Senin", "Selasa", "Rabu", "Kamis", "Jumat", "Sabtu", "Minggu"]
        now = datetime.now()
        day_name = days[now.weekday()]
        date_string = now.strftime("%d %B %Y")
        time_string = now.strftime("%H.%M.%S WIB")
        formatted = f"{day_name}, {date_string} || {time_string}"
        self.date_label.config(text=formatted)
        self.root.after(1000, self.update_clock)

    def format_currency_input(self, event):
        widget = event.widget
        text = widget.get().replace('.', '').replace('Rp', '').replace(',', '').strip()
        if text.isdigit():
            formatted = locale.format_string("%d", int(text), grouping=True)
            widget.delete(0, tk.END)
            widget.insert(0, formatted)

    def parse_currency_input(self, text):
        return int(text.replace('.', '').replace('Rp', '').replace(',', '').strip() or 0)

    def submit_data(self):
        user_id = self.user_id_entry.get()
        seal_number = self.seal_number_entry.get()
        user_seal = f"{user_id}/{seal_number}"

        try:
            values = [self.parse_currency_input(self.denom_fields[key].get()) for key in self.denom_fields]
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

    def sort_column(self, col, reverse):
        l = [(self.tree.set(k, col), k) for k in self.tree.get_children('')]
        try:
            l.sort(key=lambda t: int(t[0].replace('Rp', '').replace('.', '').replace(',', '')), reverse=reverse)
        except:
            l.sort(reverse=reverse)
        for index, (val, k) in enumerate(l):
            self.tree.move(k, '', index)
        self.tree.heading(col, command=lambda: self.sort_column(col, not reverse))

    def delete_selected_row(self):
        selected = self.tree.selection()
        if selected:
            if messagebox.askyesno("Confirm", "Are you sure you want to delete the selected row?"):
                self.deleted_row = (selected[0], self.tree.item(selected[0])['values'])
                self.tree.delete(selected)
                self.toast = ToastNotification(title="Deleted", message="Row has been deleted.", bootstyle="warning")
                self.toast.show_toast()

    def undo_delete(self):
        if self.deleted_row:
            iid, values = self.deleted_row
            self.tree.insert("", "end", iid=iid, values=values)
            self.toast = ToastNotification(title="Undo", message="Last deletion has been undone.", bootstyle="info")
            self.toast.show_toast()
            self.deleted_row = None

    def clear_all(self):
        if not messagebox.askyesno("Confirm", "Are you sure you want to clear all inputs and table data?"):
            return

        self.user_id_entry.delete(0, tk.END)
        self.seal_number_entry.delete(0, tk.END)
        for entry in self.denom_fields.values():
            entry.delete(0, tk.END)
        for row in self.tree.get_children():
            self.tree.delete(row)
        self.toast = ToastNotification(title="Cleared", message="All data has been cleared.", bootstyle="danger")
        self.toast.show_toast()

    def export_to_excel(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".xlsx", filetypes=[("Excel files", "*.xlsx")])
        if not file_path:
            return

        wb = openpyxl.Workbook()
        ws = wb.active
        ws.title = "Cash Deposit"

        days = ["Senin", "Selasa", "Rabu", "Kamis", "Jumat", "Sabtu", "Minggu"]
        now = datetime.now()
        day_name = days[now.weekday()]
        date_string = now.strftime("%d %B %Y")
        time_string = now.strftime("%H.%M.%S WIB")
        timestamp = f"{day_name}, {date_string} || {time_string}"

        ws.append(["Exported At:", timestamp])
        ws.append([])
        ws.append(self.columns)

        bold_font = Font(bold=True)
        thin_border = Border(
            left=Side(style='thin'),
            right=Side(style='thin'),
            top=Side(style='thin'),
            bottom=Side(style='thin')
        )

        for col_idx, col_name in enumerate(self.columns, 1):
            cell = ws.cell(row=3, column=col_idx)
            cell.font = bold_font
            cell.border = thin_border

        for row_idx, row in enumerate(self.tree.get_children(), start=4):
            values = self.tree.item(row)['values']
            for col_idx, value in enumerate(values, 1):
                cell = ws.cell(row=row_idx, column=col_idx, value=value)
                cell.border = thin_border

        for col in ws.columns:
            max_length = 0
            col_letter = get_column_letter(col[0].column)
            for cell in col:
                try:
                    if cell.value:
                        max_length = max(max_length, len(str(cell.value)))
                except:
                    pass
            ws.column_dimensions[col_letter].width = max_length + 2

        try:
            wb.save(file_path)
            messagebox.showinfo("Success", f"Data exported to {file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export: {e}")

if __name__ == '__main__':
    root = tk.Tk()
    app = CashDepositApp(root)
    root.mainloop()
