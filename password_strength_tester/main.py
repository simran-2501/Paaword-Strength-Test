# main.py
import tkinter as tk
from tkinter import ttk, messagebox
import threading
import password_utils as pu
import pwned_check as pc


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Password Strength Tester")
        self.geometry("560x420")
        self.resizable(False, False)
        self.build_ui()

    def build_ui(self):
        frame = ttk.Frame(self, padding=12)
        frame.pack(fill="both", expand=True)

        ttk.Label(frame, text="Enter password:").grid(row=0, column=0, sticky="w")
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(frame, textvariable=self.password_var, show='*', width=44)
        self.password_entry.grid(row=1, column=0, columnspan=2, sticky="w")
        self.password_entry.bind('<KeyRelease>', lambda e: self.evaluate())

        self.show_var = tk.BooleanVar()
        ttk.Checkbutton(frame, text="Show password", variable=self.show_var, command=self.toggle_show).grid(
            row=2, column=0, sticky='w', pady=(10, 0)
        )

        ttk.Label(frame, text="Strength:").grid(row=3, column=0, sticky='w', pady=(10, 0))
        self.score_var = tk.IntVar()
        self.score_bar = ttk.Progressbar(frame, maximum=100, length=420, variable=self.score_var)
        self.score_bar.grid(row=4, column=0, columnspan=2, sticky='w')

        self.rating_label = ttk.Label(frame, text="Rating: -")
        self.rating_label.grid(row=5, column=0, sticky='w', pady=(6, 0))

        self.details_box = tk.Text(frame, width=66, height=8, wrap='word')
        self.details_box.grid(row=6, column=0, columnspan=2, pady=(8, 0))
        self.details_box.config(state='disabled')

        self.pwned_button = ttk.Button(frame, text="Check breach (Have I Been Pwned)", command=self.start_pwned_check)
        self.pwned_button.grid(row=7, column=0, sticky='w', pady=(10, 0))

        self.pwned_label = ttk.Label(frame, text="")
        self.pwned_label.grid(row=8, column=0, sticky='w')

        # initial evaluation (empty password)
        self.evaluate()

    def toggle_show(self):
        self.password_entry.config(show='' if self.show_var.get() else '*')

    def evaluate(self):
        pw = self.password_var.get()
        result = pu.score_password(pw)

        self.score_var.set(result['score_percent'])
        self.rating_label.config(
            text=f"Rating: {result['rating']} ({result['score_percent']}%) — Entropy: {result['entropy_bits']} bits"
        )

        brute_time = pu.friendly_time(pu.brute_force_time_seconds(pw))

        text_lines = [
            f"Length: {result['length']}",
            f"Char variety: {result['variety_count']} / 4",
            f"Entropy: {result['entropy_bits']} bits",
            f"Estimated brute-force time: {brute_time}",
        ]

        if result['suggestions']:
            text_lines.append("\nSuggestions:")
            for s in result['suggestions']:
                text_lines.append(f"- {s}")

        self.details_box.config(state='normal')
        self.details_box.delete('1.0', tk.END)
        self.details_box.insert(tk.END, "\n".join(text_lines))
        self.details_box.config(state='disabled')

        # clear previous pwned label when password changes
        self.pwned_label.config(text="")

    def start_pwned_check(self):
        thread = threading.Thread(target=self.check_pwned)
        thread.daemon = True
        thread.start()

    def check_pwned(self):
        pw = self.password_var.get()
        if not pw:
            messagebox.showinfo("Error", "Enter a password first.")
            return

        # disable button while checking
        self.pwned_button.config(state='disabled')
        self.pwned_label.config(text="Checking...")

        count = pc.pwned_count(pw)

        if count > 0:
            self.pwned_label.config(text=f"Found in breaches {count} times — DO NOT USE")
        else:
            self.pwned_label.config(text="Not found in known breaches.")

        self.pwned_button.config(state='normal')


if __name__ == '__main__':
    app = App()
    app.mainloop()
