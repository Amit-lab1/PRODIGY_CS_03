import tkinter as tk
from tkinter import ttk
import re

class Tooltip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tipwindow = None
        widget.bind("<Enter>", self.showtip)
        widget.bind("<Leave>", self.hidetip)

    def showtip(self, event=None):
        if self.tipwindow or not self.text:
            return
        x, y, cx, cy = self.widget.bbox("insert")
        x += self.widget.winfo_rootx() + 25
        y += self.widget.winfo_rooty() + 20
        self.tipwindow = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        label = tk.Label(tw, text=self.text, justify='left',
                         background="#ffffe0", relief='solid', borderwidth=1,
                         font=("tahoma", "8", "normal"))
        label.pack(ipadx=5, ipady=3)

    def hidetip(self, event=None):
        if self.tipwindow:
            self.tipwindow.destroy()
        self.tipwindow = None

class PasswordStrengthChecker:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Strength Checker")
        self.root.geometry("400x320")
        self.root.resizable(False, False)
        self.root.configure(bg="#2c3e50")
        self.create_widgets()

    def create_widgets(self):
        title = tk.Label(self.root, text="Check Your Password Strength", font=("Segoe UI", 16, "bold"), bg="#2c3e50", fg="#ecf0f1")
        title.pack(pady=(20, 10))

        # Password Entry Frame
        entry_frame = tk.Frame(self.root, bg="#2c3e50")
        entry_frame.pack(pady=5)

        self.password_var = tk.StringVar()
        self.entry = ttk.Entry(entry_frame, textvariable=self.password_var, font=("Segoe UI", 14), width=24, show="*")
        self.entry.pack(side="left")
        self.entry.bind('<KeyRelease>', self.check_strength)

        # Show/hide password toggle
        self.show_password = False
        toggle_btn = ttk.Button(entry_frame, text="Show", width=5, command=self.toggle_password)
        toggle_btn.pack(side="left", padx=5)

        # Progress bar style
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("green.Horizontal.TProgressbar", foreground='green', background='green')
        style.configure("red.Horizontal.TProgressbar", foreground='red', background='red')
        style.configure("orange.Horizontal.TProgressbar", foreground='orange', background='orange')
        style.configure("yellow.Horizontal.TProgressbar", foreground='yellow', background='yellow')
        style.configure("blue.Horizontal.TProgressbar", foreground='blue', background='blue')

        self.progress = ttk.Progressbar(self.root, length=300, mode='determinate')
        self.progress.pack(pady=10)

        self.strength_label = tk.Label(self.root, text="", font=("Segoe UI", 14), bg="#2c3e50", fg="#ecf0f1")
        self.strength_label.pack()

        self.feedback_label = tk.Label(self.root, text="", wraplength=380, justify="left",
                                       font=("Segoe UI", 10), bg="#2c3e50", fg="#f39c12")
        self.feedback_label.pack(pady=10)

        # Tooltip hints for criteria
        criteria_text = ("Password must have:\n"
                         "• At least 8 characters\n"
                         "• Uppercase letter(s)\n"
                         "• Lowercase letter(s)\n"
                         "• Number(s)\n"
                         "• Special character(s)")

        Tooltip(self.entry, criteria_text)

    def toggle_password(self):
        if self.show_password:
            self.entry.config(show="*")
            self.show_password = False
        else:
            self.entry.config(show="")
            self.show_password = True

    def check_strength(self, event=None):
        password = self.password_var.get()
        score, feedback = self.evaluate_password(password)

        strength_text = {
            0: "Very Weak",
            1: "Weak",
            2: "Moderate",
            3: "Strong",
            4: "Very Strong"
        }

        color_map = {
            0: "#e74c3c",      # red
            1: "#e67e22",      # orange
            2: "#f1c40f",      # yellow
            3: "#2ecc71",      # green
            4: "#27ae60"       # darker green
        }

        self.strength_label.config(text=f"Strength: {strength_text.get(score, '')}", fg=color_map.get(score, "#95a5a6"))
        self.feedback_label.config(text=feedback, fg=color_map.get(score, "#95a5a6"))
        self.progress['value'] = (score / 4) * 100

        # Change progressbar color dynamically
        style_name = f"{color_map.get(score, '#95a5a6')}.Horizontal.TProgressbar"
        s = ttk.Style()
        s.configure(style_name, foreground=color_map.get(score), background=color_map.get(score))
        self.progress.config(style=style_name)

    def evaluate_password(self, password):
        feedback = []

        length = len(password)
        if length == 0:
            return 0, ""

        score = 0

        # Length criterion
        if length >= 8:
            score += 1
        else:
            feedback.append("• Use at least 8 characters")

        # Uppercase
        if re.search(r"[A-Z]", password):
            score += 1
        else:
            feedback.append("• Add uppercase letters")

        # Lowercase
        if re.search(r"[a-z]", password):
            score += 1
        else:
            feedback.append("• Add lowercase letters")

        # Digits
        if re.search(r"[0-9]", password):
            score += 1
        else:
            feedback.append("• Add numbers")

        # Special characters
        if re.search(r"[^A-Za-z0-9]", password):
            score += 1
        else:
            feedback.append("• Add special characters (e.g., !@#$%)")

        # Cap score at 4 for consistency
        if score > 4:
            score = 4

        if score == 4:
            feedback_text = "Excellent! Your password is very strong."
        else:
            feedback_text = "Add: " + ", ".join(feedback)

        return score, feedback_text

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordStrengthChecker(root)
    root.mainloop()
