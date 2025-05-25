import tkinter as tk
from tkinter import ttk, messagebox
import re
import random
import string
import math
import threading

COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "12345",
    "111111", "1234567", "sunshine", "qwerty", "iloveyou",
    "princess", "admin", "welcome", "666666", "abc123",
    "football", "123123", "monkey", "654321", "!@#$%^&*",
    "charlie", "aa123456", "donald", "password1", "qwerty123"
}

def calculate_entropy(password):
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"[0-9]", password):
        pool += 10
    if re.search(r"[^A-Za-z0-9]", password):
        pool += 32
    if pool == 0:
        return 0.0
    entropy = len(password) * math.log2(pool)
    return entropy

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
        try:
            x, y, cx, cy = self.widget.bbox("insert")
        except Exception:
            x = y = cx = cy = 0
        x += self.widget.winfo_rootx() + 25
        y += self.widget.winfo_rooty() + 20
        self.tipwindow = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        label = tk.Label(
            tw, text=self.text, justify='left',
            background="#ffffe0", relief='solid', borderwidth=1,
            font=("tahoma", "8", "normal")
        )
        label.pack(ipadx=5, ipady=3)

    def hidetip(self, event=None):
        if self.tipwindow:
            self.tipwindow.destroy()
        self.tipwindow = None

class AnimatedButton(ttk.Button):
    def __init__(self, master=None, **kwargs):
        super().__init__(master, **kwargs)
        self.bind("<Enter>", self.on_hover)
        self.bind("<Leave>", self.on_leave)
        self.blinking = False

    def on_hover(self, event=None):
        if not self.blinking:
            self.blinking = True
            self._blink()

    def on_leave(self, event=None):
        self.blinking = False
        # Restore default style
        self.configure(style="TButton")

    def _blink(self):
        if not self.blinking:
            return
        current_style = self.cget("style")
        hover_style = "Blink.TButton"
        default_style = "TButton"
        new_style = hover_style if current_style == default_style else default_style
        self.configure(style=new_style)
        self.after(500, self._blink)

class PasswordStrengthChecker:
    def __init__(self, root):
        self.root = root
        self.root.title("Interactive Password Strength Checker")
        self.root.geometry("480x670")
        self.root.resizable(False, False)
        self.dark_mode = True

        self.style = ttk.Style()
        self.progress_colors = ["#e74c3c", "#e67e22", "#f1c40f", "#2ecc71", "#27ae60"]
        self.progress_current_color = 0
        self.animate_progress_bar = False

        self.setup_styles()
        self.create_widgets()

    def hex_to_rgb(self, hex_color):
        hex_color = hex_color.lstrip("#")
        return tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))

    def rgb_to_hex(self, rgb):
        return f"#{''.join(f'{v:02x}' for v in rgb)}"

    def interpolate_color(self, c1, c2, factor):
        return tuple(int(c1[i] + (c2[i] - c1[i]) * factor) for i in range(3))

    def animate_progress_color(self):
        if not self.animate_progress_bar:
            return
        factor = 0.0
        direction = 1  # 1 means getting brighter, -1 dimmer
        c1 = self.hex_to_rgb(self.progress_colors[self.progress_current_color])
        c2 = self.hex_to_rgb(self.progress_colors[(self.progress_current_color + 1) % len(self.progress_colors)])
        def step():
            nonlocal factor, direction
            factor += 0.05 * direction
            if factor >= 1.0:
                factor = 1.0
                direction = -1
            elif factor <= 0:
                factor = 0
                direction = 1
                # cycle color index
                self.progress_current_color = (self.progress_current_color + 1) % len(self.progress_colors)
            blended = self.interpolate_color(c1, c2, factor)
            hexcolor = self.rgb_to_hex(blended)
            style_name = "Animated.Horizontal.TProgressbar"
            self.style.configure(style_name, foreground=hexcolor, background=hexcolor)
            self.progress.config(style=style_name)
            if self.animate_progress_bar:
                self.root.after(50, step)
        step()

    def setup_styles(self):
        bg_color = "#2c3e50" if self.dark_mode else "#f0f0f0"
        fg_color = "#ecf0f1" if self.dark_mode else "#222"
        entry_bg = "#34495e" if self.dark_mode else "#fff"
        self.root.configure(bg=bg_color)

        self.style.theme_use('clam')
        self.style.configure("TLabel", background=bg_color, foreground=fg_color, font=("Segoe UI", 11))
        self.style.configure("TButton", font=("Segoe UI", 10))
        self.style.configure("TEntry", fieldbackground=entry_bg, foreground=fg_color)
        self.style.configure("Blink.TButton", background="#f39c12", foreground="#fff")
        self.style.configure("green.Horizontal.TProgressbar", foreground='#2ecc71', background='#2ecc71')
        self.style.configure("red.Horizontal.TProgressbar", foreground='#e74c3c', background='#e74c3c')
        self.style.configure("orange.Horizontal.TProgressbar", foreground='#e67e22', background='#e67e22')
        self.style.configure("yellow.Horizontal.TProgressbar", foreground='#f1c40f', background='#f1c40f')
        self.style.configure("blue.Horizontal.TProgressbar", foreground='#3498db', background='#3498db')

    def create_widgets(self):
        # Title with animated text colors
        self.title_label = ttk.Label(self.root, text="Interactive Password Strength Checker", font=("Segoe UI", 16, "bold"))
        self.title_label.pack(pady=(20, 15))
        self.animate_title_colors()

        # Password Entry Frame
        entry_frame = ttk.Frame(self.root)
        entry_frame.pack(pady=5)

        self.password_var = tk.StringVar()
        self.entry = ttk.Entry(entry_frame, textvariable=self.password_var, width=28, font=("Segoe UI", 14), show="*")
        self.entry.pack(side="left")
        self.entry.bind('<KeyRelease>', self.check_strength)

        self.show_password = False
        self.toggle_btn = ttk.Button(entry_frame, text="Show", width=6, command=self.toggle_password)
        self.toggle_btn.pack(side="left", padx=5)

        gen_btn = ttk.Button(self.root, text="Generate Strong Password", command=self.generate_password)
        gen_btn.pack(pady=10, ipadx=5)

        self.copy_btn = AnimatedButton(self.root, text="Copy to Clipboard", command=self.copy_to_clipboard)
        self.copy_btn.pack(pady=5, ipadx=5)

        reset_btn = ttk.Button(self.root, text="Reset", command=self.reset_fields)
        reset_btn.pack(pady=5, ipadx=5)

        mode_btn = ttk.Button(self.root, text="Toggle Dark/Light Mode", command=self.toggle_mode)
        mode_btn.pack(pady=5, ipadx=5)

        self.progress = ttk.Progressbar(self.root, length=350, mode='determinate')
        self.progress.pack(pady=15)

        self.strength_label = ttk.Label(self.root, text="", font=("Segoe UI", 14, "bold"))
        self.strength_label.pack()

        self.entropy_label = ttk.Label(self.root, text="", font=("Segoe UI", 10, "italic"))
        self.entropy_label.pack(pady=3)

        self.feedback_label = ttk.Label(self.root, wraplength=440, justify="left", font=("Segoe UI", 10))
        self.feedback_label.pack(pady=(5, 15))

        criteria_title = ttk.Label(self.root, text="Password Requirements:", font=("Segoe UI", 12, "underline"))
        criteria_title.pack(anchor="w", padx=20)

        self.criteria_frame = ttk.Frame(self.root)
        self.criteria_frame.pack(padx=20, anchor="w")

        self.criteria_vars = {
            "length": tk.StringVar(value="✗ At least 8 characters"),
            "uppercase": tk.StringVar(value="✗ Uppercase letters"),
            "lowercase": tk.StringVar(value="✗ Lowercase letters"),
            "digits": tk.StringVar(value="✗ Numbers"),
            "special": tk.StringVar(value="✗ Special characters"),
            "common": tk.StringVar(value="✓ Not a common password"),
        }

        self.criteria_labels = {}
        for key, var in self.criteria_vars.items():
            color = "#e74c3c" if var.get().startswith("✗") else "#2ecc71"
            lbl = ttk.Label(self.criteria_frame, textvariable=var, foreground=color)
            lbl.pack(anchor="w")
            self.criteria_labels[key] = lbl

        criteria_text = (
            "Your password should contain at least 8 characters, including uppercase and lowercase letters, digits, "
            "and special characters. Avoid common passwords to enhance security."
        )
        Tooltip(self.entry, criteria_text)

    def animate_title_colors(self):
        colors = ["#F44336", "#E91E63", "#9C27B0", "#2196F3", "#4CAF50", "#FFC107"]
        index = 0

        def step():
            nonlocal index
            self.title_label.configure(foreground=colors[index])
            index = (index + 1) % len(colors)
            self.root.after(600, step)
        step()

    def toggle_password(self):
        if self.show_password:
            self.entry.config(show="*")
            self.show_password = False
            self.toggle_btn.config(text="Show")
        else:
            self.entry.config(show="")
            self.show_password = True
            self.toggle_btn.config(text="Hide")
        self.entry.focus()

    def check_strength(self, event=None):
        password = self.password_var.get()
        score, feedback = self.evaluate_password(password)
        entropy = calculate_entropy(password)

        strength_text = {
            0: "Very Weak",
            1: "Weak",
            2: "Moderate",
            3: "Strong",
            4: "Very Strong"
        }

        color_map = {
            0: "#e74c3c",
            1: "#e67e22",
            2: "#f1c40f",
            3: "#2ecc71",
            4: "#27ae60"
        }

        color = color_map.get(score, "#95a5a6")
        self.strength_label.config(text=f"Strength: {strength_text.get(score, '')}", foreground=color)
        self.feedback_label.config(text=feedback, foreground=color)
        self.progress['value'] = (score / 4) * 100

        style_name = "Animated.Horizontal.TProgressbar"
        self.style.configure(style_name, foreground=color, background=color)
        self.progress.config(style=style_name)

        self.entropy_label.config(text=f"Entropy: {entropy:.2f} bits")

        self.update_criteria_checklist(password)

        # Animate progress bar color
        self.animate_progress_bar = True
        threading.Thread(target=self.animate_progress_color, daemon=True).start()

    def update_criteria_checklist(self, password):
        checks = {
            "length": len(password) >= 8,
            "uppercase": bool(re.search(r"[A-Z]", password)),
            "lowercase": bool(re.search(r"[a-z]", password)),
            "digits": bool(re.search(r"[0-9]", password)),
            "special": bool(re.search(r"[^A-Za-z0-9]", password)),
            "common": password.lower() not in COMMON_PASSWORDS if password else True,
        }
        for key, passed in checks.items():
            prefix = "✓" if passed else "✗"
            color = "#2ecc71" if passed else "#e74c3c"
            current_text = self.criteria_vars[key].get()
            clean_text = current_text[2:] if len(current_text) > 2 else current_text
            self.criteria_vars[key].set(f"{prefix} {clean_text}")
            self.criteria_labels[key].configure(foreground=color)

    def evaluate_password(self, password):
        feedback = []
        length = len(password)
        if length == 0:
            return 0, ""

        score = 0

        if length >= 8:
            score += 1
        else:
            feedback.append("Use at least 8 characters")

        if re.search(r"[A-Z]", password):
            score += 1
        else:
            feedback.append("Add uppercase letters")

        if re.search(r"[a-z]", password):
            score += 1
        else:
            feedback.append("Add lowercase letters")

        if re.search(r"[0-9]", password):
            score += 1
        else:
            feedback.append("Add numbers")

        if re.search(r"[^A-Za-z0-9]", password):
            score += 1
        else:
            feedback.append("Add special characters (e.g., !@#$%)")

        if password.lower() in COMMON_PASSWORDS:
            feedback.append("Avoid common passwords")

        if score > 4:
            score = 4

        if score == 4 and password.lower() not in COMMON_PASSWORDS:
            feedback_text = "Excellent! Your password is very strong and not common."
        else:
            feedback_text = "Suggestions: " + ", ".join(feedback)

        return score, feedback_text

    def generate_password(self):
        length = random.randint(12, 16)
        characters = string.ascii_letters + string.digits + string.punctuation
        while True:
            password = ''.join(random.choice(characters) for _ in range(length))
            if (re.search(r"[A-Z]", password) and re.search(r"[a-z]", password)
                and re.search(r"[0-9]", password) and re.search(r"[^A-Za-z0-9]", password)):
                break
        self.password_var.set(password)
        self.check_strength()
        self.entry.focus()

    def copy_to_clipboard(self):
        password = self.password_var.get()
        if not password:
            messagebox.showwarning("Warning", "There is no password to copy.")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(password)
        self.root.update()
        messagebox.showinfo("Copied", "Password copied to clipboard!")

    def reset_fields(self):
        self.password_var.set("")
        self.strength_label.config(text="", foreground="")
        self.feedback_label.config(text="", foreground="")
        self.entropy_label.config(text="", foreground="")
        self.progress['value'] = 0
        for key in self.criteria_vars:
            text = self.criteria_vars[key].get()
            clean_text = text[2:] if len(text) > 2 else text
            self.criteria_vars[key].set(f"✗ {clean_text}")
            self.criteria_labels[key].configure(foreground="#e74c3c")

    def toggle_mode(self):
        self.dark_mode = not self.dark_mode
        self.setup_styles()
        bg_color = "#2c3e50" if self.dark_mode else "#f0f0f0"
        fg_color = "#ecf0f1" if self.dark_mode else "#222"
        entry_bg = "#34495e" if self.dark_mode else "#fff"
        self.root.configure(bg=bg_color)
        for widget in self.root.winfo_children():
            try:
                widget.configure(background=bg_color)
            except:
                pass
            if isinstance(widget, ttk.Label):
                try:
                    widget.configure(foreground=fg_color)
                except:
                    pass
            if isinstance(widget, ttk.Frame):
                try:
                    widget.configure(background=bg_color)
                except:
                    pass
        self.entry.configure(background=entry_bg)

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordStrengthChecker(root)
    root.mainloop()
