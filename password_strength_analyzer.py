import tkinter as tk
from tkinter import ttk, messagebox
import hashlib
import random
import sqlite3
import os
from datetime import datetime

# ---- COLORS ----
BG          = "#0d1117"
CARD        = "#161b22"
CARD2       = "#1c2128"
BORDER      = "#30363d"
TEXT        = "#e6edf3"
MUTED       = "#8b949e"
GREEN       = "#3fb950"
YELLOW      = "#d29922"
RED         = "#f85149"
ORANGE      = "#db6d28"
BLUE        = "#58a6ff"
PURPLE      = "#bc8cff"
WHITE       = "#ffffff"

# DATABASE SETUP (SQLite)
DB_FILE = "passwords.db"

def setup_database():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS password_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hash TEXT NOT NULL,
            strength TEXT NOT NULL,
            score INTEGER NOT NULL,
            saved_at TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

def save_to_db(password, strength, score):
    hashed = hashlib.sha256(password.encode()).hexdigest()
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    # Check reuse
    cursor.execute("SELECT id FROM password_history WHERE hash = ?", (hashed,))
    existing = cursor.fetchone()
    if existing:
        conn.close()
        return False, "reused"

    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    cursor.execute(
        "INSERT INTO password_history (hash, strength, score, saved_at) VALUES (?, ?, ?, ?)",
        (hashed, strength, score, now)
    )
    conn.commit()
    conn.close()
    return True, "saved"

def load_from_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT id, hash, strength, score, saved_at FROM password_history ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()
    return rows

def clear_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM password_history")
    conn.commit()
    conn.close()

def delete_one_db(row_id):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM password_history WHERE id = ?", (row_id,))
    conn.commit()
    conn.close()

# PASSWORD LOGIC

def check_length(p):    return len(p) >= 8
def check_upper(p):     return any(c.isupper() for c in p)
def check_lower(p):     return any(c.islower() for c in p)
def check_number(p):    return any(c.isdigit() for c in p)
def check_symbol(p):
    syms = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    return any(c in syms for c in p)
def check_common(p):
    bad = ["password","123456","qwerty","abc123","111111","password123","admin","letmein"]
    return p.lower() not in bad

def get_score(password):
    score = 0
    if check_length(password):  score += 1
    if len(password) >= 12:     score += 1
    if check_upper(password):   score += 1
    if check_lower(password):   score += 1
    if check_number(password):  score += 1
    if check_symbol(password):  score += 1
    if check_common(password):  score += 1
    # bonus
    if len(password) >= 16:     score += 1
    return score  # max 8

def get_strength_label(score):
    if score <= 2:   return "WEAK",   RED,    25
    elif score <= 4: return "FAIR",   ORANGE, 50
    elif score <= 6: return "GOOD",   YELLOW, 75
    else:            return "STRONG", GREEN,  100

def generate_password(length=16):
    lower   = "abcdefghijkmnpqrstuvwxyz"
    upper   = "ABCDEFGHJKLMNPQRSTUVWXYZ"
    numbers = "23456789"
    symbols = "!@#$%^&*-_=+"
    all_c   = lower + upper + numbers + symbols
    pw = [random.choice(lower), random.choice(upper),
          random.choice(numbers), random.choice(symbols)]
    pw += [random.choice(all_c) for _ in range(length - 4)]
    random.shuffle(pw)
    return "".join(pw)

# CUSTOM WIDGETS


class RoundedFrame(tk.Canvas):
    def __init__(self, parent, width, height, radius=12, bg=CARD, **kwargs):
        super().__init__(parent, width=width, height=height,
                         bg=parent["bg"], highlightthickness=0, **kwargs)
        self.radius = radius
        self.card_bg = bg
        self._draw(width, height)

    def _draw(self, w, h):
        r = self.radius
        self.create_polygon(
            r, 0, w-r, 0, w, r, w, h-r, w-r, h, r, h, 0, h-r, 0, r,
            smooth=True, fill=self.card_bg, outline=BORDER, width=1
        )

# MAIN APP


class PasswordApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Password Strength Analyzer")
        self.root.geometry("680x820")
        self.root.resizable(False, False)
        self.root.config(bg=BG)
        self.show_pw = False
        self.current_score = 0
        self.current_strength = "WEAK"

        setup_database()
        self.build_ui()
        self.refresh_history()

    # ------------------------------------------
    def build_ui(self):
        # ---- HEADER ----
        header = tk.Frame(self.root, bg="#0d1117", pady=0)
        header.pack(fill="x")

        # gradient-like header bar
        hbar = tk.Frame(header, bg="#1f6feb", height=4)
        hbar.pack(fill="x")

        tk.Label(header, text="🔐  Password Strength Analyzer",
                 font=("Segoe UI", 20, "bold"), bg=BG, fg=WHITE,
                 pady=18).pack()
        tk.Label(header, text="Secure your accounts with stronger passwords",
                 font=("Segoe UI", 10), bg=BG, fg=MUTED).pack(pady=(0, 16))

        # ---- NOTEBOOK (Tabs) ----
        style = ttk.Style()
        style.theme_use("default")
        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure("TNotebook.Tab", background=CARD2, foreground=MUTED,
                        font=("Segoe UI", 10, "bold"), padding=[18, 8],
                        borderwidth=0)
        style.map("TNotebook.Tab",
                  background=[("selected", CARD)],
                  foreground=[("selected", WHITE)])

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=20, pady=(0, 16))

        # Tab 1: Analyzer
        self.tab_analyze = tk.Frame(self.notebook, bg=BG)
        self.notebook.add(self.tab_analyze, text="  🔍 Analyzer  ")

        # Tab 2: Generator
        self.tab_gen = tk.Frame(self.notebook, bg=BG)
        self.notebook.add(self.tab_gen, text="  ⚡ Generator  ")

        # Tab 3: History (DB)
        self.tab_history = tk.Frame(self.notebook, bg=BG)
        self.notebook.add(self.tab_history, text="  🗂 History  ")

        self.build_analyzer_tab()
        self.build_generator_tab()
        self.build_history_tab()

    # ------------------------------------------
    def build_analyzer_tab(self):
        tab = self.tab_analyze
        pad = {"padx": 16, "pady": 8}

        # ---- Input card ----
        c1 = tk.Frame(tab, bg=CARD, bd=0, relief="flat")
        c1.pack(fill="x", padx=16, pady=(14, 6))

        tk.Label(c1, text="Enter Your Password", font=("Segoe UI", 11, "bold"),
                 bg=CARD, fg=TEXT).pack(anchor="w", padx=16, pady=(14, 6))

        row_entry = tk.Frame(c1, bg=CARD)
        row_entry.pack(fill="x", padx=16, pady=(0, 14))

        self.entry_var = tk.StringVar()
        self.entry_var.trace_add("write", self.on_type)

        self.entry = tk.Entry(row_entry, textvariable=self.entry_var,
                              show="●", font=("Consolas", 14),
                              bg=CARD2, fg=TEXT, insertbackground=BLUE,
                              bd=0, relief="flat", width=28)
        self.entry.pack(side="left", ipady=10, ipadx=10, fill="x", expand=True)

        self.btn_eye = tk.Button(row_entry, text="👁", font=("Segoe UI", 13),
                                 bg=CARD2, fg=MUTED, bd=0, relief="flat",
                                 cursor="hand2", command=self.toggle_show,
                                 activebackground=CARD2, activeforeground=WHITE)
        self.btn_eye.pack(side="left", ipadx=8, ipady=8)

        # border under entry
        tk.Frame(c1, bg=BORDER, height=1).pack(fill="x", padx=16, pady=(0, 4))

        # ---- Strength bar card ----
        c2 = tk.Frame(tab, bg=CARD)
        c2.pack(fill="x", padx=16, pady=6)

        row_str = tk.Frame(c2, bg=CARD)
        row_str.pack(fill="x", padx=16, pady=(14, 6))

        tk.Label(row_str, text="Strength", font=("Segoe UI", 10),
                 bg=CARD, fg=MUTED).pack(side="left")

        self.lbl_strength = tk.Label(row_str, text="---",
                                     font=("Segoe UI", 11, "bold"),
                                     bg=CARD, fg=MUTED)
        self.lbl_strength.pack(side="right")

        # bar background
        bar_bg = tk.Frame(c2, bg=BORDER, height=10)
        bar_bg.pack(fill="x", padx=16, pady=(0, 4))
        bar_bg.pack_propagate(False)

        self.bar_fill = tk.Frame(bar_bg, bg=RED, height=10, width=0)
        self.bar_fill.pack(side="left")

        # score + crack time row
        row_info = tk.Frame(c2, bg=CARD)
        row_info.pack(fill="x", padx=16, pady=(4, 14))

        self.lbl_score = tk.Label(row_info, text="Score: 0/8",
                                  font=("Consolas", 10), bg=CARD, fg=MUTED)
        self.lbl_score.pack(side="left")

        self.lbl_crack = tk.Label(row_info, text="Crack time: —",
                                  font=("Consolas", 10), bg=CARD, fg=MUTED)
        self.lbl_crack.pack(side="right")

        # ---- Checklist card ----
        c3 = tk.Frame(tab, bg=CARD)
        c3.pack(fill="x", padx=16, pady=6)

        tk.Label(c3, text="Requirements", font=("Segoe UI", 10, "bold"),
                 bg=CARD, fg=MUTED).pack(anchor="w", padx=16, pady=(12, 6))

        self.check_labels = {}
        checks = [
            ("len",    "At least 8 characters"),
            ("upper",  "Uppercase letter (A-Z)"),
            ("lower",  "Lowercase letter (a-z)"),
            ("number", "Number (0-9)"),
            ("symbol", "Special symbol (!@#...)"),
            ("common", "Not a common password"),
        ]
        grid = tk.Frame(c3, bg=CARD)
        grid.pack(fill="x", padx=16, pady=(0, 12))

        for i, (key, text) in enumerate(checks):
            col = i % 2
            row_n = i // 2
            lbl = tk.Label(grid, text="○  " + text,
                           font=("Segoe UI", 9), bg=CARD, fg=MUTED,
                           anchor="w", width=28)
            lbl.grid(row=row_n, column=col, sticky="w", pady=3)
            self.check_labels[key] = lbl

        # ---- Suggestions card ----
        c4 = tk.Frame(tab, bg=CARD)
        c4.pack(fill="x", padx=16, pady=6)

        tk.Label(c4, text="💡 Suggestions", font=("Segoe UI", 10, "bold"),
                 bg=CARD, fg=MUTED).pack(anchor="w", padx=16, pady=(12, 4))

        self.txt_suggest = tk.Text(c4, height=4, font=("Segoe UI", 9),
                                   bg=CARD2, fg=TEXT, bd=0, wrap="word",
                                   insertbackground=BLUE, state="disabled",
                                   relief="flat", padx=10, pady=8)
        self.txt_suggest.pack(fill="x", padx=16, pady=(0, 14))

        # ---- Save button ----
        self.btn_save = tk.Button(tab, text="💾   Save Password to Database",
                                  font=("Segoe UI", 11, "bold"),
                                  bg="#1f6feb", fg=WHITE, bd=0, relief="flat",
                                  cursor="hand2", pady=12,
                                  command=self.save_password,
                                  activebackground="#388bfd", activeforeground=WHITE)
        self.btn_save.pack(fill="x", padx=16, pady=8)

   
    def build_generator_tab(self):
        tab = self.tab_gen

        tk.Label(tab, text="Generate Secure Passwords",
                 font=("Segoe UI", 13, "bold"), bg=BG, fg=TEXT,
                 pady=10).pack()
        tk.Label(tab, text="All passwords include uppercase, lowercase,\nnumbers and symbols",
                 font=("Segoe UI", 9), bg=BG, fg=MUTED).pack()

        # Length slider
        c = tk.Frame(tab, bg=CARD)
        c.pack(fill="x", padx=16, pady=12)

        row = tk.Frame(c, bg=CARD)
        row.pack(fill="x", padx=16, pady=(14, 4))

        tk.Label(row, text="Password Length:", font=("Segoe UI", 10),
                 bg=CARD, fg=TEXT).pack(side="left")

        self.lbl_len_val = tk.Label(row, text="16",
                                    font=("Consolas", 11, "bold"),
                                    bg=CARD, fg=BLUE)
        self.lbl_len_val.pack(side="right")

        self.slider_len = tk.Scale(c, from_=8, to=32, orient="horizontal",
                                   bg=CARD, fg=TEXT, troughcolor=CARD2,
                                   highlightthickness=0, bd=0,
                                   activebackground=BLUE,
                                   command=self.update_len_label)
        self.slider_len.set(16)
        self.slider_len.pack(fill="x", padx=16, pady=(0, 14))

        # Generate button
        tk.Button(tab, text="⚡   Generate Passwords",
                  font=("Segoe UI", 11, "bold"),
                  bg=PURPLE, fg=WHITE, bd=0, relief="flat",
                  cursor="hand2", pady=12,
                  command=self.do_generate,
                  activebackground="#d2a8ff", activeforeground=BG).pack(
                      fill="x", padx=16, pady=(0, 12))

        # Generated list
        self.gen_frame = tk.Frame(tab, bg=BG)
        self.gen_frame.pack(fill="x", padx=16, pady=4)

        self.do_generate()  # show on load

    def update_len_label(self, val):
        self.lbl_len_val.config(text=str(val))

    def do_generate(self):
        for w in self.gen_frame.winfo_children():
            w.destroy()

        length = self.slider_len.get()

        for i in range(5):
            pw = generate_password(length)
            row = tk.Frame(self.gen_frame, bg=CARD)
            row.pack(fill="x", pady=4)

            tk.Label(row, text=str(i+1) + ".", font=("Segoe UI", 10),
                     bg=CARD, fg=MUTED, width=3).pack(side="left", padx=(12, 0), pady=10)

            lbl = tk.Label(row, text=pw, font=("Consolas", 11),
                           bg=CARD, fg=GREEN, anchor="w")
            lbl.pack(side="left", fill="x", expand=True, pady=10)

            tk.Button(row, text="Copy", font=("Segoe UI", 9),
                      bg=CARD2, fg=BLUE, bd=0, relief="flat",
                      cursor="hand2", padx=10, pady=6,
                      command=lambda p=pw: self.copy_to_clipboard(p),
                      activebackground=BORDER, activeforeground=WHITE).pack(
                          side="right", padx=12, pady=6)

    def copy_to_clipboard(self, text):
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        messagebox.showinfo("Copied!", "Password copied to clipboard!")

    def build_history_tab(self):
        tab = self.tab_history

        # Header row
        hrow = tk.Frame(tab, bg=BG)
        hrow.pack(fill="x", padx=16, pady=(14, 6))

        tk.Label(hrow, text="🗂  Saved Passwords (Database)",
                 font=("Segoe UI", 12, "bold"), bg=BG, fg=TEXT).pack(side="left")

        tk.Button(hrow, text="🗑  Clear All", font=("Segoe UI", 9),
                  bg=RED, fg=WHITE, bd=0, relief="flat", cursor="hand2",
                  padx=10, pady=4, command=self.clear_history,
                  activebackground="#ff6b6b").pack(side="right")

        # Table header
        hdr = tk.Frame(tab, bg=CARD2)
        hdr.pack(fill="x", padx=16)
        for text, w in [("#", 4), ("Hash (SHA-256)", 22), ("Strength", 10), ("Score", 6), ("Saved At", 14)]:
            tk.Label(hdr, text=text, font=("Segoe UI", 9, "bold"),
                     bg=CARD2, fg=MUTED, width=w, anchor="w").pack(side="left", padx=4, pady=6)

        # Scrollable list
        self.hist_canvas = tk.Canvas(tab, bg=BG, highlightthickness=0)
        scrollbar = tk.Scrollbar(tab, orient="vertical", command=self.hist_canvas.yview)
        self.hist_canvas.configure(yscrollcommand=scrollbar.set)

        scrollbar.pack(side="right", fill="y", padx=(0, 16))
        self.hist_canvas.pack(fill="both", expand=True, padx=16)

        self.hist_inner = tk.Frame(self.hist_canvas, bg=BG)
        self.hist_canvas.create_window((0, 0), window=self.hist_inner, anchor="nw")
        self.hist_inner.bind("<Configure>", lambda e: self.hist_canvas.configure(
            scrollregion=self.hist_canvas.bbox("all")))

        self.lbl_db_file = tk.Label(tab,
                                    text="📁 Database: " + os.path.abspath(DB_FILE),
                                    font=("Segoe UI", 8), bg=BG, fg=MUTED)
        self.lbl_db_file.pack(pady=(4, 8))

    def refresh_history(self):
        for w in self.hist_inner.winfo_children():
            w.destroy()

        rows = load_from_db()
        if not rows:
            tk.Label(self.hist_inner, text="No passwords saved yet.",
                     font=("Segoe UI", 10), bg=BG, fg=MUTED,
                     pady=20).pack()
            return

        colors_by_strength = {"WEAK": RED, "FAIR": ORANGE, "GOOD": YELLOW, "STRONG": GREEN}

        for row in rows:
            rid, h, strength, score, saved_at = row
            short_hash = h[:18] + "..."

            r = tk.Frame(self.hist_inner, bg=CARD)
            r.pack(fill="x", pady=2)

            color = colors_by_strength.get(strength, MUTED)

            for text, w in [(str(rid), 4), (short_hash, 22), (strength, 10), (str(score)+"/8", 6), (saved_at, 14)]:
                fg = color if text == strength else TEXT
                tk.Label(r, text=text, font=("Consolas", 9),
                         bg=CARD, fg=fg, width=w, anchor="w").pack(side="left", padx=4, pady=8)

            tk.Button(r, text="✕", font=("Segoe UI", 9),
                      bg=CARD, fg=RED, bd=0, relief="flat", cursor="hand2",
                      command=lambda i=rid: self.delete_row(i),
                      activebackground=CARD2).pack(side="right", padx=8)

    def clear_history(self):
        if messagebox.askyesno("Confirm", "Delete ALL saved passwords from database?"):
            clear_db()
            self.refresh_history()

    def delete_row(self, row_id):
        delete_one_db(row_id)
        self.refresh_history()

  
    # ANALYZER LOGIC
    # ------------------------------------------

    def on_type(self, *args):
        pw = self.entry_var.get()
        if not pw:
            self.reset_ui()
            return
        self.run_analysis(pw)

    def run_analysis(self, pw):
        score = get_score(pw)
        label, color, pct = get_strength_label(score)
        self.current_score = score
        self.current_strength = label

        # Bar width (max 636px area, scale to ~80% of card width)
        bar_w = int(636 * pct / 100)
        self.bar_fill.config(bg=color, width=bar_w)

        self.lbl_strength.config(text=label, fg=color)
        self.lbl_score.config(text=f"Score: {score}/8")

        # Crack time estimate
        import math
        pool = 0
        if any(c.islower() for c in pw): pool += 26
        if any(c.isupper() for c in pw): pool += 26
        if any(c.isdigit() for c in pw): pool += 10
        if any(c in "!@#$%^&*" for c in pw): pool += 32
        if pool > 0:
            entropy = len(pw) * math.log2(pool)
            secs = (2 ** entropy) / 1e10 / 2
            if secs < 1:               ct = "< 1 second"
            elif secs < 60:            ct = f"{secs:.0f} seconds"
            elif secs < 3600:          ct = f"{secs/60:.0f} minutes"
            elif secs < 86400:         ct = f"{secs/3600:.1f} hours"
            elif secs < 31536000:      ct = f"{secs/86400:.0f} days"
            elif secs < 3.15e10:       ct = f"{secs/31536000:.0f} years"
            else:                      ct = "millions of years"
            self.lbl_crack.config(text=f"Crack time: {ct}", fg=color)

        # Checklist
        funcs = {
            "len":    check_length(pw),
            "upper":  check_upper(pw),
            "lower":  check_lower(pw),
            "number": check_number(pw),
            "symbol": check_symbol(pw),
            "common": check_common(pw),
        }
        names = {
            "len":    "At least 8 characters",
            "upper":  "Uppercase letter (A-Z)",
            "lower":  "Lowercase letter (a-z)",
            "number": "Number (0-9)",
            "symbol": "Special symbol (!@#...)",
            "common": "Not a common password",
        }
        for key, passed in funcs.items():
            if passed:
                self.check_labels[key].config(text="✅  " + names[key], fg=GREEN)
            else:
                self.check_labels[key].config(text="❌  " + names[key], fg=RED)

        # Suggestions
        tips = []
        if not check_length(pw):  tips.append("→  Use at least 8 characters")
        if not check_upper(pw):   tips.append("→  Add an uppercase letter (A-Z)")
        if not check_lower(pw):   tips.append("→  Add a lowercase letter (a-z)")
        if not check_number(pw):  tips.append("→  Add a number (0-9)")
        if not check_symbol(pw):  tips.append("→  Add a special symbol (!@#$...)")
        if not check_common(pw):  tips.append("→  Avoid common passwords like 'password123'")
        if len(pw) < 16:          tips.append("→  Use 16+ characters for maximum security")

        self.txt_suggest.config(state="normal")
        self.txt_suggest.delete("1.0", tk.END)
        if tips:
            self.txt_suggest.insert(tk.END, "\n".join(tips))
        else:
            self.txt_suggest.insert(tk.END, "✅  Great password! No suggestions.")
        self.txt_suggest.config(state="disabled")

    def reset_ui(self):
        self.bar_fill.config(width=0)
        self.lbl_strength.config(text="---", fg=MUTED)
        self.lbl_score.config(text="Score: 0/8")
        self.lbl_crack.config(text="Crack time: —", fg=MUTED)
        names = {
            "len":    "At least 8 characters",
            "upper":  "Uppercase letter (A-Z)",
            "lower":  "Lowercase letter (a-z)",
            "number": "Number (0-9)",
            "symbol": "Special symbol (!@#...)",
            "common": "Not a common password",
        }
        for key, lbl in self.check_labels.items():
            lbl.config(text="○  " + names[key], fg=MUTED)
        self.txt_suggest.config(state="normal")
        self.txt_suggest.delete("1.0", tk.END)
        self.txt_suggest.config(state="disabled")

    def toggle_show(self):
        self.show_pw = not self.show_pw
        self.entry.config(show="" if self.show_pw else "●")
        self.btn_eye.config(text="🙈" if self.show_pw else "👁")

    def save_password(self):
        pw = self.entry_var.get()
        if not pw:
            messagebox.showwarning("Oops!", "Please enter a password first!")
            return

        score = get_score(pw)
        label, _, _ = get_strength_label(score)
        success, reason = save_to_db(pw, label, score)

        if reason == "reused":
            messagebox.showerror("⚠️ Reused Password!",
                                 "This password was used before!\nPlease choose a different one.")
        else:
            messagebox.showinfo("✅ Saved!", f"Password saved to database!\nStrength: {label}  |  Score: {score}/8")
            self.refresh_history()
            self.notebook.select(2)  # switch to history tab

# =============================================
# RUN
# =============================================

root = tk.Tk()
app = PasswordApp(root)
root.mainloop()
