import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import hashlib
import bcrypt
import argon2
from argon2 import PasswordHasher

class CyberHashConverter:
    def __init__(self, root):
        self.root = root
        self.root.title("▓▒░ CYBER HASH CONVERTER ░▒▓")
        self.root.geometry("650x700")
        self.root.configure(bg='#0a0a0a')
        
        # Cyberpunk styling
        self.style = ttk.Style()
        self.style.theme_use('alt')
        self.style.configure('.', background='#0a0a0a', foreground='#00ff00')
        self.style.configure('TButton', background='#1a1a1a', foreground='#00ff00',
                           font=('Courier', 10, 'bold'), borderwidth=1)
        self.style.map('TButton', background=[('active', '#2a2a2a')], 
                      foreground=[('active', '#ff00ff')])
        
        self.create_widgets()

    def create_widgets(self):
        # Header
        header = ttk.Frame(self.root)
        header.pack(pady=10, fill="x")
        ttk.Label(header, 
                 text="▓▒░ CYBER HASH CONVERTER ░▒▓", 
                 font=('Courier', 16, 'bold'),
                 foreground='#ff00ff').pack()
        ttk.Label(header, 
                 text="[ Secure Cryptographic Hashing Tool ]", 
                 font=('Courier', 10),
                 foreground='#00ff00').pack(pady=5)

        # Input Frame
        input_frame = ttk.LabelFrame(self.root, text="[ INPUT PLAINTEXT ]", padding=(15, 10))
        input_frame.pack(pady=10, padx=15, fill="x")

        self.input_text = tk.Text(input_frame, 
                                 height=5, 
                                 width=70,
                                 bg='#111111',
                                 fg='#00ff00',
                                 insertbackground='#00ff00',
                                 font=('Courier', 10),
                                 relief='sunken',
                                 borderwidth=2)
        self.input_text.pack(fill="x")

        # Algorithm Selection
        algo_frame = ttk.LabelFrame(self.root, text="[ SELECT ALGORITHM ]", padding=(15, 10))
        algo_frame.pack(pady=10, padx=15, fill="x")

        self.algo_var = tk.StringVar(value="sha256")
        
        algorithms = [
            ("SHA-256 (General Purpose)", "sha256"),
            ("SHA-512 (Stronger Hash)", "sha512"),
            ("bcrypt (Password Hashing)", "bcrypt"),
            ("Argon2 (Most Secure)", "argon2")
        ]

        for text, algo in algorithms:
            ttk.Radiobutton(
                algo_frame,
                text=text,
                variable=self.algo_var,
                value=algo,
                style='TRadiobutton'
            ).pack(anchor="w", pady=2)

        # Action Buttons
        button_frame = ttk.Frame(self.root)
        button_frame.pack(pady=10, fill="x", padx=15)

        ttk.Button(
            button_frame,
            text="[ GENERATE HASH ]",
            command=self.generate_hash,
            style='TButton'
        ).pack(side="left", padx=5, ipadx=10)

        ttk.Button(
            button_frame,
            text="[ COPY TO CLIPBOARD ]",
            command=self.copy_to_clipboard,
            style='TButton'
        ).pack(side="left", padx=5, ipadx=10)

        ttk.Button(
            button_frame,
            text="[ WIPE ALL ]",
            command=self.clear_all,
            style='TButton'
        ).pack(side="right", padx=5, ipadx=10)

        # Output Frame
        output_frame = ttk.LabelFrame(self.root, text="[ HASH OUTPUT ]", padding=(15, 10))
        output_frame.pack(pady=10, padx=15, fill="both", expand=True)

        self.output_hash = scrolledtext.ScrolledText(
            output_frame, 
            height=12, 
            width=70,
            bg='#111111',
            fg='#ff00ff',
            font=('Courier', 10),
            relief='sunken',
            borderwidth=2
        )
        self.output_hash.pack(fill="both", expand=True)

        # Status Bar
        self.status = ttk.Label(self.root, 
                              text="[ STATUS: READY ]",
                              foreground="#ffff00",
                              font=('Courier', 9))
        self.status.pack(side="bottom", fill="x", pady=5)

    def generate_hash(self):
        """Generate hash from input text using selected algorithm"""
        plaintext = self.input_text.get("1.0", "end-1c").strip()
        
        if not plaintext:
            self.status.config(text="[ STATUS: ERROR - NO INPUT TEXT ]", foreground="#ff0000")
            messagebox.showwarning("Warning", "Please enter text to hash!")
            return

        algorithm = self.algo_var.get()
        
        try:
            self.status.config(text="[ STATUS: PROCESSING... ]", foreground="#ffff00")
            self.root.update()  # Force UI update
            
            if algorithm == "sha256":
                hashed = hashlib.sha256(plaintext.encode()).hexdigest()
            elif algorithm == "sha512":
                hashed = hashlib.sha512(plaintext.encode()).hexdigest()
            elif algorithm == "bcrypt":
                salt = bcrypt.gensalt()
                hashed = bcrypt.hashpw(plaintext.encode(), salt).decode()
            elif algorithm == "argon2":
                ph = PasswordHasher(
                    time_cost=3,
                    memory_cost=65536,
                    parallelism=4,
                    hash_len=32,
                    salt_len=16
                )
                hashed = ph.hash(plaintext)
            
            self.output_hash.delete("1.0", tk.END)
            self.output_hash.insert(tk.END, hashed)
            self.status.config(text="[ STATUS: HASH GENERATED SUCCESSFULLY ]", foreground="#00ff00")
            
        except Exception as e:
            self.status.config(text=f"[ STATUS: ERROR - {str(e)} ]", foreground="#ff0000")
            messagebox.showerror("Error", f"Hash generation failed:\n{str(e)}")

    def copy_to_clipboard(self):
        """Copy hash to clipboard"""
        hash_text = self.output_hash.get("1.0", "end-1c").strip()
        if hash_text:
            self.root.clipboard_clear()
            self.root.clipboard_append(hash_text)
            self.status.config(text="[ STATUS: HASH COPIED TO CLIPBOARD ]", foreground="#00ffff")
        else:
            self.status.config(text="[ STATUS: ERROR - NO HASH TO COPY ]", foreground="#ff0000")
    def copy_to_clipboard(self):
        hash_text = self.output_hash.get("1.0", "end-1c").strip()
        if hash_text:
            self.root.clipboard_clear()
            self.root.clipboard_append(hash_text)
            messagebox.showinfo("Success", "Hash copied to clipboard!")
        else:
            messagebox.showwarning("Warning", "No hash to copy")
    def clear_all(self):
        """Clear all input and output"""
        self.input_text.delete("1.0", tk.END)
        self.output_hash.delete("1.0", tk.END)
        self.status.config(text="[ STATUS: ALL DATA WIPED ]", foreground="#ff00ff")

if __name__ == "__main__":
    root = tk.Tk()
    app = CyberHashConverter(root)
    root.mainloop()
