from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import base64
import os
import datetime
import tkinter as tk
from tkinter import messagebox, filedialog

def generate_key():
    key = os.urandom(16)
    timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    filename = f'{timestamp}.txt'
    with open(filename, 'w') as key_file:
        key_file.write(key.hex())
    messagebox.showinfo("Key Generated", f"Kunci baru telah dihasilkan dan disimpan di '{filename}'.\nKunci (hex): {key.hex()}")
    return key

def load_key():
    filename = filedialog.askopenfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
    if filename:
        with open(filename, 'r') as key_file:
            key = bytes.fromhex(key_file.read())
        messagebox.showinfo("Key Loaded", f"Kunci yang dimuat (hex): {key.hex()}")
        return key
    else:
        messagebox.showwarning("File Not Found", "File kunci tidak ditemukan.")
        return None

def camellia_encrypt_ecb(plain_text, key):
    cipher = Cipher(algorithms.Camellia(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(algorithms.Camellia.block_size).padder()
    padded_text = padder.update(plain_text.encode()) + padder.finalize()

    encrypted_text = encryptor.update(padded_text) + encryptor.finalize()
    return base64.b64encode(encrypted_text).decode()

def camellia_decrypt_ecb(encrypted_text, key):
    cipher = Cipher(algorithms.Camellia(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()

    encrypted_data = base64.b64decode(encrypted_text)

    padded_text = decryptor.update(encrypted_data) + decryptor.finalize()

    unpadder = padding.PKCS7(algorithms.Camellia.block_size).unpadder()
    plain_text = unpadder.update(padded_text) + unpadder.finalize()
    
    return plain_text.decode()

class CamelliaApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Camellia Encryption/Decryption")

        self.key = None
        self.create_widgets()

    def create_widgets(self):
        self.lbl_plain_text = tk.Label(self.root, text="Plain Text:")
        self.lbl_plain_text.grid(row=0, column=0, padx=5, pady=5, sticky="e")

        self.txt_plain_text = tk.Entry(self.root, width=50)
        self.txt_plain_text.grid(row=0, column=1, padx=5, pady=5, columnspan=3)

        self.lbl_encrypted_text = tk.Label(self.root, text="Encrypted Text:")
        self.lbl_encrypted_text.grid(row=1, column=0, padx=5, pady=5, sticky="e")

        self.txt_encrypted_text = tk.Entry(self.root, width=50)
        self.txt_encrypted_text.grid(row=1, column=1, padx=5, pady=5, columnspan=3)

        self.btn_generate_key = tk.Button(self.root, text="Generate Key", command=self.generate_key)
        self.btn_generate_key.grid(row=2, column=0, padx=5, pady=5)

        self.btn_load_key = tk.Button(self.root, text="Load Key", command=self.load_key)
        self.btn_load_key.grid(row=2, column=1, padx=5, pady=5)

        self.btn_encrypt = tk.Button(self.root, text="Encrypt", command=self.encrypt)
        self.btn_encrypt.grid(row=2, column=2, padx=5, pady=5)

        self.btn_decrypt = tk.Button(self.root, text="Decrypt", command=self.decrypt)
        self.btn_decrypt.grid(row=2, column=3, padx=5, pady=5)

        self.btn_exit = tk.Button(self.root, text="Exit", command=self.root.quit)
        self.btn_exit.grid(row=2, column=4, padx=5, pady=5)

    def generate_key(self):
        self.key = generate_key()

    def load_key(self):
        self.key = load_key()

    def encrypt(self):
        if self.key:
            plain_text = self.txt_plain_text.get()
            encrypted_text = camellia_encrypt_ecb(plain_text, self.key)
            self.txt_encrypted_text.delete(0, tk.END)
            self.txt_encrypted_text.insert(0, encrypted_text)
        else:
            messagebox.showwarning("No Key", "Silakan muat atau buat kunci terlebih dahulu.")

    def decrypt(self):
        if self.key:
            encrypted_text = self.txt_encrypted_text.get()
            try:
                plain_text = camellia_decrypt_ecb(encrypted_text, self.key)
                self.txt_plain_text.delete(0, tk.END)
                self.txt_plain_text.insert(0, plain_text)
            except Exception as e:
                messagebox.showerror("Error", f"Terjadi kesalahan: {e}")
        else:
            messagebox.showwarning("No Key", "Silakan muat atau buat kunci terlebih dahulu.")

if __name__ == "__main__":
    root = tk.Tk()
    app = CamelliaApp(root)
    root.mainloop()
