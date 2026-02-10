#!/usr/bin/env python3
"""priv-share UI: Tkinter desktop app for asymmetric secret sharing."""

import base64
import binascii
import hashlib
import os
import tkinter as tk
from tkinter import messagebox
from pathlib import Path

from nacl.exceptions import CryptoError
from nacl.public import PrivateKey, PublicKey, SealedBox

KEY_DIR = Path.home() / ".privshare"
PRIVATE_KEY_FILE = KEY_DIR / "private.key"
PUBLIC_KEY_FILE = KEY_DIR / "public.key"


def encode_key(key_bytes: bytes) -> str:
    return base64.urlsafe_b64encode(key_bytes).decode()


def b64decode_safe(s: str) -> bytes:
    s = s.strip()
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s.encode())


def fingerprint(pk_bytes: bytes) -> str:
    return hashlib.sha256(pk_bytes).hexdigest()[:12]


def generate_keys():
    old_umask = os.umask(0o077)
    try:
        KEY_DIR.mkdir(parents=True, exist_ok=True)
        KEY_DIR.chmod(0o700)
        private_key = PrivateKey.generate()
        PRIVATE_KEY_FILE.write_text(encode_key(bytes(private_key)))
        PRIVATE_KEY_FILE.chmod(0o600)
        PUBLIC_KEY_FILE.write_text(encode_key(bytes(private_key.public_key)))
    finally:
        os.umask(old_umask)
    return private_key


def load_or_create_keys():
    if PRIVATE_KEY_FILE.exists():
        raw = b64decode_safe(PRIVATE_KEY_FILE.read_text().strip())
        return PrivateKey(raw)
    return generate_keys()


class App:
    def __init__(self, root):
        self.root = root
        root.title("priv-share")
        root.resizable(False, False)

        self.private_key = load_or_create_keys()
        pad = {"padx": 10, "pady": (5, 0)}

        # --- Keys section ---
        keys_frame = tk.LabelFrame(root, text="Your Keys", padx=10, pady=5)
        keys_frame.pack(fill="x", **pad)

        row = tk.Frame(keys_frame)
        row.pack(fill="x", pady=2)
        tk.Label(row, text="Public Key:").pack(side="left")
        self.pubkey_var = tk.StringVar()
        e = tk.Entry(row, textvariable=self.pubkey_var, state="readonly", width=50)
        e.pack(side="left", padx=(5, 5), fill="x", expand=True)
        tk.Button(row, text="Copy", width=5, command=self.copy_pubkey).pack(side="left")

        row2 = tk.Frame(keys_frame)
        row2.pack(fill="x", pady=2)
        tk.Label(row2, text="Fingerprint:").pack(side="left")
        self.fp_var = tk.StringVar()
        tk.Label(row2, textvariable=self.fp_var, font=("monospace", 10)).pack(side="left", padx=5)
        tk.Button(row2, text="Rotate Keys", command=self.rotate_keys).pack(side="right")

        # --- Encrypt section ---
        enc_frame = tk.LabelFrame(root, text="Encrypt", padx=10, pady=5)
        enc_frame.pack(fill="x", **pad)

        tk.Label(enc_frame, text="Recipient's Public Key:").pack(anchor="w")
        self.enc_pubkey = tk.Entry(enc_frame, width=60)
        self.enc_pubkey.pack(fill="x", pady=2)

        tk.Label(enc_frame, text="Secret:").pack(anchor="w")
        self.enc_secret = tk.Entry(enc_frame, width=60, show="*")
        self.enc_secret.pack(fill="x", pady=2)

        btn_row = tk.Frame(enc_frame)
        btn_row.pack(fill="x", pady=2)
        tk.Button(btn_row, text="Encrypt", command=self.encrypt).pack(side="left")

        res_row = tk.Frame(enc_frame)
        res_row.pack(fill="x", pady=2)
        tk.Label(res_row, text="Result:").pack(side="left")
        self.enc_result_var = tk.StringVar()
        tk.Entry(res_row, textvariable=self.enc_result_var, state="readonly", width=48).pack(
            side="left", padx=(5, 5), fill="x", expand=True
        )
        tk.Button(res_row, text="Copy", width=5, command=self.copy_enc_result).pack(side="left")

        # --- Decrypt section ---
        dec_frame = tk.LabelFrame(root, text="Decrypt", padx=10, pady=5)
        dec_frame.pack(fill="x", padx=10, pady=(5, 10))

        tk.Label(dec_frame, text="Encrypted Blob:").pack(anchor="w")
        self.dec_blob = tk.Entry(dec_frame, width=60)
        self.dec_blob.pack(fill="x", pady=2)

        btn_row2 = tk.Frame(dec_frame)
        btn_row2.pack(fill="x", pady=2)
        tk.Button(btn_row2, text="Decrypt", command=self.decrypt).pack(side="left")

        res_row2 = tk.Frame(dec_frame)
        res_row2.pack(fill="x", pady=2)
        tk.Label(res_row2, text="Result:").pack(side="left")
        self.dec_result_var = tk.StringVar()
        tk.Entry(res_row2, textvariable=self.dec_result_var, state="readonly", width=48).pack(
            side="left", padx=(5, 5), fill="x", expand=True
        )
        tk.Button(res_row2, text="Copy", width=5, command=self.copy_dec_result).pack(side="left")

        self.refresh_key_display()

    def refresh_key_display(self):
        pk_bytes = bytes(self.private_key.public_key)
        self.pubkey_var.set(encode_key(pk_bytes))
        self.fp_var.set(fingerprint(pk_bytes))

    def copy_to_clipboard(self, text):
        self.root.clipboard_clear()
        self.root.clipboard_append(text)

    def copy_pubkey(self):
        self.copy_to_clipboard(self.pubkey_var.get())

    def copy_enc_result(self):
        self.copy_to_clipboard(self.enc_result_var.get())

    def copy_dec_result(self):
        self.copy_to_clipboard(self.dec_result_var.get())

    def rotate_keys(self):
        if not messagebox.askyesno(
            "Rotate Keys",
            "This will invalidate your old key.\nAnything encrypted for the old key cannot be decrypted.\n\nContinue?",
        ):
            return
        self.private_key = generate_keys()
        self.refresh_key_display()
        self.enc_result_var.set("")
        self.dec_result_var.set("")

    def encrypt(self):
        pubkey_str = self.enc_pubkey.get().strip()
        secret = self.enc_secret.get()
        if not pubkey_str:
            messagebox.showerror("Error", "Enter the recipient's public key.")
            return
        if not secret:
            messagebox.showerror("Error", "Enter a secret to encrypt.")
            return
        try:
            raw = b64decode_safe(pubkey_str)
            if len(raw) != 32:
                raise ValueError("bad length")
            pk = PublicKey(raw)
        except Exception:
            messagebox.showerror("Error", "Invalid public key.")
            return
        box = SealedBox(pk)
        encrypted = box.encrypt(secret.encode())
        self.enc_result_var.set(base64.urlsafe_b64encode(encrypted).decode())

    def decrypt(self):
        blob_str = self.dec_blob.get().strip()
        if not blob_str:
            messagebox.showerror("Error", "Enter an encrypted blob.")
            return
        try:
            blob_bytes = b64decode_safe(blob_str)
        except Exception:
            messagebox.showerror("Error", "Invalid base64 encoding.")
            return
        box = SealedBox(self.private_key)
        try:
            decrypted = box.decrypt(blob_bytes)
        except CryptoError:
            messagebox.showerror("Error", "Decryption failed.\nWrong key or corrupted blob.")
            return
        self.dec_result_var.set(decrypted.decode())


if __name__ == "__main__":
    root = tk.Tk()
    App(root)
    root.mainloop()
