#!/usr/bin/env python3
"""priv-share: dead-simple secret sharing with asymmetric encryption."""

import base64
import binascii
import getpass
import hashlib
import os
import sys
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
    try:
        return base64.urlsafe_b64decode(s.encode())
    except binascii.Error:
        print("Error: invalid base64 encoding.")
        sys.exit(1)


def fingerprint(pk_bytes: bytes) -> str:
    return hashlib.sha256(pk_bytes).hexdigest()[:12]


def load_pubkey(s: str) -> PublicKey:
    raw = b64decode_safe(s)
    if len(raw) != 32:
        print(f"Error: public key must be 32 bytes, got {len(raw)}.")
        sys.exit(1)
    return PublicKey(raw)


def load_private_key() -> PrivateKey:
    if not PRIVATE_KEY_FILE.exists():
        print("No private key found. Run: python share.py keygen")
        sys.exit(1)
    raw = b64decode_safe(PRIVATE_KEY_FILE.read_text().strip())
    return PrivateKey(raw)


def cmd_keygen():
    if PRIVATE_KEY_FILE.exists():
        pk_bytes = b64decode_safe(PUBLIC_KEY_FILE.read_text().strip())
        print(f"Keys already exist at {KEY_DIR}/")
        print(f"Your public key:\n  {encode_key(pk_bytes)}")
        print(f"Fingerprint:\n  {fingerprint(pk_bytes)}")
        print("\nTo regenerate, delete ~/.privshare/ first.")
        return

    old_umask = os.umask(0o077)
    try:
        KEY_DIR.mkdir(parents=True, exist_ok=True)
        KEY_DIR.chmod(0o700)

        private_key = PrivateKey.generate()
        public_key = private_key.public_key

        PRIVATE_KEY_FILE.write_text(encode_key(bytes(private_key)))
        PRIVATE_KEY_FILE.chmod(0o600)

        PUBLIC_KEY_FILE.write_text(encode_key(bytes(public_key)))
    finally:
        os.umask(old_umask)

    pk_bytes = bytes(public_key)
    print(f"Keys saved to {KEY_DIR}/")
    print(f"\nYour public key (share this freely):\n  {encode_key(pk_bytes)}")
    print(f"Fingerprint:\n  {fingerprint(pk_bytes)}")


def cmd_pub():
    if not PUBLIC_KEY_FILE.exists():
        print("No keys found. Run: python share.py keygen")
        sys.exit(1)
    pk_bytes = b64decode_safe(PUBLIC_KEY_FILE.read_text().strip())
    print(f"Your public key:\n  {encode_key(pk_bytes)}")
    print(f"Fingerprint:\n  {fingerprint(pk_bytes)}")


def cmd_encrypt(recipient_pubkey_str: str, secret: str):
    recipient_pubkey = load_pubkey(recipient_pubkey_str)
    box = SealedBox(recipient_pubkey)
    encrypted = box.encrypt(secret.encode())
    blob = base64.urlsafe_b64encode(encrypted).decode()
    print(f"Encrypted (send this to them):\n  {blob}")


def cmd_decrypt(blob: str, raw: bool = False):
    private_key = load_private_key()
    box = SealedBox(private_key)
    try:
        decrypted = box.decrypt(b64decode_safe(blob))
    except CryptoError:
        print("Error: decryption failed. Wrong key or corrupted blob.")
        sys.exit(1)
    if raw:
        sys.stdout.write(decrypted.decode())
    else:
        print(f"Decrypted secret:\n  {decrypted.decode()}")


def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python share.py keygen")
        print("  python share.py pub")
        print("  python share.py encrypt <public-key> [secret]")
        print("  python share.py decrypt [--raw] <encrypted-blob>")
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == "keygen":
        cmd_keygen()
    elif cmd == "pub":
        cmd_pub()
    elif cmd == "encrypt":
        if len(sys.argv) < 3:
            print("Usage: python share.py encrypt <public-key> [secret]")
            sys.exit(1)
        pubkey = sys.argv[2]
        if len(sys.argv) >= 4:
            secret = sys.argv[3]
        elif not sys.stdin.isatty():
            secret = sys.stdin.read().rstrip("\n")
        else:
            secret = getpass.getpass("Secret (won't echo): ")
        cmd_encrypt(pubkey, secret)
    elif cmd == "decrypt":
        args = sys.argv[2:]
        raw = "--raw" in args
        args = [a for a in args if a != "--raw"]
        if not args:
            print('Usage: python share.py decrypt [--raw] "encrypted-blob"')
            sys.exit(1)
        cmd_decrypt(args[0], raw=raw)
    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)


if __name__ == "__main__":
    main()
