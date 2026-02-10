#!/usr/bin/env python3
"""priv-share: dead-simple secret sharing with asymmetric encryption."""

import base64
import os
import sys
from pathlib import Path

from nacl.public import PrivateKey, PublicKey, SealedBox

KEY_DIR = Path.home() / ".privshare"
PRIVATE_KEY_FILE = KEY_DIR / "private.key"
PUBLIC_KEY_FILE = KEY_DIR / "public.key"


def encode_key(key_bytes: bytes) -> str:
    return base64.urlsafe_b64encode(key_bytes).decode()


def decode_key(key_str: str) -> bytes:
    return base64.urlsafe_b64decode(key_str)


def cmd_keygen():
    if PRIVATE_KEY_FILE.exists():
        print(f"Keys already exist at {KEY_DIR}/")
        print(f"Your public key:\n  {PUBLIC_KEY_FILE.read_text().strip()}")
        print("\nTo regenerate, delete ~/.privshare/ first.")
        return

    KEY_DIR.mkdir(parents=True, exist_ok=True)

    private_key = PrivateKey.generate()
    public_key = private_key.public_key

    PRIVATE_KEY_FILE.write_text(encode_key(bytes(private_key)))
    PRIVATE_KEY_FILE.chmod(0o600)

    PUBLIC_KEY_FILE.write_text(encode_key(bytes(public_key)))

    print(f"Keys saved to {KEY_DIR}/")
    print(f"\nYour public key (share this freely):\n  {encode_key(bytes(public_key))}")


def cmd_encrypt(recipient_pubkey_str: str, secret: str):
    recipient_pubkey = PublicKey(decode_key(recipient_pubkey_str))
    box = SealedBox(recipient_pubkey)
    encrypted = box.encrypt(secret.encode())
    blob = base64.urlsafe_b64encode(encrypted).decode()
    print(f"Encrypted (send this to them):\n  {blob}")


def cmd_decrypt(blob: str):
    if not PRIVATE_KEY_FILE.exists():
        print("No private key found. Run: python share.py keygen")
        sys.exit(1)

    private_key = PrivateKey(decode_key(PRIVATE_KEY_FILE.read_text().strip()))
    box = SealedBox(private_key)
    decrypted = box.decrypt(base64.urlsafe_b64decode(blob))
    print(f"Decrypted secret:\n  {decrypted.decode()}")


def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python share.py keygen")
        print('  python share.py encrypt <public-key> "secret message"')
        print('  python share.py decrypt "encrypted-blob"')
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == "keygen":
        cmd_keygen()
    elif cmd == "encrypt":
        if len(sys.argv) < 3:
            print('Usage: python share.py encrypt <public-key> "secret"')
            sys.exit(1)
        pubkey = sys.argv[2]
        if len(sys.argv) >= 4:
            secret = sys.argv[3]
        elif not sys.stdin.isatty():
            secret = sys.stdin.read().strip()
        else:
            print('Usage: python share.py encrypt <public-key> "secret"')
            print("  Or pipe via stdin: echo 'secret' | python share.py encrypt <key>")
            sys.exit(1)
        cmd_encrypt(pubkey, secret)
    elif cmd == "decrypt":
        if len(sys.argv) < 3:
            print('Usage: python share.py decrypt "encrypted-blob"')
            sys.exit(1)
        cmd_decrypt(sys.argv[2])
    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)


if __name__ == "__main__":
    main()
