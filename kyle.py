#!/usr/bin/env python3
"""
Simple Hybrid Encryption (AES-GCM + RSA-OAEP) — Minimal, Educational
- AES-256-GCM to encrypt data
- RSA-3072 OAEP(SHA-256) to wrap the AES key
- JSON package holds: RSA-wrapped key, nonce, tag+ciphertext, and params

USAGE (see README for more):
  python mini_hybrid.py genkeys --private-out private.pem --public-out public.pem
  python mini_hybrid.py enc -k public.pem -i secret.txt -o package.json
  python mini_hybrid.py enc -k public.pem -m "hello team" -o package.json
  python mini_hybrid.py dec -k private.pem -p package.json -o recovered.txt
"""
import argparse, json, os, sys, base64
from typing import Optional

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---------- Helpers ----------
def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode('utf-8')

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode('utf-8'))

# ---------- Key generation ----------
def genkeys(private_out: str, public_out: str) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    priv_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with open(private_out, "wb") as f:
        f.write(priv_pem)
    with open(public_out, "wb") as f:
        f.write(pub_pem)
    print(f"[ok] wrote RSA-3072 keys:\n  private -> {private_out}\n  public  -> {public_out}")

# ---------- Encrypt ----------
def encrypt(pubkey_path: str, in_path: Optional[str], message: Optional[str], out_path: str) -> None:
    if not ((in_path and os.path.exists(in_path)) or message is not None):
        raise SystemExit("Provide an input file (-i) or a message (-m).")
    with open(pubkey_path, "rb") as f:
        pub = serialization.load_pem_public_key(f.read())

    # 32-byte AES key, 12-byte nonce for GCM
    aes_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)

    if in_path:
        data = open(in_path, "rb").read()
    else:
        data = message.encode("utf-8")

    # AEAD: returns ciphertext||tag
    ct = aesgcm.encrypt(nonce, data, associated_data=None)

    # Wrap AES key with RSA-OAEP(SHA-256)
    wrapped_key = pub.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None)
    )

    package = {
        "version": 1,
        "scheme": {
            "symmetric": "AES-256-GCM",
            "asymmetric_wrap": "RSA-3072-OAEP-SHA256"
        },
        "wrapped_key_b64": b64e(wrapped_key),
        "nonce_b64": b64e(nonce),
        "ciphertext_b64": b64e(ct),
    }

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(package, f, indent=2)

    print(f"[ok] wrote encrypted package -> {out_path}")

# ---------- Decrypt ----------
def decrypt(privkey_path: str, package_path: str, out_path: Optional[str]) -> None:
    with open(privkey_path, "rb") as f:
        priv = serialization.load_pem_private_key(f.read(), password=None)

    package = json.load(open(package_path, "r", encoding="utf-8"))
    wrapped_key = b64d(package["wrapped_key_b64"])
    nonce = b64d(package["nonce_b64"])
    ct = b64d(package["ciphertext_b64"])

    # Unwrap AES key
    aes_key = priv.decrypt(
        wrapped_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None)
    )

    aesgcm = AESGCM(aes_key)
    try:
        pt = aesgcm.decrypt(nonce, ct, associated_data=None)
    except Exception as e:
        raise SystemExit(f"Decryption failed: {e}")

    if out_path:
        with open(out_path, "wb") as f:
            f.write(pt)
        print(f"[ok] wrote plaintext -> {out_path}")
    else:
        # Print to stdout as UTF-8 (best-effort)
        try:
            print(pt.decode("utf-8"))
        except UnicodeDecodeError:
            # If binary, note length
            sys.stdout.buffer.write(pt)

# ---------- CLI ----------
def main():
    p = argparse.ArgumentParser(description="Minimal Hybrid Encryption (AES-GCM + RSA-OAEP)")
    sub = p.add_subparsers(dest="cmd", required=True)

    p_gen = sub.add_parser("genkeys", help="Generate RSA keypair")
    p_gen.add_argument("--private-out", required=True)
    p_gen.add_argument("--public-out", required=True)

    p_enc = sub.add_parser("enc", help="Encrypt a file or message")
    p_enc.add_argument("-k", "--pubkey", required=True, help="Path to recipient public.pem")
    g = p_enc.add_mutually_exclusive_group(required=True)
    g.add_argument("-i", "--infile", help="Path to input file")
    g.add_argument("-m", "--message", help="Short message to encrypt")
    p_enc.add_argument("-o", "--out", required=True, help="Output JSON package path")

    p_dec = sub.add_parser("dec", help="Decrypt a package")
    p_dec.add_argument("-k", "--privkey", required=True, help="Path to private.pem")
    p_dec.add_argument("-p", "--package", required=True, help="Path to JSON package")
    p_dec.add_argument("-o", "--out", help="Output plaintext file (omit to print to stdout)")

    args = p.parse_args()
    if args.cmd == "genkeys":
        genkeys(args.private_out, args.public_out)
    elif args.cmd == "enc":
        encrypt(args.pubkey, args.infile, args.message, args.out)
    elif args.cmd == "dec":
        decrypt(args.privkey, args.package, args.out)

if __name__ == "__main__":
    main()
# Write your individual encryption and decryption implementation below:
