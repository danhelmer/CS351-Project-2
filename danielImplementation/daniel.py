import os
import json
import base64
from pathlib import Path
from typing import Dict
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ======================
# Configuration
# ======================
OUT_DIR = Path("output")
OUT_DIR.mkdir(exist_ok=True)

# ======================
# RSA Key Helpers
# ======================
def generate_rsa_keypair(key_size: int = 2048):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    public_key = private_key.public_key()
    return private_key, public_key

def save_private_key_to_pem(private_key, filepath: Path, password: bytes | None = None):
    enc_alg = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc_alg,
    )
    filepath.write_bytes(pem)

def save_public_key_to_pem(public_key, filepath: Path):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    filepath.write_bytes(pem)

def load_private_key_from_pem(filepath: Path, password: bytes | None = None):
    data = filepath.read_bytes()
    return serialization.load_pem_private_key(data, password=password)

def load_public_key_from_pem(filepath: Path):
    data = filepath.read_bytes()
    return serialization.load_pem_public_key(data)

# ======================
# Base64 helpers
# ======================
def _b64(x: bytes) -> str:
    return base64.b64encode(x).decode("ascii")

def _unb64(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))

# ======================
# Hybrid Encryption
# ======================
def wrap_aes_key_with_rsa(pubkey, aes_key: bytes) -> bytes:
    return pubkey.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def unwrap_aes_key_with_rsa(privkey, wrapped_key: bytes) -> bytes:
    return privkey.decrypt(
        wrapped_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def encrypt_message_with_public_key(pubkey, plaintext: bytes) -> Dict[str, str]:
    aes_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    wrapped_key = wrap_aes_key_with_rsa(pubkey, aes_key)

    return {
        "wrapped_key": _b64(wrapped_key),
        "nonce": _b64(nonce),
        "ciphertext": _b64(ciphertext),
    }

def decrypt_message_with_private_key(privkey, data: Dict[str, str]) -> bytes:
    wrapped_key = _unb64(data["wrapped_key"])
    nonce = _unb64(data["nonce"])
    ciphertext = _unb64(data["ciphertext"])
    aes_key = unwrap_aes_key_with_rsa(privkey, wrapped_key)
    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    return plaintext

# ======================
# File Encryption / Decryption
# ======================
def encrypt_file_to_bundle(pubkey, in_filepath: Path):
    plaintext = in_filepath.read_bytes()
    bundle = encrypt_message_with_public_key(pubkey, plaintext)
    bundle["filename"] = in_filepath.name

    out_path = OUT_DIR / f"{in_filepath.stem}_encrypted.json"
    out_path.write_text(json.dumps(bundle))
    print(f"🔒 Encrypted file written to {out_path}")

def decrypt_bundle_to_file(privkey, bundle_path: Path):
    bundle = json.loads(bundle_path.read_text())
    plaintext = decrypt_message_with_private_key(privkey, bundle)
    filename = bundle.get("filename", "decrypted.bin")
    out_path = OUT_DIR / f"{Path(filename).stem}_decrypted{Path(filename).suffix}"
    out_path.write_bytes(plaintext)
    print(f"🔓 Decrypted file written to {out_path}")

# ======================
# Example Usage
# ======================
def main_example():
    # --- Key generation ---
    priv, pub = generate_rsa_keypair()
    save_private_key_to_pem(priv, OUT_DIR / "private_key.pem")
    save_public_key_to_pem(pub, OUT_DIR / "public_key.pem")

    # --- Create example file ---
    input_file = OUT_DIR / "example_input.bin"
    input_file.write_bytes(b"This is a secret file content for hybrid encryption demo!")

    # --- Encrypt the file ---
    encrypt_file_to_bundle(pub, input_file)

    # --- Decrypt the file ---
    encrypted_file = OUT_DIR / "example_input_encrypted.json"
    decrypt_bundle_to_file(priv, encrypted_file)

if __name__ == "__main__":
    main_example()
