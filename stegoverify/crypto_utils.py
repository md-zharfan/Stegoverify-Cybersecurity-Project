"""Hashing, Ed25519 digital signatures, HMAC start-location keys and
AES-256-GCM protection for the confidential ("custom") payload.
Only `cryptography` is required."""
from __future__ import annotations

import hashlib
import hmac
import os

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

SIG_ALG = "Ed25519"
HASH_ALG = "SHA-256"


# --------------------------------------------------------------------------
# hashing
def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


# --------------------------------------------------------------------------
# Ed25519 key management
def generate_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    priv = Ed25519PrivateKey.generate()
    return priv, priv.public_key()


def save_private_key(priv: Ed25519PrivateKey, path: str, passphrase: str | None = None) -> None:
    enc = (serialization.BestAvailableEncryption(passphrase.encode())
           if passphrase else serialization.NoEncryption())
    pem = priv.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.PKCS8, enc)
    with open(path, "wb") as fh:
        fh.write(pem)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def save_public_key(pub: Ed25519PublicKey, path: str) -> None:
    pem = pub.public_bytes(serialization.Encoding.PEM,
                           serialization.PublicFormat.SubjectPublicKeyInfo)
    with open(path, "wb") as fh:
        fh.write(pem)


def load_private_key(path: str, passphrase: str | None = None) -> Ed25519PrivateKey:
    with open(path, "rb") as fh:
        key = serialization.load_pem_private_key(
            fh.read(), passphrase.encode() if passphrase else None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("private key is not an Ed25519 key")
    return key


def load_public_key(path: str) -> Ed25519PublicKey:
    with open(path, "rb") as fh:
        key = serialization.load_pem_public_key(fh.read())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("public key is not an Ed25519 key")
    return key


def public_key_fingerprint(pub: Ed25519PublicKey) -> str:
    raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()[:16]


def sign(priv: Ed25519PrivateKey, message: bytes) -> bytes:
    return priv.sign(message)


def verify(pub: Ed25519PublicKey, message: bytes, signature: bytes) -> bool:
    try:
        pub.verify(signature, message)
        return True
    except InvalidSignature:
        return False


# --------------------------------------------------------------------------
# keyed start location
def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()


# --------------------------------------------------------------------------
# confidential payload (AES-256-GCM, key from a passphrase via scrypt)
def _derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=2 ** 14, r=8, p=1)
    return kdf.derive(passphrase.encode("utf-8"))


def encrypt_bytes(plaintext: bytes, passphrase: str, aad: bytes = b"") -> tuple[dict, bytes]:
    """-> (metadata for the signed record, ciphertext||tag bytes)."""
    salt, iv = os.urandom(16), os.urandom(12)
    key = _derive_key(passphrase, salt)
    ct = AESGCM(key).encrypt(iv, plaintext, aad)
    return {"enc": "AES-256-GCM", "kdf": "scrypt-n14-r8-p1", "salt": salt.hex(), "iv": iv.hex()}, ct


def decrypt_bytes(meta: dict, ct: bytes, passphrase: str, aad: bytes = b"") -> bytes:
    key = _derive_key(passphrase, bytes.fromhex(meta["salt"]))
    try:
        return AESGCM(key).decrypt(bytes.fromhex(meta["iv"]), ct, aad)
    except InvalidTag as e:
        raise ValueError("wrong passphrase or ciphertext modified (GCM tag mismatch)") from e


def encrypt_message(plaintext: bytes, passphrase: str, aad: bytes = b"") -> dict:
    salt, iv = os.urandom(16), os.urandom(12)
    key = _derive_key(passphrase, salt)
    ct = AESGCM(key).encrypt(iv, plaintext, aad)
    return {"enc": "AES-256-GCM", "kdf": "scrypt-n14-r8-p1",
            "salt": salt.hex(), "iv": iv.hex(), "ct": ct.hex()}


def decrypt_message(blob: dict, passphrase: str, aad: bytes = b"") -> bytes:
    key = _derive_key(passphrase, bytes.fromhex(blob["salt"]))
    try:
        return AESGCM(key).decrypt(bytes.fromhex(blob["iv"]), bytes.fromhex(blob["ct"]), aad)
    except InvalidTag as e:
        raise ValueError("wrong passphrase or ciphertext modified (GCM tag mismatch)") from e
