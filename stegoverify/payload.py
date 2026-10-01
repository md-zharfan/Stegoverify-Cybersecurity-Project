"""Verification payload (FR3) and the on-wire container format.

Container layout, version 2 (all integers big-endian):

    0  4  MAGIC  b"SVFY"
    4  1  version (2)
    5  1  flags   bit0 = message encrypted, bit1 = message is a file
    6  4  record length   (canonical JSON, UTF-8)
    10 2  signature length (64 for Ed25519)
    12 4  message length  (raw bytes: text, picture, audio, video ... or ciphertext)
    16 .. record || signature || message || CRC-32(record || signature || message)

The *record* is a small JSON object with media ID, timestamp, nonce, media
hash, LSB depth, metadata **and the SHA-256 of the hidden message** (both of
the original plaintext and of the bytes actually stored).  The Ed25519
signature covers the record, so every field - and through the SHA-256 values
the message itself - is protected against modification.

Storing the message as raw bytes after the record (instead of base64 inside
the JSON) means a picture / audio / video payload costs exactly its own size.
"""
from __future__ import annotations

import datetime as _dt
import json
import mimetypes
import os
import struct
import uuid
import zlib

from . import crypto_utils as cu

MAGIC = b"SVFY"
VERSION = 2
HEADER_FMT = ">4sBBIHI"
HEADER_LEN = struct.calcsize(HEADER_FMT)     # 16
CRC_LEN = 4
FLAG_ENCRYPTED = 0x01
FLAG_FILE = 0x02
MAX_RECORD = 64 * 1024

mimetypes.add_type("audio/wav", ".wav")
mimetypes.add_type("video/mp4", ".mp4")


class ContainerError(ValueError):
    pass


def canonical(record: dict) -> bytes:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def guess_type(name: str | None) -> str:
    if not name:
        return "text/plain; charset=utf-8"
    return mimetypes.guess_type(name)[0] or "application/octet-stream"


def kind_of(mime: str) -> str:
    """'text' | 'image' | 'audio' | 'video' | 'file' - used by the GUI."""
    top = mime.split("/")[0]
    return top if top in ("text", "image", "audio", "video") else "file"


def build_record(cover, n_lsb: int, message: bytes, *, issuer: str, team: str,
                 filename: str, passphrase: str | None = None,
                 message_name: str | None = None, extra_meta: dict | None = None) -> tuple[dict, bytes, int]:
    """Return (record, stored_message_bytes, flags)."""
    media_hash = cover.masked_hash(n_lsb)
    nonce = os.urandom(16)
    media_id = uuid.uuid4().hex
    mime = guess_type(message_name)
    msg = {"name": message_name, "mime": mime, "size": len(message),
           "sha256": cu.sha256(message).hex()}
    flags = FLAG_FILE if message_name else 0
    if passphrase:
        # AAD binds the ciphertext to this media object and nonce
        meta, stored = cu.encrypt_bytes(message, passphrase, bytes.fromhex(media_id) + nonce)
        msg.update(meta)
        flags |= FLAG_ENCRYPTED
    else:
        msg["enc"] = "none"
        stored = message
    msg["stored_size"] = len(stored)
    msg["stored_sha256"] = cu.sha256(stored).hex()
    record = {
        "v": VERSION,
        "media_id": media_id,
        "cover_type": cover.kind,
        "ts": now_iso(),
        "nonce": nonce.hex(),
        "hash_alg": f"{cu.HASH_ALG}/LSB{n_lsb}-masked",
        "hash": media_hash.hex(),
        "lsb_bits": n_lsb,
        "sig_alg": cu.SIG_ALG,
        "flags": flags,
        "meta": {"issuer": issuer, "team": team, "filename": filename,
                 "cover": cover.describe(), **(extra_meta or {})},
        "msg": msg,
    }
    return record, stored, flags


def open_message(record: dict, stored: bytes, passphrase: str | None = None) -> bytes:
    msg = record.get("msg", {})
    if msg.get("enc") == "AES-256-GCM":
        if not passphrase:
            raise ValueError("message is encrypted - a passphrase is required to read it")
        aad = bytes.fromhex(record["media_id"]) + bytes.fromhex(record["nonce"])
        return cu.decrypt_bytes(msg, stored, passphrase, aad)
    return stored


# --------------------------------------------------------------------------
def pack(record: dict, signature: bytes, stored: bytes, flags: int) -> bytes:
    body = canonical(record)
    head = struct.pack(HEADER_FMT, MAGIC, VERSION, flags, len(body), len(signature), len(stored))
    crc = struct.pack(">I", zlib.crc32(stored, zlib.crc32(body + signature)) & 0xFFFFFFFF)
    return head + body + signature + stored + crc


def container_size(record: dict, stored_len: int, sig_len: int = 64) -> int:
    return HEADER_LEN + len(canonical(record)) + sig_len + stored_len + CRC_LEN


def parse_header(head: bytes) -> tuple[int, int, int, int]:
    """-> (flags, record_len, sig_len, msg_len); raises ContainerError if not ours."""
    if len(head) < HEADER_LEN:
        raise ContainerError("header too short")
    magic, ver, flags, plen, slen, mlen = struct.unpack(HEADER_FMT, head[:HEADER_LEN])
    if magic != MAGIC:
        raise ContainerError("no payload marker at this location")
    if ver != VERSION:
        raise ContainerError(f"unsupported container version {ver}")
    if plen < 2 or plen > MAX_RECORD or slen != 64 or mlen > 1 << 31:
        raise ContainerError("header fields are implausible (corrupted)")
    return flags, plen, slen, mlen


def unpack_body(body: bytes, plen: int, slen: int, mlen: int):
    """-> (record_or_None, record_bytes, signature, stored_message, crc_ok)."""
    pbytes = body[:plen]
    sig = body[plen:plen + slen]
    stored = body[plen + slen:plen + slen + mlen]
    crc = body[plen + slen + mlen:plen + slen + mlen + CRC_LEN]
    calc = zlib.crc32(stored, zlib.crc32(pbytes + sig)) & 0xFFFFFFFF
    crc_ok = struct.pack(">I", calc) == crc
    try:
        record = json.loads(pbytes.decode("utf-8"))
        if not isinstance(record, dict):
            record = None
    except (UnicodeDecodeError, ValueError):
        record = None
    return record, pbytes, sig, stored, crc_ok


def total_len(plen: int, slen: int, mlen: int) -> int:
    return HEADER_LEN + plen + slen + mlen + CRC_LEN
