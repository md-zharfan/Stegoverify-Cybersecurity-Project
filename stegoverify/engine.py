"""High-level workflows: protect (encode + sign + embed), verify (locate +
extract + check), and tamper helpers used for negative test cases."""
from __future__ import annotations

import array
import math
import os
from collections import Counter
from dataclasses import dataclass, field

from . import crypto_utils as cu
from . import lsb, payload as pl, startloc
from .covers import AudioCover, CoverError, ImageCover, load_cover

# verdict categories (FR10)
AUTHENTIC = "Authentic"
TAMPERED = "Tampered"
SIG_INVALID = "Signature Invalid"
MISSING = "Payload Missing"
WRONG_START = "Wrong Start Location"
CANNOT = "Cannot Verify"


class CapacityError(ValueError):
    pass


def human(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if abs(n) < 1024 or unit == "GB":
            return f"{n:,.0f} {unit}" if unit == "B" else f"{n:,.1f} {unit}"
        n /= 1024


# --------------------------------------------------------------------------
def estimate_container(cover, n_lsb: int, message_len: int, *, encrypted: bool = False,
                       message_name: str | None = None, issuer: str = "", team: str = "",
                       filename: str = "", mode: str = startloc.MODE_KEYED) -> int:
    """Exact (to within a few bytes) size of the signed container, computed
    from a template record with fields of the real length."""
    msg = {"name": message_name, "mime": pl.guess_type(message_name), "size": message_len,
           "sha256": "0" * 64, "enc": "none", "stored_size": message_len, "stored_sha256": "0" * 64}
    stored = message_len
    if encrypted:
        msg.update({"enc": "AES-256-GCM", "kdf": "scrypt-n14-r8-p1", "salt": "0" * 32, "iv": "0" * 24})
        stored += 16                                   # GCM tag
        msg["stored_size"] = stored
    record = {"v": pl.VERSION, "media_id": "0" * 32, "cover_type": cover.kind, "ts": "2026-01-01T00:00:00Z",
              "nonce": "0" * 32, "hash_alg": f"SHA-256/LSB{n_lsb}-masked", "hash": "0" * 64,
              "lsb_bits": n_lsb, "sig_alg": cu.SIG_ALG, "flags": 3,
              "meta": {"issuer": issuer, "team": team, "filename": filename, "cover": cover.describe(),
                       "start_mode": mode}, "msg": msg}
    return pl.container_size(record, stored) + 8        # small margin for number widths


def capacity_report(cover, n_lsb: int, message_len: int, encrypted: bool = False, **kw) -> dict:
    """Pre-flight check shown in the GUI before embedding (FR: capacity check)."""
    cap = lsb.capacity_bytes(cover.num_units, n_lsb)
    need = estimate_container(cover, n_lsb, message_len, encrypted=encrypted, **kw)
    min_n = next((n for n in range(1, 9) if estimate_container(cover, n, message_len, encrypted=encrypted, **kw)
                  <= lsb.capacity_bytes(cover.num_units, n)), None)
    return {"capacity_bytes": cap, "estimated_container_bytes": need,
            "fits": need <= cap, "utilisation": need / cap if cap else math.inf,
            "units": cover.num_units, "n_lsb": n_lsb, "min_lsb_that_fits": min_n}


@dataclass
class ProtectResult:
    stego_path: str
    payload: dict
    signature: bytes
    n_lsb: int
    mode: str
    start_unit: int
    start_desc: str
    container_len: int
    capacity_bytes: int
    changed_units: int
    quality: dict
    cover: object
    stego: object
    units_used: int = 0
    message_sha256: str = ""


def protect(cover_path: str, out_path: str, message: bytes, n_lsb: int, priv_key, *,
            mode: str = startloc.MODE_KEYED, secret: str | None = None,
            manual_unit: int | None = None, passphrase: str | None = None,
            issuer: str = "StegoVerify", team: str = "", message_name: str | None = None) -> ProtectResult:
    lsb.check_n(n_lsb)
    cover = load_cover(cover_path)

    # ---- capacity check first: refuse before doing any crypto work
    cap = lsb.capacity_bytes(cover.num_units, n_lsb)
    est = estimate_container(cover, n_lsb, len(message), encrypted=bool(passphrase), message_name=message_name,
                             issuer=issuer, team=team, filename=os.path.basename(cover_path), mode=mode)
    if est > cap:
        rep = capacity_report(cover, n_lsb, len(message), bool(passphrase), message_name=message_name)
        hint = (f"It would fit at {rep['min_lsb_that_fits']} LSB." if rep["min_lsb_that_fits"]
                else "It does not fit even at 8 LSB - choose a bigger cover object.")
        raise CapacityError(
            f"Payload too large: the payload is {human(len(message))} and the signed container needs "
            f"{human(est)}, but this cover only holds {human(cap)} at {n_lsb} LSB "
            f"({cover.num_units:,} units x {n_lsb} bit). {hint}")

    stego = cover.copy()
    record, stored, flags = pl.build_record(
        cover, n_lsb, message, issuer=issuer, team=team,
        filename=os.path.basename(cover_path), passphrase=passphrase, message_name=message_name,
        extra_meta={"start_mode": mode})
    signature = cu.sign(priv_key, pl.canonical(record))
    container = pl.pack(record, signature, stored, flags)
    if len(container) > cap:                                    # safety net (estimate is exact)
        raise CapacityError(f"Payload too large: container {human(len(container))} > capacity {human(cap)}")

    if mode == startloc.MODE_KEYED:
        start = startloc.derive_start(secret, cover.kind, bytes.fromhex(record["hash"]), n_lsb, cover.num_units)
    elif mode == startloc.MODE_MANUAL:
        if manual_unit is None or not 0 <= manual_unit < cover.num_units:
            raise ValueError("manual start location is outside the cover")
        start = manual_unit
    else:
        raise ValueError("unknown start-location mode")

    units = stego.units()
    changed = lsb.embed(units, container, start, n_lsb)
    stego.set_units(units)
    stego.save(out_path)
    stego.source = out_path
    return ProtectResult(out_path, record, signature, n_lsb, mode, start,
                         startloc.describe_unit(cover, start), len(container), cap, changed,
                         quality_metrics(cover, stego), cover, stego,
                         units_used=lsb.units_needed(len(container), n_lsb),
                         message_sha256=record["msg"]["sha256"])


# --------------------------------------------------------------------------
@dataclass
class VerifyResult:
    verdict: str
    reason: str
    details: list = field(default_factory=list)
    payload: dict | None = None
    message: bytes | None = None
    message_error: str | None = None
    n_lsb: int | None = None
    expected_unit: int | None = None
    found_unit: int | None = None
    sig_ok: bool | None = None
    hash_ok: bool | None = None
    crc_ok: bool | None = None
    cover: object = None
    # payload integrity (hash of initial payload vs hash of extracted payload)
    payload_hash_signed: str | None = None
    payload_hash_extracted: str | None = None
    payload_hash_ok: bool | None = None
    container_len: int | None = None

    @property
    def ok(self):
        return self.verdict == AUTHENTIC

    @property
    def payload_kind(self) -> str:
        if not self.payload:
            return "file"
        return pl.kind_of(self.payload.get("msg", {}).get("mime", ""))


def _locate(cover, units, n_lsb, expected, scan):
    """-> (start_unit, flags, plen, slen, mlen, at_expected) or None."""
    if expected is not None:
        try:
            head = lsb.extract(units, expected, n_lsb, pl.HEADER_LEN)
            return (expected, *pl.parse_header(head), True)
        except (pl.ContainerError, ValueError):
            pass
    if scan:
        for hit in lsb.find_pattern(units, n_lsb, pl.MAGIC):
            try:
                head = lsb.extract(units, hit, n_lsb, pl.HEADER_LEN)
                return (hit, *pl.parse_header(head), False)
            except (pl.ContainerError, ValueError):
                continue
    return None


def verify(stego_path: str, n_lsb: int | None, pub_key, *, mode: str = startloc.MODE_KEYED,
           secret: str | None = None, manual_unit: int | None = None,
           passphrase: str | None = None, scan: bool = True) -> VerifyResult:
    """n_lsb=None -> try 1..8 (auto-detect)."""
    details: list[str] = []
    try:
        cover = load_cover(stego_path)
    except (CoverError, OSError) as e:
        return VerifyResult(CANNOT, f"cannot open cover object: {e}")
    if pub_key is None:
        return VerifyResult(CANNOT, "no public key selected - cannot check the signature")

    candidates = [n_lsb] if n_lsb else list(range(1, 9))
    units = cover.units()
    located = None
    for n in candidates:
        expected = None
        try:
            if mode == startloc.MODE_KEYED:
                if secret:
                    expected = startloc.derive_start(secret, cover.kind, cover.masked_hash(n), n, cover.num_units)
                elif n == candidates[0]:
                    details.append("no secret given - relying on payload scan only")
            elif mode == startloc.MODE_MANUAL:
                expected = manual_unit
        except (ValueError, CoverError) as e:
            return VerifyResult(CANNOT, f"cannot derive start location: {e}", details, cover=cover)
        loc = _locate(cover, units, n, expected, scan)
        if loc:
            located = (n, expected, *loc)
            break
    if not located:
        hint = ("no payload marker found at the expected location or anywhere else for LSB setting "
                + (f"{n_lsb}" if n_lsb else "1-8") + " - the payload was never embedded, was stripped, "
                "or a different LSB depth was used")
        return VerifyResult(MISSING, hint, details, n_lsb=n_lsb, cover=cover, expected_unit=None)

    n, expected, start, flags, plen, slen, mlen, at_expected = located
    details.append(f"payload marker found using {n} LSB at {startloc.describe_unit(cover, start)}")
    if expected is not None:
        details.append(f"expected start location: {startloc.describe_unit(cover, expected)}"
                       + (" (match)" if at_expected else " (MISMATCH)"))
    res = VerifyResult(CANNOT, "", details, n_lsb=n, expected_unit=expected, found_unit=start, cover=cover)

    total = pl.total_len(plen, slen, mlen)
    res.container_len = total
    if total > lsb.capacity_bytes(cover.num_units, n):
        res.verdict, res.reason = TAMPERED, "container header claims more data than the cover can hold (corrupted)"
        return res
    body = lsb.extract(units, start, n, total)[pl.HEADER_LEN:]
    record, pbytes, sig, stored, crc_ok = pl.unpack_body(body, plen, slen, mlen)
    res.crc_ok = crc_ok
    details.append(f"extracted container: {human(total)} (record {plen} B, signature {slen} B, message {human(mlen)})")
    details.append(f"container CRC-32: {'OK' if crc_ok else 'MISMATCH'}")
    if record is None or not crc_ok:
        res.verdict, res.reason = TAMPERED, "embedded payload region is corrupted (CRC/JSON failure) - LSBs were overwritten after protection"
        return res
    res.payload = record
    msg = record.get("msg", {})
    res.payload_hash_signed = msg.get("sha256")

    res.sig_ok = cu.verify(pub_key, pbytes, sig)
    details.append(f"Ed25519 signature: {'VALID' if res.sig_ok else 'INVALID'} "
                   f"(key {cu.public_key_fingerprint(pub_key)})")
    if not res.sig_ok:
        res.verdict, res.reason = SIG_INVALID, "signature does not verify with the selected public key - payload forged, altered or signed by an unknown party"
        return res

    stored_ok = cu.sha256(stored).hex() == msg.get("stored_sha256")
    details.append(f"stored message bytes SHA-256 vs signed value: {'MATCH' if stored_ok else 'MISMATCH'}")
    if not stored_ok:
        res.verdict, res.reason = TAMPERED, "the hidden message bytes do not match the SHA-256 in the signed record - payload altered"
        return res

    p_n = int(record.get("lsb_bits", n))
    try:
        current = cover.masked_hash(p_n).hex()
    except CoverError as e:
        res.verdict, res.reason = CANNOT, str(e)
        return res
    res.hash_ok = (current == record.get("hash")) and record.get("cover_type") == cover.kind
    details.append(f"media hash ({record.get('hash_alg')}): {'MATCH' if res.hash_ok else 'MISMATCH'}")
    details.append(f"  signed  : {record.get('hash', '')[:32]}...")
    details.append(f"  current : {current[:32]}...")
    if not res.hash_ok:
        res.verdict, res.reason = TAMPERED, "signature is genuine but the media content no longer matches the signed hash - the cover was modified after protection"
        return res

    if not at_expected:
        res.verdict, res.reason = WRONG_START, ("a genuine, intact payload exists but NOT at the start location derived from "
                                                 "your secret / manual position - wrong secret or wrong coordinates supplied")
        return res

    try:
        res.message = pl.open_message(record, stored, passphrase)
    except ValueError as e:
        res.message_error = str(e)
    if res.message is not None:
        res.payload_hash_extracted = cu.sha256(res.message).hex()
        res.payload_hash_ok = res.payload_hash_extracted == res.payload_hash_signed
        details.append("payload SHA-256 (initial, signed)  : " + str(res.payload_hash_signed))
        details.append("payload SHA-256 (extracted, now)   : " + res.payload_hash_extracted)
        details.append(f"payload integrity: {'MATCH - extracted payload is identical to the original' if res.payload_hash_ok else 'MISMATCH'}")
        if not res.payload_hash_ok:
            res.verdict, res.reason = TAMPERED, "extracted payload hash differs from the original payload hash"
            return res
    else:
        details.append("payload SHA-256 (extracted): not computed - " + (res.message_error or "message sealed"))

    res.verdict, res.reason = AUTHENTIC, ("payload located, signature valid, media hash matches, "
                                          + ("extracted payload hash == original payload hash"
                                             if res.payload_hash_ok else "message sealed (passphrase needed)"))
    return res


# --------------------------------------------------------------------------
def _xor(a: bytes, b: bytes) -> bytes:
    n = min(len(a), len(b))
    return (int.from_bytes(a[:n], "big") ^ int.from_bytes(b[:n], "big")).to_bytes(n, "big")


def _sq_err(a: bytes, b: bytes) -> int:
    """sum((a_i - b_i)^2) using a C-accelerated pair histogram."""
    n = min(len(a), len(b))
    pairs = bytearray(2 * n)
    pairs[0::2], pairs[1::2] = a[:n], b[:n]
    hist = Counter(array.array("H", bytes(pairs)))
    total = 0
    for v, c in hist.items():
        x, y = v & 0xFF, v >> 8                         # byte order irrelevant: squared
        if x != y:
            total += c * (x - y) ** 2
    return total


def quality_metrics(cover, stego) -> dict:
    a, b = bytes(cover.units()), bytes(stego.units())
    x = _xor(a, b)
    diff_units = len(x) - x.count(0)
    sq = _sq_err(a, b)
    out = {"changed_units": diff_units, "total_units": len(a),
           "changed_pct": 100.0 * diff_units / max(1, len(a)),
           "mse": sq / max(1, len(a)), "max_abs_diff": max(x) if x else 0}
    if cover.kind == "image":
        out["psnr_db"] = math.inf if sq == 0 else 10 * math.log10(255 ** 2 / out["mse"])
    else:
        # the unit is the least-significant byte of each sample and the high bytes are untouched,
        # so the per-sample error equals the unit error exactly
        w = cover.sampwidth
        if w == 2:
            sa = array.array("h", bytes(cover.frames))
            sig = sum(v * v for v in sa)
        elif w == 1:
            sig = sum((v - 128) ** 2 for v in cover.frames)
        else:
            top = cover.frames[w - 1::w]
            sig = sum((((v + 128) & 0xFF) - 128) ** 2 for v in top) * (256 ** (2 * (w - 1)))
        out["snr_db"] = math.inf if sq == 0 else 10 * math.log10(max(sig, 1) / sq)
        out["psnr_db"] = math.inf if sq == 0 else 10 * math.log10(
            (2 ** (8 * w - 1)) ** 2 / (sq / max(1, len(a))))
    return out


def difference_image(cover: ImageCover, stego: ImageCover, gain: int = 64) -> ImageCover:
    """Amplified (cover XOR stego) picture so the LSB changes become visible
    (black = unchanged)."""
    x = _xor(bytes(cover.units()), bytes(stego.units()))
    d = x.translate(bytes(min(255, v * gain) for v in range(256)))
    img = stego.img.copy()
    out = ImageCover(img)
    out.set_units(d)
    if img.channels in (2, 4):                      # make alpha opaque
        img.pixels[img.colour_channels::img.channels] = b"\xff" * (img.width * img.height)
    return out


# --------------------------------------------------------------------------
# tamper helpers (negative cases)
def tamper_content(stego_path: str, out_path: str) -> str:
    """Modify *high* bits well away from the LSBs: a visible red square /
    a 0.25 s silent gap.  Expected verdict: Tampered."""
    cover = load_cover(stego_path)
    if isinstance(cover, ImageCover):
        w, h, c, cc = cover.width, cover.height, cover.img.channels, cover.colour_channels
        x0, y0, size = w // 2 - 20, h // 2 - 20, 40
        for y in range(max(0, y0), min(h, y0 + size)):
            for x in range(max(0, x0), min(w, x0 + size)):
                i = (y * w + x) * c
                cover.img.pixels[i] = 0xF0 | (cover.img.pixels[i] & 0x0F)  # keep LSBs, change high bits
                for k in range(1, cc):
                    cover.img.pixels[i + k] = 0x10 | (cover.img.pixels[i + k] & 0x0F)
        what = "40x40 red square painted at image centre (LSBs preserved)"
    else:
        w, ch = cover.sampwidth, cover.channels
        mid = cover.nframes // 2
        n = int(0.25 * cover.framerate)
        for f in range(mid, min(cover.nframes, mid + n)):
            for k in range(ch):
                base = (f * ch + k) * w
                for j in range(1, w):
                    cover.frames[base + j] = 0
                if w == 1:
                    cover.frames[base] = 0x80 | (cover.frames[base] & 0x0F)
        what = "0.25 s of audio at the midpoint muted (LSB byte preserved)"
    cover.save(out_path)
    return what


def tamper_lsb_region(stego_path: str, out_path: str, n_lsb: int, start_unit: int, span: int = 4096) -> str:
    """Overwrite LSBs inside the payload span -> container corrupted. Expected: Tampered."""
    cover = load_cover(stego_path)
    units = cover.units()
    total = len(units)
    mask = (1 << n_lsb) - 1
    for i in range(span):
        u = (start_unit + pl.HEADER_LEN * 8 // n_lsb + 8 + i) % total
        units[u] ^= mask
    cover.set_units(units)
    cover.save(out_path)
    return f"{span} units of LSBs inside the payload span inverted"


def strip_payload(stego_path: str, out_path: str, n_lsb: int) -> str:
    """Zero every LSB (what a 'cleaning' filter or re-encoding would do). Expected: Payload Missing."""
    cover = load_cover(stego_path)
    keep = 0xFF ^ ((1 << n_lsb) - 1)
    cover.set_units(bytes(cover.units()).translate(bytes(b & keep for b in range(256))))
    cover.save(out_path)
    return f"all {n_lsb} LSB planes zeroed"


def truncate_audio(stego_path: str, out_path: str, seconds: float = 0.5) -> str:
    cover = load_cover(stego_path)
    if not isinstance(cover, AudioCover):
        raise CoverError("truncate is an audio tamper case")
    cut = int(seconds * cover.framerate) * cover.channels * cover.sampwidth
    cover.frames = cover.frames[:-cut]
    cover.save(out_path)
    return f"last {seconds} s of audio removed"
