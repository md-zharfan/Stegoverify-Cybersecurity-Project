"""Generic n-LSB replacement engine (n = 1..8) over a bytearray of *units*.

The payload bit-stream (MSB first) is cut into n-bit chunks; chunk i replaces
the n least-significant bits of unit (start + i) mod N.  Because indices wrap
around the end of the cover, *every* unit index is a valid start location and
capacity never depends on where the payload begins.

Implementation note: everything is done with C-speed primitives
(bytes.translate, extended slicing and big-integer bitwise OR) instead of a
Python loop per bit, so multi-megabyte payloads (audio / video files) embed
and extract in well under a second on a laptop.
"""
from __future__ import annotations

import math


def check_n(n_lsb: int) -> None:
    if not 1 <= int(n_lsb) <= 8:
        raise ValueError("number of LSBs must be between 1 and 8")


def capacity_bytes(num_units: int, n_lsb: int) -> int:
    check_n(n_lsb)
    return (num_units * n_lsb) // 8


def units_needed(num_bytes: int, n_lsb: int) -> int:
    return math.ceil(num_bytes * 8 / n_lsb)


# --------------------------------------------------------------------------
# lookup tables
_BIT_OF = [bytes((b >> (7 - k)) & 1 for b in range(256)) for k in range(8)]          # byte -> bit k (MSB first)
_BIT_TO = [bytes(((b & 1) << s) for b in range(256)) for s in range(8)]               # 0/1 -> 1<<s
_MASK = {n: bytes(b & ((1 << n) - 1) for b in range(256)) for n in range(1, 9)}      # keep low n bits
_KEEP = {n: bytes(b & (0xFF ^ ((1 << n) - 1)) for b in range(256)) for n in range(1, 9)}  # clear low n bits
_CHUNK_BIT = {n: [bytes((c >> (n - 1 - j)) & 1 for c in range(256)) for j in range(n)] for n in range(1, 9)}


def _or_bytes(a: bytes, b: bytes) -> bytes:
    """Element-wise OR of two equal-length byte strings (via big ints)."""
    if not a:
        return b""
    return (int.from_bytes(a, "big") | int.from_bytes(b, "big")).to_bytes(len(a), "big")


def _to_bits(data: bytes) -> bytearray:
    """One byte (0/1) per bit, MSB first."""
    bits = bytearray(len(data) * 8)
    for k in range(8):
        bits[k::8] = data.translate(_BIT_OF[k])
    return bits


def _from_bits(bits) -> bytes:
    """Inverse of _to_bits (len(bits) must be a multiple of 8)."""
    nbytes = len(bits) // 8
    acc = 0
    for k in range(8):
        acc |= int.from_bytes(bytes(bits[k::8]).translate(_BIT_TO[7 - k]), "big")
    return acc.to_bytes(nbytes, "big") if nbytes else b""


def bytes_to_chunks(data: bytes, n_lsb: int) -> bytes:
    """Split data (MSB first) into n-bit chunks, one chunk value per output byte."""
    check_n(n_lsb)
    data = bytes(data)
    if not data:
        return b""
    if n_lsb == 8:
        return data
    bits = _to_bits(data)
    bits += bytes((-len(bits)) % n_lsb)
    count = len(bits) // n_lsb
    acc = 0
    for j in range(n_lsb):
        acc |= int.from_bytes(bytes(bits[j::n_lsb]).translate(_BIT_TO[n_lsb - 1 - j]), "big")
    return acc.to_bytes(count, "big")


def chunks_to_bytes(chunks, n_lsb: int, num_bytes: int) -> bytes:
    check_n(n_lsb)
    chunks = bytes(chunks)
    if n_lsb == 8:
        if len(chunks) < num_bytes:
            raise ValueError("not enough chunks for the requested byte count")
        return chunks[:num_bytes]
    if len(chunks) * n_lsb < num_bytes * 8:
        raise ValueError("not enough chunks for the requested byte count")
    bits = bytearray(len(chunks) * n_lsb)
    for j in range(n_lsb):
        bits[j::n_lsb] = chunks.translate(_CHUNK_BIT[n_lsb][j])
    return _from_bits(bits[:num_bytes * 8])


def _wrapped_indices(start: int, count: int, total: int):
    """Yield (slice_start, slice_stop) pairs covering count units from start with wrap."""
    if count > total:
        raise ValueError("payload needs more units than the cover has")
    start %= total
    end = start + count
    if end <= total:
        yield start, end
    else:
        yield start, total
        yield 0, end - total


def embed(units: bytearray, data: bytes, start: int, n_lsb: int) -> int:
    """Embed `data` in place.  Returns the number of unit bytes that changed."""
    chunks = bytes_to_chunks(data, n_lsb)
    total = len(units)
    if len(chunks) > total:
        raise ValueError(f"payload ({len(data)} bytes) exceeds capacity "
                         f"({capacity_bytes(total, n_lsb)} bytes at {n_lsb} LSB)")
    changed = 0
    ci = 0
    for a, b in _wrapped_indices(start, len(chunks), total):
        seg = bytes(units[a:b])
        new = _or_bytes(seg.translate(_KEEP[n_lsb]), chunks[ci:ci + (b - a)])
        diff = (int.from_bytes(seg, "big") ^ int.from_bytes(new, "big")).to_bytes(b - a, "big")
        changed += (b - a) - diff.count(0)
        units[a:b] = new
        ci += b - a
    return changed


def extract(units, start: int, n_lsb: int, num_bytes: int) -> bytes:
    check_n(n_lsb)
    count = units_needed(num_bytes, n_lsb)
    total = len(units)
    if count > total:
        raise ValueError("requested more data than the cover can hold")
    parts = [bytes(units[a:b]).translate(_MASK[n_lsb]) for a, b in _wrapped_indices(start, count, total)]
    return chunks_to_bytes(b"".join(parts), n_lsb, num_bytes)


def find_pattern(units, n_lsb: int, pattern: bytes, limit: int = 8) -> list[int]:
    """Unit offsets (wrap-aware) at which an embedded `pattern` begins."""
    check_n(n_lsb)
    full = (len(pattern) * 8) // n_lsb            # only whole chunks are fully determined
    pat = bytes_to_chunks(pattern, n_lsb)[:full]
    stream = bytes(units).translate(_MASK[n_lsb])
    stream += stream[:len(pat)]
    hits, pos, total = [], 0, len(units)
    while len(hits) < limit:
        i = stream.find(pat, pos)
        if i < 0 or i >= total:
            break
        hits.append(i)
        pos = i + 1
    return hits


def lsb_plane(units, bit: int = 0) -> bytes:
    """0/1 per unit: the value of bit `bit` (0 = least significant)."""
    return bytes(units).translate(bytes((b >> bit) & 1 for b in range(256)))
