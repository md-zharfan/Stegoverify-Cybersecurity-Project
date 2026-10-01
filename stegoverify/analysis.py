"""Steganalysis: how visible / detectable is the embedded payload?

Two families of checks are provided.

Non-blind (the analyst has the original cover as well as the stego object)
    * distortion metrics  - MSE, PSNR, SNR, % units changed, max change
    * amplified difference image / difference waveform (stego - cover)
    * where the changes are (difference envelope along the file)
    * histogram overlay of cover vs stego values

Blind (only the suspect file)
    * LSB-plane view      - the "visual attack": the chosen bit of every unit
                            drawn as black/white.  Clean graphics and digital
                            silence have a structured LSB plane; an embedded
                            (random-looking) payload shows up as a noise band.
    * chi-square attack   - Westfeld & Pfitzmann "pairs of values" test run per
                            block of the file.  LSB replacement equalises the
                            counts of values that differ only in their low n
                            bits; p close to 1 means the block's histogram looks
                            equalised, i.e. embedding is likely.  Works for
                            images; in 16-bit audio the low byte is random
                            anyway, so the test is not meaningful there.
    * silence check       - in digital silence every sample is 0; non-zero
                            values of at most +/-(2^n - 1) inside silent
                            stretches betray LSB embedding in audio.
    * format-signature scan - searches for this tool's own container marker
                            (shows that a known tool format is detectable).
"""
from __future__ import annotations

import array
import math
from collections import Counter

from . import lsb, payload as pl
from .covers import AudioCover, ImageCover


# --------------------------------------------------------------------------
# statistics helpers
def _gammq(a: float, x: float) -> float:
    """Regularised upper incomplete gamma Q(a, x) (Numerical Recipes)."""
    if x <= 0:
        return 1.0
    gln = math.lgamma(a)
    if x < a + 1:                                  # series
        ap, s = a, 1.0 / a
        d = s
        for _ in range(2000):
            ap += 1
            d *= x / ap
            s += d
            if abs(d) < abs(s) * 1e-12:
                break
        return max(0.0, 1.0 - s * math.exp(-x + a * math.log(x) - gln))
    tiny = 1e-300                                  # continued fraction
    b = x + 1 - a
    c, d = 1 / tiny, 1 / b
    h = d
    for i in range(1, 2000):
        an = -i * (i - a)
        b += 2
        d = an * d + b
        d = d if abs(d) > tiny else tiny
        c = b + an / c
        c = c if abs(c) > tiny else tiny
        d = 1 / d
        de = d * c
        h *= de
        if abs(de - 1) < 1e-12:
            break
    return min(1.0, math.exp(-x + a * math.log(x) - gln) * h)


def chi_square_p(hist, n_lsb: int = 1) -> float | None:
    """p-value that the histogram is 'equalised' within groups of 2^n values
    (i.e. consistent with LSB replacement).  None if too little data."""
    g = 1 << n_lsb
    stat, df = 0.0, 0
    for base in range(0, 256, g):
        cnt = [hist[base + k] for k in range(g)]
        e = sum(cnt) / g
        if e < 5:
            continue
        stat += sum((c - e) ** 2 / e for c in cnt)
        df += g - 1
    if df == 0:
        return None
    return _gammq(df / 2.0, stat / 2.0)


def histogram(data) -> list[int]:
    c = Counter(bytes(data))
    return [c.get(v, 0) for v in range(256)]


def chi_square_blocks(units, n_lsb: int = 1, blocks: int = 48) -> list[tuple[int, int, float | None]]:
    """[(start_unit, end_unit, p)] for consecutive blocks along the file."""
    total = len(units)
    blocks = max(1, min(blocks, total // 64 or 1))
    size = total // blocks
    out = []
    data = bytes(units)
    for i in range(blocks):
        a = i * size
        b = total if i == blocks - 1 else a + size
        out.append((a, b, chi_square_p(histogram(data[a:b]), n_lsb)))
    return out


# --------------------------------------------------------------------------
# non-blind comparison
def xor_units(cover, stego) -> bytes:
    a, b = bytes(cover.units()), bytes(stego.units())
    n = min(len(a), len(b))
    return (int.from_bytes(a[:n], "big") ^ int.from_bytes(b[:n], "big")).to_bytes(n, "big")


def changed_region(cover, stego) -> tuple[int, int, int] | None:
    """(first_changed_unit, last_changed_unit, count) or None if identical.
    With wrap-around the payload may occupy the end *and* the start of the file."""
    x = xor_units(cover, stego)
    count = len(x) - x.count(0)
    if count == 0:
        return None
    first = next(i for i, v in enumerate(x) if v)
    last = len(x) - 1 - next(i for i, v in enumerate(reversed(x)) if v)
    return first, last, count


def change_envelope(cover, stego, buckets: int = 400) -> list[float]:
    """Fraction of units changed per bucket along the file (0..1)."""
    x = xor_units(cover, stego)
    n = len(x)
    if n == 0:
        return []
    step = max(1, math.ceil(n / buckets))
    return [(len(x[i:i + step]) - x[i:i + step].count(0)) / len(x[i:i + step]) for i in range(0, n, step)]


def samples(audio: AudioCover, channel: int = 0):
    """All samples of one channel as Python ints (signed, full scale)."""
    w, ch = audio.sampwidth, audio.channels
    if w == 2:
        arr = array.array("h", bytes(audio.frames))
        return arr[channel::ch]
    if w == 1:
        return [b - 128 for b in audio.frames[channel::ch]]
    frames = bytes(audio.frames)
    out = []
    stride = w * ch
    for i in range(channel * w, len(frames), stride):
        out.append(int.from_bytes(frames[i:i + w], "little", signed=True))
    return out


def sample_histogram(audio: AudioCover, lo: int = -48, hi: int = 48) -> list[int]:
    vals = []
    for ch in range(audio.channels):
        vals.extend(samples(audio, ch))
    c = Counter(v for v in vals if lo <= v <= hi)
    return [c.get(v, 0) for v in range(lo, hi + 1)]


def silence_check(audio: AudioCover, n_lsb: int = 1, block: int = 2048) -> dict:
    """Blind audio check: look at stretches whose samples are all within
    +/-(2^n-1) ("would be silence if the LSBs were cleared").  In a genuine
    recording those stretches are digital silence (all zero); after LSB
    embedding they are filled with small non-zero values."""
    lim = (1 << n_lsb) - 1
    vals = samples(audio, 0)
    quiet_blocks = noisy = 0
    positions = []
    for i in range(0, len(vals) - block + 1, block):
        seg = vals[i:i + block]
        if max(seg) <= lim and min(seg) >= -lim:
            quiet_blocks += 1
            nz = sum(1 for v in seg if v)
            if nz > block * 0.05:
                noisy += 1
                positions.append(i)
    return {"quiet_blocks": quiet_blocks, "suspicious_blocks": noisy, "block": block,
            "positions": positions, "total_blocks": len(vals) // block}


def signature_scan(obj, n_lsb: int | None = None) -> list[tuple[int, int]]:
    """[(n_lsb, unit)] where this tool's container marker was found."""
    units = obj.units()
    hits = []
    for n in ([n_lsb] if n_lsb else range(1, 9)):
        for u in lsb.find_pattern(units, n, pl.MAGIC, limit=4):
            try:
                pl.parse_header(lsb.extract(units, u, n, pl.HEADER_LEN))
                hits.append((n, u))
            except (pl.ContainerError, ValueError):
                pass
    return hits


# --------------------------------------------------------------------------
# pictures for the GUI
def lsb_plane_image(obj, bit: int = 0, width: int | None = None) -> ImageCover:
    """Bit plane as a picture.  Images keep their geometry (each colour channel
    shows its own bit, so a random plane looks like colour noise); audio units
    are laid out row by row (time runs left-to-right, top-to-bottom) in a
    roughly 4:3 greyscale picture."""
    from .pngcodec import Image
    table = bytes(255 if (v >> bit) & 1 else 0 for v in range(256))
    if isinstance(obj, ImageCover):
        units = bytes(obj.units()).translate(table)
        cc = obj.colour_channels
        img = Image(obj.width, obj.height, cc if cc in (1, 3) else 3, bytearray())
        if cc in (1, 3):
            img.pixels = bytearray(units)
        else:                                      # 2 colour channels cannot happen; keep safe
            img.pixels = bytearray(units[0::cc] * 3)
        return ImageCover(img)
    units = bytes(obj.units()).translate(table)
    if width is None:
        width = max(64, int(math.sqrt(len(units) * 4 / 3)))
    height = max(1, len(units) // width)
    units = units[:width * height]
    return ImageCover(Image(width, height, 1, bytearray(units)))


def crop(obj: ImageCover, x: int, y: int, w: int, h: int) -> ImageCover:
    from .pngcodec import Image
    x = max(0, min(obj.width - 1, x))
    y = max(0, min(obj.height - 1, y))
    w = min(w, obj.width - x)
    h = min(h, obj.height - y)
    c = obj.img.channels
    rows = bytearray()
    for yy in range(y, y + h):
        s = (yy * obj.width + x) * c
        rows += obj.img.pixels[s:s + w * c]
    return ImageCover(Image(w, h, c, rows))
