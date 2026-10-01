"""Minimal, dependency-free PNG codec (8-bit, non-interlaced).

Supports colour types 0 (grey), 2 (RGB), 3 (palette -> expanded to RGB),
4 (grey+alpha) and 6 (RGBA).  Written so the whole project only needs the
Python standard library plus `cryptography`.
"""
from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass

_SIG = b"\x89PNG\r\n\x1a\n"
_CHANNELS = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}


class PNGError(ValueError):
    pass


@dataclass
class Image:
    width: int
    height: int
    channels: int          # 1 = L, 2 = LA, 3 = RGB, 4 = RGBA
    pixels: bytearray      # row-major, interleaved, 8 bits per channel

    @property
    def mode(self) -> str:
        return {1: "L", 2: "LA", 3: "RGB", 4: "RGBA"}[self.channels]

    @property
    def colour_channels(self) -> int:
        """Channels that carry colour (alpha excluded)."""
        return self.channels - (1 if self.channels in (2, 4) else 0)

    def copy(self) -> "Image":
        return Image(self.width, self.height, self.channels, bytearray(self.pixels))


def _paeth(a: int, b: int, c: int) -> int:
    p = a + b - c
    pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
    if pa <= pb and pa <= pc:
        return a
    return b if pb <= pc else c


def _unfilter(raw: bytes, width: int, height: int, bpp: int) -> bytearray:
    stride = width * bpp
    out = bytearray(stride * height)
    prev = bytearray(stride)
    pos = 0
    for y in range(height):
        ftype = raw[pos]
        pos += 1
        line = bytearray(raw[pos:pos + stride])
        pos += stride
        if ftype == 0:
            pass
        elif ftype == 1:
            for i in range(bpp, stride):
                line[i] = (line[i] + line[i - bpp]) & 0xFF
        elif ftype == 2:
            for i in range(stride):
                line[i] = (line[i] + prev[i]) & 0xFF
        elif ftype == 3:
            for i in range(stride):
                left = line[i - bpp] if i >= bpp else 0
                line[i] = (line[i] + ((left + prev[i]) >> 1)) & 0xFF
        elif ftype == 4:
            for i in range(stride):
                a = line[i - bpp] if i >= bpp else 0
                c = prev[i - bpp] if i >= bpp else 0
                line[i] = (line[i] + _paeth(a, prev[i], c)) & 0xFF
        else:
            raise PNGError(f"unknown PNG filter type {ftype}")
        out[y * stride:(y + 1) * stride] = line
        prev = line
    return out


def decode(data: bytes) -> Image:
    if not data.startswith(_SIG):
        raise PNGError("not a PNG file")
    pos = len(_SIG)
    width = height = depth = ctype = interlace = None
    palette = None
    idat = []
    while pos < len(data):
        (length,) = struct.unpack(">I", data[pos:pos + 4])
        ctag = data[pos + 4:pos + 8]
        body = data[pos + 8:pos + 8 + length]
        pos += 12 + length
        if ctag == b"IHDR":
            width, height, depth, ctype, _c, _f, interlace = struct.unpack(">IIBBBBB", body)
        elif ctag == b"PLTE":
            palette = body
        elif ctag == b"IDAT":
            idat.append(body)
        elif ctag == b"IEND":
            break
    if width is None:
        raise PNGError("missing IHDR")
    if depth != 8:
        raise PNGError(f"only 8-bit PNGs are supported (this file is {depth}-bit)")
    if interlace:
        raise PNGError("interlaced PNGs are not supported - re-save without interlacing")
    if ctype not in _CHANNELS:
        raise PNGError(f"unsupported PNG colour type {ctype}")
    channels = _CHANNELS[ctype]
    raw = zlib.decompress(b"".join(idat))
    pixels = _unfilter(raw, width, height, channels)
    if ctype == 3:
        if palette is None:
            raise PNGError("palette PNG without PLTE")
        rgb = bytearray(width * height * 3)
        for i, idx in enumerate(pixels):
            rgb[i * 3:i * 3 + 3] = palette[idx * 3:idx * 3 + 3]
        pixels, channels = rgb, 3
    return Image(width, height, channels, pixels)


def encode(img: Image) -> bytes:
    ctype = {1: 0, 2: 4, 3: 2, 4: 6}[img.channels]
    stride = img.width * img.channels
    raw = bytearray()
    for y in range(img.height):
        raw.append(0)  # filter type None -> lossless, keeps our LSBs intact
        raw += img.pixels[y * stride:(y + 1) * stride]

    def chunk(tag: bytes, body: bytes) -> bytes:
        return (struct.pack(">I", len(body)) + tag + body
                + struct.pack(">I", zlib.crc32(tag + body) & 0xFFFFFFFF))

    ihdr = struct.pack(">IIBBBBB", img.width, img.height, 8, ctype, 0, 0, 0)
    return (_SIG + chunk(b"IHDR", ihdr)
            + chunk(b"IDAT", zlib.compress(bytes(raw), 6))
            + chunk(b"IEND", b""))


def _load_with_pillow(path: str) -> Image | None:
    """Fast path when Pillow is installed (optional dependency).  Also copes
    with 16-bit and interlaced PNGs by converting them to 8-bit."""
    try:
        from PIL import Image as PILImage
    except ImportError:
        return None
    with PILImage.open(path) as im:
        if im.format != "PNG":
            raise PNGError(f"not a PNG file (detected {im.format})")
        if im.mode not in ("L", "LA", "RGB", "RGBA"):
            im = im.convert("RGBA" if ("A" in im.mode or "transparency" in im.info) else "RGB")
        ch = {"L": 1, "LA": 2, "RGB": 3, "RGBA": 4}[im.mode]
        return Image(im.width, im.height, ch, bytearray(im.tobytes()))


def load(path: str) -> Image:
    with open(path, "rb") as fh:
        data = fh.read()
    if not data.startswith(_SIG):
        raise PNGError("not a PNG file")
    try:
        img = _load_with_pillow(path)
        if img is not None:
            return img
    except PNGError:
        raise
    except Exception:
        pass                              # fall back to the built-in decoder
    return decode(data)


def save(img: Image, path: str) -> None:
    with open(path, "wb") as fh:
        fh.write(encode(img))
