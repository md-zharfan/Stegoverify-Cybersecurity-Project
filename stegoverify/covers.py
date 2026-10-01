"""Cover-object adapters for PNG images and WAV/PCM audio.

Both adapters expose the same tiny interface used by the LSB engine:

    units()            -> bytearray   one byte per "unit"; the n LSBs of each
                                      unit are the bits we may overwrite
    set_units(bytes)                  write the (modified) unit bytes back
    masked_hash(n)     -> bytes       SHA-256 over the cover with the n LSBs of
                                      every unit zeroed (the *stable
                                      representation* - identical before and
                                      after embedding, see docs/DESIGN.md)
    describe()         -> dict        structural metadata for the payload
    save(path)

For images a unit is one colour channel byte (alpha is left untouched so
transparency is never altered).  For audio a unit is the least-significant
byte of one PCM sample (little-endian), for every channel.
"""
from __future__ import annotations

import array
import hashlib
import os
import struct
import wave

from . import pngcodec

IMAGE_EXT = (".png",)
AUDIO_EXT = (".wav", ".wave")


class CoverError(ValueError):
    pass


def _mask_table(n_lsb: int) -> bytes:
    keep = 0xFF ^ ((1 << n_lsb) - 1)
    return bytes(b & keep for b in range(256))


class ImageCover:
    kind = "image"

    def __init__(self, img: pngcodec.Image, source: str = ""):
        self.img = img
        self.source = source

    @classmethod
    def load(cls, path: str) -> "ImageCover":
        try:
            return cls(pngcodec.load(path), path)
        except pngcodec.PNGError as e:
            raise CoverError(str(e)) from e

    # -- geometry ---------------------------------------------------------
    @property
    def width(self):
        return self.img.width

    @property
    def height(self):
        return self.img.height

    @property
    def colour_channels(self):
        return self.img.colour_channels

    @property
    def num_units(self) -> int:
        return self.img.width * self.img.height * self.img.colour_channels

    def pixel_to_unit(self, x: int, y: int) -> int:
        if not (0 <= x < self.width and 0 <= y < self.height):
            raise CoverError(f"pixel ({x},{y}) is outside the {self.width}x{self.height} image")
        return (y * self.width + x) * self.colour_channels

    def unit_to_pixel(self, u: int):
        p = u // self.colour_channels
        return p % self.width, p // self.width

    # -- unit access -------------------------------------------------------
    def units(self) -> bytearray:
        c, cc = self.img.channels, self.img.colour_channels
        if c == cc:
            return bytearray(self.img.pixels)
        out = bytearray(self.num_units)
        for ch in range(cc):
            out[ch::cc] = self.img.pixels[ch::c]
        return out

    def set_units(self, units) -> None:
        c, cc = self.img.channels, self.img.colour_channels
        if c == cc:
            self.img.pixels[:] = units
            return
        for ch in range(cc):
            self.img.pixels[ch::c] = units[ch::cc]

    def masked_hash(self, n_lsb: int) -> bytes:
        h = hashlib.sha256()
        h.update(b"SVFY-IMG")
        h.update(struct.pack(">IIB", self.width, self.height, self.img.channels))
        h.update(bytes(self.units()).translate(_mask_table(n_lsb)))
        c, cc = self.img.channels, self.img.colour_channels
        if c != cc:                      # alpha plane is hashed unmodified
            h.update(bytes(self.img.pixels[cc::c]))
        return h.digest()

    def describe(self) -> dict:
        return {"format": "PNG", "width": self.width, "height": self.height,
                "mode": self.img.mode, "units": self.num_units}

    def save(self, path: str) -> None:
        pngcodec.save(self.img, path)

    def copy(self) -> "ImageCover":
        return ImageCover(self.img.copy(), self.source)


class AudioCover:
    kind = "audio"

    def __init__(self, params, frames: bytearray, source: str = ""):
        self.params = params          # wave _wave_params
        self.frames = frames
        self.source = source

    @classmethod
    def load(cls, path: str) -> "AudioCover":
        try:
            with wave.open(path, "rb") as w:
                params = w.getparams()
                frames = bytearray(w.readframes(w.getnframes()))
        except (wave.Error, EOFError) as e:
            raise CoverError(f"cannot read WAV/PCM file: {e}") from e
        if params.comptype != "NONE":
            raise CoverError("only uncompressed PCM WAV is supported")
        return cls(params, frames, path)

    @property
    def sampwidth(self):
        return self.params.sampwidth

    @property
    def channels(self):
        return self.params.nchannels

    @property
    def framerate(self):
        return self.params.framerate

    @property
    def nframes(self):
        return len(self.frames) // (self.sampwidth * self.channels)

    @property
    def duration(self) -> float:
        return self.nframes / self.framerate

    @property
    def num_units(self) -> int:
        return len(self.frames) // self.sampwidth

    def sample_to_unit(self, sample_index: int) -> int:
        """sample_index counts frames (all channels of one instant = 1 frame)."""
        if not (0 <= sample_index < self.nframes):
            raise CoverError(f"sample {sample_index} is outside the file ({self.nframes} frames)")
        return sample_index * self.channels

    def seconds_to_unit(self, seconds: float) -> int:
        return self.sample_to_unit(int(seconds * self.framerate))

    def unit_to_sample(self, u: int) -> int:
        return u // self.channels

    def units(self) -> bytearray:
        return bytearray(self.frames[0::self.sampwidth])

    def set_units(self, units) -> None:
        self.frames[0::self.sampwidth] = units

    def masked_hash(self, n_lsb: int) -> bytes:
        h = hashlib.sha256()
        h.update(b"SVFY-WAV")
        h.update(struct.pack(">BBI", self.sampwidth, self.channels, self.framerate))
        w = self.sampwidth
        if w == 1:
            h.update(bytes(self.frames).translate(_mask_table(n_lsb)))
        else:
            tmp = bytearray(self.frames)
            tmp[0::w] = bytes(tmp[0::w]).translate(_mask_table(n_lsb))
            h.update(bytes(tmp))
        return h.digest()

    def describe(self) -> dict:
        return {"format": "WAV/PCM", "sample_rate": self.framerate, "channels": self.channels,
                "bits_per_sample": self.sampwidth * 8, "frames": self.nframes,
                "duration_s": round(self.duration, 3), "units": self.num_units}

    def save(self, path: str) -> None:
        with wave.open(path, "wb") as w:
            w.setparams(self.params._replace(nframes=self.nframes))
            w.writeframes(bytes(self.frames))

    def copy(self) -> "AudioCover":
        return AudioCover(self.params, bytearray(self.frames), self.source)

    def envelope(self, buckets: int = 400):
        """(min, max) pairs of channel-0 samples for a quick waveform sketch."""
        w = self.sampwidth
        if w == 2:
            arr = array.array("h", bytes(self.frames))
            if array.array("h").itemsize != 2:
                raise CoverError("unexpected platform int size")
            vals = arr[0::self.channels]
            scale = 32768.0
        elif w == 1:
            vals = [b - 128 for b in self.frames[0::self.channels]]
            scale = 128.0
        else:  # 24/32-bit: use the top byte only for the sketch
            top = self.frames[w - 1::w * self.channels]
            vals = [((b + 128) & 0xFF) - 128 for b in top]
            scale = 128.0
        n = len(vals)
        if n == 0:
            return []
        step = max(1, n // buckets)
        out = []
        for i in range(0, n, step):
            seg = vals[i:i + step]
            out.append((min(seg) / scale, max(seg) / scale))
        return out


def load_cover(path: str):
    ext = os.path.splitext(path)[1].lower()
    if ext in IMAGE_EXT:
        return ImageCover.load(path)
    if ext in AUDIO_EXT:
        return AudioCover.load(path)
    raise CoverError("unsupported cover type - use a .png image or a .wav audio file "
                     "(JPEG/MP3 are lossy and would destroy the LSB payload)")
