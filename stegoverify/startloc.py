"""Start-location design (FR7 / Learning Outcome 6).

Two modes are offered in the GUI:

* **manual** - the sender picks an explicit pixel (x, y) or audio sample index.
  The value must be shared with the receiver out-of-band.  Simple, but easy to
  guess and a nuisance to manage.

* **keyed** (default, our innovation) - the start unit is *derived*:

        start = HMAC-SHA256(secret, "SVFY-start" | cover_kind | masked_hash | n_lsb)
                mod number_of_units

  where `masked_hash` is the SHA-256 of the cover with the n LSBs of every
  unit zeroed.  Embedding only ever touches those LSBs, so the *stego* object
  has exactly the same masked hash as the original cover.  The receiver can
  therefore recompute the identical start unit from the stego file itself plus
  the shared secret - nothing about the location is stored in the file or sent
  alongside it.

  Security properties:
   - without the secret the location is uniformly distributed over the whole
     cover (millions of candidates) and is different for every cover, every
     LSB setting and every re-encode of the same picture;
   - the location is *content-bound*: modifying the cover's higher bits
     changes the masked hash and therefore the derived location, so a tampered
     file no longer even points at its own payload;
   - HMAC is a PRF, so observing the location for one file leaks nothing about
     the location in another.

  The same secret can also be typed wrongly on purpose to demonstrate the
  "Wrong Start Location" verdict.
"""
from __future__ import annotations

from . import crypto_utils as cu

MODE_KEYED = "keyed"
MODE_MANUAL = "manual"


def derive_start(secret: str, cover_kind: str, masked_hash: bytes, n_lsb: int, num_units: int) -> int:
    if not secret:
        raise ValueError("a start-location secret is required in keyed mode")
    msg = b"SVFY-start|" + cover_kind.encode() + b"|" + masked_hash + bytes([n_lsb])
    mac = cu.hmac_sha256(secret.encode("utf-8"), msg)
    return int.from_bytes(mac, "big") % num_units


def describe_unit(cover, unit: int) -> str:
    if cover.kind == "image":
        x, y = cover.unit_to_pixel(unit)
        ch = "RGB"[unit % cover.colour_channels] if cover.colour_channels == 3 else f"ch{unit % cover.colour_channels}"
        return f"unit {unit} = pixel (x={x}, y={y}) channel {ch}"
    s = cover.unit_to_sample(unit)
    return f"unit {unit} = sample {s} (t = {s / cover.framerate:.3f} s, channel {unit % cover.channels})"
