"""Generate the sample cover objects (samples/) and the sample payload
files (samples/payloads/) shipped with the project.

    python tools/make_samples.py            # covers + payloads

Covers need only the standard library.  The picture / audio / video payloads
additionally use Pillow and ffmpeg when available (they are already included
in the zip, so regenerating them is optional).
"""
from __future__ import annotations

import math
import os
import random
import shutil
import struct
import subprocess
import sys
import wave

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from stegoverify import pngcodec  # noqa: E402

OUT = os.path.join(os.path.dirname(__file__), "..", "samples")


def make_image(path, w=512, h=384, seed=7, noise=4.0):
    """A colourful, photo-like synthetic scene: sky gradient, sun, hills, noise.
    Drawn in a 512x384 coordinate system and scaled to w x h."""
    rnd = random.Random(seed)
    px = bytearray(w * h * 3)
    W0, H0 = 512, 384
    hills = [(rnd.uniform(0, W0), rnd.uniform(60, 160), rnd.uniform(40, 120)) for _ in range(6)]
    for yy in range(h):
        y = yy * H0 / h
        for xx in range(w):
            x = xx * W0 / w
            t = y / H0
            r, g, b = 40 + 120 * t, 90 + 110 * t, 180 + 60 * (1 - t)
            d = math.hypot(x - W0 * 0.72, y - H0 * 0.28)
            if d < 38:
                r, g, b = 255, 230, 120
            elif d < 60:
                k = (60 - d) / 22
                r, g, b = r + (255 - r) * k, g + (200 - g) * k, b + (80 - b) * k * 0.5
            ground = H0 * 0.62
            for cx, hh, ww in hills:
                ground = min(ground, H0 * 0.62 - hh * math.exp(-((x - cx) / ww) ** 2))
            if y > ground:
                k = (y - ground) / (H0 - ground)
                r, g, b = 30 + 40 * k, 110 + 60 * k, 40 + 20 * k
            n = rnd.gauss(0, noise) if noise else 0.0
            i = (yy * w + xx) * 3
            px[i] = max(0, min(255, int(r + n)))
            px[i + 1] = max(0, min(255, int(g + n)))
            px[i + 2] = max(0, min(255, int(b + n)))
    pngcodec.save(pngcodec.Image(w, h, 3, px), path)


def make_small_image(path, w=48, h=32):
    """Tiny image used to demonstrate the capacity check failing."""
    px = bytearray(((x * 5 + y * 3 + c * 40) & 0xFF) for y in range(h) for x in range(w) for c in range(3))
    pngcodec.save(pngcodec.Image(w, h, 3, px), path)


def make_audio(path, seconds=4.0, rate=22050, seed=3):
    """A stereo 16-bit PCM clip: two-note chime with decaying harmonics + soft noise."""
    rnd = random.Random(seed)
    n = int(seconds * rate)
    frames = bytearray()
    for i in range(n):
        t = i / rate
        env = math.exp(-1.2 * (t % 2.0))
        f = 440.0 if t < 2.0 else 554.37
        s = (math.sin(2 * math.pi * f * t) + 0.4 * math.sin(2 * math.pi * 2 * f * t)
             + 0.2 * math.sin(2 * math.pi * 3 * f * t)) * env
        s += rnd.gauss(0, 0.004)
        left = int(max(-1, min(1, s * 0.8)) * 32767)
        right = int(max(-1, min(1, s * 0.6 + 0.1 * math.sin(2 * math.pi * 0.5 * t))) * 32767)
        frames += struct.pack("<hh", left, right)
    with wave.open(path, "wb") as w:
        w.setnchannels(2)
        w.setsampwidth(2)
        w.setframerate(rate)
        w.writeframes(bytes(frames))


def make_small_audio(path, seconds=0.05, rate=8000):
    n = int(seconds * rate)
    frames = b"".join(struct.pack("<h", int(2000 * math.sin(i / 5))) for i in range(n))
    with wave.open(path, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(rate)
        w.writeframes(frames)


def make_music(path, seconds=20.0, rate=44100, channels=2, seed=11, note_len=0.5, quiet_every=8, lead=0.0):
    """Longer 16-bit PCM melody (pentatonic arpeggio with decaying harmonics).
    Every `quiet_every`-th note (and `lead` seconds at each end) is true
    digital silence, as in real recordings - LSB changes are easiest to spot
    there, both in the waveform difference and in the LSB plane."""
    rnd = random.Random(seed)
    scale = [261.63, 293.66, 329.63, 392.00, 440.00, 523.25, 587.33, 659.25]
    n = int(seconds * rate)
    notes = [rnd.choice(scale) for _ in range(int(seconds / note_len) + 1)]
    frames = bytearray(n * channels * 2)
    pos = 0
    for i in range(n):
        t = i / rate
        k = int(t / note_len)
        tn = t - k * note_len
        f = notes[k]
        rest = (k % quiet_every == quiet_every - 1) or t < lead or t > seconds - lead
        env = math.exp(-5 * tn) * min(1.0, tn * 200)
        if rest:
            s = 0.0                                    # true digital silence (all-zero samples)
        else:
            s = 0.7 * env * (math.sin(2 * math.pi * f * t) + 0.35 * math.sin(4 * math.pi * f * t)
                             + 0.15 * math.sin(6 * math.pi * f * t))
            s += rnd.gauss(0, 0.002)
        left = int(max(-1, min(1, s)) * 32767)
        if channels == 1:
            struct.pack_into("<h", frames, pos, left)
            pos += 2
        else:
            right = int(max(-1, min(1, s * 0.8)) * 32767)
            struct.pack_into("<hh", frames, pos, left, right)
            pos += 4
    with wave.open(path, "wb") as w:
        w.setnchannels(channels)
        w.setsampwidth(2)
        w.setframerate(rate)
        w.writeframes(bytes(frames[:pos]))


# --------------------------------------------------------------------------
# payload files (picture / audio / video / text) of different sizes
def make_payloads(out_dir):
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
    from stegoverify import constants as C
    os.makedirs(out_dir, exist_ok=True)
    P = lambda name: os.path.join(out_dir, name)  # noqa: E731

    with open(P("01_short_text_LO.txt"), "w", encoding="utf-8") as fh:
        fh.write(C.SHORT_MESSAGE)
    with open(P("02_large_text_overview.txt"), "w", encoding="utf-8") as fh:
        fh.write(C.LARGE_MESSAGE)
    with open(P("03_confidential_record.txt"), "w", encoding="utf-8") as fh:
        fh.write(C.CUSTOM_MESSAGE)

    # 04 small picture (PNG logo, a few KB) - built with our own PNG encoder
    w, h = 160, 120
    px = bytearray(w * h * 3)
    for y in range(h):
        for x in range(w):
            i = (y * w + x) * 3
            d = math.hypot(x - 80, y - 60)
            if d < 40:
                c = (230, 57, 70) if (x - 80) * (y - 60) >= 0 else (29, 53, 87)
            elif abs(y - 60) < 6 or abs(x - 80) < 6:
                c = (241, 250, 238)
            else:
                c = (69, 123, 157) if (x // 20 + y // 20) % 2 else (168, 218, 220)
            px[i:i + 3] = bytes(c)
    pngcodec.save(pngcodec.Image(w, h, 3, px), P("04_picture_logo.png"))

    # 05 photo (JPEG) - resized cover scene, needs Pillow
    try:
        from PIL import Image as PILImage
        with PILImage.open(os.path.join(OUT, "cover_image.png")) as im:
            im.convert("RGB").resize((480, 360)).save(P("05_picture_photo.jpg"), quality=85)
    except ImportError:
        print("  (Pillow not installed - skipped 05_picture_photo.jpg)")

    # 06 audio clip (WAV) - 3 s mono 16 kHz
    make_music(P("06_audio_clip.wav"), seconds=3.0, rate=16000, channels=1, seed=5, note_len=0.25, quiet_every=99)

    ff = shutil.which("ffmpeg")
    if not ff:
        print("  (ffmpeg not found - skipped MP3/MP4 payloads)")
        return
    q = [ff, "-hide_banner", "-loglevel", "error", "-y"]
    # 07 audio (MP3) - 10 s melody
    tmp = P("_tmp.wav")
    make_music(tmp, seconds=10.0, rate=44100, channels=2, seed=9, note_len=0.3, quiet_every=99)
    subprocess.run(q + ["-i", tmp, "-b:a", "96k", P("07_audio_song.mp3")], check=True)
    os.remove(tmp)
    # 08 small video (MP4) - 4 s 320x240 with tone
    subprocess.run(q + ["-f", "lavfi", "-i", "testsrc2=size=320x240:rate=15:duration=4",
                        "-f", "lavfi", "-i", "sine=frequency=660:duration=4",
                        "-c:v", "libx264", "-pix_fmt", "yuv420p", "-crf", "30", "-preset", "slow",
                        "-c:a", "aac", "-b:a", "48k", "-shortest", "-movflags", "+faststart",
                        P("08_video_small.mp4")], check=True)
    # 09 large video (MP4, ~2.5 MB) - used to demonstrate the "payload too big" error
    subprocess.run(q + ["-f", "lavfi", "-i", "testsrc2=size=640x480:rate=30:duration=10",
                        "-f", "lavfi", "-i", "sine=frequency=440:duration=10",
                        "-c:v", "libx264", "-pix_fmt", "yuv420p", "-b:v", "1900k", "-maxrate", "1900k",
                        "-bufsize", "2M", "-c:a", "aac", "-b:a", "96k", "-shortest",
                        "-movflags", "+faststart", P("09_video_large.mp4")], check=True)


if __name__ == "__main__":
    os.makedirs(OUT, exist_ok=True)
    only_payloads = "--payloads" in sys.argv
    if not only_payloads:
        make_image(os.path.join(OUT, "cover_image.png"))
        make_small_image(os.path.join(OUT, "tiny_image.png"))
        make_audio(os.path.join(OUT, "cover_audio.wav"))
        make_small_audio(os.path.join(OUT, "tiny_audio.wav"))
        print("building large covers (takes ~30 s)...")
        make_image(os.path.join(OUT, "cover_image_large.png"), 1280, 960, seed=21, noise=1.5)
        make_image(os.path.join(OUT, "cover_graphic.png"), 512, 384, seed=7, noise=0)
        make_music(os.path.join(OUT, "cover_audio_long.wav"), seconds=20.0, quiet_every=6, lead=1.0)
    make_payloads(os.path.join(OUT, "payloads"))
    print("samples written to", os.path.abspath(OUT))
    for root, _, files in os.walk(OUT):
        for f in sorted(files):
            p = os.path.join(root, f)
            print(f"  {os.path.relpath(p, OUT):<40} {os.path.getsize(p):>12,} bytes")
