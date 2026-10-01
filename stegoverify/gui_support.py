"""Small helpers shared by the Tkinter GUI: media playback / opening files
with the OS default app, image thumbnails without Pillow, waveform drawing."""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import tkinter as tk

from . import pngcodec
from .covers import AudioCover, ImageCover

_TMP = tempfile.mkdtemp(prefix="stegoverify_")


def open_with_default_app(path: str) -> str:
    try:
        if sys.platform.startswith("win"):
            os.startfile(path)  # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            subprocess.Popen(["open", path])
        else:
            subprocess.Popen(["xdg-open", path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return f"opened {os.path.basename(path)} with the system default application"
    except Exception as e:  # pragma: no cover
        return f"could not open {path}: {e}"


_players: list[subprocess.Popen] = []


def stop_audio() -> None:
    if sys.platform.startswith("win"):
        try:
            import winsound
            winsound.PlaySound(None, winsound.SND_PURGE)
        except Exception:
            pass
    for p in _players:
        if p.poll() is None:
            p.terminate()
    _players.clear()


def play_audio(path: str) -> str:
    """Play a WAV with whatever the platform offers (no third-party deps)."""
    stop_audio()
    if sys.platform.startswith("win"):
        import winsound
        winsound.PlaySound(path, winsound.SND_FILENAME | winsound.SND_ASYNC)
        return "playing via winsound"
    candidates = ([["afplay", path]] if sys.platform == "darwin" else
                  [["paplay", path], ["aplay", "-q", path], ["ffplay", "-nodisp", "-autoexit", "-loglevel", "quiet", path],
                   ["play", "-q", path]])
    for cmd in candidates:
        if shutil.which(cmd[0]):
            _players.append(subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
            return f"playing via {cmd[0]}"
    return open_with_default_app(path)


# --------------------------------------------------------------------------
def photo_for(path_or_cover, max_w: int = 420, max_h: int = 300) -> tuple[tk.PhotoImage, str]:
    """Return a Tk PhotoImage (Tk 8.6 decodes PNG natively) scaled to fit."""
    if isinstance(path_or_cover, ImageCover):
        path = os.path.join(_TMP, f"prev_{id(path_or_cover)}.png")
        pngcodec.save(path_or_cover.img, path)
    else:
        path = path_or_cover
    photo = tk.PhotoImage(file=path)
    k = max(1, -(-photo.width() // max_w), -(-photo.height() // max_h))
    if k > 1:
        photo = photo.subsample(k, k)
    return photo, f"{'1:%d' % k if k > 1 else '1:1'}"


def draw_waveform(canvas: tk.Canvas, cover: AudioCover | None, colour="#2b6cb0", marker_unit: int | None = None):
    canvas.delete("all")
    w = int(canvas.winfo_width() or canvas["width"])
    h = int(canvas.winfo_height() or canvas["height"])
    mid = h // 2
    canvas.create_line(0, mid, w, mid, fill="#cbd5e0")
    if cover is None:
        return
    env = cover.envelope(buckets=max(50, w))
    if not env:
        return
    step = w / len(env)
    for i, (lo, hi) in enumerate(env):
        x = int(i * step)
        canvas.create_line(x, mid - hi * (mid - 2), x, mid - lo * (mid - 2), fill=colour)
    if marker_unit is not None and cover.num_units:
        x = int(marker_unit / cover.num_units * w)
        canvas.create_line(x, 0, x, h, fill="#e53e3e", width=2, dash=(4, 2))
        canvas.create_text(min(w - 4, x + 4), 8, text="payload start", anchor="nw", fill="#e53e3e", font=("TkDefaultFont", 8))


def temp_path(name: str) -> str:
    return os.path.join(_TMP, name)
