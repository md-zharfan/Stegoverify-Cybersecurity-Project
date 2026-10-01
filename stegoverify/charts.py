"""Tiny chart toolkit for Tk canvases (line / step / bar series, shaded
bands, legend, hover read-out).  Colours follow a validated colour-blind-safe
pair: cover = blue, stego = orange."""
from __future__ import annotations

import math
import tkinter as tk

SURFACE = "#fcfcfb"
INK = "#0b0b0b"
INK2 = "#52514e"
MUTED = "#8a8984"
GRID = "#e6e5e1"
COVER = "#2a78d6"
STEGO = "#eb6834"
BAND = "#fbe3d8"          # light tint of STEGO for "payload region"
FONT = ("TkDefaultFont", 8)
FONT_B = ("TkDefaultFont", 9, "bold")


def _nice_ticks(lo: float, hi: float, n: int = 5):
    if hi <= lo:
        hi = lo + 1
    span = hi - lo
    raw = span / max(1, n)
    mag = 10 ** math.floor(math.log10(raw))
    step = min((m * mag for m in (1, 2, 2.5, 5, 10) if m * mag >= raw), default=mag * 10)
    start = math.ceil(lo / step) * step
    ticks = []
    v = start
    while v <= hi + step * 1e-9:
        ticks.append(round(v, 10))
        v += step
    return ticks


def _fmt(v: float) -> str:
    if v == 0:
        return "0"
    a = abs(v)
    if a >= 1e6:
        return f"{v / 1e6:.1f}M"
    if a >= 1e4:
        return f"{v / 1e3:.0f}k"
    if a >= 100 or float(v).is_integer():
        return f"{v:.0f}"
    return f"{v:.2g}"


def draw_chart(canvas: tk.Canvas, series: list[dict], *, title: str = "", x_label: str = "",
               y_label: str = "", x0: float = 0.0, x1: float | None = None,
               y_range: tuple[float, float] | None = None, bands=(), note: str = "",
               x_fmt=_fmt, y_fmt=_fmt, hover_fmt=None):
    """series: [{label, ys, color, kind:'line'|'step'|'bar', xs(optional), dash(optional)}]
    Values of None create gaps.  bands: [(xa, xb, label)] shaded in the background.
    The chart re-draws itself whenever the canvas is resized (e.g. when a hidden
    sub-tab becomes visible)."""
    args = dict(title=title, x_label=x_label, y_label=y_label, x0=x0, x1=x1, y_range=y_range, bands=bands,
                note=note, x_fmt=x_fmt, y_fmt=y_fmt, hover_fmt=hover_fmt)

    def _redraw(ev, _last=[None]):
        size = (ev.width, ev.height)
        if size != _last[0] and ev.width > 50:
            _last[0] = size
            _draw(canvas, series, **args)
    canvas.bind("<Configure>", _redraw)
    _draw(canvas, series, **args)


def _draw(canvas, series, *, title, x_label, y_label, x0, x1, y_range, bands, note, x_fmt, y_fmt, hover_fmt):
    canvas.delete("all")
    W = max(200, int(canvas.winfo_width() if canvas.winfo_width() > 50 else canvas["width"]))
    H = max(120, int(canvas.winfo_height() if canvas.winfo_height() > 50 else canvas["height"]))
    canvas.configure(bg=SURFACE)
    L, R, T, B = 52, 12, 24 if title else 10, 34
    pw, ph = W - L - R, H - T - B

    # x domain
    n_max = max((len(s["ys"]) for s in series), default=1)
    if x1 is None:
        x1 = x0 + max(1, n_max - 1)
    xs_of = {}
    for i, s in enumerate(series):
        xs = s.get("xs")
        if xs is None:
            n = len(s["ys"])
            step = (x1 - x0) / max(1, n - 1) if s.get("kind") != "bar" else (x1 - x0) / max(1, n)
            xs = [x0 + k * step for k in range(n)]
        xs_of[i] = xs
    vals = [v for s in series for v in s["ys"] if v is not None]
    if y_range is None:
        lo, hi = (min(vals), max(vals)) if vals else (0, 1)
        if lo > 0 and lo < hi * 0.5:
            lo = 0
        pad = (hi - lo) * 0.06 or 1
        y_range = (lo - (pad if lo < 0 else 0), hi + pad)
    ylo, yhi = y_range

    def X(x):
        return L + (x - x0) / (x1 - x0 or 1) * pw

    def Y(y):
        return T + ph - (y - ylo) / (yhi - ylo or 1) * ph

    if title:
        canvas.create_text(L, 4, text=title, anchor="nw", fill=INK, font=FONT_B)
    for xa, xb, lab in bands:
        canvas.create_rectangle(X(max(x0, xa)), T, X(min(x1, xb)), T + ph, fill=BAND, outline="")
        if lab:
            canvas.create_text(X(max(x0, xa)) + 3, T + 3, text=lab, anchor="nw", fill=INK2, font=FONT)
    for t in _nice_ticks(ylo, yhi, 4):
        y = Y(t)
        canvas.create_line(L, y, L + pw, y, fill=GRID)
        canvas.create_text(L - 4, y, text=y_fmt(t), anchor="e", fill=INK2, font=FONT)
    for t in _nice_ticks(x0, x1, 6):
        x = X(t)
        canvas.create_line(x, T + ph, x, T + ph + 3, fill=MUTED)
        canvas.create_text(x, T + ph + 5, text=x_fmt(t), anchor="n", fill=INK2, font=FONT)
    canvas.create_line(L, T + ph, L + pw, T + ph, fill=MUTED)
    if ylo < 0 < yhi:
        canvas.create_line(L, Y(0), L + pw, Y(0), fill=MUTED)
    if x_label:
        canvas.create_text(L + pw, H - 2, text=x_label, anchor="se", fill=INK2, font=FONT)
    if y_label:
        canvas.create_text(2, T + ph / 2, text=y_label, anchor="w", fill=INK2, font=FONT, angle=90)

    nbars = sum(1 for s in series if s.get("kind") == "bar")
    bi = 0
    for i, s in enumerate(series):
        ys, xs, col, kind = s["ys"], xs_of[i], s["color"], s.get("kind", "line")
        if kind == "bar":
            n = len(ys)
            slot = pw / max(1, n)
            bw = max(1.0, (slot - 2) / max(1, nbars))
            for k, v in enumerate(ys):
                if v is None:
                    continue
                xa = L + k * slot + 1 + bi * bw
                canvas.create_rectangle(xa, Y(max(v, ylo)), xa + bw - (1 if bw > 3 else 0), Y(max(0, ylo)),
                                        fill=col, outline="")
            bi += 1
            continue
        # decimate long series to per-pixel min/max columns
        pts = [(X(x), Y(v)) for x, v in zip(xs, ys) if v is not None]
        if len(pts) > pw * 2 and kind != "step":
            cols = {}
            for px, py in pts:
                c = int(px)
                lo_, hi_ = cols.get(c, (py, py))
                cols[c] = (min(lo_, py), max(hi_, py))
            for c, (a, b) in cols.items():
                canvas.create_line(c, a, c, b + 1, fill=col)
            continue
        segs, cur = [], []
        for x, v in zip(xs, ys):
            if v is None:
                if cur:
                    segs.append(cur)
                cur = []
                continue
            if kind == "step" and cur:
                cur.append((X(x), cur[-1][1]))
            cur.append((X(x), Y(v)))
        if cur:
            segs.append(cur)
        for seg in segs:
            if len(seg) == 1:
                px, py = seg[0]
                canvas.create_oval(px - 2, py - 2, px + 2, py + 2, fill=col, outline="")
            else:
                canvas.create_line(*[c for p in seg for c in p], fill=col, width=2 if len(seg) < 600 else 1,
                                   dash=s.get("dash"))
    # legend (always for >= 2 series)
    if len(series) >= 2:
        lx = L + pw
        for s in reversed(series):
            tw = len(s["label"]) * 6 + 18
            lx -= tw
            canvas.create_rectangle(lx, 6, lx + 10, 14, fill=s["color"], outline="")
            canvas.create_text(lx + 13, 10, text=s["label"], anchor="w", fill=INK, font=FONT)
    if note:
        canvas.create_text(L + 4, T + ph - 4, text=note, anchor="sw", fill=INK2, font=FONT)

    # hover read-out
    def on_move(ev):
        canvas.delete("hover")
        if not (L <= ev.x <= L + pw and T <= ev.y <= T + ph):
            return
        xv = x0 + (ev.x - L) / pw * (x1 - x0)
        lines = [f"x = {x_fmt(xv)}"]
        for i, s in enumerate(series):
            xs = xs_of[i]
            if not xs:
                continue
            if s.get("kind") == "bar":
                k = min(len(s["ys"]) - 1, max(0, int((ev.x - L) / (pw / len(s["ys"])))))
            else:
                k = min(range(len(xs)), key=lambda j: abs(xs[j] - xv)) if len(xs) < 3000 else \
                    min(len(xs) - 1, max(0, int((xv - xs[0]) / ((xs[-1] - xs[0]) / (len(xs) - 1) or 1))))
            v = s["ys"][k]
            txt = "-" if v is None else (hover_fmt(v) if hover_fmt else f"{v:.4g}")
            lines.append(f"{s['label']}: {txt}")
        canvas.create_line(ev.x, T, ev.x, T + ph, fill=INK2, dash=(2, 2), tags="hover")
        tx = ev.x + 8 if ev.x < L + pw - 150 else ev.x - 8
        anchor = "nw" if ev.x < L + pw - 150 else "ne"
        tid = canvas.create_text(tx, T + 6, text="\n".join(lines), anchor=anchor, fill=INK, font=FONT, tags="hover")
        bx = canvas.bbox(tid)
        rid = canvas.create_rectangle(bx[0] - 4, bx[1] - 3, bx[2] + 4, bx[3] + 3, fill="#ffffff", outline=GRID, tags="hover")
        canvas.tag_raise(tid, rid)

    canvas.bind("<Motion>", on_move)
    canvas.bind("<Leave>", lambda e: canvas.delete("hover"))


def message(canvas: tk.Canvas, text: str):
    canvas.delete("all")
    canvas.configure(bg=SURFACE)
    canvas.update_idletasks()
    W = int(canvas.winfo_width() or canvas["width"])
    H = int(canvas.winfo_height() or canvas["height"])
    canvas.create_text(W // 2, H // 2, text=text, fill=INK2, font=FONT, width=W - 40, justify="center")
