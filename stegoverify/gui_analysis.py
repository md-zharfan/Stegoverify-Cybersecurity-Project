"""Tab 5 - Steganalysis: distortion, waveform difference, LSB-plane visual
attack, histograms, chi-square attack and audio silence check."""
from __future__ import annotations

import functools
import math
import os
import tkinter as tk
from tkinter import filedialog, scrolledtext, ttk

from . import analysis as an
from . import charts as ch
from . import engine
from . import gui_support as gs
from .covers import AudioCover, CoverError, ImageCover, load_cover


def _runs(env, threshold=0.0):
    """Contiguous index ranges where env > threshold."""
    out, start = [], None
    for i, v in enumerate(env + [0]):
        if v > threshold and start is None:
            start = i
        elif v <= threshold and start is not None:
            out.append((start, i))
            start = None
    return out


class SteganalysisTab(ttk.Frame):
    def __init__(self, master, app, scroll_cls):
        super().__init__(master)
        self.app = app
        self.cover = self.stego = None
        self._photos = []

        leftcol = ttk.Frame(self)
        leftcol.pack(side="left", fill="y")
        ttk.Button(leftcol, text="ANALYSE", style="Big.TButton", command=self.run).pack(
            side="bottom", fill="x", padx=8, pady=8)
        sc = scroll_cls(leftcol)
        sc.pack(side="top", fill="both", expand=True)
        f = sc.inner

        ttk.Label(f, text="Files to analyse", style="H.TLabel").pack(anchor="w")
        ttk.Label(f, text="Suspect / stego file (required)").pack(anchor="w", pady=(4, 0))
        row = ttk.Frame(f)
        row.pack(fill="x")
        self.stego_path = tk.StringVar()
        ttk.Entry(row, textvariable=self.stego_path, width=40).pack(side="left")
        ttk.Button(row, text="...", width=3, command=lambda: self._browse(self.stego_path)).pack(side="left", padx=4)
        ttk.Label(f, text="Original cover (optional - enables the\nnon-blind comparison views)").pack(anchor="w", pady=(6, 0))
        row = ttk.Frame(f)
        row.pack(fill="x")
        self.cover_path = tk.StringVar()
        ttk.Entry(row, textvariable=self.cover_path, width=40).pack(side="left")
        ttk.Button(row, text="...", width=3, command=lambda: self._browse(self.cover_path)).pack(side="left", padx=4)
        ttk.Button(f, text="Use cover + stego from the last Protect", command=self.use_last).pack(anchor="w", pady=6)

        ttk.Label(f, text="Settings", style="H.TLabel").pack(anchor="w", pady=(8, 0))
        row = ttk.Frame(f)
        row.pack(fill="x", pady=2)
        ttk.Label(row, text="LSBs to analyse (1-8):").pack(side="left")
        self.n = tk.IntVar(value=1)
        ttk.Spinbox(row, from_=1, to=8, textvariable=self.n, width=4).pack(side="left", padx=4)
        row = ttk.Frame(f)
        row.pack(fill="x", pady=2)
        ttk.Label(row, text="bit plane to show (0 = LSB):").pack(side="left")
        self.bit = tk.IntVar(value=0)
        ttk.Spinbox(row, from_=0, to=7, textvariable=self.bit, width=4).pack(side="left", padx=4)
        row = ttk.Frame(f)
        row.pack(fill="x", pady=2)
        ttk.Label(row, text="audio zoom: start sample").pack(side="left")
        self.zoom_start = tk.StringVar(value="auto")
        ttk.Entry(row, textvariable=self.zoom_start, width=9).pack(side="left", padx=4)
        row = ttk.Frame(f)
        row.pack(fill="x", pady=2)
        ttk.Label(row, text="audio zoom: length (samples)").pack(side="left")
        self.zoom_len = tk.StringVar(value="300")
        ttk.Combobox(row, textvariable=self.zoom_len, values=["100", "300", "1000", "5000"], width=7).pack(side="left", padx=4)

        ttk.Label(f, text="Findings", style="H.TLabel").pack(anchor="w", pady=(10, 0))
        self.report = scrolledtext.ScrolledText(f, width=50, height=26, wrap="word", font=("Courier", 8))
        self.report.pack(fill="both", expand=True)

        # views
        right = ttk.Frame(self, padding=4)
        right.pack(side="left", fill="both", expand=True)
        self.views = ttk.Notebook(right)
        self.views.pack(fill="both", expand=True)
        self.v_side = ttk.Frame(self.views)
        self.v_diff = ttk.Frame(self.views)
        self.v_plane = ttk.Frame(self.views)
        self.v_hist = ttk.Frame(self.views)
        self.v_stat = ttk.Frame(self.views)
        self.views.add(self.v_side, text=" Side by side / waveform ")
        self.views.add(self.v_diff, text=" Difference ")
        self.views.add(self.v_plane, text=" LSB plane (visual attack) ")
        self.views.add(self.v_hist, text=" Histogram ")
        self.views.add(self.v_stat, text=" Chi-square / silence test ")
        for fr in (self.v_side, self.v_diff, self.v_plane, self.v_hist, self.v_stat):
            ttk.Label(fr, text="Choose a stego file (and ideally its original cover) and press ANALYSE.",
                      foreground="#52514e").pack(pady=40)

    # ------------------------------------------------------------------
    def _browse(self, var):
        p = filedialog.askopenfilename(filetypes=[("Cover / stego objects", "*.png *.wav"), ("All", "*.*")])
        if p:
            var.set(p)

    def use_last(self):
        a = self.app
        if not a.last_stego_path:
            self.app.log("steganalysis: nothing protected yet in this session")
            return
        self.stego_path.set(a.last_stego_path)
        self.cover_path.set(a.p_cover.get())
        self.n.set(a.last_n)

    def _clear(self, frame):
        for w in frame.winfo_children():
            w.destroy()

    def _canvas(self, frame, height=220):
        c = tk.Canvas(frame, height=height, bg=ch.SURFACE, highlightthickness=0)
        c.pack(fill="both", expand=True, padx=4, pady=3)
        return c

    def _img(self, parent, obj, title, max_w=380, max_h=280, zoom=1, row=0, col=0, marker=None):
        box = ttk.LabelFrame(parent, text=title, padding=3)
        box.grid(row=row, column=col, sticky="nsew", padx=3, pady=3)
        photo, scale = gs.photo_for(obj, max_w, max_h)
        if zoom > 1:
            photo = photo.zoom(zoom, zoom)
        self._photos.append(photo)
        cv = tk.Canvas(box, width=photo.width() + 4, height=photo.height() + 4, highlightthickness=0, bg=ch.SURFACE)
        cv.pack()
        cv.create_image(2, 2, image=photo, anchor="nw")
        if marker:
            x, y, w, h = marker
            k = int(scale.split(":")[1])
            cv.create_rectangle(2 + x // k, 2 + y // k, 2 + (x + w) // k, 2 + (y + h) // k, outline=ch.STEGO, width=2)
        return box

    # ------------------------------------------------------------------
    def run(self):
        sp, cp = self.stego_path.get().strip(), self.cover_path.get().strip()
        if not sp or not os.path.exists(sp):
            self.app.error("Steganalysis", "choose the suspect / stego file first")
            return
        try:
            stego = load_cover(sp)
            cover = load_cover(cp) if cp and os.path.exists(cp) else None
            n = int(self.n.get())
            bit = int(self.bit.get())
        except (CoverError, OSError, ValueError, tk.TclError) as e:
            self.app.error("Steganalysis", e)
            return
        if cover is not None and (cover.kind != stego.kind or cover.num_units != stego.num_units):
            self.app.error("Steganalysis", "the cover and the stego file must be the same type and size")
            return
        self.cover, self.stego = cover, stego
        self._photos = []
        self.app.config(cursor="watch")
        self.update_idletasks()
        try:
            lines = [f"suspect : {os.path.basename(sp)}",
                     f"cover   : {os.path.basename(cp) if cover else '(not given - blind analysis only)'}",
                     f"type    : {stego.kind}, {stego.num_units:,} units, analysing {n} LSB", ""]
            region = an.changed_region(cover, stego) if cover else None
            sig = an.signature_scan(stego)
            env = an.change_envelope(cover, stego, 400) if cover else []
            if cover:
                q = engine.quality_metrics(cover, stego)
                lines += ["NON-BLIND (cover vs stego)",
                          f"  units changed   : {q['changed_units']:,} of {q['total_units']:,} ({q['changed_pct']:.2f}%)",
                          f"  max change      : {q['max_abs_diff']} (= 2^{n}-1 = {2 ** n - 1} expected at {n} LSB)",
                          f"  MSE             : {q['mse']:.4f}",
                          f"  PSNR            : {q['psnr_db']:.2f} dB" + ("  (>40 dB: invisible, <30 dB: visible)" if stego.kind == 'image' else ""),
                          ] + ([f"  SNR             : {q['snr_db']:.2f} dB  (>60 dB: inaudible)"] if "snr_db" in q else []) + [""]
            if stego.kind == "image":
                self._image_views(cover, stego, n, bit, region, env, sig, lines)
            else:
                self._audio_views(cover, stego, n, bit, region, env, sig, lines)
            lines += ["", "FORMAT-SIGNATURE SCAN (knows this tool's container marker)"]
            lines += ([f"  marker found at {k} LSB, unit {u:,}" for k, u in sig] or ["  no marker found"])
            if sig:
                lines.append("  -> anyone who knows the tool can locate the payload; see DESIGN.md limitations")
            self.report.delete("1.0", "end")
            self.report.insert("1.0", "\n".join(lines))
            self.app.log(f"STEGANALYSIS {os.path.basename(sp)} vs {os.path.basename(cp) if cover else '-'} | {n} LSB")
        except Exception as e:  # never crash the GUI
            self.app.error("Steganalysis", e)
        finally:
            self.app.config(cursor="")

    # ------------------------------------------------------------------
    def _image_views(self, cover, stego, n, bit, region, env, sig, lines):
        # side by side + magnified crop
        self._clear(self.v_side)
        grid = ttk.Frame(self.v_side)
        grid.pack(fill="both", expand=True)
        start_u = sig[0][1] if sig else (region[0] if region else 0)
        sx, sy = stego.unit_to_pixel(start_u)
        cw, chh = 64, 48
        cx, cy = max(0, sx - cw // 2), max(0, sy - chh // 2)
        if cover:
            self._img(grid, cover, "Original cover", row=0, col=0, marker=(cx, cy, cw, chh))
        self._img(grid, stego, "Stego object", row=0, col=1, marker=(cx, cy, cw, chh))
        if cover:
            self._img(grid, an.crop(cover, cx, cy, cw, chh), f"Cover, zoom x5 at payload start (x={sx}, y={sy})", zoom=5, row=1, col=0)
        self._img(grid, an.crop(stego, cx, cy, cw, chh), "Stego, zoom x5 (same spot)", zoom=5, row=1, col=1)

        # difference
        self._clear(self.v_diff)
        if cover:
            top = ttk.Frame(self.v_diff)
            top.pack(fill="x")
            gain = max(1, 128 // (2 ** n))
            self._img(top, engine.difference_image(cover, stego, gain), f"Difference |cover XOR stego| x{gain} (black = unchanged)",
                      max_w=520, max_h=330)
            c = self._canvas(self.v_diff, 170)
            c.after(50, functools.partial(ch.draw_chart, 
                c, [{"label": "units changed", "ys": [v * 100 for v in env], "color": ch.STEGO, "kind": "line"}],
                title="Where the payload is: % of units changed along the file (row-major pixel order)",
                x0=0, x1=100, x_label="position in file (%)", y_label="% changed",
                y_range=(0, 100), hover_fmt=lambda v: f"{v:.1f} %"))
        else:
            ttk.Label(self.v_diff, text="Load the original cover to see the difference image.").pack(pady=40)

        # LSB plane
        self._clear(self.v_plane)
        grid = ttk.Frame(self.v_plane)
        grid.pack(fill="both", expand=True)
        if cover:
            self._img(grid, an.lsb_plane_image(cover, bit), f"Cover - bit plane {bit}", max_w=370, max_h=330, row=0, col=0)
        self._img(grid, an.lsb_plane_image(stego, bit), f"Stego - bit plane {bit}", max_w=370, max_h=330, row=0, col=1)
        ttk.Label(self.v_plane, wraplength=860, justify="left", foreground="#52514e", text=(
            "Visual attack: each colour channel's bit is drawn as full on/off. A clean graphic has a structured plane; "
            "the embedded (random-looking) payload appears as a band of colour noise. On a noisy photo the plane is "
            "already random, so this attack fails - the cover choice matters.")).pack(anchor="w", padx=6)

        # histogram
        self._clear(self.v_hist)
        hs = an.histogram(stego.units())
        series = []
        if cover:
            series.append({"label": "cover", "ys": an.histogram(cover.units()), "color": ch.COVER, "kind": "line"})
        series.append({"label": "stego", "ys": hs, "color": ch.STEGO, "kind": "line"})
        c = self._canvas(self.v_hist, 300)
        c.after(50, functools.partial(ch.draw_chart, c, series, title="Histogram of channel values (all pixels, all colour channels)",
                                          x0=0, x1=255, x_label="value", y_label="count",
                                          hover_fmt=lambda v: f"{v:,.0f}"))
        ttk.Label(self.v_hist, wraplength=860, justify="left", foreground="#52514e", text=(
            "LSB replacement moves values only between 'pairs' (2k, 2k+1) - at 1 LSB the cover's uneven pair counts become "
            "equal in the stego histogram (the 'pairs of values' artefact that the chi-square attack measures).")).pack(anchor="w", padx=6)

        # chi-square
        self._clear(self.v_stat)
        blocks = 40
        st = an.chi_square_blocks(stego.units(), n, blocks)
        series = []
        if cover:
            cv = an.chi_square_blocks(cover.units(), n, blocks)
            series.append({"label": "cover", "ys": [p for *_, p in cv], "color": ch.COVER, "kind": "bar"})
        series.append({"label": "stego", "ys": [p for *_, p in st], "color": ch.STEGO, "kind": "bar"})
        bands = [(a * 100 / len(env), b * 100 / len(env), "payload" if k == 0 else "") for k, (a, b) in enumerate(_runs(env))] if env else []
        c = self._canvas(self.v_stat, 280)
        c.after(50, functools.partial(ch.draw_chart, c, series, title=f"Chi-square attack per block ({blocks} blocks, {n} LSB): p = probability of embedding",
                                          x0=0, x1=100, y_range=(0, 1.0), x_label="position in file (%)", y_label="p",
                                          bands=bands, hover_fmt=lambda v: f"{v:.3f}"))
        hot = sum(1 for *_, p in st if p is not None and p > 0.05)
        lines += ["BLIND (stego only)",
                  f"  chi-square: {hot}/{len(st)} blocks with p > 0.05 (embedding suspected)",
                  "  note: works best when the hidden bits look random (encrypted or compressed payload);",
                  "        plain text is biased (ASCII top bit = 0) and is detected less reliably."]
        ttk.Label(self.v_stat, wraplength=860, justify="left", foreground="#52514e", text=(
            "Westfeld & Pfitzmann chi-square attack. p near 0: histogram looks natural. p near 1: values inside each "
            "group of 2^n look equalised, which is what LSB replacement with random-looking data causes. "
            "Shaded = where the payload really is (from the non-blind comparison).")).pack(anchor="w", padx=6)

    # ------------------------------------------------------------------
    def _audio_views(self, cover, stego, n, bit, region, env, sig, lines):
        start_u = sig[0][1] if sig else (region[0] if region else 0)
        start_frame = stego.unit_to_sample(start_u)
        try:
            zs = self.zoom_start.get().strip()
            z0 = max(0, int(zs)) if zs and zs != "auto" else max(0, start_frame - 20)
            zl = max(20, int(self.zoom_len.get()))
        except ValueError:
            z0, zl = max(0, start_frame - 20), 300
        z1 = min(stego.nframes, z0 + zl)
        s_st = an.samples(stego, 0)
        s_cv = an.samples(cover, 0) if cover else None

        # side by side / waveform comparison (the lecturer's "difference between the waveform")
        self._clear(self.v_side)
        c1 = self._canvas(self.v_side, 150)
        c2 = self._canvas(self.v_side, 170)
        c3 = self._canvas(self.v_side, 170)
        full = []
        step = max(1, len(s_st) // 1200)
        if cover:
            full.append({"label": "cover", "ys": [max(s_cv[i:i + step], key=abs) for i in range(0, len(s_cv), step)],
                         "color": ch.COVER})
        full.append({"label": "stego", "ys": [max(s_st[i:i + step], key=abs) for i in range(0, len(s_st), step)],
                     "color": ch.STEGO})
        secs = stego.nframes / stego.framerate
        bands = [(a * secs / len(env), b * secs / len(env), "payload" if k == 0 else "") for k, (a, b) in enumerate(_runs(env))] if env else []
        zoom_band = [(z0 / stego.framerate, z1 / stego.framerate, "zoom")]
        c1.after(50, functools.partial(ch.draw_chart, c1, full, title="Whole file, channel 0 - the two waveforms are indistinguishable at this scale",
                                           x0=0, x1=secs, x_label="time (s)", y_label="sample", bands=bands + zoom_band,
                                           x_fmt=lambda v: f"{v:.1f}", hover_fmt=lambda v: f"{v:,.0f}"))
        zoom = []
        if cover:
            zoom.append({"label": "cover", "ys": list(s_cv[z0:z1]), "color": ch.COVER, "xs": list(range(z0, z1))})
        zoom.append({"label": "stego", "ys": list(s_st[z0:z1]), "color": ch.STEGO, "xs": list(range(z0, z1)), "dash": (4, 2)})
        c2.after(60, functools.partial(ch.draw_chart, c2, zoom, title=f"Zoom: samples {z0:,}-{z1:,} (cover solid, stego dashed)",
                                           x0=z0, x1=z1 - 1, x_label="sample index", y_label="value",
                                           hover_fmt=lambda v: f"{v:,.0f}"))
        if cover:
            diff = [b - a for a, b in zip(s_cv[z0:z1], s_st[z0:z1])]
            lim = max(1, 2 ** n - 1)
            c3.after(70, functools.partial(ch.draw_chart, 
                c3, [{"label": "stego - cover", "ys": diff, "color": ch.STEGO, "kind": "step", "xs": list(range(z0, z1))}],
                title=f"Difference waveform (stego - cover): only +/-{lim} out of +/-32768 - far below hearing",
                x0=z0, x1=z1 - 1, y_range=(-lim - 0.5, lim + 0.5), x_label="sample index", y_label="difference",
                hover_fmt=lambda v: f"{v:+.0f}"))
        else:
            ch.message(c3, "Load the original cover to plot the difference waveform.")

        # difference along the whole file
        self._clear(self.v_diff)
        if cover:
            c = self._canvas(self.v_diff, 200)
            c.after(50, functools.partial(ch.draw_chart, 
                c, [{"label": "units changed", "ys": [v * 100 for v in env], "color": ch.STEGO}],
                title="Where the payload is: % of samples changed along the file", x0=0, x1=secs,
                x_label="time (s)", y_label="% changed", y_range=(0, 100), x_fmt=lambda v: f"{v:.1f}",
                hover_fmt=lambda v: f"{v:.1f} %"))
            d_all = [b - a for a, b in zip(s_cv, s_st)]
            step2 = max(1, len(d_all) // 1200)
            dmax = [max(d_all[i:i + step2], key=abs) for i in range(0, len(d_all), step2)]
            c2b = self._canvas(self.v_diff, 200)
            c2b.after(60, functools.partial(ch.draw_chart, 
                c2b, [{"label": "stego - cover", "ys": dmax, "color": ch.STEGO}],
                title="Difference waveform, whole file (largest change per slice)", x0=0, x1=secs,
                x_label="time (s)", y_label="difference", x_fmt=lambda v: f"{v:.1f}", hover_fmt=lambda v: f"{v:+.0f}"))
        else:
            ttk.Label(self.v_diff, text="Load the original cover to see where samples changed.").pack(pady=40)

        # LSB plane as picture
        self._clear(self.v_plane)
        grid = ttk.Frame(self.v_plane)
        grid.pack(fill="both", expand=True)
        if cover:
            self._img(grid, an.lsb_plane_image(cover, bit), f"Cover - bit {bit} of every sample", max_w=370, max_h=330, row=0, col=0)
        self._img(grid, an.lsb_plane_image(stego, bit), f"Stego - bit {bit} of every sample", max_w=370, max_h=330, row=0, col=1)
        ttk.Label(self.v_plane, wraplength=860, justify="left", foreground="#52514e", text=(
            "Every sample's bit drawn as black/white, row after row (time runs left-to-right, top-to-bottom). "
            "Digital silence is solid black in the cover; LSB embedding fills it with noise.")).pack(anchor="w", padx=6)

        # histogram of small sample values
        self._clear(self.v_hist)
        lo, hi = -40, 40
        series = []
        if cover:
            series.append({"label": "cover", "ys": an.sample_histogram(cover, lo, hi), "color": ch.COVER, "kind": "bar"})
        series.append({"label": "stego", "ys": an.sample_histogram(stego, lo, hi), "color": ch.STEGO, "kind": "bar"})
        c = self._canvas(self.v_hist, 300)
        c.after(50, functools.partial(ch.draw_chart, c, series, title=f"Histogram of sample values {lo}..{hi} (quiet parts of the signal)",
                                          x0=lo, x1=hi + 1, x_label="sample value", y_label="count",
                                          hover_fmt=lambda v: f"{v:,.0f}"))
        ttk.Label(self.v_hist, wraplength=860, justify="left", foreground="#52514e", text=(
            "Digital silence puts a single huge spike at 0 in the cover; after embedding it is spread over "
            f"0..+/-{2 ** n - 1}.")).pack(anchor="w", padx=6)

        # silence test
        self._clear(self.v_stat)
        blk = 2048
        lim = 2 ** n - 1

        def per_block(vals):
            out = []
            for i in range(0, len(vals) - blk + 1, blk):
                seg = vals[i:i + blk]
                if max(seg) <= lim and min(seg) >= -lim:
                    out.append(100.0 * sum(1 for v in seg if v) / blk)
                else:
                    out.append(None)
            return out
        series = []
        if cover:
            series.append({"label": "cover", "ys": per_block(s_cv), "color": ch.COVER, "kind": "bar"})
        series.append({"label": "stego", "ys": per_block(s_st), "color": ch.STEGO, "kind": "bar"})
        c = self._canvas(self.v_stat, 280)
        c.after(50, functools.partial(ch.draw_chart, c, series, title=f"Silence test: % non-zero samples inside near-silent blocks ({blk} samples/block)",
                                          x0=0, x1=secs, y_range=(0, 100), x_label="time (s)", y_label="% non-zero",
                                          bands=bands, x_fmt=lambda v: f"{v:.1f}", hover_fmt=lambda v: f"{v:.1f} %"))
        sc = an.silence_check(stego, n, blk)
        lines += ["BLIND (stego only)",
                  f"  silence test: {sc['suspicious_blocks']} of {sc['quiet_blocks']} near-silent blocks contain LSB noise",
                  "    -> " + ("EMBEDDING SUSPECTED (digital silence should be all zeros)" if sc["suspicious_blocks"]
                             else "no evidence (no silent stretches were disturbed)"),
                  "  chi-square is not used for 16-bit audio: the low byte of every sample is",
                  "  already random, so the pairs-of-values test cannot tell cover from stego."]
        ttk.Label(self.v_stat, wraplength=860, justify="left", foreground="#52514e", text=(
            "Blocks without a bar are loud (not near-silent). Shaded = true payload position (non-blind).")).pack(anchor="w", padx=6)
