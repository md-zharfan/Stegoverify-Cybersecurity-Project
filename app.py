#!/usr/bin/env python3
"""StegoVerify - GUI for LSB-replacement steganography with hashing and
Ed25519 digital signatures (INF2005 ACW1).

    python app.py
"""
from __future__ import annotations

import json
import os
import sys
import tkinter as tk
import traceback
from datetime import datetime
from tkinter import filedialog, messagebox, scrolledtext, ttk

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from stegoverify import constants as C  # noqa: E402
from stegoverify import crypto_utils as cu  # noqa: E402
from stegoverify import engine, gui_support as gs, startloc  # noqa: E402
from stegoverify import payload as pl  # noqa: E402
from stegoverify.gui_analysis import SteganalysisTab  # noqa: E402
from stegoverify.covers import AudioCover, CoverError, ImageCover, load_cover  # noqa: E402

PAYLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "samples", "payloads")

BASE = os.path.dirname(os.path.abspath(__file__))
KEY_DIR = os.path.join(BASE, "keys")
OUT_DIR = os.path.join(BASE, "output")

VERDICT_COLOURS = {
    engine.AUTHENTIC: ("#276749", "#c6f6d5"),
    engine.TAMPERED: ("#9b2c2c", "#fed7d7"),
    engine.SIG_INVALID: ("#9b2c2c", "#fed7d7"),
    engine.MISSING: ("#975a16", "#fefcbf"),
    engine.WRONG_START: ("#975a16", "#fefcbf"),
    engine.CANNOT: ("#4a5568", "#e2e8f0"),
}


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{C.APP_NAME} {C.APP_VERSION} - LSB steganography + hash + digital signature")
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        w, h = min(1240, sw - 40), min(820, sh - 80)
        self.geometry(f"{w}x{h}+10+10")
        self.minsize(min(900, w), min(560, h))
        if sh < 900:
            try:
                self.state("zoomed")          # maximise on small / scaled screens (Windows)
            except tk.TclError:
                pass
        os.makedirs(KEY_DIR, exist_ok=True)
        os.makedirs(OUT_DIR, exist_ok=True)

        style = ttk.Style(self)
        if "clam" in style.theme_names():
            style.theme_use("clam")
        style.configure("Big.TButton", font=("TkDefaultFont", 11, "bold"), padding=8)
        style.configure("H.TLabel", font=("TkDefaultFont", 11, "bold"))
        style.configure("Good.Horizontal.TProgressbar", background="#38a169", troughcolor="#e2e8f0")
        style.configure("Bad.Horizontal.TProgressbar", background="#e53e3e", troughcolor="#e2e8f0")

        # shared state
        self.priv_key = self.pub_key = None
        self.priv_path = tk.StringVar()
        self.pub_path = tk.StringVar()
        self.attacker_priv_path = tk.StringVar()
        self.issuer = tk.StringVar(value="Party A (media verification desk)")
        self.team = tk.StringVar(value="INF2005 Team")
        self.last_stego_path: str | None = None
        self.last_start_unit: int | None = None
        self.last_n: int = 1
        self._photos = {}

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=6, pady=6)
        self.nb = nb
        self.tab_keys = ttk.Frame(nb)
        self.tab_protect = ttk.Frame(nb)
        self.tab_verify = ttk.Frame(nb)
        self.tab_tamper = ttk.Frame(nb)
        self.tab_log = ttk.Frame(nb)
        nb.add(self.tab_keys, text=" 1. Keys & identity ")
        nb.add(self.tab_protect, text=" 2. Protect (Party A) ")
        nb.add(self.tab_verify, text=" 3. Verify (Party B) ")
        nb.add(self.tab_tamper, text=" 4. Tamper lab ")
        self.tab_analysis = ttk.Frame(nb)
        nb.add(self.tab_analysis, text=" 5. Steganalysis ")
        nb.add(self.tab_log, text=" Log / evidence ")

        self._build_log()
        self._build_keys()
        self._build_protect()
        self._build_verify()
        self._build_tamper()
        self.analysis = SteganalysisTab(self.tab_analysis, self, ScrollColumn)
        self.analysis.pack(fill="both", expand=True)
        self._autoload_keys()
        self.log(f"{C.APP_NAME} started")

    # ------------------------------------------------------------------ log
    def _build_log(self):
        self.logbox = scrolledtext.ScrolledText(self.tab_log, wrap="word", font=("Courier", 9))
        self.logbox.pack(fill="both", expand=True, padx=6, pady=6)
        bar = ttk.Frame(self.tab_log)
        bar.pack(fill="x", padx=6, pady=(0, 6))
        ttk.Button(bar, text="Save log as evidence...", command=self.save_log).pack(side="left")
        ttk.Button(bar, text="Clear", command=lambda: self.logbox.delete("1.0", "end")).pack(side="left", padx=6)

    def log(self, msg: str):
        stamp = datetime.now().strftime("%H:%M:%S")
        self.logbox.insert("end", f"[{stamp}] {msg}\n")
        self.logbox.see("end")

    def save_log(self):
        p = filedialog.asksaveasfilename(defaultextension=".txt", initialdir=OUT_DIR, initialfile="stegoverify_log.txt")
        if p:
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(self.logbox.get("1.0", "end"))
            self.log(f"log saved to {p}")

    def error(self, title, exc):
        self.log(f"ERROR {title}: {exc}")
        messagebox.showerror(title, str(exc))

    # ----------------------------------------------------------------- keys
    def _build_keys(self):
        f = ttk.Frame(self.tab_keys, padding=12)
        f.pack(fill="both", expand=True)
        ttk.Label(f, text="Signer identity (embedded in the payload metadata)", style="H.TLabel").grid(row=0, column=0, columnspan=3, sticky="w")
        ttk.Label(f, text="Issuer / Party A name").grid(row=1, column=0, sticky="w", pady=4)
        ttk.Entry(f, textvariable=self.issuer, width=50).grid(row=1, column=1, sticky="w")
        ttk.Label(f, text="Team").grid(row=2, column=0, sticky="w", pady=4)
        ttk.Entry(f, textvariable=self.team, width=50).grid(row=2, column=1, sticky="w")

        ttk.Separator(f).grid(row=3, column=0, columnspan=3, sticky="ew", pady=12)
        ttk.Label(f, text="Ed25519 key pair", style="H.TLabel").grid(row=4, column=0, columnspan=3, sticky="w")
        ttk.Label(f, text="Private key (Party A signs with this - keep secret)").grid(row=5, column=0, sticky="w", pady=4)
        ttk.Entry(f, textvariable=self.priv_path, width=70).grid(row=5, column=1, sticky="w")
        ttk.Button(f, text="Load...", command=self.load_priv).grid(row=5, column=2, padx=4)
        ttk.Label(f, text="Public key (Party B verifies with this - distribute freely)").grid(row=6, column=0, sticky="w", pady=4)
        ttk.Entry(f, textvariable=self.pub_path, width=70).grid(row=6, column=1, sticky="w")
        ttk.Button(f, text="Load...", command=self.load_pub).grid(row=6, column=2, padx=4)
        ttk.Button(f, text="Generate new team key pair", style="Big.TButton", command=self.gen_keys).grid(row=7, column=1, sticky="w", pady=10)
        self.key_info = ttk.Label(f, text="no keys loaded", foreground="#4a5568")
        self.key_info.grid(row=8, column=0, columnspan=3, sticky="w")

        ttk.Separator(f).grid(row=9, column=0, columnspan=3, sticky="ew", pady=12)
        ttk.Label(f, text="Attacker key pair (for the 'Signature Invalid' negative case)", style="H.TLabel").grid(row=10, column=0, columnspan=3, sticky="w")
        ttk.Entry(f, textvariable=self.attacker_priv_path, width=70).grid(row=11, column=1, sticky="w", pady=4)
        ttk.Button(f, text="Generate attacker key pair", command=self.gen_attacker).grid(row=11, column=2, padx=4)

        ttk.Separator(f).grid(row=12, column=0, columnspan=3, sticky="ew", pady=12)
        txt = ("Workflow:  Party A generates a key pair once, protects media (tab 2) and sends the stego file plus the\n"
               "public key to Party B (e.g. by e-mail).  The start-location secret is shared separately (out of band).\n"
               "Party B verifies the received file (tab 3).  Tab 4 manufactures tampered copies for the negative cases.")
        ttk.Label(f, text=txt, foreground="#4a5568", justify="left").grid(row=13, column=0, columnspan=3, sticky="w")

    def _autoload_keys(self):
        priv, pub = os.path.join(KEY_DIR, "team_private.pem"), os.path.join(KEY_DIR, "team_public.pem")
        if os.path.exists(priv) and os.path.exists(pub):
            try:
                self.priv_key, self.pub_key = cu.load_private_key(priv), cu.load_public_key(pub)
                self.priv_path.set(priv)
                self.pub_path.set(pub)
                self._key_status()
            except Exception as e:  # pragma: no cover
                self.log(f"could not auto-load keys: {e}")
        att = os.path.join(KEY_DIR, "attacker_private.pem")
        if os.path.exists(att):
            self.attacker_priv_path.set(att)

    def _key_status(self):
        parts = []
        if self.priv_key:
            parts.append("private key loaded")
        if self.pub_key:
            parts.append(f"public key fingerprint {cu.public_key_fingerprint(self.pub_key)}")
        self.key_info.config(text=" | ".join(parts) or "no keys loaded")
        if hasattr(self, "v_pubinfo"):
            self.v_pubinfo.config(text=f"public key: {os.path.basename(self.pub_path.get()) or '-'}"
                                       + (f"  (fp {cu.public_key_fingerprint(self.pub_key)})" if self.pub_key else ""))

    def gen_keys(self):
        priv, pub = cu.generate_keypair()
        pp, up = os.path.join(KEY_DIR, "team_private.pem"), os.path.join(KEY_DIR, "team_public.pem")
        cu.save_private_key(priv, pp)
        cu.save_public_key(pub, up)
        self.priv_key, self.pub_key = priv, pub
        self.priv_path.set(pp)
        self.pub_path.set(up)
        self._key_status()
        self.log(f"generated Ed25519 key pair -> {pp}, {up} (fingerprint {cu.public_key_fingerprint(pub)})")

    def gen_attacker(self):
        priv, pub = cu.generate_keypair()
        pp = os.path.join(KEY_DIR, "attacker_private.pem")
        cu.save_private_key(priv, pp)
        cu.save_public_key(pub, os.path.join(KEY_DIR, "attacker_public.pem"))
        self.attacker_priv_path.set(pp)
        self.log(f"generated attacker key pair -> {pp}")

    def load_priv(self):
        p = filedialog.askopenfilename(initialdir=KEY_DIR, filetypes=[("PEM", "*.pem"), ("All", "*.*")])
        if not p:
            return
        try:
            self.priv_key = cu.load_private_key(p)
            self.priv_path.set(p)
            self._key_status()
            self.log(f"loaded private key {p}")
        except Exception as e:
            self.error("Load private key", e)

    def load_pub(self):
        p = filedialog.askopenfilename(initialdir=KEY_DIR, filetypes=[("PEM", "*.pem"), ("All", "*.*")])
        if not p:
            return
        try:
            self.pub_key = cu.load_public_key(p)
            self.pub_path.set(p)
            self._key_status()
            self.log(f"loaded public key {p}")
        except Exception as e:
            self.error("Load public key", e)

    # -------------------------------------------------------------- protect
    def _build_protect(self):
        outer = ttk.Frame(self.tab_protect)
        outer.pack(fill="both", expand=True)
        leftcol = ttk.Frame(outer)
        leftcol.pack(side="left", fill="y")
        ttk.Button(leftcol, text="PROTECT  (hash -> sign -> embed)", style="Big.TButton",
                   command=self.p_run).pack(side="bottom", fill="x", padx=8, pady=8)
        scroll = ScrollColumn(leftcol)
        scroll.pack(side="top", fill="both", expand=True)
        left = scroll.inner
        right = ttk.Frame(outer, padding=8)
        right.pack(side="left", fill="both", expand=True)

        # cover
        ttk.Label(left, text="Cover object", style="H.TLabel").pack(anchor="w")
        row = ttk.Frame(left)
        row.pack(fill="x", pady=2)
        self.p_cover = tk.StringVar()
        ttk.Entry(row, textvariable=self.p_cover, width=44).pack(side="left")
        ttk.Button(row, text="Browse...", command=self.p_browse_cover).pack(side="left", padx=4)
        self.p_cover_info = ttk.Label(left, text="PNG image or WAV/PCM audio", foreground="#4a5568", wraplength=380, justify="left")
        self.p_cover_info.pack(anchor="w")

        # message
        ttk.Label(left, text="Hidden message (payload)", style="H.TLabel").pack(anchor="w", pady=(10, 0))
        row = ttk.Frame(left)
        row.pack(fill="x")
        ttk.Button(row, text="Short (LO)", command=lambda: self.p_set_msg(C.SHORT_MESSAGE)).pack(side="left")
        ttk.Button(row, text="Large (Overview)", command=lambda: self.p_set_msg(C.LARGE_MESSAGE)).pack(side="left", padx=3)
        ttk.Button(row, text="Custom (confidential)", command=self.p_custom).pack(side="left")
        ttk.Button(row, text="File...", command=self.p_msg_file).pack(side="left", padx=3)
        self.p_msg = scrolledtext.ScrolledText(left, width=52, height=7, wrap="word")
        self.p_msg.pack(fill="x", pady=2)
        self.p_msg.insert("1.0", C.SHORT_MESSAGE)
        self.p_msg.bind("<KeyRelease>", lambda e: self.p_update_capacity())
        self.p_msg_file_path: str | None = None
        self.p_msg_file_lbl = ttk.Label(left, text="", foreground="#4a5568")
        self.p_msg_file_lbl.pack(anchor="w")
        row = ttk.Frame(left)
        row.pack(fill="x")
        self.p_encrypt = tk.BooleanVar(value=False)
        ttk.Checkbutton(row, text="Encrypt message (AES-256-GCM)  passphrase:", variable=self.p_encrypt,
                        command=self.p_update_capacity).pack(side="left")
        self.p_pass = tk.StringVar()
        ttk.Entry(row, textvariable=self.p_pass, width=16, show="*").pack(side="left")

        # LSB + capacity
        ttk.Label(left, text="LSB depth and capacity", style="H.TLabel").pack(anchor="w", pady=(10, 0))
        row = ttk.Frame(left)
        row.pack(fill="x")
        ttk.Label(row, text="number of LSBs (1-8):").pack(side="left")
        self.p_n = tk.IntVar(value=1)
        sp = ttk.Spinbox(row, from_=1, to=8, textvariable=self.p_n, width=4, command=self.p_update_capacity)
        sp.pack(side="left", padx=4)
        self.p_n.trace_add("write", lambda *a: self.p_update_capacity())
        self.p_cap_bar = ttk.Progressbar(left, length=380, maximum=100)
        self.p_cap_bar.pack(anchor="w", pady=2)
        self.p_cap_lbl = ttk.Label(left, text="select a cover to see capacity", foreground="#4a5568", wraplength=380, justify="left")
        self.p_cap_lbl.pack(anchor="w")

        # start location
        ttk.Label(left, text="Payload start location", style="H.TLabel").pack(anchor="w", pady=(10, 0))
        self.p_mode = tk.StringVar(value=startloc.MODE_KEYED)
        row = ttk.Frame(left)
        row.pack(fill="x")
        ttk.Radiobutton(row, text="Keyed (HMAC of secret + cover hash)", variable=self.p_mode,
                        value=startloc.MODE_KEYED, command=self.p_mode_changed).pack(side="left")
        ttk.Radiobutton(row, text="Manual", variable=self.p_mode, value=startloc.MODE_MANUAL,
                        command=self.p_mode_changed).pack(side="left", padx=8)
        self.p_start_box = ttk.Frame(left)
        self.p_start_box.pack(fill="x")
        self.p_keyed_frame = ttk.Frame(self.p_start_box)
        self.p_keyed_frame.pack(fill="x")
        ttk.Label(self.p_keyed_frame, text="shared secret:").pack(side="left")
        self.p_secret = tk.StringVar(value="team-secret-2026")
        ttk.Entry(self.p_keyed_frame, textvariable=self.p_secret, width=28, show="*").pack(side="left", padx=4)
        self.p_manual_frame = ttk.Frame(self.p_start_box)
        self.p_mx, self.p_my, self.p_ms = tk.StringVar(value="100"), tk.StringVar(value="100"), tk.StringVar(value="20000")
        self.p_manual_img = ttk.Frame(self.p_manual_frame)
        ttk.Label(self.p_manual_img, text="pixel x:").pack(side="left")
        ttk.Entry(self.p_manual_img, textvariable=self.p_mx, width=7).pack(side="left")
        ttk.Label(self.p_manual_img, text=" y:").pack(side="left")
        ttk.Entry(self.p_manual_img, textvariable=self.p_my, width=7).pack(side="left")
        self.p_manual_aud = ttk.Frame(self.p_manual_frame)
        ttk.Label(self.p_manual_aud, text="sample index:").pack(side="left")
        ttk.Entry(self.p_manual_aud, textvariable=self.p_ms, width=10).pack(side="left")

        # output + go
        ttk.Label(left, text="Output stego file", style="H.TLabel").pack(anchor="w", pady=(10, 0))
        row = ttk.Frame(left)
        row.pack(fill="x")
        self.p_out = tk.StringVar()
        ttk.Entry(row, textvariable=self.p_out, width=44).pack(side="left")
        ttk.Button(row, text="...", width=3, command=self.p_browse_out).pack(side="left", padx=4)
        ttk.Label(left, text="Result", style="H.TLabel").pack(anchor="w", pady=(10, 0))
        self.p_roundtrip = tk.Label(left, text="round-trip check appears here after Protect", anchor="w", justify="left",
                                    font=("Courier", 8), bg="#e2e8f0", fg="#4a5568", padx=6, pady=4)
        self.p_roundtrip.pack(fill="x", pady=2)
        ttk.Button(left, text="Steganalysis of this result (tab 5)",
                   command=lambda: (self.nb.select(self.tab_analysis), self.analysis.run())).pack(anchor="w", pady=2)
        self.p_result = scrolledtext.ScrolledText(left, width=52, height=12, wrap="word", font=("Courier", 8))
        self.p_result.pack(fill="both", expand=True)

        # previews
        self.p_prev = PreviewPane(right, "Original cover", "Stego object", self)
        self.p_prev.pack(fill="both", expand=True)

    def p_browse_cover(self):
        p = filedialog.askopenfilename(initialdir=os.path.join(BASE, "samples"),
                                       filetypes=[("Cover objects", "*.png *.wav"), ("PNG image", "*.png"), ("WAV audio", "*.wav")])
        if p:
            self.p_cover.set(p)
            self.p_cover_loaded()

    def p_cover_loaded(self):
        p = self.p_cover.get()
        try:
            cover = load_cover(p)
        except (CoverError, OSError) as e:
            self.error("Open cover", e)
            return
        self.p_cover_obj = cover
        d = cover.describe()
        self.p_cover_info.config(text=", ".join(f"{k}={v}" for k, v in d.items()))
        base, ext = os.path.splitext(os.path.basename(p))
        self.p_out.set(os.path.join(OUT_DIR, f"stego_{base}{ext}"))
        self.p_prev.show_left(cover)
        self.p_prev.show_right(None)
        self.p_result.delete("1.0", "end")
        self.p_roundtrip.config(text="round-trip check appears here after Protect", background="#e2e8f0", foreground="#4a5568")
        self.p_mode_changed()
        self.p_update_capacity()
        self.log(f"cover loaded: {p} ({d})")

    def p_mode_changed(self):
        self.p_keyed_frame.pack_forget()
        self.p_manual_frame.pack_forget()
        self.p_manual_img.pack_forget()
        self.p_manual_aud.pack_forget()
        if self.p_mode.get() == startloc.MODE_KEYED:
            self.p_keyed_frame.pack(fill="x")
        else:
            self.p_manual_frame.pack(fill="x")
            cover = getattr(self, "p_cover_obj", None)
            (self.p_manual_aud if isinstance(cover, AudioCover) else self.p_manual_img).pack(side="left")

    def p_set_msg(self, text):
        self.p_msg_file_path = None
        self.p_msg_file_lbl.config(text="")
        self.p_msg.delete("1.0", "end")
        self.p_msg.insert("1.0", text)
        self.p_update_capacity()

    def p_custom(self):
        self.p_set_msg(C.CUSTOM_MESSAGE)
        self.p_encrypt.set(True)
        if not self.p_pass.get():
            self.p_pass.set("release-2026")
        self.p_update_capacity()

    def p_msg_file(self):
        p = filedialog.askopenfilename(title="Payload file to hide (text, picture, audio, video, any file)",
                                       initialdir=PAYLOAD_DIR if os.path.isdir(PAYLOAD_DIR) else BASE)
        if p:
            self.p_use_file(p)

    def p_use_file(self, p):
        if True:
            self.p_msg_file_path = p
            with open(p, "rb") as fh:
                data = fh.read()
            mime = pl.guess_type(os.path.basename(p))
            self.p_msg_file_lbl.config(text=(f"file payload: {os.path.basename(p)}  [{pl.kind_of(mime)}: {mime}]  "
                                             f"{engine.human(len(data))}\ninitial payload SHA-256: {cu.sha256(data).hex()[:32]}..."))
            self.p_msg.delete("1.0", "end")
            self.p_msg.insert("1.0", f"[payload is the file {os.path.basename(p)} - click Short/Large/Custom to go back to text]")
            self.log(f"payload file selected: {p} ({len(data):,} bytes, {mime}, sha256 {cu.sha256(data).hex()})")
            self.p_update_capacity()

    def p_message_bytes(self) -> tuple[bytes, str | None]:
        if self.p_msg_file_path:
            with open(self.p_msg_file_path, "rb") as fh:
                return fh.read(), os.path.basename(self.p_msg_file_path)
        return self.p_msg.get("1.0", "end-1c").encode("utf-8"), None

    def p_update_capacity(self):
        cover = getattr(self, "p_cover_obj", None)
        if cover is None:
            return
        try:
            n = int(self.p_n.get())
            if not 1 <= n <= 8:
                raise ValueError
        except (ValueError, tk.TclError):
            self.p_cap_lbl.config(text="LSB depth must be 1-8", foreground="#9b2c2c")
            return
        msg, name = self.p_message_bytes()
        rep = engine.capacity_report(cover, n, len(msg), self.p_encrypt.get(), message_name=name,
                                     issuer=self.issuer.get(), team=self.team.get(),
                                     filename=os.path.basename(self.p_cover.get()), mode=self.p_mode.get())
        pct = min(100, 100 * rep["utilisation"])
        self.p_cap_bar["value"] = pct
        self.p_cap_bar.configure(style="Good.Horizontal.TProgressbar" if rep["fits"] else "Bad.Horizontal.TProgressbar")
        colour = "#276749" if rep["fits"] else "#9b2c2c"
        if rep["fits"]:
            verdict = f"FITS ({rep['utilisation'] * 100:.1f}% of capacity)"
        else:
            verdict = ("TOO LARGE - payload exceeds cover capacity. "
                       + (f"Needs at least {rep['min_lsb_that_fits']} LSB." if rep["min_lsb_that_fits"]
                          else "Does not fit even at 8 LSB - use a bigger cover."))
        self.p_cap_lbl.config(
            text=(f"cover capacity {engine.human(rep['capacity_bytes'])} at {n} LSB ({rep['units']:,} units x {n} bit)\n"
                  f"payload {engine.human(len(msg))} -> signed container {engine.human(rep['estimated_container_bytes'])}\n"
                  f"{verdict}"),
            foreground=colour)

    def p_browse_out(self):
        p = filedialog.asksaveasfilename(initialdir=OUT_DIR, initialfile=os.path.basename(self.p_out.get()))
        if p:
            self.p_out.set(p)

    def p_manual_unit(self, cover):
        if isinstance(cover, ImageCover):
            return cover.pixel_to_unit(int(self.p_mx.get()), int(self.p_my.get()))
        return cover.sample_to_unit(int(self.p_ms.get()))

    def p_run(self):
        cover = getattr(self, "p_cover_obj", None)
        if cover is None:
            messagebox.showwarning("Protect", "Select a cover object first.")
            return
        if self.priv_key is None:
            messagebox.showwarning("Protect", "Generate or load a private key in tab 1 first.")
            self.nb.select(self.tab_keys)
            return
        try:
            n = int(self.p_n.get())
            msg, name = self.p_message_bytes()
            mode = self.p_mode.get()
            passphrase = self.p_pass.get() if self.p_encrypt.get() else None
            if self.p_encrypt.get() and not passphrase:
                raise ValueError("enter a passphrase for the encrypted message")
            out = self.p_out.get()
            if not out:
                raise ValueError("choose an output path")
            manual = self.p_manual_unit(cover) if mode == startloc.MODE_MANUAL else None
            self.config(cursor="watch")
            self.update_idletasks()
            r = engine.protect(self.p_cover.get(), out, msg, n, self.priv_key, mode=mode,
                               secret=self.p_secret.get(), manual_unit=manual, passphrase=passphrase,
                               issuer=self.issuer.get(), team=self.team.get(), message_name=name)
        except (engine.CapacityError, CoverError, ValueError, OSError) as e:
            self.config(cursor="")
            self.p_result.delete("1.0", "end")
            self.p_result.insert("1.0", f"FAILED: {e}\n")
            self.p_roundtrip.config(text="NOT EMBEDDED - " + ("payload too large for this cover"
                                                            if isinstance(e, engine.CapacityError) else "error, see below"),
                                    background="#fed7d7", foreground="#9b2c2c")
            self.p_prev.show_right(None)
            self.error("Protect failed", e)
            return
        finally:
            self.config(cursor="")
        self.last_stego_path, self.last_start_unit, self.last_n = r.stego_path, r.start_unit, n
        q = r.quality
        qtxt = (f"SNR {q['snr_db']:.2f} dB" if "snr_db" in q else
                f"PSNR {q['psnr_db']:.2f} dB" if "psnr_db" in q else "")
        # round trip: decode the stego file we just wrote and compare payload hashes
        rt = engine.verify(r.stego_path, n, self.priv_key.public_key(), mode=mode, secret=self.p_secret.get(),
                           manual_unit=manual, passphrase=passphrase)
        ok = bool(rt.payload_hash_ok) and rt.message == msg
        self.p_roundtrip.config(
            text=(("ROUND TRIP OK - extracted payload is identical to the original\n" if ok else
                   "ROUND TRIP FAILED - extracted payload differs\n")
                  + f"initial   SHA-256 {r.message_sha256[:40]}...\n"
                  + f"extracted SHA-256 {(rt.payload_hash_extracted or '-')[:40]}..."),
            background="#c6f6d5" if ok else "#fed7d7", foreground="#276749" if ok else "#9b2c2c")
        lines = [
            "ROUND-TRIP CHECK (embed -> save -> reload -> extract -> compare)",
            f"  initial payload   : {name or 'text message'}  {len(msg):,} bytes",
            f"  initial   SHA-256 : {r.message_sha256}",
            f"  extracted SHA-256 : {rt.payload_hash_extracted}",
            f"  result            : {'MATCH - identical' if ok else 'MISMATCH'}  (verifier verdict: {rt.verdict})",
            "",
            "DISTORTION",
            f"  units changed {q['changed_units']:,} of {q['total_units']:,} ({q['changed_pct']:.2f}%), "
            f"max change {q['max_abs_diff']}, MSE {q['mse']:.4f}, {qtxt}",
            "  (tab 5 Steganalysis shows the difference image / waveform in detail)",
            "",
            f"STEGO WRITTEN: {r.stego_path}",
            f"cover units: {r.cover.num_units:,}   LSB depth: {n}   capacity: {r.capacity_bytes:,} B",
            f"signed container: {r.container_len:,} B  ({r.container_len / r.capacity_bytes * 100:.2f}% of capacity)",
            f"start location ({r.mode}): {r.start_desc}",
            f"units changed: {q['changed_units']:,} ({q['changed_pct']:.2f}%)   {qtxt}",
            f"media_id: {r.payload['media_id']}",
            f"timestamp: {r.payload['ts']}   nonce: {r.payload['nonce']}",
            f"hash ({r.payload['hash_alg']}): {r.payload['hash']}",
            f"signature (Ed25519, 64 B): {r.signature.hex()[:48]}...",
            f"message: {'encrypted AES-256-GCM' if passphrase else 'plain'}{' file ' + name if name else ''} ({len(msg):,} B, {r.payload['msg']['mime']})",
            "",
            "payload JSON:",
            json.dumps(r.payload, indent=1),
        ]
        self.p_result.delete("1.0", "end")
        self.p_result.insert("1.0", "\n".join(lines))
        self.p_prev.show_right(r.stego, start_unit=r.start_unit, cover_for_diff=r.cover)
        self.v_file.set(r.stego_path)
        self.t_file.set(r.stego_path)
        self.v_n.set(str(n))
        self.v_mode.set(mode)
        self.v_secret.set(self.p_secret.get())
        self.v_mx.set(self.p_mx.get())
        self.v_my.set(self.p_my.get())
        self.v_ms.set(self.p_ms.get())
        self.v_mode_changed()
        self.log(f"PROTECT ok: {r.stego_path} | {n} LSB | {r.mode} start {r.start_desc} | container {r.container_len} B | "
                 f"changed {q['changed_units']} units | {qtxt} | media_id {r.payload['media_id']}")
        self.log(f"ROUND TRIP: initial sha256 {r.message_sha256} | extracted sha256 {rt.payload_hash_extracted} | "
                 f"{'MATCH' if ok else 'MISMATCH'}")
        self.analysis.stego_path.set(r.stego_path)
        self.analysis.cover_path.set(self.p_cover.get())
        self.analysis.n.set(n)

    # --------------------------------------------------------------- verify
    def _build_verify(self):
        outer = ttk.Frame(self.tab_verify)
        outer.pack(fill="both", expand=True)
        leftcol = ttk.Frame(outer)
        leftcol.pack(side="left", fill="y")
        ttk.Button(leftcol, text="VERIFY  (locate -> extract -> signature -> hash)", style="Big.TButton",
                   command=self.v_run).pack(side="bottom", fill="x", padx=8, pady=8)
        scroll = ScrollColumn(leftcol)
        scroll.pack(side="top", fill="both", expand=True)
        left = scroll.inner
        right = ttk.Frame(outer, padding=8)
        right.pack(side="left", fill="both", expand=True)

        ttk.Label(left, text="Received stego object", style="H.TLabel").pack(anchor="w")
        row = ttk.Frame(left)
        row.pack(fill="x", pady=2)
        self.v_file = tk.StringVar()
        ttk.Entry(row, textvariable=self.v_file, width=44).pack(side="left")
        ttk.Button(row, text="Browse...", command=self.v_browse).pack(side="left", padx=4)
        self.v_pubinfo = ttk.Label(left, text="public key: -", foreground="#4a5568")
        self.v_pubinfo.pack(anchor="w")
        ttk.Button(left, text="Load a different public key...", command=self.load_pub).pack(anchor="w", pady=2)

        ttk.Label(left, text="Extraction parameters", style="H.TLabel").pack(anchor="w", pady=(10, 0))
        row = ttk.Frame(left)
        row.pack(fill="x")
        ttk.Label(row, text="number of LSBs:").pack(side="left")
        self.v_n = tk.StringVar(value="1")
        ttk.Combobox(row, textvariable=self.v_n, values=["auto"] + [str(i) for i in range(1, 9)], width=6, state="readonly").pack(side="left", padx=4)
        self.v_scan = tk.BooleanVar(value=True)
        ttk.Checkbutton(row, text="scan whole cover if not at expected location", variable=self.v_scan).pack(side="left")

        self.v_mode = tk.StringVar(value=startloc.MODE_KEYED)
        row = ttk.Frame(left)
        row.pack(fill="x", pady=2)
        ttk.Radiobutton(row, text="Keyed start (secret)", variable=self.v_mode, value=startloc.MODE_KEYED, command=self.v_mode_changed).pack(side="left")
        ttk.Radiobutton(row, text="Manual start", variable=self.v_mode, value=startloc.MODE_MANUAL, command=self.v_mode_changed).pack(side="left", padx=8)
        self.v_start_box = ttk.Frame(left)
        self.v_start_box.pack(fill="x")
        self.v_keyed = ttk.Frame(self.v_start_box)
        ttk.Label(self.v_keyed, text="shared secret:").pack(side="left")
        self.v_secret = tk.StringVar(value="team-secret-2026")
        ttk.Entry(self.v_keyed, textvariable=self.v_secret, width=28, show="*").pack(side="left", padx=4)
        self.v_manual = ttk.Frame(self.v_start_box)
        self.v_mx, self.v_my, self.v_ms = tk.StringVar(value="100"), tk.StringVar(value="100"), tk.StringVar(value="20000")
        ttk.Label(self.v_manual, text="pixel x:").pack(side="left")
        ttk.Entry(self.v_manual, textvariable=self.v_mx, width=7).pack(side="left")
        ttk.Label(self.v_manual, text=" y:").pack(side="left")
        ttk.Entry(self.v_manual, textvariable=self.v_my, width=7).pack(side="left")
        ttk.Label(self.v_manual, text="   or audio sample:").pack(side="left")
        ttk.Entry(self.v_manual, textvariable=self.v_ms, width=10).pack(side="left")
        self.v_keyed.pack(fill="x")
        row = ttk.Frame(left)
        row.pack(fill="x", pady=2)
        ttk.Label(row, text="message passphrase (if encrypted):").pack(side="left")
        self.v_pass = tk.StringVar()
        ttk.Entry(row, textvariable=self.v_pass, width=16, show="*").pack(side="left", padx=4)

        self.v_banner = tk.Label(left, text="no verdict yet", font=("TkDefaultFont", 16, "bold"), bg="#e2e8f0", fg="#4a5568", pady=12)
        self.v_banner.pack(fill="x")
        self.v_reason = ttk.Label(left, text="", wraplength=400, justify="left")
        self.v_reason.pack(anchor="w", pady=4)
        self.v_integrity = tk.Label(left, text="PAYLOAD INTEGRITY: -", anchor="w", justify="left",
                                    font=("Courier", 8), bg="#e2e8f0", fg="#4a5568", padx=6, pady=4)
        self.v_integrity.pack(fill="x", pady=2)
        ttk.Label(left, text="Extracted message", style="H.TLabel").pack(anchor="w")
        self.v_msg = scrolledtext.ScrolledText(left, width=52, height=6, wrap="word")
        self.v_msg.pack(fill="x")
        row = ttk.Frame(left)
        row.pack(fill="x", pady=2)
        ttk.Button(row, text="Save / open extracted payload...", command=self.v_save_payload).pack(side="left")
        ttk.Label(left, text="Verification trace", style="H.TLabel").pack(anchor="w", pady=(6, 0))
        self.v_detail = scrolledtext.ScrolledText(left, width=52, height=10, wrap="word", font=("Courier", 8))
        self.v_detail.pack(fill="both", expand=True)

        self.v_prev = PreviewPane(right, "Received stego object", "Embedded payload record", self, single=True)
        self.v_prev.pack(fill="both", expand=True)
        self.v_last = None

    def v_mode_changed(self):
        self.v_keyed.pack_forget()
        self.v_manual.pack_forget()
        (self.v_keyed if self.v_mode.get() == startloc.MODE_KEYED else self.v_manual).pack(fill="x")

    def v_browse(self):
        p = filedialog.askopenfilename(initialdir=OUT_DIR, filetypes=[("Stego objects", "*.png *.wav"), ("All", "*.*")])
        if p:
            self.v_file.set(p)
            self.v_preview()

    def v_preview(self):
        try:
            cover = load_cover(self.v_file.get())
            self.v_prev.show_left(cover)
        except (CoverError, OSError) as e:
            self.v_prev.show_left(None)
            self.log(f"preview failed: {e}")

    def v_run(self):
        path = self.v_file.get()
        if not path or not os.path.exists(path):
            messagebox.showwarning("Verify", "Choose the received stego file first.")
            return
        n = None if self.v_n.get() == "auto" else int(self.v_n.get())
        manual = None
        mode = self.v_mode.get()
        try:
            cover = load_cover(path)
            self.v_prev.show_left(cover)
            if mode == startloc.MODE_MANUAL:
                manual = (cover.pixel_to_unit(int(self.v_mx.get()), int(self.v_my.get())) if isinstance(cover, ImageCover)
                          else cover.sample_to_unit(int(self.v_ms.get())))
        except (CoverError, ValueError, OSError) as e:
            res = engine.VerifyResult(engine.CANNOT, str(e))
        else:
            self.config(cursor="watch")
            self.update_idletasks()
            try:
                res = engine.verify(path, n, self.pub_key, mode=mode, secret=self.v_secret.get(), manual_unit=manual,
                                    passphrase=self.v_pass.get() or None, scan=self.v_scan.get())
            except Exception as e:  # defensive: never crash the GUI on weird input
                res = engine.VerifyResult(engine.CANNOT, f"internal error: {e}")
                self.log(traceback.format_exc())
            finally:
                self.config(cursor="")
        self.v_last = res
        fg, bg = VERDICT_COLOURS.get(res.verdict, ("#000", "#fff"))
        self.v_banner.config(text=res.verdict.upper(), fg=fg, bg=bg)
        self.v_reason.config(text=res.reason)
        self.v_msg.delete("1.0", "end")
        if res.message is not None:
            m = (res.payload or {}).get("msg", {})
            name = m.get("name")
            if name:
                self.v_msg.insert("1.0", f"[{res.payload_kind} payload '{name}' ({m.get('mime')}), "
                                         f"{len(res.message):,} bytes - preview on the right, or Save/open]")
            else:
                self.v_msg.insert("1.0", res.message.decode("utf-8", "replace"))
        elif res.message_error:
            self.v_msg.insert("1.0", f"[message not readable: {res.message_error}]")
        elif res.payload and res.verdict != engine.AUTHENTIC:
            self.v_msg.insert("1.0", "[message withheld - verification did not pass]")
        lines = [f"file: {path}", f"verdict: {res.verdict}", f"reason: {res.reason}", ""] + res.details
        if res.payload:
            lines += ["", "payload JSON:", json.dumps(res.payload, indent=1)]
        self.v_detail.delete("1.0", "end")
        self.v_detail.insert("1.0", "\n".join(lines))
        self.v_prev.show_record(res)
        if res.payload_hash_ok is not None:
            ok = res.payload_hash_ok
            self.v_integrity.config(
                text=(f"PAYLOAD INTEGRITY: {'MATCH' if ok else 'MISMATCH'}\n"
                      f"initial   SHA-256 (signed) : {res.payload_hash_signed[:40]}...\n"
                      f"extracted SHA-256 (now)    : {res.payload_hash_extracted[:40]}..."),
                background="#c6f6d5" if ok else "#fed7d7", foreground="#276749" if ok else "#9b2c2c")
        else:
            self.v_integrity.config(text="PAYLOAD INTEGRITY: not checked ("
                                    + (res.message_error or "payload not extracted") + ")",
                                    background="#e2e8f0", foreground="#4a5568")
        self.log(f"VERIFY {os.path.basename(path)} | LSB {self.v_n.get()} | {mode} | verdict={res.verdict} | {res.reason}")
        if res.payload_hash_extracted:
            self.log(f"  payload sha256 signed {res.payload_hash_signed} | extracted {res.payload_hash_extracted} | "
                     f"{'MATCH' if res.payload_hash_ok else 'MISMATCH'}")

    def v_save_payload(self):
        res = self.v_last
        if not res or res.message is None:
            messagebox.showinfo("Payload", "No readable message extracted yet.")
            return
        name = (res.payload or {}).get("msg", {}).get("name") or "extracted_message.txt"
        p = filedialog.asksaveasfilename(initialdir=OUT_DIR, initialfile=name)
        if p:
            with open(p, "wb") as fh:
                fh.write(res.message)
            self.log(f"extracted payload saved to {p}; " + gs.open_with_default_app(p))

    # --------------------------------------------------------------- tamper
    def _build_tamper(self):
        f = ttk.Frame(self.tab_tamper, padding=12)
        f.pack(fill="both", expand=True)
        ttk.Label(f, text="Manufacture negative test cases from a stego file", style="H.TLabel").grid(row=0, column=0, columnspan=3, sticky="w")
        self.t_file = tk.StringVar()
        ttk.Entry(f, textvariable=self.t_file, width=80).grid(row=1, column=0, columnspan=2, sticky="w", pady=6)
        ttk.Button(f, text="Browse...", command=self.t_browse).grid(row=1, column=2, padx=4)
        ttk.Label(f, text="LSB depth used when it was protected:").grid(row=2, column=0, sticky="w")
        self.t_n = tk.IntVar(value=1)
        ttk.Spinbox(f, from_=1, to=8, textvariable=self.t_n, width=4).grid(row=2, column=1, sticky="w")

        cases = [
            ("Modify content (paint square / mute 0.25 s)", "Tampered", self.t_content),
            ("Corrupt LSBs inside the payload span", "Tampered (payload corrupted)", self.t_lsb),
            ("Strip all LSB planes (payload removed)", "Payload Missing", self.t_strip),
            ("Truncate audio by 0.5 s (audio only)", "Tampered", self.t_trunc),
            ("Forge: re-protect the cover with the ATTACKER key", "Signature Invalid", self.t_forge),
            ("Wrong secret / wrong coordinates (just verify with them)", "Wrong Start Location", None),
            ("Send a JPEG/MP3 or a plain cover with no payload", "Payload Missing / Cannot Verify", None),
        ]
        for i, (label, expect, cmd) in enumerate(cases, start=4):
            b = ttk.Button(f, text=label, command=cmd, width=52)
            b.grid(row=i, column=0, sticky="w", pady=3)
            if cmd is None:
                b.state(["disabled"])
            ttk.Label(f, text=f"expected verdict: {expect}", foreground="#4a5568").grid(row=i, column=1, columnspan=2, sticky="w")
        self.t_info = ttk.Label(f, text="", foreground="#2b6cb0", wraplength=900, justify="left")
        self.t_info.grid(row=20, column=0, columnspan=3, sticky="w", pady=12)

    def t_browse(self):
        p = filedialog.askopenfilename(initialdir=OUT_DIR, filetypes=[("Stego objects", "*.png *.wav")])
        if p:
            self.t_file.set(p)

    def _t_out(self, tag):
        base, ext = os.path.splitext(self.t_file.get())
        return f"{base}_{tag}{ext}"

    def _t_done(self, out, what, expect):
        self.t_info.config(text=f"written {out}\n{what}\nexpected verdict: {expect}  -> loaded into the Verify tab")
        self.v_file.set(out)
        self.v_preview()
        self.log(f"TAMPER {what} -> {out} (expect {expect})")
        self.nb.select(self.tab_verify)

    def _t_guard(self):
        if not self.t_file.get() or not os.path.exists(self.t_file.get()):
            messagebox.showwarning("Tamper lab", "Choose a stego file first (protect one in tab 2).")
            return False
        return True

    def t_content(self):
        if self._t_guard():
            try:
                out = self._t_out("tampered_content")
                self._t_done(out, engine.tamper_content(self.t_file.get(), out), "Tampered")
            except Exception as e:
                self.error("Tamper", e)

    def t_lsb(self):
        if self._t_guard():
            try:
                start = self.last_start_unit if self.t_file.get() == self.last_stego_path else 0
                out = self._t_out("tampered_lsb")
                self._t_done(out, engine.tamper_lsb_region(self.t_file.get(), out, int(self.t_n.get()), start or 0), "Tampered")
            except Exception as e:
                self.error("Tamper", e)

    def t_strip(self):
        if self._t_guard():
            try:
                out = self._t_out("stripped")
                self._t_done(out, engine.strip_payload(self.t_file.get(), out, int(self.t_n.get())), "Payload Missing")
            except Exception as e:
                self.error("Tamper", e)

    def t_trunc(self):
        if self._t_guard():
            try:
                out = self._t_out("truncated")
                self._t_done(out, engine.truncate_audio(self.t_file.get(), out), "Tampered")
            except Exception as e:
                self.error("Tamper", e)

    def t_forge(self):
        if not self._t_guard():
            return
        try:
            if not self.attacker_priv_path.get():
                self.gen_attacker()
            att = cu.load_private_key(self.attacker_priv_path.get())
            out = self._t_out("forged")
            src = self.p_cover.get() or self.t_file.get()
            r = engine.protect(src, out, b"FORGED by attacker: this record was never issued by Party A", int(self.t_n.get()), att,
                               mode=startloc.MODE_KEYED, secret=self.p_secret.get(), issuer="Mallory", team="attacker")
            self._t_done(out, f"cover re-protected and signed with the attacker's key ({r.start_desc})", "Signature Invalid")
        except Exception as e:
            self.error("Forge", e)


class ScrollColumn(ttk.Frame):
    """A vertically scrollable column; widgets go into `.inner`."""

    def __init__(self, master, width=430):
        super().__init__(master)
        self.canvas = tk.Canvas(self, width=width, highlightthickness=0, borderwidth=0)
        self.bar = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.inner = ttk.Frame(self.canvas, padding=8)
        self.inner.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self._win = self.canvas.create_window((0, 0), window=self.inner, anchor="nw")
        self.canvas.bind("<Configure>", lambda e: self.canvas.itemconfigure(self._win, width=e.width))
        self.canvas.configure(yscrollcommand=self.bar.set)
        self.canvas.pack(side="left", fill="both", expand=True)
        self.bar.pack(side="right", fill="y")
        for w in (self.canvas, self.inner):
            w.bind("<Enter>", lambda e: self.canvas.bind_all("<MouseWheel>", self._wheel))
            w.bind("<Leave>", lambda e: self.canvas.unbind_all("<MouseWheel>"))

    def _wheel(self, event):
        self.canvas.yview_scroll(int(-event.delta / 120) or (-1 if event.delta > 0 else 1), "units")


class PreviewPane(ttk.Frame):
    """Side-by-side preview of two media objects (image thumbnails or
    waveforms) with play / open buttons and an amplified-difference view."""

    def __init__(self, master, left_title, right_title, app: App, single=False):
        super().__init__(master)
        self.app = app
        self.single = single
        self.left_obj = self.right_obj = None
        self._photos = []
        top = ttk.Frame(self)
        top.pack(fill="both", expand=True)
        self.lf = ttk.LabelFrame(top, text=left_title, padding=4)
        self.lf.pack(side="left", fill="both", expand=True, padx=2)
        self.rf = ttk.LabelFrame(top, text=right_title, padding=4)
        self.rf.pack(side="left", fill="both", expand=True, padx=2)
        self.lcanvas = tk.Canvas(self.lf, width=440, height=310, bg="#f7fafc", highlightthickness=0)
        self.lcanvas.pack(fill="both", expand=True)
        self.linfo = ttk.Label(self.lf, text="", foreground="#4a5568", wraplength=430, justify="left")
        self.linfo.pack(anchor="w")
        lb = ttk.Frame(self.lf)
        lb.pack(fill="x")
        ttk.Button(lb, text="Play / open", command=lambda: self.play(self.left_obj)).pack(side="left")
        ttk.Button(lb, text="Stop audio", command=gs.stop_audio).pack(side="left", padx=4)
        if single:
            self.record = scrolledtext.ScrolledText(self.rf, width=48, height=14, wrap="word", font=("Courier", 8))
            self.record.pack(fill="both", expand=True)
            pv = ttk.LabelFrame(self.rf, text="Extracted payload", padding=4)
            pv.pack(fill="both", expand=True, pady=(6, 0))
            self.pv_canvas = tk.Canvas(pv, width=420, height=220, bg="#f7fafc", highlightthickness=0)
            self.pv_canvas.pack(fill="both", expand=True)
            pb = ttk.Frame(pv)
            pb.pack(fill="x", pady=(4, 0))
            self.pv_play = ttk.Button(pb, text="Play / open payload", command=self.play_payload)
            self.pv_play.pack(side="left")
            ttk.Button(pb, text="Stop audio", command=gs.stop_audio).pack(side="left", padx=4)
            self.pv_info = ttk.Label(pv, text="", foreground="#4a5568", wraplength=420, justify="left")
            self.pv_info.pack(anchor="w")
            self.pv_res = None
        else:
            self.rcanvas = tk.Canvas(self.rf, width=440, height=310, bg="#f7fafc", highlightthickness=0)
            self.rcanvas.pack(fill="both", expand=True)
            self.rinfo = ttk.Label(self.rf, text="", foreground="#4a5568", wraplength=430, justify="left")
            self.rinfo.pack(anchor="w")
            rb = ttk.Frame(self.rf)
            rb.pack(fill="x")
            ttk.Button(rb, text="Play / open", command=lambda: self.play(self.right_obj)).pack(side="left")
            ttk.Button(rb, text="Stop audio", command=gs.stop_audio).pack(side="left", padx=4)
            self.diff_btn = ttk.Button(rb, text="Show difference x64", command=self.toggle_diff)
            self.diff_btn.pack(side="left", padx=4)
            self.showing_diff = False
            self.diff_cover = None
            self.start_unit = None

    def _draw(self, canvas, info, obj, marker=None):
        canvas.delete("all")
        if obj is None:
            info.config(text="")
            return
        if isinstance(obj, ImageCover):
            photo, scale = gs.photo_for(obj)
            self._photos.append(photo)
            self._photos = self._photos[-6:]
            canvas.create_image(2, 2, image=photo, anchor="nw")
            if marker is not None:
                x, y = obj.unit_to_pixel(marker)
                k = int(scale.split(":")[1])
                cx, cy = 2 + x // k, 2 + y // k
                canvas.create_oval(cx - 6, cy - 6, cx + 6, cy + 6, outline="#e53e3e", width=2)
                canvas.create_text(cx + 9, cy, text="payload start", anchor="w", fill="#e53e3e", font=("TkDefaultFont", 8, "bold"))
            info.config(text=f"{obj.width}x{obj.height} {obj.img.mode}, preview scale {scale}")
        else:
            canvas.update_idletasks()
            gs.draw_waveform(canvas, obj, marker_unit=marker)
            info.config(text=f"{obj.framerate} Hz, {obj.channels} ch, {obj.sampwidth * 8}-bit, {obj.duration:.2f} s")

    def show_left(self, obj):
        self.left_obj = obj
        self._draw(self.lcanvas, self.linfo, obj)

    def show_right(self, obj, start_unit=None, cover_for_diff=None):
        self.right_obj = obj
        self.start_unit = start_unit
        self.diff_cover = cover_for_diff
        self.showing_diff = False
        self.diff_btn.config(text="Show difference x64")
        self._draw(self.rcanvas, self.rinfo, obj, marker=start_unit)

    def toggle_diff(self):
        if self.right_obj is None:
            return
        if isinstance(self.right_obj, ImageCover) and self.diff_cover is not None and not self.showing_diff:
            d = engine.difference_image(self.diff_cover, self.right_obj)
            self._draw(self.rcanvas, self.rinfo, d, marker=self.start_unit)
            self.rinfo.config(text=self.rinfo.cget("text") + "  |  |cover - stego| x 64 (black = unchanged)")
            self.showing_diff = True
            self.diff_btn.config(text="Show stego")
        elif isinstance(self.right_obj, AudioCover) and self.diff_cover is not None and not self.showing_diff:
            from stegoverify import analysis as an
            self.rcanvas.delete("all")
            w = int(self.rcanvas.winfo_width() or 440)
            h = int(self.rcanvas.winfo_height() or 310)
            env = an.change_envelope(self.diff_cover, self.right_obj, w)
            step = w / max(1, len(env))
            for i, v in enumerate(env):
                if v:
                    x = int(i * step)
                    self.rcanvas.create_line(x, h * 0.5 - v * h * 0.4, x, h * 0.5 + v * h * 0.4, fill="#e53e3e")
            self.rcanvas.create_text(6, 6, anchor="nw", text="red = where samples changed (bar height = % changed)", fill="#e53e3e")
            self.showing_diff = True
            self.diff_btn.config(text="Show stego")
        else:
            self._draw(self.rcanvas, self.rinfo, self.right_obj, marker=self.start_unit)
            self.showing_diff = False
            self.diff_btn.config(text="Show difference x64")

    def show_record(self, res: engine.VerifyResult):
        self.record.delete("1.0", "end")
        if res.payload:
            p = res.payload
            txt = [f"media_id   : {p.get('media_id')}", f"cover_type : {p.get('cover_type')}",
                   f"timestamp  : {p.get('ts')}", f"nonce      : {p.get('nonce')}",
                   f"hash_alg   : {p.get('hash_alg')}", f"hash       : {p.get('hash')}",
                   f"lsb_bits   : {p.get('lsb_bits')}", f"issuer     : {p.get('meta', {}).get('issuer')}",
                   f"team       : {p.get('meta', {}).get('team')}", f"filename   : {p.get('meta', {}).get('filename')}",
                   f"start_mode : {p.get('meta', {}).get('start_mode')}",
                   f"message enc: {p.get('msg', {}).get('enc')}", "",
                   f"signature  : {'VALID' if res.sig_ok else 'INVALID' if res.sig_ok is False else 'not checked'}",
                   f"media hash : {'MATCH' if res.hash_ok else 'MISMATCH' if res.hash_ok is False else 'not checked'}",
                   f"located at : unit {res.found_unit}", f"expected   : unit {res.expected_unit}"]
            self.record.insert("1.0", "\n".join(txt))
        else:
            self.record.insert("1.0", "no payload record could be recovered")
        self.show_payload(res)

    def _payload_file(self, res) -> str | None:
        if res is None or res.message is None:
            return None
        name = (res.payload or {}).get("msg", {}).get("name") or "extracted_message.txt"
        path = gs.temp_path("extracted_" + os.path.basename(name))
        with open(path, "wb") as fh:
            fh.write(res.message)
        return path

    def show_payload(self, res):
        self.pv_res = res
        c = self.pv_canvas
        c.delete("all")
        c.update_idletasks()
        W, H = int(c.winfo_width() or 420), int(c.winfo_height() or 220)
        if res is None or res.message is None:
            c.create_text(W // 2, H // 2, text="no payload extracted", fill="#4a5568")
            self.pv_info.config(text="")
            return
        kind = res.payload_kind
        m = res.payload.get("msg", {})
        self.pv_info.config(text=f"{kind}  |  {m.get('mime')}  |  {len(res.message):,} bytes  |  "
                                 f"SHA-256 {res.payload_hash_extracted[:16]}...")
        path = self._payload_file(res)
        if kind == "image":
            try:
                photo = self._photo_any(path, W - 8, H - 8)
                self._photos.append(photo)
                c.create_image(W // 2, H // 2, image=photo)
                return
            except Exception:
                c.create_text(W // 2, H // 2, width=W - 20, justify="center", fill="#4a5568",
                              text=(f"picture payload {m.get('name')}\n(in-app preview of this format needs Pillow: "
                                    "pip install pillow)\npress 'Play / open payload' to view it"))
                return
        if kind == "text":
            c.create_text(8, 8, anchor="nw", text=res.message[:1500].decode("utf-8", "replace"), width=W - 16,
                          fill="#1a202c", font=("TkDefaultFont", 9))
            return
        if kind == "audio" and m.get("mime") in ("audio/wav", "audio/x-wav"):
            try:
                gs.draw_waveform(c, AudioCover.load(path), colour="#2b6cb0")
                c.create_text(6, 6, anchor="nw", text="audio payload - press Play", fill="#1a202c")
                return
            except Exception:
                pass
        icon = {"audio": "AUDIO payload", "video": "VIDEO payload"}.get(kind, "FILE payload")
        c.create_text(W // 2, H // 2 - 10, text=icon, fill="#1a202c", font=("TkDefaultFont", 16, "bold"))
        c.create_text(W // 2, H // 2 + 16, text=f"{m.get('name')} - press 'Play / open payload'", fill="#4a5568")

    def _photo_any(self, path, mw, mh):
        try:
            from PIL import Image as PILImage, ImageTk
            im = PILImage.open(path)
            im.thumbnail((mw, mh))
            return ImageTk.PhotoImage(im)
        except ImportError:
            photo = tk.PhotoImage(file=path)          # PNG / GIF without Pillow
            k = max(1, -(-photo.width() // mw), -(-photo.height() // mh))
            return photo.subsample(k, k) if k > 1 else photo

    def play_payload(self):
        path = self._payload_file(self.pv_res)
        if not path:
            return
        if path.lower().endswith(".wav"):
            self.app.log(gs.play_audio(path))
        else:
            self.app.log(gs.open_with_default_app(path))

    def play(self, obj):
        if obj is None:
            return
        path = obj.source
        if isinstance(obj, AudioCover):
            if not path or not os.path.exists(path):
                path = gs.temp_path("play.wav")
                obj.save(path)
            self.app.log(gs.play_audio(path))
        else:
            if not path or not os.path.exists(path):
                path = gs.temp_path("view.png")
                obj.save(path)
            self.app.log(gs.open_with_default_app(path))


def main():
    app = App()
    if len(sys.argv) > 1 and os.path.exists(sys.argv[1]):
        app.p_cover.set(sys.argv[1])
        app.p_cover_loaded()
    app.mainloop()


if __name__ == "__main__":
    main()
