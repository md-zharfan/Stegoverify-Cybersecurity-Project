"""Reproducible test-case runner (FR11 / FR12).

Runs every positive and negative case for BOTH cover objects from the command
line, writes the resulting stego / tampered files to evidence/files/ and a
Markdown + JSON report to evidence/.  Run:

    python tools/run_cases.py
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from stegoverify import constants as C  # noqa: E402
from stegoverify import crypto_utils as cu  # noqa: E402
from stegoverify import analysis as an  # noqa: E402
from stegoverify import engine, startloc  # noqa: E402
from stegoverify.covers import load_cover  # noqa: E402

BASE = os.path.join(os.path.dirname(__file__), "..")
SAMPLES = os.path.join(BASE, "samples")
EVID = os.path.join(BASE, "evidence")
FILES = os.path.join(EVID, "files")
SECRET = "team-secret-2026"
PASS = "release-2026"

results = []
payload_rows = []
analysis_rows = []


def record(cid, kind, cover, title, expected, verdict, extra=""):
    ok = verdict == expected
    results.append({"id": cid, "type": kind, "cover": cover, "case": title, "expected": expected,
                    "actual": verdict, "pass": ok, "notes": extra})
    print(f"[{'PASS' if ok else 'FAIL'}] {cid:<6} {cover:<5} {title:<58} expected={expected:<22} got={verdict}")


def main():
    if os.path.isdir(FILES):
        shutil.rmtree(FILES)
    os.makedirs(FILES, exist_ok=True)
    priv, pub = cu.generate_keypair()
    att_priv, att_pub = cu.generate_keypair()
    cu.save_public_key(pub, os.path.join(EVID, "team_public.pem"))

    covers = {"image": os.path.join(SAMPLES, "cover_image.png"),
              "audio": os.path.join(SAMPLES, "cover_audio.wav")}
    tiny = {"image": os.path.join(SAMPLES, "tiny_image.png"),
            "audio": os.path.join(SAMPLES, "tiny_audio.wav")}
    msgs = {"short": C.SHORT_MESSAGE.encode(), "large": C.LARGE_MESSAGE.encode(), "custom": C.CUSTOM_MESSAGE.encode()}

    n_case = 0
    for kind, cover in covers.items():
        ext = os.path.splitext(cover)[1]
        K = kind[0].upper()

        # ---------------- positive cases -----------------------------------
        for label, lsb_n in (("short", 1), ("large", 3), ("custom", 2)):
            n_case += 1
            out = os.path.join(FILES, f"{kind}_P{n_case}_{label}_{lsb_n}lsb{ext}")
            pw = PASS if label == "custom" else None
            t = time.time()
            r = engine.protect(cover, out, msgs[label], lsb_n, priv, secret=SECRET, passphrase=pw,
                               issuer="Party A", team="INF2005 Team")
            v = engine.verify(out, lsb_n, pub, secret=SECRET, passphrase=pw)
            good = v.ok and v.message == msgs[label]
            q = r.quality
            qual = f"PSNR {q['psnr_db']:.1f} dB" if "psnr_db" in q else f"SNR {q['snr_db']:.1f} dB"
            record(f"{K}-P{n_case}", "positive", kind,
                   f"{label} message ({len(msgs[label])} B){' AES-GCM encrypted' if pw else ''}, {lsb_n} LSB, keyed start",
                   engine.AUTHENTIC, v.verdict if good else "message mismatch",
                   f"container {r.container_len} B / cap {r.capacity_bytes} B; start {r.start_desc}; "
                   f"{q['changed_units']} units changed; {qual}; {time.time() - t:.2f}s")
            if label == "short":
                first_stego, first_n = out, lsb_n

        # auto-detect LSB depth + manual start location, 8 LSB
        n_case += 1
        out = os.path.join(FILES, f"{kind}_P{n_case}_manual_8lsb{ext}")
        c = engine.load_cover(cover)
        manual = c.pixel_to_unit(123, 45) if kind == "image" else c.sample_to_unit(30000)
        r = engine.protect(cover, out, msgs["large"], 8, priv, mode=startloc.MODE_MANUAL, manual_unit=manual)
        v = engine.verify(out, None, pub, mode=startloc.MODE_MANUAL, manual_unit=manual)
        record(f"{K}-P{n_case}", "positive", kind, "large message, 8 LSB, MANUAL start, LSB depth auto-detected",
               engine.AUTHENTIC, v.verdict, f"start {r.start_desc}; detected {v.n_lsb} LSB")

        # "sent from A to B": copy the file to a different folder (as a mail client download would) and verify there
        n_case += 1
        inbox = os.path.join(FILES, "party_B_downloads")
        os.makedirs(inbox, exist_ok=True)
        received = shutil.copy(first_stego, os.path.join(inbox, "attachment" + ext))
        v = engine.verify(received, first_n, cu.load_public_key(os.path.join(EVID, "team_public.pem")), secret=SECRET)
        record(f"{K}-P{n_case}", "positive", kind, "file transferred to Party B folder, verified with distributed public key",
               engine.AUTHENTIC, v.verdict, f"sha256(sent)={cu.sha256_file(first_stego)[:16]} == sha256(received)={cu.sha256_file(received)[:16]}")

        # ---------------- negative cases -----------------------------------
        n_case += 1
        try:
            engine.protect(tiny[kind], os.path.join(FILES, "never_written" + ext), msgs["large"], 1, priv, secret=SECRET)
            got = "embedded (!)"
        except engine.CapacityError as e:
            got = "Capacity check rejected"
            note = str(e)
        record(f"{K}-N{n_case}", "negative", kind, "capacity check: large message into tiny cover at 1 LSB",
               "Capacity check rejected", got, note)

        n_case += 1
        out = os.path.join(FILES, f"{kind}_N{n_case}_tampered_content{ext}")
        what = engine.tamper_content(first_stego, out)
        v = engine.verify(out, first_n, pub, secret=SECRET)
        record(f"{K}-N{n_case}", "negative", kind, f"content modified after protection ({what})", engine.TAMPERED, v.verdict)

        n_case += 1
        out = os.path.join(FILES, f"{kind}_N{n_case}_forged{ext}")
        engine.protect(cover, out, b"forged record", first_n, att_priv, secret=SECRET, issuer="Mallory")
        v = engine.verify(out, first_n, pub, secret=SECRET)
        record(f"{K}-N{n_case}", "negative", kind, "payload signed with an attacker's key (forgery)", engine.SIG_INVALID, v.verdict)

        n_case += 1
        v = engine.verify(first_stego, first_n, pub, secret="wrong-secret")
        record(f"{K}-N{n_case}", "negative", kind, "verifier supplies the wrong start-location secret", engine.WRONG_START, v.verdict,
               f"expected unit {v.expected_unit}, payload actually at {v.found_unit}")

        n_case += 1
        out = os.path.join(FILES, f"{kind}_N{n_case}_stripped{ext}")
        engine.strip_payload(first_stego, out, first_n)
        v = engine.verify(out, first_n, pub, secret=SECRET)
        record(f"{K}-N{n_case}", "negative", kind, "LSB planes wiped (payload removed)", engine.MISSING, v.verdict)

        n_case += 1
        v = engine.verify(cover, first_n, pub, secret=SECRET)
        record(f"{K}-N{n_case}", "negative", kind, "original unprotected cover presented as stego", engine.MISSING, v.verdict)

        n_case += 1
        out = os.path.join(FILES, f"{kind}_N{n_case}_lsb_corrupted{ext}")
        r0 = engine.verify(first_stego, first_n, pub, secret=SECRET)
        engine.tamper_lsb_region(first_stego, out, first_n, r0.found_unit)
        v = engine.verify(out, first_n, pub, secret=SECRET)
        record(f"{K}-N{n_case}", "negative", kind, "LSBs inside the payload span overwritten", engine.TAMPERED, v.verdict)

        n_case += 1
        v = engine.verify(first_stego, first_n, None, secret=SECRET)
        record(f"{K}-N{n_case}", "negative", kind, "no public key available to the verifier", engine.CANNOT, v.verdict)

        n_case += 1
        v = engine.verify(first_stego, (first_n % 8) + 1, pub, secret=SECRET)
        record(f"{K}-N{n_case}", "negative", kind, "wrong LSB depth selected by verifier", engine.MISSING, v.verdict)

        if kind == "audio":
            n_case += 1
            out = os.path.join(FILES, f"{kind}_N{n_case}_truncated{ext}")
            engine.truncate_audio(first_stego, out)
            v = engine.verify(out, first_n, pub, secret=SECRET)
            record(f"{K}-N{n_case}", "negative", kind, "audio truncated by 0.5 s", engine.TAMPERED, v.verdict)

            n_case += 1
            # encrypted message + wrong passphrase: media authentic, message unreadable
            out = os.path.join(FILES, f"{kind}_N{n_case}_wrong_pass{ext}")
            engine.protect(cover, out, msgs["custom"], 2, priv, secret=SECRET, passphrase=PASS)
            v = engine.verify(out, 2, pub, secret=SECRET, passphrase="nope")
            record(f"{K}-N{n_case}", "negative", kind, "confidential message, wrong passphrase (media authentic, message sealed)",
                   engine.AUTHENTIC, v.verdict, f"message_error='{v.message_error}'")
        else:
            n_case += 1
            bad = os.path.join(FILES, "not_a_png.png")
            with open(bad, "wb") as fh:
                fh.write(b"\xff\xd8\xff\xe0JFIF fake jpeg bytes")
            v = engine.verify(bad, 1, pub, secret=SECRET)
            record(f"{K}-N{n_case}", "negative", kind, "unsupported / corrupt file (JPEG bytes with .png name)", engine.CANNOT, v.verdict)


    # ---------------- payload types & sizes: embed -> extract -> compare SHA-256 ----------------
    PAY = os.path.join(SAMPLES, "payloads")
    plan = [  # (payload file, cover, LSBs, encrypt)
        ("01_short_text_LO.txt", "cover_image.png", 1, False),
        ("02_large_text_overview.txt", "cover_audio.wav", 1, False),
        ("03_confidential_record.txt", "cover_image.png", 2, True),
        ("04_picture_logo.png", "cover_audio.wav", 1, False),
        ("05_picture_photo.jpg", "cover_image.png", 1, False),
        ("05_picture_photo.jpg", "cover_graphic.png", 1, True),
        ("06_audio_clip.wav", "cover_audio_long.wav", 1, False),
        ("06_audio_clip.wav", "cover_image.png", 2, False),
        ("07_audio_song.mp3", "cover_audio_long.wav", 1, False),
        ("08_video_small.mp4", "cover_image_large.png", 1, False),
        ("08_video_small.mp4", "cover_audio.wav", 4, False),
        ("09_video_large.mp4", "cover_image_large.png", 6, False),
    ]
    for pay, cov, n, enc in plan:
        pp, cp = os.path.join(PAY, pay), os.path.join(SAMPLES, cov)
        if not (os.path.exists(pp) and os.path.exists(cp)):
            continue
        data = open(pp, "rb").read()
        out = os.path.join(FILES, f"PT_{os.path.splitext(pay)[0]}_in_{os.path.splitext(cov)[0]}_{n}lsb{os.path.splitext(cov)[1]}")
        t = time.time()
        r = engine.protect(cp, out, data, n, priv, secret=SECRET, passphrase=PASS if enc else None, message_name=pay)
        v = engine.verify(out, n, pub, secret=SECRET, passphrase=PASS if enc else None)
        dt = time.time() - t
        same = v.message == data and v.payload_hash_ok
        q = r.quality
        qual = f"SNR {q['snr_db']:.1f} dB" if "snr_db" in q else f"PSNR {q['psnr_db']:.1f} dB"
        n_case += 1
        record(f"PT{n_case}", "positive", "image" if cov.endswith(".png") else "audio",
               f"payload type: {pay} ({engine.human(len(data))}){' encrypted' if enc else ''} in {cov} at {n} LSB",
               engine.AUTHENTIC, v.verdict if same else "hash mismatch",
               f"initial sha256 {r.message_sha256[:16]}... = extracted {str(v.payload_hash_extracted)[:16]}...; {qual}")
        payload_rows.append({"payload": pay, "kind": v.payload_kind, "size": len(data), "cover": cov, "lsb": n,
                             "encrypted": enc, "capacity": r.capacity_bytes, "container": r.container_len,
                             "initial_sha256": r.message_sha256, "extracted_sha256": v.payload_hash_extracted,
                             "match": bool(same), "quality": qual, "changed_pct": round(q["changed_pct"], 2),
                             "seconds": round(dt, 2), "verdict": v.verdict})

        # steganalysis of this stego object
        c_obj, s_obj = load_cover(cp), load_cover(out)
        if c_obj.kind == "image":
            cb = an.chi_square_blocks(c_obj.units(), n, 40)
            sb = an.chi_square_blocks(s_obj.units(), n, 40)
            hot_c = sum(1 for *_, p in cb if p is not None and p > 0.05)
            hot_s = sum(1 for *_, p in sb if p is not None and p > 0.05)
            blind = f"chi-square blocks p>0.05: cover {hot_c}/40, stego {hot_s}/40"
        else:
            sc_c, sc_s = an.silence_check(c_obj, n), an.silence_check(s_obj, n)
            blind = (f"silence test: cover {sc_c['suspicious_blocks']}/{sc_c['quiet_blocks']}, "
                     f"stego {sc_s['suspicious_blocks']}/{sc_s['quiet_blocks']} silent blocks disturbed")
        analysis_rows.append({"stego": os.path.basename(out), "lsb": n, "changed_pct": round(q["changed_pct"], 2),
                              "max_change": q["max_abs_diff"], "quality": qual, "blind": blind})

    # ---------------- payload too big ----------------
    for pay, cov, n in [("09_video_large.mp4", "cover_audio_long.wav", 8),
                        ("09_video_large.mp4", "cover_image_large.png", 1),
                        ("06_audio_clip.wav", "cover_audio.wav", 1),
                        ("08_video_small.mp4", "tiny_image.png", 8)]:
        pp, cp = os.path.join(PAY, pay), os.path.join(SAMPLES, cov)
        if not (os.path.exists(pp) and os.path.exists(cp)):
            continue
        data = open(pp, "rb").read()
        n_case += 1
        try:
            engine.protect(cp, os.path.join(FILES, "never_written" + os.path.splitext(cov)[1]), data, n, priv,
                           secret=SECRET, message_name=pay)
            got, note = "embedded (!)", ""
        except engine.CapacityError as e:
            got, note = "Capacity check rejected", str(e)
        record(f"TB{n_case}", "negative", "image" if cov.endswith(".png") else "audio",
               f"payload too big: {pay} ({engine.human(len(data))}) into {cov} at {n} LSB",
               "Capacity check rejected", got, note)

    # ---------------- write report ----------------------------------------
    os.makedirs(EVID, exist_ok=True)
    with open(os.path.join(EVID, "results.json"), "w") as fh:
        json.dump({"cases": results, "payload_types": payload_rows, "steganalysis": analysis_rows}, fh, indent=1)
    passed = sum(r["pass"] for r in results)
    lines = [f"# StegoVerify test evidence", "",
             f"Generated {time.strftime('%Y-%m-%d %H:%M:%S')} by `tools/run_cases.py` - {passed}/{len(results)} cases passed.", "",
             "Positive cases prove the round trip (embed -> transfer -> extract -> signature + hash OK); negative cases prove that "
             "each failure mode is detected and reported with the correct verdict category.", "",
             "| ID | Type | Cover | Case | Expected | Actual | Pass | Notes |", "|---|---|---|---|---|---|---|---|"]
    for r in results:
        lines.append(f"| {r['id']} | {r['type']} | {r['cover']} | {r['case']} | {r['expected']} | {r['actual']} | "
                     f"{'yes' if r['pass'] else 'NO'} | {r['notes']} |")
    lines += ["", "## Payload types and sizes: initial vs extracted SHA-256", "",
              "Each payload file was embedded, the stego file saved and re-loaded, the payload extracted, and the SHA-256 of "
              "the extracted payload compared with the SHA-256 of the initial payload (which is also inside the signed record).", "",
              "| Payload | Kind | Size | Cover | LSB | Enc | Container / capacity | Initial SHA-256 | Extracted SHA-256 | Match | Distortion | Time |",
              "|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for r in payload_rows:
        lines.append(f"| {r['payload']} | {r['kind']} | {engine.human(r['size'])} | {r['cover']} | {r['lsb']} | "
                     f"{'yes' if r['encrypted'] else 'no'} | {engine.human(r['container'])} / {engine.human(r['capacity'])} | "
                     f"`{r['initial_sha256'][:16]}...` | `{str(r['extracted_sha256'])[:16]}...` | "
                     f"{'MATCH' if r['match'] else 'NO'} | {r['quality']}, {r['changed_pct']}% units changed | {r['seconds']} s |")
    lines += ["", "## Steganalysis of the stego objects above", "",
              "| Stego object | LSB | Units changed | Max change | Distortion | Blind test |", "|---|---|---|---|---|---|"]
    for r in analysis_rows:
        lines.append(f"| {r['stego']} | {r['lsb']} | {r['changed_pct']}% | {r['max_change']} | {r['quality']} | {r['blind']} |")
    with open(os.path.join(EVID, "TEST_EVIDENCE.md"), "w") as fh:
        fh.write("\n".join(lines) + "\n")
    print(f"\n{passed}/{len(results)} passed -> {os.path.abspath(os.path.join(EVID, 'TEST_EVIDENCE.md'))}")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
