"""Drive the GUI headlessly (used under Xvfb to produce screenshots and to
make sure every tab renders).  Usage:  xvfb-run python tools/gui_selftest.py
"""
from __future__ import annotations

import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import app as appmod  # noqa: E402

SHOTS = os.path.join(os.path.dirname(__file__), "..", "docs", "screenshots")
os.makedirs(SHOTS, exist_ok=True)


def shot(name):
    time.sleep(0.4)
    subprocess.run(["import", "-window", "root", os.path.join(SHOTS, name)], check=False)


def main():
    a = appmod.App()
    a.update()
    if a.priv_key is None:
        a.gen_keys()
    a.nb.select(a.tab_keys)
    a.update()
    shot("01_keys.png")

    # ---- image protect
    a.nb.select(a.tab_protect)
    a.p_cover.set(os.path.join(appmod.BASE, "samples", "cover_image.png"))
    a.p_cover_loaded()
    a.p_set_msg(appmod.C.LARGE_MESSAGE)
    a.p_n.set(2)
    a.update()
    a.p_run()
    a.update()
    shot("02_protect_image.png")
    a.p_prev.toggle_diff()
    a.update()
    shot("03_protect_image_diff.png")

    # ---- verify image (positive)
    a.nb.select(a.tab_verify)
    a.update()
    a.v_run()
    a.update()
    shot("04_verify_image_authentic.png")

    # wrong secret
    a.v_secret.set("wrong-secret")
    a.v_run()
    a.update()
    shot("05_verify_wrong_start.png")
    a.v_secret.set("team-secret-2026")

    # ---- tamper lab -> content
    a.nb.select(a.tab_tamper)
    a.t_n.set(2)
    a.update()
    shot("06_tamper_lab.png")
    a.t_content()
    a.update()
    a.v_run()
    a.update()
    shot("07_verify_tampered.png")

    # ---- audio protect with encrypted custom message
    a.nb.select(a.tab_protect)
    a.p_cover.set(os.path.join(appmod.BASE, "samples", "cover_audio.wav"))
    a.p_cover_loaded()
    a.p_custom()
    a.p_n.set(1)
    a.update()
    a.p_run()
    a.update()
    shot("08_protect_audio.png")
    a.p_prev.toggle_diff()
    a.update()
    shot("09_protect_audio_diff.png")

    a.nb.select(a.tab_verify)
    a.v_pass.set("release-2026")
    a.update()
    a.v_run()
    a.update()
    shot("10_verify_audio_authentic.png")

    # forged
    a.nb.select(a.tab_tamper)
    a.t_n.set(1)
    a.t_forge()
    a.update()
    a.v_run()
    a.update()
    shot("11_verify_forged_signature_invalid.png")

    # stripped
    a.t_file.set(a.last_stego_path)
    a.t_strip()
    a.update()
    a.v_run()
    a.update()
    shot("12_verify_payload_missing.png")

    # ---- lecturer feedback: file payloads, hash comparison, steganalysis, too big
    a.nb.select(a.tab_protect)
    a.p_cover.set(os.path.join(appmod.BASE, "samples", "cover_graphic.png"))
    a.p_cover_loaded()
    a.p_use_file(os.path.join(appmod.BASE, "samples", "payloads", "05_picture_photo.jpg"))
    a.p_encrypt.set(True)
    a.p_pass.set("release-2026")
    a.p_n.set(1)
    a.update()
    a.p_run()
    a.update()
    shot("15_protect_picture_payload_roundtrip.png")
    a.nb.select(a.tab_verify)
    a.v_pass.set("release-2026")
    a.update()
    a.v_run()
    a.update()
    shot("16_verify_picture_payload_hash_match.png")
    a.nb.select(a.tab_analysis)
    a.update()
    a.analysis.run()
    a.update()
    for i, (v, name) in enumerate([(a.analysis.v_side, "side_by_side"), (a.analysis.v_diff, "difference"),
                                   (a.analysis.v_plane, "lsb_plane"), (a.analysis.v_hist, "histogram"),
                                   (a.analysis.v_stat, "chi_square")]):
        a.analysis.views.select(v)
        a.update()
        shot(f"17{'abcde'[i]}_steganalysis_image_{name}.png")

    a.nb.select(a.tab_protect)
    a.p_cover.set(os.path.join(appmod.BASE, "samples", "cover_audio_long.wav"))
    a.p_cover_loaded()
    a.p_use_file(os.path.join(appmod.BASE, "samples", "payloads", "07_audio_song.mp3"))
    a.p_encrypt.set(False)
    a.p_n.set(1)
    a.update()
    a.p_run()
    a.update()
    shot("18_protect_audio_payload_roundtrip.png")
    a.nb.select(a.tab_verify)
    a.update()
    a.v_run()
    a.update()
    shot("19_verify_audio_payload.png")
    a.nb.select(a.tab_analysis)
    a.update()
    a.analysis.run()
    a.update()
    for i, (v, name) in enumerate([(a.analysis.v_side, "waveform_difference"), (a.analysis.v_diff, "difference"),
                                   (a.analysis.v_plane, "lsb_plane"), (a.analysis.v_hist, "histogram"),
                                   (a.analysis.v_stat, "silence_test")]):
        a.analysis.views.select(v)
        a.update()
        shot(f"20{'abcde'[i]}_steganalysis_audio_{name}.png")

    a.nb.select(a.tab_protect)
    a.p_cover.set(os.path.join(appmod.BASE, "samples", "cover_audio.wav"))
    a.p_cover_loaded()
    a.p_use_file(os.path.join(appmod.BASE, "samples", "payloads", "09_video_large.mp4"))
    a.p_n.set(8)
    a.update()
    a.p_run()
    a.update()
    shot("21_video_payload_too_big.png")

    # capacity failure
    a.nb.select(a.tab_protect)
    a.p_cover.set(os.path.join(appmod.BASE, "samples", "tiny_image.png"))
    a.p_cover_loaded()
    a.p_set_msg(appmod.C.LARGE_MESSAGE)
    a.p_n.set(1)
    a.update()
    shot("13_capacity_check_too_large.png")

    a.nb.select(a.tab_log)
    a.update()
    shot("14_log.png")
    print("\n".join(sorted(os.listdir(SHOTS))))
    a.destroy()


if __name__ == "__main__":
    # avoid modal dialogs blocking the headless run
    appmod.messagebox.showerror = lambda t, m: print("ERRORBOX", t, m)
    appmod.messagebox.showwarning = lambda t, m: print("WARNBOX", t, m)
    appmod.messagebox.showinfo = lambda t, m: print("INFOBOX", t, m)
    main()
