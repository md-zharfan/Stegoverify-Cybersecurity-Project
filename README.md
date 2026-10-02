# StegoVerify - LSB steganography + hashing + digital signatures

INF2005 ACW1 (2026). A window-based (Tkinter) tool that hides a *payload* (text, picture,
audio, video or any file) plus a *signed verification record* inside a **PNG image** or a
**WAV/PCM audio** cover using **LSB replacement (1–8 selectable bits)**. It extracts the
payload again, proves it is unchanged by comparing the **SHA-256 of the initial payload with
the SHA-256 of the extracted payload**, verifies an **Ed25519 signature** and a **SHA-256 media
hash**, and returns one of the verdicts *Authentic, Tampered, Signature Invalid, Payload
Missing, Wrong Start Location, Cannot Verify*. A **Steganalysis** tab measures how visible and
detectable the embedding is.

```
python app.py
```

## 1. Requirements and installation

* Python 3.10 or newer **with Tkinter** (included in the python.org installers for Windows and
  macOS; on Debian/Ubuntu run `sudo apt install python3-tk`).
* `cryptography` (Ed25519, AES-GCM, scrypt) – required.
* `pillow` – optional but recommended: faster loading of large or real-camera PNGs and in-app
  preview of JPEG picture payloads. Everything works without it.

```
pip install -r requirements.txt
python app.py                     # start the GUI
python tools/make_samples.py      # (optional) regenerate samples/ - already included
```

The PNG codec, WAV handling and LSB engine use only the standard library
(`stegoverify/pngcodec.py`, `covers.py`, `lsb.py`); the LSB engine works on whole byte strings,
so a 2.4 MB video payload embeds in well under a second. Audio playback uses `winsound` on
Windows, `afplay` on macOS and `paplay`/`aplay`/`ffplay` on Linux; other payload types (MP3,
MP4, JPEG ...) are opened with the system's default application.

## 2. Lecturer feedback → where it is in the tool

| Feedback | Where / how |
|---|---|
| Display the stego image, check for distortion | Tab 2 shows cover and stego side by side + *Show difference ×64*; PSNR/SNR, MSE, % units changed, max change. Tab 5 adds a ×5 magnified crop at the payload start, a full difference image and the difference waveform. |
| Decode to get the payload out | Tab 3 *Verify* extracts it; text is shown, pictures are previewed, audio can be played, video/other files open in the default player; *Save / open extracted payload*. |
| Compare hash of initial payload with hash of final payload | The initial payload's SHA-256 is stored in the **signed** record. After Protect, tab 2 immediately runs a **round trip** (save → reload → extract) and shows `initial SHA-256` vs `extracted SHA-256` → MATCH. Tab 3 shows the same **PAYLOAD INTEGRITY** panel for received files. Evidence table in `evidence/TEST_EVIDENCE.md`. |
| Different sizes and types of payload (audio, video, picture) | `samples/payloads/` – text (127 B, 672 B, 355 B), picture (PNG 733 B, JPEG 22 KB), audio (WAV 94 KB, MP3 118 KB), video (MP4 84 KB, MP4 2.4 MB). *File...* in tab 2 accepts any file. |
| Payload too big → error message | Live capacity bar (green/red) with *"TOO LARGE ... needs at least N LSB"* or *"does not fit even at 8 LSB"*; Protect refuses with an error dialog. |
| Steganalysis (e.g. waveform difference for audio) | Tab 5: cover-vs-stego waveform overlay + **difference waveform**, where-the-payload-is chart, LSB-plane *visual attack*, histograms, **chi-square attack** (images) and **silence test** (audio). |

## 3. Repository layout

| Path | Purpose |
|---|---|
| `app.py` | Tkinter GUI: Keys · Protect (Party A) · Verify (Party B) · Tamper lab · Steganalysis · Log |
| `stegoverify/lsb.py` | n-LSB replacement engine (1–8 bits), wrap-around addressing, marker scan |
| `stegoverify/covers.py` | PNG and WAV adapters, *LSB-masked* SHA-256 stable representation |
| `stegoverify/pngcodec.py` | PNG decoder/encoder (standard library; Pillow fast path if installed) |
| `stegoverify/payload.py` | Signed record (media ID, timestamp, hashes, nonce, metadata) + binary container |
| `stegoverify/crypto_utils.py` | SHA-256, Ed25519 sign/verify, HMAC, AES-256-GCM + scrypt |
| `stegoverify/startloc.py` | Keyed (HMAC, content-bound) and manual start-location schemes |
| `stegoverify/engine.py` | `protect()`, `verify()` with verdict logic, capacity check, quality metrics, tamper helpers |
| `stegoverify/analysis.py` | Steganalysis: bit planes, histograms, chi-square attack, silence test, signature scan |
| `stegoverify/gui_analysis.py`, `charts.py` | Steganalysis tab and its charts |
| `tools/make_samples.py` | Generates the sample covers and payload files |
| `tools/run_cases.py` | Reproduces every case → `evidence/TEST_EVIDENCE.md`, `evidence/files/` |
| `tools/gui_selftest.py` | Drives the GUI headlessly and captures `docs/screenshots/` |
| `tests/test_core.py` | 19 unit tests (`python -m unittest tests.test_core`) |
| `docs/DESIGN.md` | Architecture, start location, innovation, steganalysis, limitations |
| `docs/DEMO_SCRIPT.md` | 25-minute demo run sheet |
| `docs/DECLARATION_OF_ORIGINALITY.md`, `docs/CONTRIBUTION_STATEMENT.md` | Templates to complete and sign |
| `samples/`, `samples/payloads/` | Cover objects and payload files (below) |
| `keys/`, `output/` | Created at run time: PEM keys, stego outputs |

## 4. Sample covers and payloads

| Cover | Details | Capacity at 1 / 4 / 8 LSB |
|---|---|---|
| `cover_image.png` | 512×384 RGB, photo-like (noisy) | 72 KB / 288 KB / 576 KB |
| `cover_graphic.png` | 512×384 RGB, clean graphic (no noise) – shows the LSB-plane visual attack | 72 KB / 288 KB / 576 KB |
| `cover_image_large.png` | 1280×960 RGB, photo-like | 450 KB / 1.8 MB / 3.5 MB |
| `cover_audio.wav` | 4 s, 22.05 kHz stereo 16-bit | 21.5 KB / 86 KB / 172 KB |
| `cover_audio_long.wav` | 20 s, 44.1 kHz stereo 16-bit, with digital-silence rests | 215 KB / 861 KB / 1.7 MB |
| `tiny_image.png`, `tiny_audio.wav` | 48×32 / 0.05 s – for the capacity-check failure | < 1 KB |

Minimum LSB depth needed for each payload (✗ = does not fit even at 8 LSB):

| Payload | Size | cover_image | cover_image_large | cover_audio | cover_audio_long |
|---|---|---|---|---|---|
| 01_short_text_LO.txt | 127 B | 1 | 1 | 1 | 1 |
| 02_large_text_overview.txt | 672 B | 1 | 1 | 1 | 1 |
| 03_confidential_record.txt | 355 B | 1 | 1 | 1 | 1 |
| 04_picture_logo.png | 733 B | 1 | 1 | 1 | 1 |
| 05_picture_photo.jpg | 22 KB | 1 | 1 | 2 | 1 |
| 06_audio_clip.wav | 94 KB | 2 | 1 | 5 | 1 |
| 07_audio_song.mp3 | 118 KB | 2 | 1 | 6 | 1 |
| 08_video_small.mp4 | 84 KB | 2 | 1 | 4 | 1 |
| 09_video_large.mp4 | 2.4 MB | ✗ | 6 | ✗ | ✗ |

## 5. Using the GUI (the Party A → Party B workflow)

1. **Keys & identity** – click *Generate new team key pair*. `keys/team_private.pem` stays with
   Party A; `keys/team_public.pem` is distributed to verifiers.
2. **Protect (Party A)** – *Browse* a `.png` or `.wav` cover. Pick the payload: *Short (LO)*,
   *Large (Overview)*, *Custom (confidential)* (AES-256-GCM encrypted) or **File...** (opens
   `samples/payloads/`; shows the file's type, size and initial SHA-256). Choose the **number of
   LSBs (1–8)** – the capacity bar turns red and names the minimum LSB depth when the payload is
   too big. Choose the **start location** (*Keyed* secret or *Manual* x,y / sample). Click
   **PROTECT**. The stego object appears next to the cover; the **round-trip panel** confirms
   `initial SHA-256 == extracted SHA-256`.
3. Send `output/stego_*.png|wav` to Party B (e-mail, USB, chat – PNG and WAV are lossless so the
   LSBs survive). Party B also needs `team_public.pem` and – separately – the shared secret.
4. **Verify (Party B)** – *Browse* the downloaded file, set LSBs (or *auto*), enter the secret
   and passphrase, click **VERIFY**. Verdict banner, **PAYLOAD INTEGRITY** panel (initial vs
   extracted SHA-256), verification trace, and a preview / *Play / open payload* button.
5. **Tamper lab** – one click creates each negative case from the last stego file and loads it
   into Verify.
6. **Steganalysis** – *Use cover + stego from the last Protect* (or pick any two files, or only a
   suspect file for blind analysis) → **ANALYSE**. Views: *Side by side / waveform*,
   *Difference*, *LSB plane*, *Histogram*, *Chi-square / silence test*; the findings box
   summarises PSNR/SNR and what each blind test concluded.

## 6. Reproducing the test evidence

```
python tools/run_cases.py          # 47 cases -> evidence/TEST_EVIDENCE.md (+ payload & steganalysis tables)
python -m unittest tests.test_core # 19 unit tests
```

## 7. Security design in one paragraph

Party A computes the **LSB-masked SHA-256** of the cover (all bits except the n LSBs that will
be overwritten), builds a JSON record `{media_id, ts, nonce, hash, lsb_bits, meta, msg:{name,
mime, size, sha256, ...}}`, signs it with **Ed25519**, and embeds
`MAGIC‖header‖record‖signature‖payload‖CRC32` starting at a unit derived as
`HMAC-SHA256(secret, kind‖masked_hash‖n) mod units`. Party B recomputes the same hash and start
location from the stego file alone, extracts, verifies the signature, checks the payload bytes
against the signed SHA-256, compares the media hash, and reports the verdict. See
`docs/DESIGN.md` for details, steganalysis results and limitations.
