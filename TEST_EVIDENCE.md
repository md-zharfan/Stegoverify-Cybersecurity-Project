# StegoVerify test evidence

Generated 2026-09-24 08:59:10 by `tools/run_cases.py` - 47/47 cases passed.

Positive cases prove the round trip (embed -> transfer -> extract -> signature + hash OK); negative cases prove that each failure mode is detected and reported with the correct verdict category.

| ID | Type | Cover | Case | Expected | Actual | Pass | Notes |
|---|---|---|---|---|---|---|---|
| I-P1 | positive | image | short message (127 B), 1 LSB, keyed start | Authentic | Authentic | yes | container 940 B / cap 73728 B; start unit 358456 = pixel (x=189, y=233) channel G; 3719 units changed; PSNR 70.1 dB; 0.11s |
| I-P2 | positive | image | large message (672 B), 3 LSB, keyed start | Authentic | Authentic | yes | container 1485 B / cap 221184 B; start unit 538849 = pixel (x=416, y=350) channel G; 3454 units changed; PSNR 60.0 dB; 0.08s |
| I-P3 | positive | image | custom message (355 B) AES-GCM encrypted, 2 LSB, keyed start | Authentic | Authentic | yes | container 1290 B / cap 147456 B; start unit 288679 = pixel (x=482, y=187) channel G; 3897 units changed; PSNR 64.7 dB; 0.17s |
| I-P4 | positive | image | large message, 8 LSB, MANUAL start, LSB depth auto-detected | Authentic | Authentic | yes | start unit 69489 = pixel (x=123, y=45) channel R; detected 8 LSB |
| I-P5 | positive | image | file transferred to Party B folder, verified with distributed public key | Authentic | Authentic | yes | sha256(sent)=70856bf2a917fff1 == sha256(received)=70856bf2a917fff1 |
| I-N6 | negative | image | capacity check: large message into tiny cover at 1 LSB | Capacity check rejected | Capacity check rejected | yes | Payload too large: the payload is 672 B and the signed container needs 1.4 KB, but this cover only holds 576 B at 1 LSB (4,608 units x 1 bit). It would fit at 3 LSB. |
| I-N7 | negative | image | content modified after protection (40x40 red square painted at image centre (LSBs preserved)) | Tampered | Tampered | yes |  |
| I-N8 | negative | image | payload signed with an attacker's key (forgery) | Signature Invalid | Signature Invalid | yes |  |
| I-N9 | negative | image | verifier supplies the wrong start-location secret | Wrong Start Location | Wrong Start Location | yes | expected unit 441080, payload actually at 358456 |
| I-N10 | negative | image | LSB planes wiped (payload removed) | Payload Missing | Payload Missing | yes |  |
| I-N11 | negative | image | original unprotected cover presented as stego | Payload Missing | Payload Missing | yes |  |
| I-N12 | negative | image | LSBs inside the payload span overwritten | Tampered | Tampered | yes |  |
| I-N13 | negative | image | no public key available to the verifier | Cannot Verify | Cannot Verify | yes |  |
| I-N14 | negative | image | wrong LSB depth selected by verifier | Payload Missing | Payload Missing | yes |  |
| I-N15 | negative | image | unsupported / corrupt file (JPEG bytes with .png name) | Cannot Verify | Cannot Verify | yes |  |
| A-P16 | positive | audio | short message (127 B), 1 LSB, keyed start | Authentic | Authentic | yes | container 992 B / cap 22050 B; start unit 73220 = sample 36610 (t = 1.660 s, channel 0); 3945 units changed; PSNR 106.8 dB; 0.02s |
| A-P17 | positive | audio | large message (672 B), 3 LSB, keyed start | Authentic | Authentic | yes | container 1537 B / cap 66150 B; start unit 152081 = sample 76040 (t = 3.449 s, channel 1); 3575 units changed; PSNR 96.7 dB; 0.02s |
| A-P18 | positive | audio | custom message (355 B) AES-GCM encrypted, 2 LSB, keyed start | Authentic | Authentic | yes | container 1342 B / cap 44100 B; start unit 42863 = sample 21431 (t = 0.972 s, channel 1); 4046 units changed; PSNR 101.5 dB; 0.08s |
| A-P19 | positive | audio | large message, 8 LSB, MANUAL start, LSB depth auto-detected | Authentic | Authentic | yes | start unit 60000 = sample 30000 (t = 1.361 s, channel 0); detected 8 LSB |
| A-P20 | positive | audio | file transferred to Party B folder, verified with distributed public key | Authentic | Authentic | yes | sha256(sent)=a37cb8233a6cf5c9 == sha256(received)=a37cb8233a6cf5c9 |
| A-N21 | negative | audio | capacity check: large message into tiny cover at 1 LSB | Capacity check rejected | Capacity check rejected | yes | Payload too large: the payload is 672 B and the signed container needs 1.5 KB, but this cover only holds 50 B at 1 LSB (400 units x 1 bit). It does not fit even at 8 LSB - choose a bigger cover object. |
| A-N22 | negative | audio | content modified after protection (0.25 s of audio at the midpoint muted (LSB byte preserved)) | Tampered | Tampered | yes |  |
| A-N23 | negative | audio | payload signed with an attacker's key (forgery) | Signature Invalid | Signature Invalid | yes |  |
| A-N24 | negative | audio | verifier supplies the wrong start-location secret | Wrong Start Location | Wrong Start Location | yes | expected unit 98612, payload actually at 73220 |
| A-N25 | negative | audio | LSB planes wiped (payload removed) | Payload Missing | Payload Missing | yes |  |
| A-N26 | negative | audio | original unprotected cover presented as stego | Payload Missing | Payload Missing | yes |  |
| A-N27 | negative | audio | LSBs inside the payload span overwritten | Tampered | Tampered | yes |  |
| A-N28 | negative | audio | no public key available to the verifier | Cannot Verify | Cannot Verify | yes |  |
| A-N29 | negative | audio | wrong LSB depth selected by verifier | Payload Missing | Payload Missing | yes |  |
| A-N30 | negative | audio | audio truncated by 0.5 s | Tampered | Tampered | yes |  |
| A-N31 | negative | audio | confidential message, wrong passphrase (media authentic, message sealed) | Authentic | Authentic | yes | message_error='wrong passphrase or ciphertext modified (GCM tag mismatch)' |
| PT32 | positive | image | payload type: 01_short_text_LO.txt (127 B) in cover_image.png at 1 LSB | Authentic | Authentic | yes | initial sha256 0768a05582364a80... = extracted 0768a05582364a80...; PSNR 70.1 dB |
| PT33 | positive | audio | payload type: 02_large_text_overview.txt (672 B) in cover_audio.wav at 1 LSB | Authentic | Authentic | yes | initial sha256 9da29847729bc5ad... = extracted 9da29847729bc5ad...; SNR 93.0 dB |
| PT34 | positive | image | payload type: 03_confidential_record.txt (355 B) encrypted in cover_image.png at 2 LSB | Authentic | Authentic | yes | initial sha256 993fcc6759c4452a... = extracted 993fcc6759c4452a...; PSNR 64.7 dB |
| PT35 | positive | audio | payload type: 04_picture_logo.png (733 B) in cover_audio.wav at 1 LSB | Authentic | Authentic | yes | initial sha256 23c152b2339207d4... = extracted 23c152b2339207d4...; SNR 92.8 dB |
| PT36 | positive | image | payload type: 05_picture_photo.jpg (22.0 KB) in cover_image.png at 1 LSB | Authentic | Authentic | yes | initial sha256 f923ecbb452c10cf... = extracted f923ecbb452c10cf...; PSNR 56.1 dB |
| PT37 | positive | image | payload type: 05_picture_photo.jpg (22.0 KB) encrypted in cover_graphic.png at 1 LSB | Authentic | Authentic | yes | initial sha256 f923ecbb452c10cf... = extracted f923ecbb452c10cf...; PSNR 56.1 dB |
| PT38 | positive | audio | payload type: 06_audio_clip.wav (93.8 KB) in cover_audio_long.wav at 1 LSB | Authentic | Authentic | yes | initial sha256 9d628819e729a1f6... = extracted 9d628819e729a1f6...; SNR 82.1 dB |
| PT39 | positive | image | payload type: 06_audio_clip.wav (93.8 KB) in cover_image.png at 2 LSB | Authentic | Authentic | yes | initial sha256 9d628819e729a1f6... = extracted 9d628819e729a1f6...; PSNR 45.8 dB |
| PT40 | positive | audio | payload type: 07_audio_song.mp3 (117.9 KB) in cover_audio_long.wav at 1 LSB | Authentic | Authentic | yes | initial sha256 d4c13cd5e1fdad22... = extracted d4c13cd5e1fdad22...; SNR 81.2 dB |
| PT41 | positive | image | payload type: 08_video_small.mp4 (83.5 KB) in cover_image_large.png at 1 LSB | Authentic | Authentic | yes | initial sha256 e7eeb2f5d374d278... = extracted e7eeb2f5d374d278...; PSNR 58.4 dB |
| PT42 | positive | audio | payload type: 08_video_small.mp4 (83.5 KB) in cover_audio.wav at 4 LSB | Authentic | Authentic | yes | initial sha256 e7eeb2f5d374d278... = extracted e7eeb2f5d374d278...; SNR 62.1 dB |
| PT43 | positive | image | payload type: 09_video_large.mp4 (2.4 MB) in cover_image_large.png at 6 LSB | Authentic | Authentic | yes | initial sha256 2e761822a39815dc... = extracted 2e761822a39815dc...; PSNR 20.2 dB |
| TB44 | negative | audio | payload too big: 09_video_large.mp4 (2.4 MB) into cover_audio_long.wav at 8 LSB | Capacity check rejected | Capacity check rejected | yes | Payload too large: the payload is 2.4 MB and the signed container needs 2.4 MB, but this cover only holds 1.7 MB at 8 LSB (1,764,000 units x 8 bit). It does not fit even at 8 LSB - choose a bigger cover object. |
| TB45 | negative | image | payload too big: 09_video_large.mp4 (2.4 MB) into cover_image_large.png at 1 LSB | Capacity check rejected | Capacity check rejected | yes | Payload too large: the payload is 2.4 MB and the signed container needs 2.4 MB, but this cover only holds 450.0 KB at 1 LSB (3,686,400 units x 1 bit). It would fit at 6 LSB. |
| TB46 | negative | audio | payload too big: 06_audio_clip.wav (93.8 KB) into cover_audio.wav at 1 LSB | Capacity check rejected | Capacity check rejected | yes | Payload too large: the payload is 93.8 KB and the signed container needs 94.6 KB, but this cover only holds 21.5 KB at 1 LSB (176,400 units x 1 bit). It would fit at 5 LSB. |
| TB47 | negative | image | payload too big: 08_video_small.mp4 (83.5 KB) into tiny_image.png at 8 LSB | Capacity check rejected | Capacity check rejected | yes | Payload too large: the payload is 83.5 KB and the signed container needs 84.3 KB, but this cover only holds 4.5 KB at 8 LSB (4,608 units x 8 bit). It does not fit even at 8 LSB - choose a bigger cover object. |

## Payload types and sizes: initial vs extracted SHA-256

Each payload file was embedded, the stego file saved and re-loaded, the payload extracted, and the SHA-256 of the extracted payload compared with the SHA-256 of the initial payload (which is also inside the signed record).

| Payload | Kind | Size | Cover | LSB | Enc | Container / capacity | Initial SHA-256 | Extracted SHA-256 | Match | Distortion | Time |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 01_short_text_LO.txt | text | 127 B | cover_image.png | 1 | no | 935 B / 72.0 KB | `0768a05582364a80...` | `0768a05582364a80...` | MATCH | PSNR 70.1 dB, 0.64% units changed | 0.07 s |
| 02_large_text_overview.txt | text | 672 B | cover_audio.wav | 1 | no | 1.5 KB / 21.5 KB | `9da29847729bc5ad...` | `9da29847729bc5ad...` | MATCH | SNR 93.0 dB, 3.5% units changed | 0.02 s |
| 03_confidential_record.txt | text | 355 B | cover_image.png | 2 | yes | 1.3 KB / 144.0 KB | `993fcc6759c4452a...` | `993fcc6759c4452a...` | MATCH | PSNR 64.7 dB, 0.66% units changed | 0.14 s |
| 04_picture_logo.png | image | 733 B | cover_audio.wav | 1 | no | 1.6 KB / 21.5 KB | `23c152b2339207d4...` | `23c152b2339207d4...` | MATCH | SNR 92.8 dB, 3.6% units changed | 0.02 s |
| 05_picture_photo.jpg | image | 22.0 KB | cover_image.png | 1 | no | 22.8 KB / 72.0 KB | `f923ecbb452c10cf...` | `f923ecbb452c10cf...` | MATCH | PSNR 56.1 dB, 15.83% units changed | 0.08 s |
| 05_picture_photo.jpg | image | 22.0 KB | cover_graphic.png | 1 | yes | 22.9 KB / 72.0 KB | `f923ecbb452c10cf...` | `f923ecbb452c10cf...` | MATCH | PSNR 56.1 dB, 15.91% units changed | 0.13 s |
| 06_audio_clip.wav | audio | 93.8 KB | cover_audio_long.wav | 1 | no | 94.6 KB / 215.3 KB | `9d628819e729a1f6...` | `9d628819e729a1f6...` | MATCH | SNR 82.1 dB, 21.97% units changed | 0.19 s |
| 06_audio_clip.wav | audio | 93.8 KB | cover_image.png | 2 | no | 94.6 KB / 144.0 KB | `9d628819e729a1f6...` | `9d628819e729a1f6...` | MATCH | PSNR 45.8 dB, 49.21% units changed | 0.08 s |
| 07_audio_song.mp3 | audio | 117.9 KB | cover_audio_long.wav | 1 | no | 118.8 KB / 215.3 KB | `d4c13cd5e1fdad22...` | `d4c13cd5e1fdad22...` | MATCH | SNR 81.2 dB, 27.2% units changed | 0.19 s |
| 08_video_small.mp4 | video | 83.5 KB | cover_image_large.png | 1 | no | 84.3 KB / 450.0 KB | `e7eeb2f5d374d278...` | `e7eeb2f5d374d278...` | MATCH | PSNR 58.4 dB, 9.35% units changed | 0.55 s |
| 08_video_small.mp4 | video | 83.5 KB | cover_audio.wav | 4 | no | 84.3 KB / 86.1 KB | `e7eeb2f5d374d278...` | `e7eeb2f5d374d278...` | MATCH | SNR 62.1 dB, 91.79% units changed | 0.03 s |
| 09_video_large.mp4 | video | 2.4 MB | cover_image_large.png | 6 | no | 2.4 MB / 2.6 MB | `2e761822a39815dc...` | `2e761822a39815dc...` | MATCH | PSNR 20.2 dB, 90.94% units changed | 0.61 s |

## Steganalysis of the stego objects above

| Stego object | LSB | Units changed | Max change | Distortion | Blind test |
|---|---|---|---|---|---|
| PT_01_short_text_LO_in_cover_image_1lsb.png | 1 | 0.64% | 1 | PSNR 70.1 dB | chi-square blocks p>0.05: cover 0/40, stego 0/40 |
| PT_02_large_text_overview_in_cover_audio_1lsb.wav | 1 | 3.5% | 1 | SNR 93.0 dB | silence test: cover 0/0, stego 0/0 silent blocks disturbed |
| PT_03_confidential_record_in_cover_image_2lsb.png | 2 | 0.66% | 3 | PSNR 64.7 dB | chi-square blocks p>0.05: cover 0/40, stego 0/40 |
| PT_04_picture_logo_in_cover_audio_1lsb.wav | 1 | 3.6% | 1 | SNR 92.8 dB | silence test: cover 0/0, stego 0/0 silent blocks disturbed |
| PT_05_picture_photo_in_cover_image_1lsb.png | 1 | 15.83% | 1 | PSNR 56.1 dB | chi-square blocks p>0.05: cover 0/40, stego 3/40 |
| PT_05_picture_photo_in_cover_graphic_1lsb.png | 1 | 15.91% | 1 | PSNR 56.1 dB | chi-square blocks p>0.05: cover 0/40, stego 11/40 |
| PT_06_audio_clip_in_cover_audio_long_1lsb.wav | 1 | 21.97% | 1 | SNR 82.1 dB | silence test: cover 0/99, stego 60/99 silent blocks disturbed |
| PT_06_audio_clip_in_cover_image_2lsb.png | 2 | 49.21% | 3 | PSNR 45.8 dB | chi-square blocks p>0.05: cover 0/40, stego 0/40 |
| PT_07_audio_song_in_cover_audio_long_1lsb.wav | 1 | 27.2% | 1 | SNR 81.2 dB | silence test: cover 0/99, stego 70/99 silent blocks disturbed |
| PT_08_video_small_in_cover_image_large_1lsb.png | 1 | 9.35% | 1 | PSNR 58.4 dB | chi-square blocks p>0.05: cover 0/40, stego 3/40 |
| PT_08_video_small_in_cover_audio_4lsb.wav | 4 | 91.79% | 15 | SNR 62.1 dB | silence test: cover 0/0, stego 0/0 silent blocks disturbed |
| PT_09_video_large_in_cover_image_large_6lsb.png | 6 | 90.94% | 63 | PSNR 20.2 dB | chi-square blocks p>0.05: cover 0/40, stego 36/40 |
