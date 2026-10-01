"""Unit tests - run with `python -m pytest -q` (or `python -m unittest`)."""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from stegoverify import constants as C  # noqa: E402
from stegoverify import crypto_utils as cu  # noqa: E402
from stegoverify import engine, lsb, payload as pl, pngcodec, startloc  # noqa: E402
from stegoverify.covers import AudioCover, ImageCover, load_cover  # noqa: E402

SAMPLES = os.path.join(os.path.dirname(__file__), "..", "samples")
IMG = os.path.join(SAMPLES, "cover_image.png")
WAV = os.path.join(SAMPLES, "cover_audio.wav")


class LSBTests(unittest.TestCase):
    def test_chunks_roundtrip_all_depths(self):
        data = os.urandom(333)
        for n in range(1, 9):
            chunks = lsb.bytes_to_chunks(data, n)
            self.assertTrue(all(c < (1 << n) for c in chunks))
            self.assertEqual(lsb.chunks_to_bytes(chunks, n, len(data)), data)

    def test_embed_extract_with_wraparound(self):
        units = bytearray(os.urandom(1000))
        data = b"hello wrap-around world" * 4
        for n in (1, 3, 8):
            u = bytearray(units)
            start = 990                       # forces wrap past the end
            lsb.embed(u, data, start, n)
            self.assertEqual(lsb.extract(u, start, n, len(data)), data)
            # only the n LSBs changed
            keep = 0xFF ^ ((1 << n) - 1)
            self.assertTrue(all((a & keep) == (b & keep) for a, b in zip(units, u)))

    def test_capacity_error(self):
        units = bytearray(100)
        with self.assertRaises(ValueError):
            lsb.embed(units, b"x" * 200, 0, 1)

    def test_find_pattern(self):
        units = bytearray(os.urandom(5000))
        lsb.embed(units, pl.MAGIC + b"payload", 4321, 2)
        self.assertIn(4321, lsb.find_pattern(units, 2, pl.MAGIC))


class CoverTests(unittest.TestCase):
    def test_png_roundtrip(self):
        img = pngcodec.Image(5, 4, 4, bytearray(os.urandom(80)))
        self.assertEqual(pngcodec.decode(pngcodec.encode(img)).pixels, img.pixels)

    def test_masked_hash_invariant_under_embedding(self):
        for path in (IMG, WAV):
            cover = load_cover(path)
            stego = cover.copy()
            u = stego.units()
            lsb.embed(u, os.urandom(2000), 777, 4)
            stego.set_units(u)
            self.assertEqual(cover.masked_hash(4), stego.masked_hash(4))
            self.assertNotEqual(cover.masked_hash(1), stego.masked_hash(1))  # bits 2-4 differ

    def test_alpha_untouched(self):
        img = pngcodec.Image(8, 8, 4, bytearray(os.urandom(256)))
        cover = ImageCover(img)
        u = cover.units()
        lsb.embed(u, b"z" * 20, 0, 8)
        cover.set_units(u)
        self.assertEqual(cover.img.pixels[3::4], img.pixels[3::4])


class WorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.priv, cls.pub = cu.generate_keypair()
        cls.tmp = tempfile.mkdtemp()

    def _out(self, name):
        return os.path.join(self.tmp, name)

    def test_roundtrip_every_depth_both_covers(self):
        for path, ext in ((IMG, ".png"), (WAV, ".wav")):
            for n in range(1, 9):
                r = engine.protect(path, self._out(f"s{n}{ext}"), C.LARGE_MESSAGE.encode(), n, self.priv, secret="s")
                v = engine.verify(r.stego_path, n, self.pub, secret="s")
                self.assertEqual(v.verdict, engine.AUTHENTIC, (path, n, v.reason))
                self.assertEqual(v.message.decode(), C.LARGE_MESSAGE)

    def test_start_location_is_content_bound_and_secret_bound(self):
        cover = load_cover(IMG)
        h = cover.masked_hash(1)
        a = startloc.derive_start("k1", "image", h, 1, cover.num_units)
        b = startloc.derive_start("k2", "image", h, 1, cover.num_units)
        c = startloc.derive_start("k1", "image", h, 2, cover.num_units)
        self.assertNotEqual(a, b)
        self.assertNotEqual(a, c)
        self.assertEqual(a, startloc.derive_start("k1", "image", h, 1, cover.num_units))

    def test_verdicts(self):
        r = engine.protect(WAV, self._out("v.wav"), b"msg", 2, self.priv, secret="s")
        self.assertEqual(engine.verify(r.stego_path, 2, self.pub, secret="bad").verdict, engine.WRONG_START)
        _, other = cu.generate_keypair()
        self.assertEqual(engine.verify(r.stego_path, 2, other, secret="s").verdict, engine.SIG_INVALID)
        engine.tamper_content(r.stego_path, self._out("t.wav"))
        self.assertEqual(engine.verify(self._out("t.wav"), 2, self.pub, secret="s").verdict, engine.TAMPERED)
        engine.strip_payload(r.stego_path, self._out("x.wav"), 2)
        self.assertEqual(engine.verify(self._out("x.wav"), 2, self.pub, secret="s").verdict, engine.MISSING)
        self.assertEqual(engine.verify(r.stego_path, 2, None, secret="s").verdict, engine.CANNOT)

    def test_encrypted_message(self):
        r = engine.protect(IMG, self._out("e.png"), b"secret text", 1, self.priv, secret="s", passphrase="pw")
        self.assertNotIn("secret text", pl.canonical(r.payload).decode())
        v = engine.verify(r.stego_path, 1, self.pub, secret="s", passphrase="pw")
        self.assertEqual(v.message, b"secret text")
        v = engine.verify(r.stego_path, 1, self.pub, secret="s", passphrase="wrong")
        self.assertEqual(v.verdict, engine.AUTHENTIC)
        self.assertIsNone(v.message)
        self.assertTrue(v.message_error)

    def test_capacity(self):
        with self.assertRaises(engine.CapacityError):
            engine.protect(os.path.join(SAMPLES, "tiny_audio.wav"), self._out("c.wav"), b"x" * 5000, 1, self.priv, secret="s")


class PayloadTypeTests(unittest.TestCase):
    """Lecturer feedback: picture / audio / video payloads, initial vs extracted hash, too-big payloads."""

    @classmethod
    def setUpClass(cls):
        cls.priv, cls.pub = cu.generate_keypair()
        cls.tmp = tempfile.mkdtemp()
        cls.pay = os.path.join(SAMPLES, "payloads")

    def test_file_payloads_roundtrip_with_hash(self):
        for name, cover in (("04_picture_logo.png", WAV), ("05_picture_photo.jpg", IMG),
                            ("06_audio_clip.wav", os.path.join(SAMPLES, "cover_audio_long.wav")),
                            ("08_video_small.mp4", os.path.join(SAMPLES, "cover_image_large.png"))):
            path = os.path.join(self.pay, name)
            if not os.path.exists(path):
                continue
            with open(path, "rb") as fh:
                data = fh.read()
            out = os.path.join(self.tmp, "p" + os.path.splitext(cover)[1])
            r = engine.protect(cover, out, data, 1, self.priv, secret="s", message_name=name)
            v = engine.verify(out, 1, self.pub, secret="s")
            self.assertEqual(v.verdict, engine.AUTHENTIC, (name, v.reason))
            self.assertEqual(v.message, data)
            self.assertEqual(r.message_sha256, cu.sha256(data).hex())
            self.assertEqual(v.payload_hash_extracted, r.message_sha256)
            self.assertTrue(v.payload_hash_ok)
            self.assertEqual(v.payload["msg"]["name"], name)

    def test_capacity_estimate_is_exact_and_safe(self):
        cover = load_cover(IMG)
        for n in (1, 4, 8):
            for size in (0, 10, 5000):
                for enc in (False, True):
                    est = engine.estimate_container(cover, n, size, encrypted=enc, message_name="x.mp4",
                                                    issuer="StegoVerify", filename="cover_image.png")
                    r = engine.protect(IMG, os.path.join(self.tmp, "c.png"), os.urandom(size), n, self.priv,
                                       secret="s", passphrase="p" if enc else None, message_name="x.mp4")
                    self.assertGreaterEqual(est, r.container_len)
                    self.assertLessEqual(est - r.container_len, 16)

    def test_too_big_payload_is_rejected_with_message(self):
        big = os.urandom(200_000)
        with self.assertRaises(engine.CapacityError) as cm:
            engine.protect(WAV, os.path.join(self.tmp, "x.wav"), big, 8, self.priv, secret="s", message_name="v.mp4")
        self.assertIn("Payload too large", str(cm.exception))
        self.assertIn("does not fit even at 8 LSB", str(cm.exception))
        rep = engine.capacity_report(load_cover(IMG), 1, 100_000, message_name="v.mp4")
        self.assertFalse(rep["fits"])
        self.assertEqual(rep["min_lsb_that_fits"], 2)

    def test_altered_message_bytes_detected(self):
        """Attacker rewrites the hidden bytes and fixes the CRC -> signed SHA-256 catches it."""
        import struct
        import zlib
        r = engine.protect(IMG, os.path.join(self.tmp, "a.png"), b"original payload", 1, self.priv, secret="s")
        stego = load_cover(r.stego_path)
        units = stego.units()
        blob = bytearray(lsb.extract(units, r.start_unit, 1, r.container_len))
        _, _, _, plen, slen, mlen = struct.unpack(pl.HEADER_FMT, bytes(blob[:pl.HEADER_LEN]))
        m0 = pl.HEADER_LEN + plen + slen
        blob[m0:m0 + mlen] = b"FORGED  payload!"[:mlen]
        body = bytes(blob[pl.HEADER_LEN:m0 + mlen])
        blob[m0 + mlen:] = struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)
        lsb.embed(units, bytes(blob), r.start_unit, 1)
        stego.set_units(units)
        stego.save(os.path.join(self.tmp, "a2.png"))
        v = engine.verify(os.path.join(self.tmp, "a2.png"), 1, self.pub, secret="s")
        self.assertEqual(v.verdict, engine.TAMPERED)


class SteganalysisTests(unittest.TestCase):
    def test_chi_square_detects_random_payload(self):
        from stegoverify import analysis as an
        cover = load_cover(IMG)
        units = cover.units()
        clean = an.chi_square_blocks(units, 1, 10)
        lsb.embed(units, os.urandom(len(units) // 16), 0, 1)       # first half of the image, random bits
        dirty = an.chi_square_blocks(units, 1, 10)
        self.assertTrue(all(p is not None and p < 0.05 for *_, p in clean))
        self.assertGreaterEqual(sum(1 for *_, p in dirty[:4] if p > 0.05), 3)

    def test_silence_check_audio(self):
        from stegoverify import analysis as an
        long_wav = os.path.join(SAMPLES, "cover_audio_long.wav")
        cover = load_cover(long_wav)
        self.assertEqual(an.silence_check(cover, 1)["suspicious_blocks"], 0)
        units = cover.units()
        lsb.embed(units, os.urandom(len(units) // 8), 0, 1)
        cover.set_units(units)
        self.assertGreater(an.silence_check(cover, 1)["suspicious_blocks"], 10)

    def test_quality_metrics_values(self):
        cover = load_cover(IMG)
        stego = cover.copy()
        u = stego.units()
        u[0] ^= 1
        u[1] ^= 3
        stego.set_units(u)
        q = engine.quality_metrics(cover, stego)
        a, b = cover.units(), stego.units()
        expected_mse = sum((x - y) ** 2 for x, y in zip(a, b)) / len(a)       # slow reference formula
        self.assertEqual(q["changed_units"], 2)
        self.assertAlmostEqual(q["mse"], expected_mse, places=12)
        self.assertEqual(q["max_abs_diff"], 3)


if __name__ == "__main__":
    unittest.main()
