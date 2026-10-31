import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import order_wire_static as ows

PACKET = ROOT / "research" / "work-items" / "order-wire-94"
BINARY = ROOT / ows.BINARY_REL


class OrderWireStaticTests(unittest.TestCase):
    def test_binary_digest(self):
        self.assertTrue(BINARY.exists())
        data = BINARY.read_bytes()
        ows.check_digest(data)
        with self.assertRaises(ows.EvidenceError):
            ows.check_digest(b"corrupt")

    def test_fde_extents_and_digests(self):
        data = BINARY.read_bytes()
        analysis = ows.analyse(data)
        self.assertEqual(len(analysis["fdes"]), 2)
        total_bytes = sum(f["bytes"] for f in analysis["fdes"])
        self.assertEqual(total_bytes, 4080)
        self.assertEqual(analysis["fdes"][0]["bytes"], 912)
        self.assertEqual(analysis["fdes"][1]["bytes"], 3168)

    def test_stride(self):
        data = BINARY.read_bytes()
        analysis = ows.analyse(data)
        self.assertEqual(analysis["stride"], 56)
        self.assertEqual(ows.ORDER_WIRE_STRIDE, 56)

    def test_panic_records(self):
        data = BINARY.read_bytes()
        analysis = ows.analyse(data)
        records = analysis["source_records"]
        self.assertEqual(len(records), 3)
        for va_str, info in ows.PANIC_LOCATIONS.items():
            self.assertIn(va_str, records)
            self.assertEqual(records[va_str]["line"], info["line"])
            self.assertEqual(records[va_str]["col"], info["col"])
            self.assertEqual(records[va_str]["path"], info["path"])

    def test_controls(self):
        data = BINARY.read_bytes()
        analysis = ows.analyse(data)
        controls = analysis["controls"]
        self.assertEqual(len(controls), len(ows.CONTROLS))
        for va, op in ows.CONTROLS.items():
            self.assertIn(hex(va), controls)
            self.assertEqual(controls[hex(va)], op)

    def test_negative_control_mutation(self):
        data = BINARY.read_bytes()
        orig = ows.CONTROLS[0x3341602]
        try:
            ows.CONTROLS[0x3341602] = "90909090"
            with self.assertRaises(ows.EvidenceError):
                ows.analyse(data)
        finally:
            ows.CONTROLS[0x3341602] = orig

    def test_manifest_verification(self):
        manifest_path = PACKET / "MANIFEST.sha256"
        self.assertTrue(manifest_path.exists())
        lines = manifest_path.read_text(encoding="utf-8").splitlines()
        self.assertGreaterEqual(len(lines), 4)
        for line in lines:
            digest, rel_path = line.split("  ")
            target = PACKET / rel_path
            self.assertTrue(target.is_file(), f"Target missing: {target}")
            data = target.read_bytes()
            self.assertFalse(b"\r" in data, f"CRLF in {target}")
            self.assertEqual(hashlib.sha256(data).hexdigest(), digest)

    def test_packet_regeneration(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            ows.generate_packet(tmp_path, BINARY)
            manifest_orig = (PACKET / "MANIFEST.sha256").read_bytes()
            manifest_new = (tmp_path / "MANIFEST.sha256").read_bytes()
            self.assertEqual(manifest_orig, manifest_new)

    def test_wire_decimal_codec(self):
        d1 = ows.WireDecimal.parse("123.456")
        self.assertEqual(d1.raw, 12345600000)
        self.assertEqual(d1.to_string(), "123.456")

        d2 = ows.WireDecimal.parse("0.00000001")
        self.assertEqual(d2.raw, 1)
        self.assertEqual(d2.to_string(), "0.00000001")

        d3 = ows.WireDecimal.parse("50000")
        self.assertEqual(d3.raw, 5000000000000)
        self.assertEqual(d3.to_string(), "50000")

        with self.assertRaises(ows.EvidenceError):
            ows.WireDecimal.parse("1.123456789")  # 9 decimal places exceeds 8
        with self.assertRaises(ows.EvidenceError):
            ows.WireDecimal.parse("abc")

    def test_compact_order_roundtrip(self):
        px = ows.WireDecimal.parse("2500.5")
        sz = ows.WireDecimal.parse("10.25")
        trig = ows.WireDecimal.parse("2400.0")
        cloid = bytes.fromhex("0123456789abcdef0123456789abcdef")

        # Basic order
        enc = ows.encode_compact_order(
            asset=4,
            is_buy=True,
            limit_px=px,
            sz=sz,
            reduce_only=False,
            type_code=2,
        )
        self.assertEqual(len(enc), 21)
        dec, used = ows.decode_compact_order(enc)
        self.assertEqual(used, 21)
        self.assertEqual(dec["asset"], 4)
        self.assertTrue(dec["is_buy"])
        self.assertEqual(dec["limit_px"], px)
        self.assertEqual(dec["sz"], sz)
        self.assertFalse(dec["reduce_only"])
        self.assertEqual(dec["type_code"], 2)
        self.assertIsNone(dec["trigger_px"])
        self.assertIsNone(dec["cloid"])

        # Extended order with trigger_px and cloid
        enc_ext = ows.encode_compact_order(
            asset=7,
            is_buy=False,
            limit_px=px,
            sz=sz,
            reduce_only=True,
            type_code=4,
            trigger_px=trig,
            cloid=cloid,
        )
        self.assertEqual(len(enc_ext), 21 + 8 + 16)
        dec_ext, used_ext = ows.decode_compact_order(enc_ext)
        self.assertEqual(used_ext, 45)
        self.assertEqual(dec_ext["asset"], 7)
        self.assertFalse(dec_ext["is_buy"])
        self.assertEqual(dec_ext["limit_px"], px)
        self.assertEqual(dec_ext["sz"], sz)
        self.assertTrue(dec_ext["reduce_only"])
        self.assertEqual(dec_ext["type_code"], 4)
        self.assertEqual(dec_ext["trigger_px"], trig)
        self.assertEqual(dec_ext["cloid"], cloid)


if __name__ == "__main__":
    unittest.main()
