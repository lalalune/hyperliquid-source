"""Static target binding plus synthetic formula examples, not target execution.

The formula examples check the documented projection and its counterexamples.
They are not differential execution or a recovered Rust implementation.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research/work-items/RE-008-timeout-wire-projection-94"
spec = importlib.util.spec_from_file_location("timeout_wire_projection94_build", PACKET / "build.py")
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)


def synthetic_v(value):
    """Mathematical V from the proof; never interprets captured instructions."""
    if value < 251:
        return bytes([value])
    width, marker = next((width, marker) for width, marker in ((2, 251), (4, 252), (8, 253))
                         if value < 1 << (8 * width))
    return bytes([marker]) + value.to_bytes(width, "little")


def synthetic_projection(layout, payload, rows):
    def word(data, offset):
        return struct.unpack_from("<Q", data, int(offset, 16))[0]
    signer = int(layout["timeout_signer_offset"], 16)
    block_hash = int(layout["qc_hash_offset"], 16)
    result = b"\x02" + payload[signer:signer + 20]
    result += b"".join(synthetic_v(word(payload, off)) for off in layout["timeout_u64_offsets_in_order"])
    result += payload[block_hash:block_hash + 32]
    count = word(payload, layout["qc_vote_count_offset"])
    if count != len(rows):
        raise ValueError("synthetic row count mismatch")
    result += synthetic_v(count)
    for row in rows:
        result += row[:20]
        result += b"".join(synthetic_v(word(row, hex(0x18 + int(off, 16))))
                           for off in layout["nested_signature_limb_offsets_in_order"])
        result += row[0x58:0x59]
    return result


class TimeoutWireProjection94(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = b.Image((ROOT / "artifacts/node/94/hl-node").read_bytes())
        cls.pins = json.loads((PACKET / "pins.json").read_text())
        cls.frozen = json.loads((PACKET / "observed/records.json").read_text())

    def test_native_projection_and_instruction_witnesses(self):
        b.check_witnesses(self.image, self.pins)
        actual = b.projection(self.image)
        self.assertEqual(actual, self.frozen["projection"])
        self.assertEqual(actual["timeout_u64_offsets_in_order"], ["0x50", "0x18", "0x20", "0x28"])
        self.assertEqual(actual["nested_signature_limb_offsets_in_order"],
                         [hex(8 * i) for i in range(8)])

    def test_selected_bytes_and_whole_owner_fdes(self):
        _, fdes = b.eh_frame_records(self.image.data)
        for record in self.frozen["functions"]:
            with self.subTest(record=record["name"]):
                start, end = int(record["owner_start"], 16), int(record["owner_end"], 16)
                self.assertEqual([(f["start"], f["end"], hex(f["fde"])) for f in fdes if f["start"] == start],
                                 [(start, end, record["fde"]["va"])])
                self.assertEqual(hashlib.sha256(self.image.read(start, end-start)).hexdigest(), record["body_sha256"])
                for va, raw, _ in b.rows((PACKET / "observed" / (record["name"] + ".gnu.txt")).read_text()):
                    self.assertEqual(self.image.read(va, len(raw)), raw)

    def test_synthetic_v_boundaries(self):
        # Explicit independently written boundary encodings, including both
        # sides of each native-pinned scalar threshold.
        cases = [(0, "00"), (250, "fa"), (251, "fbfb00"), (65535, "fbffff"),
                 (65536, "fc00000100"), (2**32-1, "fcffffffff"),
                 (2**32, "fd0000000001000000"), (2**64-1, "fdffffffffffffffff")]
        for value, expected in cases:
            with self.subTest(value=value):
                self.assertEqual(synthetic_v(value).hex(), expected)

    def test_synthetic_order_size_and_raw_signature_counterexample(self):
        payload = bytearray(0xB8)
        payload[0x58:0x6C] = b"T" * 20
        payload[0x30:0x50] = b"H" * 32
        for off, value in ((0x50, 250), (0x18, 251), (0x20, 65535), (0x28, 65536), (0x10, 2)):
            struct.pack_into("<Q", payload, off, value)
        first, second = bytearray(0x60), bytearray(0x60)
        first[:20], second[:20] = b"A" * 20, b"B" * 20
        first[0x58], second[0x58] = 7, 9
        for i, value in enumerate((0, 250, 251, 65535, 65536, 2**32-1, 2**32, 2**64-1)):
            struct.pack_into("<Q", second, 0x18 + 8 * i, value)
        actual = synthetic_projection(b.projection(self.image), payload, [first, second])
        header = b"\x02" + b"T" * 20 + bytes.fromhex("fa fbfb00 fbffff fc00000100") + b"H" * 32 + b"\x02"
        signature = bytes.fromhex("00 fa fbfb00 fbffff fc00000100 fcffffffff fd0000000001000000 fdffffffffffffffff 09")
        expected = header + b"A" * 20 + b"\0" * 8 + b"\x07" + b"B" * 20 + signature
        self.assertEqual(actual, expected)
        self.assertEqual(len(actual), 152)
        raw_wrong = header + bytes(first[:20] + first[0x18:0x59] + second[:20] + second[0x18:0x59])
        self.assertNotEqual(actual, raw_wrong)
        wrong_order = dict(b.projection(self.image), timeout_u64_offsets_in_order=["0x18", "0x50", "0x20", "0x28"])
        self.assertNotEqual(synthetic_projection(wrong_order, payload, [first, second]), expected)

    def test_changed_native_field_displacement_rejected_below_digest(self):
        image = self.image
        class ChangedField:
            def read(self, va, size):
                raw = bytearray(image.read(va, size))
                changed = 0x4778860  # last byte of mov rcx,[r15+0x50]
                if va <= changed < va + size:
                    raw[changed - va] = 0x18
                return bytes(raw)
        self.assertNotEqual(b.projection(ChangedField()), self.frozen["projection"])
        with self.assertRaisesRegex(ValueError, "witness"):
            b.check_witnesses(ChangedField(), self.pins)


if __name__ == "__main__":
    unittest.main()
