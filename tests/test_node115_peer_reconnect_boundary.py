"""Real target byte controls; no captured execution or invented behavior."""
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
import unittest

PACKET = Path(__file__).resolve().parents[1] / "research/work-items/RE-001-node115-peer-reconnect-boundary"
spec = importlib.util.spec_from_file_location("peer_reconnect_boundary", PACKET / "verify.py")
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)


class NativeBoundary(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = v.TARGET.read_bytes()
        v.authenticate(cls.data)
        cls.elf = v.Elf(cls.data)

    def test_authentic_native_sites(self):
        result = v.verify_sites(self.elf)
        self.assertEqual(result["source_association"], "node/src/nv_stream.rs:254:37")
        self.assertEqual(result["diagnostic_bytes"], 83)

    def check_mutation(self, offset, label):
        data = bytearray(self.data)
        data[offset] ^= 1
        with self.assertRaisesRegex(ValueError, label):
            v.verify_sites(v.Elf(data))

    def test_real_instruction_and_data_controls(self):
        for va, label in [(0x5a87933, "diagnostic xref"),
                          (0x445ff7, "diagnostic bytes"),
                          (0x5a879ce, "Location xref"),
                          (0x64b9238, "Location fields"),
                          (0x5a879fc, "native site"),
                          (0x5a87a24, "native site"),
                          (0x5a87a37, "native site"),
                          (0x5a87a50, "continuation edge")]:
            with self.subTest(va=hex(va)):
                self.check_mutation(self.elf.offset(va, 1), label)

    def test_real_relocation_controls(self):
        for slot, label in [(0x64b9228, "Location relative relocation"),
                            (0x64e0b18, "call relative relocation")]:
            with self.subTest(slot=hex(slot)):
                self.check_mutation(self.elf.relocation_offsets[slot] + 8, label)

    def test_full_native_replay(self):
        raw = subprocess.check_output([sys.executable, str(PACKET / "verify.py")], text=True)
        result = json.loads(raw)
        self.assertEqual(result["fde"], ["0x5a82670", "0x5a89535"])
        self.assertEqual(result["excerpt_bytes"], 290)
        self.assertFalse(result["captured_code_executed"])

    def test_identity_control(self):
        data = bytearray(self.data)
        data[self.elf.offset(0x5a87a37, 1)] ^= 1
        with self.assertRaisesRegex(ValueError, "target digest"):
            v.authenticate(data)


if __name__ == "__main__":
    unittest.main()
