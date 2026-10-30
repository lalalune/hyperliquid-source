"""RE-013 static visor lifecycle evidence and corruption controls."""
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from state_roots import EvidenceError, Elf
from visor_lifecycle import (CONTROLS, EXPECTED_SHA256, TARGET, _validate,
                             direct_call_target, rip_target)


class VisorLifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = TARGET.read_bytes()
        cls.elf = Elf(cls.data)

    def test_pinned_visor_lifecycle_obligations(self):
        result = _validate(self.data)
        self.assertEqual(result["binary_sha256"], EXPECTED_SHA256)
        self.assertFalse(result["captured_binary_executed"])
        self.assertEqual(len(result["ranges"]), 11)

    def test_corrupted_artifact_is_rejected_before_elf_analysis(self):
        changed = bytearray(self.data)
        changed[-1] ^= 1
        with self.assertRaisesRegex(EvidenceError, "binary sha256"):
            _validate(changed)

    def test_every_cited_instruction_is_bound_to_target_bytes(self):
        for va, expected in CONTROLS.items():
            with self.subTest(va=hex(va)):
                self.assertEqual(self.elf.read(va, len(bytes.fromhex(expected))).hex(), expected)

    def test_synthetic_rip_relative_fixture(self):
        site, target = 0x1000, 0x2345
        fixture = b"\x48\x8d\x35" + struct.pack("<i", target - site - 7)
        self.assertEqual(rip_target(site, fixture), target)
        with self.assertRaisesRegex(EvidenceError, "truncated"):
            rip_target(site, fixture[:6])

    def test_synthetic_direct_call_fixture_and_negative_opcode(self):
        site, target = 0x4000, 0x1234
        fixture = b"\xe8" + struct.pack("<i", target - site - 5)
        self.assertEqual(direct_call_target(site, fixture), target)
        with self.assertRaisesRegex(EvidenceError, "not a complete"):
            direct_call_target(site, b"\xe9" + fixture[1:])


if __name__ == "__main__":
    unittest.main()
