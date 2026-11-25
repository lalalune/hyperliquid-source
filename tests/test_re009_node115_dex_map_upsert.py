"""Target-bound regression checks for the RE-009 DEX map upsert packet."""

from __future__ import annotations

import hashlib
import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research/work-items/RE-009-node115-dex-map-upsert"
SPEC = importlib.util.spec_from_file_location("re009_dex_map_upsert", PACKET / "verify.py")
assert SPEC and SPEC.loader
VERIFY = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = VERIFY
SPEC.loader.exec_module(VERIFY)


class DexMapUpsertPacketTests(unittest.TestCase):
    def test_pinned_target_anchors_and_fde_rows(self) -> None:
        output = VERIFY.check(VERIFY.ELF.read_bytes())
        self.assertEqual(len(output), len(VERIFY.ANCHORS))

    def test_mutated_target_is_rejected(self) -> None:
        data = bytearray(VERIFY.ELF.read_bytes())
        address = 0x4DD5C57
        offset = VERIFY.va_to_offset(data, address)
        data[offset] ^= 1
        with self.assertRaisesRegex(ValueError, "target digest mismatch"):
            VERIFY.check(bytes(data))

    def test_each_anchor_comparison_rejects_a_byte_mutation(self) -> None:
        data = VERIFY.ELF.read_bytes()
        for address, expected in VERIFY.ANCHORS.items():
            with self.subTest(address=hex(address)):
                mutant = bytearray(data)
                offset = VERIFY.va_to_offset(data, address)
                mutant[offset + len(expected) - 1] ^= 1
                with self.assertRaisesRegex(ValueError, "anchor mismatch"):
                    VERIFY.check_anchors(bytes(mutant))

    def test_fde_extents_are_recomputed_from_target_bytes(self) -> None:
        data = VERIFY.ELF.read_bytes()
        VERIFY.check_fde_rows(data)
        retained = VERIFY.FDE_RECORD.read_text().replace(
            "0x4dd59a0\t0x4dd6145\t1957\t.text\n", ""
        )
        with self.assertRaisesRegex(ValueError, "ELF-derived extents"):
            VERIFY.check_fde_rows(data, retained)

    def test_packet_manifest_matches_files(self) -> None:
        for line in (PACKET / "MANIFEST.sha256").read_text().splitlines():
            expected, name = line.split("  ", 1)
            actual = hashlib.sha256((PACKET / name).read_bytes()).hexdigest()
            self.assertEqual(actual, expected, name)


if __name__ == "__main__":
    unittest.main()
