"""Digest, complete-body, critical-transfer and data controls for TC abort."""
import importlib.util
import json
from pathlib import Path
import struct
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research/work-items/RE-008-tc-parallel-abort-94"
SPEC = importlib.util.spec_from_file_location("tc_parallel_abort_static", PACKET / "static.py")
STATIC = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(STATIC)


class TcParallelAbort(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = (ROOT / "artifacts/node/94/hl-node").read_bytes()
        cls.image = STATIC.Image(cls.raw)

    def mutate(self, va, replacement):
        data = bytearray(self.raw)
        off = self.image.offset(va, len(replacement))
        data[off:off + len(replacement)] = replacement
        return bytes(data)

    def admitted(self, data, **kwargs):
        return STATIC.collect(data, admitted_digest=STATIC.digest(data), **kwargs)

    def test_retained_complete_record(self):
        result = STATIC.collect(self.raw)
        retained = json.loads((PACKET / "static/records.json").read_bytes())
        self.assertEqual(result, retained)
        subject = [b for b in result["bodies"] if b["role"] == "subject"]
        self.assertEqual(sum(b["bytes"] for b in subject), 2144)
        self.assertEqual(sum(len(b["instructions"]) for b in subject), 421)
        self.assertEqual(len(result["direct_incoming_candidates"]), 5)
        self.assertTrue(all(r["instruction_confirmed"] for r in result["direct_incoming_candidates"]))

    def test_wrong_whole_target_rejected(self):
        data = self.mutate(0x4768F80, b"\x54")
        with self.assertRaisesRegex(ValueError, "target digest"):
            STATIC.collect(data)

    def test_every_critical_anchor_below_digest_guard(self):
        for address, value in STATIC.ANCHORS.items():
            with self.subTest(address=hex(address)):
                data = self.mutate(address, bytes([bytes.fromhex(value)[0] ^ 1]))
                with self.assertRaisesRegex(ValueError, "critical instruction"):
                    self.admitted(data, check_core_hashes=False)

    def test_complete_unanchored_core_byte_is_bound(self):
        # Epilogue register changes are outside the selective semantic anchors.
        data = self.mutate(0x4768FD1, b"\x41\x5d")
        with self.assertRaisesRegex(ValueError, "complete core body hash"):
            self.admitted(data)

    def test_selected_relocation_addends_below_digest_guard(self):
        for slot in [0x5773298, 0x576E010, 0x5776AE8]:
            with self.subTest(slot=hex(slot)):
                row = self.image.relocations[slot]
                off = int(row["file_offset"], 16)
                data = bytearray(self.raw)
                old = struct.unpack_from("<q", data, off + 16)[0]
                struct.pack_into("<q", data, off + 16, old + 1)
                with self.assertRaisesRegex(ValueError, "selected relocation"):
                    self.admitted(bytes(data), check_core_hashes=False)

    def test_duplicate_relocation_slot_rejected(self):
        data = bytearray(self.raw)
        first = int(self.image.relocations[0x5773298]["file_offset"], 16)
        second = int(self.image.relocations[0x5776AE8]["file_offset"], 16)
        data[second:second + 8] = data[first:first + 8]
        with self.assertRaisesRegex(ValueError, "duplicate relocation"):
            self.admitted(bytes(data))

    def test_fde_end_corruption_rejected(self):
        fde = self.image.owner(0x4768F80)
        # FDE start is sdata4 at +8, range is the following sdata4.
        address = fde["fde"] + 12
        old = struct.unpack("<i", self.image.raw(address, 4))[0]
        data = self.mutate(address, struct.pack("<i", old - 1))
        with self.assertRaisesRegex(ValueError, "FDE extent"):
            self.admitted(data, check_core_hashes=False)

    def test_drop_table_corruption_rejected(self):
        # An offset outside the four valid targets cannot be accepted as a drop arm.
        old = struct.unpack("<i", self.image.raw(0x6F9758, 4))[0]
        data = self.mutate(0x6F9758, struct.pack("<i", old + 1))
        with self.assertRaisesRegex(ValueError, "drop table"):
            self.admitted(data, check_core_hashes=False)


if __name__ == "__main__":
    unittest.main()
