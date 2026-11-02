"""Tests for node #94's WAL reader constructor 0x51632f0 (RE-001).

Pins the field writes in research/work-items/RE-001-wal-reader-ctor-94/
and the packet itself (verify script, sampled instructions, corruption
control), following the pattern of the earlier WAL reader tests.
"""
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

from wal_reader_ctor import (BUFFER_SIZE, STATIC_SLICE_PTR, VTABLE_PTR,
                             RefCounted, TakenSlot, construct)

REPO = Path(__file__).resolve().parent.parent
PACKET = REPO / "research" / "work-items" / "RE-001-wal-reader-ctor-94"


def make_reader(**overrides):
    kwargs = dict(
        source_first="pair-first",
        source_second=RefCounted(3),
        taken_slot=TakenSlot("taken-value"),
        rcx_value="rcx-value",
        flag_byte=1,
        log_number=42,
        global_flag_byte=0,
    )
    kwargs.update(overrides)
    return construct(**kwargs)


class TestWalReaderCtor(unittest.TestCase):
    def test_every_field_write(self):
        slot = TakenSlot("taken-value")
        shared = RefCounted(3)
        reader = construct("first", shared, slot, "rcx", 1, 42, 0)
        f = reader.fields
        self.assertEqual(f["vtable"], VTABLE_PTR)
        self.assertEqual(VTABLE_PTR, 0x575B0B8)
        self.assertEqual(f["pair_first"], "first")
        self.assertIs(f["pair_second"], shared)
        self.assertEqual(f["taken"], "taken-value")
        self.assertIsNone(slot.value)  # slot cleared by the move
        self.assertEqual(f["rcx_value"], "rcx")
        self.assertEqual(f["flag_byte"], 1)
        self.assertEqual(len(f["buffer"]), BUFFER_SIZE)
        self.assertEqual(BUFFER_SIZE, 0x8000)
        self.assertEqual(f["slice_ptr"], STATIC_SLICE_PTR)
        self.assertEqual(STATIC_SLICE_PTR, 0x1E629B)
        self.assertEqual(f["slice_len"], 0)
        self.assertEqual(f["flags_u16"], 0)
        for key in ("field_0x50", "field_0x58", "field_0x60",
                    "field_0x70", "field_0x78", "field_0x80",
                    "field_0xa8", "field_0xb0"):
            self.assertEqual(f[key], 0, key)
        self.assertEqual(f["log_number"], 42)
        self.assertEqual(f["string_ptr"], "inline+0x98")
        self.assertEqual(f["string_len"], 0)
        self.assertEqual(f["string_first_byte"], 0)

    def test_refcount_null_source_skips_increment(self):
        reader = construct("first", None, TakenSlot("v"), "rcx", 1, 0, 0)
        self.assertIsNone(reader.fields["pair_second"])
        self.assertIsNone(reader.fields["refcount_form"])

    def test_refcount_both_increment_forms(self):
        shared = RefCounted(7)
        reader = construct("first", shared, TakenSlot("v"), "rcx", 1, 0, 0)
        self.assertEqual(shared.refcount, 8)
        self.assertEqual(reader.fields["refcount_form"], "lock")
        shared2 = RefCounted(7)
        reader2 = construct("first", shared2, TakenSlot("v"), "rcx", 1, 0, 5)
        self.assertEqual(shared2.refcount, 8)
        self.assertEqual(reader2.fields["refcount_form"], "plain")

    def test_flag_byte_is_low_byte_only(self):
        reader = make_reader(flag_byte=0x1FF)
        self.assertEqual(reader.fields["flag_byte"], 0xFF)

    def test_log_number_zero_and_buffers_are_fresh(self):
        first = make_reader(log_number=0)
        second = make_reader(log_number=0)
        self.assertEqual(first.fields["log_number"], 0)
        self.assertIsNot(first.fields["buffer"], second.fields["buffer"])
        first.fields["buffer"][0] = 9
        self.assertEqual(second.fields["buffer"][0], 0)

    def test_caller_flag_table(self):
        records = json.loads((PACKET / "records.json").read_text())
        callers = {c["address"]: c for c in records["callers"]}
        self.assertEqual(len(callers), 7)
        constant_one = [a for a, c in callers.items()
                        if c["arg_setup"]["r8"] == 1]
        self.assertEqual(len(constant_one), 6)
        self.assertNotEqual(callers["0x52136b9"]["arg_setup"]["r8"], 1)
        zero_log = [a for a, c in callers.items()
                    if c["arg_setup"]["r9"] == 0]
        self.assertEqual(len(zero_log), 3)

    def test_packet_verify_passes(self):
        result = subprocess.run(
            [sys.executable, str(PACKET / "verify.py")],
            cwd=REPO, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0,
                         result.stdout + result.stderr)
        self.assertIn("ALL CHECKS PASSED", result.stdout)

    def test_packet_excerpt_regeneration(self):
        result = subprocess.run(
            [sys.executable, str(PACKET / "export_excerpts.py")],
            cwd=REPO, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0,
                         result.stdout + result.stderr)
        result = subprocess.run(
            [sys.executable, str(PACKET / "verify.py")],
            cwd=REPO, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)

    def test_sampled_instructions_byte_for_byte(self):
        data = (REPO / "work" / "hl-node-94.bin").read_bytes()
        samples = {
            0x51632F0: bytes.fromhex("f30f1efa"),
            0x5163354: bytes.fromhex("e897d14f00"),
            0x5163335: bytes.fromhex("83420801"),
            0x51633C8: bytes.fromhex("f083420801"),
        }
        for vaddr, expected in samples.items():
            off = vaddr - 0x1000
            self.assertEqual(data[off:off + len(expected)], expected,
                             hex(vaddr))

    def test_corruption_control_fails_verification(self):
        with tempfile.TemporaryDirectory() as tmp:
            copy = Path(tmp) / "packet"
            shutil.copytree(PACKET, copy)
            window = copy / "window.txt"
            text = window.read_text()
            window.write_text(text.replace("endbr64", "endbrXX", 1))
            result = subprocess.run(
                [sys.executable, str(copy / "verify.py"),
                 "--packet-dir", str(copy)],
                cwd=REPO, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
