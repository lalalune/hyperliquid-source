"""Tests for the node #94 snapshot identity-format model."""

import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import foundation_snapshot_identity_format as subject

REPO = Path(__file__).resolve().parents[1]
PACKET = REPO / "research" / "work-items" / "RE-001-snapshot-identity-format-94"

CELL70 = "cell70"
CELL78 = "cell78"
CELL88 = "cell88"
CELL80 = "cell80"
SENTINELS = {0x70: CELL70, 0x78: CELL78, 0x88: CELL88, 0x80: CELL80}


def chain(specs):
    """Build a wrapper chain from [(slot_values, handlers), ...].

    ``specs`` is head-first; each entry is (slot_values, handlers).
    """
    head = None
    for slot_values, handlers in reversed(specs):
        head = subject.Wrapper(
            subject.Inner(slot_values=slot_values, handlers=handlers),
            head)
    return head


def single(name="alpha", value70="v70", value78="v78",
           value88=CELL88, value80=CELL80):
    inner = subject.Inner(
        name=name,
        slot_values={0x70: value70, 0x78: value78,
                     0x88: value88, 0x80: value80},
        handlers={0x70: lambda w: "r70",
                  0x78: lambda w: "r78"})
    return subject.Wrapper(inner)


class IdentityFormatTests(unittest.TestCase):
    def test_format_is_name_at_pointer_hash_pid(self):
        self.assertEqual(
            subject.format_identity("alpha", 0x7FFE0100, 4242),
            "alpha@0x7ffe0100#4242")

    def test_format_pointer_null_is_bare_zero(self):
        self.assertEqual(subject.format_pointer(0), "0")
        self.assertEqual(subject.format_identity("a", 0, 7), "a@0#7")

    def test_null_name_gives_empty_string(self):
        self.assertEqual(subject.format_identity(None, 0x100, 9), "")

    def test_walk_dispatch_at_each_position(self):
        for position in range(5):
            specs = []
            for i in range(5):
                if i < position:
                    specs.append(({0x70: CELL70}, {}))
                elif i == position:
                    specs.append(({0x70: "live"},
                                  {0x70: lambda w, i=i: "hit%d" % i}))
                else:
                    specs.append(({0x70: "other"}, {}))
            head = chain(specs)
            self.assertEqual(subject.walk_dispatch(head, 0x70, CELL70),
                             "hit%d" % position)

    def test_walk_fifth_node_is_called_unconditionally(self):
        head = chain([({0x70: CELL70}, {}) for _ in range(4)]
                     + [({0x70: CELL70},
                         {0x70: lambda w: "fifth"})])
        self.assertEqual(subject.walk_dispatch(head, 0x70, CELL70),
                         "fifth")

    def test_walk_short_all_sentinel_chain_raises(self):
        head = chain([({0x70: CELL70}, {}),
                      ({0x70: CELL70}, {})])
        with self.assertRaises(subject.ChainExhausted):
            subject.walk_dispatch(head, 0x70, CELL70)

    def test_walk_second_slot_uses_its_own_sentinel(self):
        head = chain([({0x70: CELL70, 0x78: CELL78}, {}),
                      ({0x70: "x", 0x78: "live78"},
                       {0x78: lambda w: "hit78"})])
        self.assertEqual(subject.walk_dispatch(head, 0x78, CELL78),
                         "hit78")

    def test_side_effect_dispatches_called_only_when_non_sentinel(self):
        calls = []
        inner = subject.Inner(
            slot_values={0x88: "live88", 0x80: CELL80},
            handlers={0x88: lambda w: calls.append("88"),
                      0x80: lambda w: calls.append("80")})
        head = subject.Wrapper(inner)
        called = subject.run_side_effect_dispatches(head, CELL88, CELL80)
        self.assertEqual(called, [0x88])
        self.assertEqual(calls, ["88"])

    def test_side_effect_dispatches_both_called_and_discarded(self):
        inner = subject.Inner(
            slot_values={0x88: "a", 0x80: "b"},
            handlers={0x88: lambda w: "ignored",
                      0x80: lambda w: "ignored"})
        head = subject.Wrapper(inner)
        called = subject.run_side_effect_dispatches(head, CELL88, CELL80)
        self.assertEqual(called, [0x88, 0x80])

    def test_build_end_to_end(self):
        head = single()
        snap = subject.build_snapshot(
            41, head, 123456, 4242, SENTINELS, 0x7FFE0100)
        self.assertEqual(snap.dispatch70, "r70")
        self.assertEqual(snap.dispatch78, "r78")
        self.assertEqual(snap.text, "alpha@0x7ffe0100#4242")
        self.assertEqual(snap.field_10, 0)
        self.assertEqual(snap.field_18, -1)
        self.assertEqual(snap.zero_block, bytes(0xE0))
        self.assertEqual(snap.counter, 42)
        self.assertEqual(snap.value, 123456)
        self.assertEqual(snap.side_calls, [])

    def test_build_counter_wraps_at_32_bits(self):
        head = single()
        snap = subject.build_snapshot(
            0xFFFFFFFF, head, 0, 1, SENTINELS, 0x100)
        self.assertEqual(snap.counter, 0)

    def test_build_null_name_text_is_empty_but_rest_builds(self):
        head = single(name=None)
        snap = subject.build_snapshot(
            0, head, 5, 99, SENTINELS, 0x100)
        self.assertEqual(snap.text, "")
        self.assertEqual(snap.dispatch70, "r70")
        self.assertEqual(snap.counter, 1)

    def test_build_value_passes_through_verbatim(self):
        head = single()
        snap = subject.build_snapshot(
            7, head, -3, 1, SENTINELS, 0x100)
        self.assertEqual(snap.value, -3)

    def test_packet_verification_passes(self):
        # Run from the repo root with the relative binary path, so
        # objdump's header line spells the path exactly as the
        # stored excerpts do (an absolute path would differ).
        result = subprocess.run(
            [sys.executable, str(PACKET / "verify.py"),
             "--binary", "work/hl-node-94.bin"],
            capture_output=True, text=True, cwd=str(REPO))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("ALL CHECKS PASSED", result.stdout)

    def test_packet_excerpts_regenerate_byte_for_byte(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run(
                [sys.executable, str(PACKET / "export_excerpts.py"),
                 "--binary", "work/hl-node-94.bin",
                 "--out", tmp],
                capture_output=True, text=True, cwd=str(REPO))
            self.assertEqual(result.returncode, 0, result.stderr)
            for name in ("window.objdump.txt", "cleanup.objdump.txt",
                         "moveassign.objdump.txt", "getpid.objdump.txt",
                         "caller.objdump.txt"):
                self.assertEqual((PACKET / name).read_bytes(),
                                 (Path(tmp) / name).read_bytes(), name)

    def test_corruption_control_tampered_binary_fails(self):
        binary = (REPO / "work" / "hl-node-94.bin").read_bytes()
        # Flip one byte inside the window range: map VA 0x514ed50
        # through the executable PT_LOAD segment, as verify.py does.
        import struct as _struct
        (phoff,) = _struct.unpack_from("<Q", binary, 0x20)
        (phentsize, phnum) = _struct.unpack_from("<HH", binary, 0x36)
        window_off = None
        for i in range(phnum):
            off = phoff + i * phentsize
            (ptype, _f, poff, pvaddr, _p,
             pfilesz, _m, _a) = _struct.unpack_from(
                "<IIQQQQQQ", binary, off)
            if ptype == 1 and pvaddr <= 0x514ed50 < pvaddr + pfilesz:
                window_off = poff + (0x514ed50 - pvaddr)
                break
        self.assertIsNotNone(window_off)
        tampered = bytearray(binary)
        tampered[window_off] ^= 0xFF
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "bad.bin"
            bad.write_bytes(bytes(tampered))
            result = subprocess.run(
                [sys.executable, str(PACKET / "verify.py"),
                 "--binary", str(bad)],
                capture_output=True, text=True, cwd=str(REPO))
            self.assertNotEqual(result.returncode, 0)

    def test_corruption_control_tampered_record_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            packet_copy = Path(tmp) / "packet"
            shutil.copytree(PACKET, packet_copy)
            records = packet_copy / "records.json"
            text = records.read_text()
            # Tamper the checked window SHA, not prose: verify.py
            # compares this digest against the binary bytes.
            self.assertIn("7ac5ba1c", text)
            records.write_text(text.replace("7ac5ba1c", "8ac5ba1c",
                                            1))
            result = subprocess.run(
                [sys.executable, str(packet_copy / "verify.py"),
                 "--binary", "work/hl-node-94.bin"],
                capture_output=True, text=True, cwd=str(REPO))
            self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
