"""Tests for tools/wal_reader_dtor.py (node #94 WAL reader destructor
0x5162ed0 and deleting destructor 0x51632b0).

Run from the repository root:
    python3 -m unittest tests.test_wal_reader_dtor -v
"""
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import wal_reader_dtor as tool  # noqa: E402

PACKET = ROOT / "research" / "work-items" / "RE-001-wal-reader-dtor-94"
BINARY = ROOT / "work" / "hl-node-94.bin"


def ctrl(strong, weak):
    return tool.Control(strong, weak)


def reader(**kwargs):
    return tool.WalReader(**kwargs)


def inline_string(ptr):
    return tool.String(ptr, 0, ptr)


def heap_string(ptr, capacity):
    return tool.String(ptr, capacity, ("buf", ptr))


class TeardownOrderTests(unittest.TestCase):
    def test_empty_reader(self):
        events = tool.destroy_reader(reader(), 1)
        self.assertEqual(events, [
            ("vtable_install", 0x575B0B8),
            ("skip_null", "buffer30"),
            ("skip_null", "obj78"),
            ("skip_null", "prefix_a8"),
            ("skip_null", "prefix_b0"),
            ("skip_null", "string88"),
            ("skip_null", "buffer80"),
            ("skip_null", "sub18"),
            ("skip_null", "ref10"),
        ])

    def test_buffers_and_prefixes(self):
        r = reader(buffer30=True, buffer80=True,
                   prefix_a8=(0x1000, 5), prefix_b0=None)
        events = tool.destroy_reader(r, 1)
        self.assertIn(("delete_array", "buffer30"), events)
        self.assertIn(("delete_array", "buffer80"), events)
        # prefix-free address is pointer minus the stored prefix byte
        self.assertIn(("prefix_free", "prefix_a8", 0x543BE20, 0xFFB),
                      events)
        self.assertIn(("skip_null", "prefix_b0"), events)

    def test_obj78_unknown_type_uses_virtual_delete(self):
        r = reader(obj78=tool.Obj78(0x1234567))
        events = tool.destroy_reader(r, 1)
        self.assertIn(("virtual_delete", "obj78", 0x1234567), events)
        self.assertNotIn(("vtable_install", 0x5766048), events)

    def test_obj78_known_type_inlines_its_destructor(self):
        r = reader(obj78=tool.Obj78(0x5160EC0))
        events = tool.destroy_reader(r, 1)
        self.assertEqual(events[2:5], [
            ("vtable_install", 0x5766048),
            ("call", 0x55D9080, "obj78_field18"),
            ("sized_delete", "obj78", 0x38),
        ])

    def test_string88_heap_vs_inline(self):
        heap = tool.destroy_reader(
            reader(string88=heap_string(0x2000, 0x40)), 1)
        self.assertIn(("sized_delete", "string88", 0x2000, 0x41), heap)
        inline = tool.destroy_reader(
            reader(string88=inline_string(0x3000)), 1)
        self.assertIn(("skip_inline", "string88"), inline)


class RefcountTests(unittest.TestCase):
    def test_sentinel_disposes_and_destroys(self):
        c = ctrl(1, 1)
        events = []
        tail = tool.release_control(c, events, 1, "ref10")
        self.assertTrue(tail)
        self.assertEqual(events, [
            ("dispose", "ref10"), ("destroy_control", "ref10")])
        self.assertEqual(c.word, 0)

    def test_plain_decrement_survives(self):
        c = ctrl(3, 2)
        events = []
        tail = tool.release_control(c, events, 1, "x")
        self.assertFalse(tail)
        self.assertEqual(events, [("decrement", "x", "plain", 3)])
        self.assertEqual((c.strong, c.weak), (2, 2))

    def test_lock_decrement_when_flag_zero(self):
        c = ctrl(3, 2)
        events = []
        tool.release_control(c, events, 0, "x")
        self.assertEqual(events, [("decrement", "x", "lock", 3)])

    def test_old_strong_one_calls_release(self):
        c = ctrl(1, 3)
        events = []
        tool.release_control(c, events, 1, "x")
        self.assertEqual(events, [
            ("decrement", "x", "plain", 1),
            ("release_call", "x", 0x4F94A40),
            ("dispose", "x"),
        ])
        self.assertEqual((c.strong, c.weak), (0, 2))

    def test_ref10_sentinel_tail_destroys(self):
        events = tool.destroy_reader(reader(ref10=ctrl(1, 1)), 1)
        self.assertEqual(events[-3:], [
            ("dispose", "ref10"), ("destroy_control", "ref10"),
            ("tail_destroy", "ref10")])


class SubobjectTests(unittest.TestCase):
    def make_sub(self):
        return tool.SubObject(
            elements=[ctrl(1, 1), ctrl(3, 2), ctrl(1, 3), None],
            array_begin=0x4000, array_cap_end=0x4040,
            string60=heap_string(0x5000, 0x10),
            ref50=ctrl(2, 1),
            obj40_deleting_dtor=0x7654321,
            ref28=ctrl(1, 1),
            string00=inline_string(0x6000),
        )

    def test_subobject_full_order(self):
        events = tool.destroy_reader(reader(sub18=self.make_sub()), 1)
        # the sub-object phase starts after the reader's own fields
        start = events.index(("dispose", "array_element"))
        phase = events[start:]
        kinds = [e[0] for e in phase]
        self.assertEqual(kinds, [
            "dispose", "destroy_control",  # sentinel element
            "decrement",                  # strong 3 -> 2
            "decrement", "release_call", "dispose",  # strong 1, weak 3
            "skip_null",                  # null element
            "array_buffer_delete",
            "vtable_reset",               # 0x575f6a0
            "sized_delete",               # string60 heap
            "decrement",                  # ref50 strong 2 -> 1
            "vtable_reset",               # 0x5759bc0
            "virtual_delete",             # obj40
            "dispose", "destroy_control",  # ref28 sentinel
            "skip_inline",                # string00 inline
            "sized_delete",               # sub-object 0xa8
            "skip_null",                  # ref10
        ])
        self.assertEqual(phase[7],
                         ("array_buffer_delete", 0x4000, 0x4040))
        self.assertEqual(phase[8], ("vtable_reset", 0x575F6A0))
        self.assertEqual(phase[11], ("vtable_reset", 0x5759BC0))
        self.assertEqual(phase[-2], ("sized_delete", "subobject", 0xA8))

    def test_subobject_lock_form(self):
        sub = self.make_sub()
        events = tool.destroy_reader(reader(sub18=sub), 0)
        forms = [e[2] for e in events
                 if e[0] == "decrement"]
        self.assertTrue(forms)
        self.assertTrue(all(f == "lock" for f in forms))

    def test_deleting_dtor_frees_reader(self):
        events = tool.deleting_dtor(reader(ref10=ctrl(2, 1)), 1)
        self.assertEqual(events[-2:], [
            ("decrement", "ref10", "plain", 2),
            ("sized_delete", "reader", 0xB8),
        ])


class PacketTests(unittest.TestCase):
    def test_samples_byte_for_byte(self):
        if not BINARY.exists():
            self.skipTest("digest-verified binary not present")
        data = BINARY.read_bytes()
        samples = {
            0x5162ED0: bytes.fromhex("f30f1efa"),
            0x5162EFC: bytes.fromhex("e87fd54f00"),
            0x51632B8: bytes.fromhex("e813fcffff"),
            0x543BE34: bytes.fromhex("e8c7432200"),
        }
        for vaddr, expected in samples.items():
            off = vaddr - 0x1000
            self.assertEqual(data[off:off + len(expected)], expected)

    def test_verify_passes(self):
        if not BINARY.exists():
            self.skipTest("digest-verified binary not present")
        out = subprocess.run(
            [sys.executable, str(PACKET / "verify.py")],
            capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(out.returncode, 0, out.stdout)
        self.assertIn("ALL CHECKS PASSED", out.stdout)

    def test_excerpts_regenerate_identically(self):
        if not BINARY.exists():
            self.skipTest("digest-verified binary not present")
        before = {p.name: p.read_bytes()
                  for p in PACKET.glob("*.txt")}
        out = subprocess.run(
            [sys.executable, str(PACKET / "export_excerpts.py")],
            capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(out.returncode, 0, out.stderr)
        after = {p.name: p.read_bytes()
                 for p in PACKET.glob("*.txt")}
        self.assertEqual(before, after)

    def test_corrupt_binary_sample_fails_verify(self):
        if not BINARY.exists():
            self.skipTest("digest-verified binary not present")
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "bad.bin"
            data = bytearray(BINARY.read_bytes())
            data[0x5162ED0 - 0x1000] ^= 0xFF
            bad.write_bytes(data)
            out = subprocess.run(
                [sys.executable, str(PACKET / "verify.py"),
                 "--binary", str(bad)],
                capture_output=True, text=True, cwd=ROOT)
            self.assertNotEqual(out.returncode, 0)

    def test_records_missing_key_fails_verify(self):
        with tempfile.TemporaryDirectory() as tmp:
            pkt = Path(tmp) / "pkt"
            shutil.copytree(PACKET, pkt)
            records = json.loads((pkt / "records.json").read_text())
            del records["teardown_order"]
            (pkt / "records.json").write_text(json.dumps(records))
            out = subprocess.run(
                [sys.executable, str(pkt / "verify.py"),
                 "--packet-dir", str(pkt)],
                capture_output=True, text=True, cwd=ROOT)
            self.assertNotEqual(out.returncode, 0)


if __name__ == "__main__":
    unittest.main()
