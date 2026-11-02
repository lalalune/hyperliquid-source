#!/usr/bin/env python3
"""Tests for RE-001 list teardown (function 0x514bd40, node #94).

Run from the repository root:

    python3 tests/test_foundation_list_teardown.py

The binary path defaults to the digest-verified work copy; pass
``--binary`` to point at another copy of node #94. All expectations
are read from the bytes: per node the next pointer is saved before
any free, a heap string buffer is deleted with size capacity + 1, an
inline string (pointer == node + 0x18) skips the buffer delete, the
node itself is deleted with size 0x78, then the array is memset with
count * 8 zero bytes, [object + 0x10] and [object + 0x18] are
zeroed, and the array is deleted with size count * 8 unless its
pointer equals object + 0x30.
"""

import argparse
import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from tools.foundation_list_teardown import (  # noqa: E402
    NODE_SIZE, Node, StrField, check_packet, list_teardown)

PACKET_DIR = os.path.join(
    os.path.dirname(__file__), "..", "research", "work-items",
    "RE-001-list-teardown-94")
DEFAULT_BINARY = os.path.join("work", "hl-node-94.bin")
BINARY = os.environ.get("HL_NODE94_BIN", DEFAULT_BINARY)
OBJ = 0x1000
HEAP_ARRAY = 0x5000


class ListPhaseTests(unittest.TestCase):
    def test_null_head_runs_only_array_phase(self):
        events, head, tail = list_teardown(OBJ, HEAP_ARRAY, 3, None)
        self.assertEqual(events, [("memset", HEAP_ARRAY, 24),
                                  ("delete_array", 24)])
        self.assertTrue(head)
        self.assertTrue(tail)

    def test_single_inline_string_node(self):
        node = Node(StrField(inline=True, capacity=999))
        events, _, _ = list_teardown(OBJ, HEAP_ARRAY, 0, node)
        self.assertEqual(events, [("delete_node", NODE_SIZE),
                                  ("memset", HEAP_ARRAY, 0),
                                  ("delete_array", 0)])

    def test_single_heap_string_node_delete_size_is_capacity_plus_one(self):
        node = Node(StrField(inline=False, capacity=15))
        events, _, _ = list_teardown(OBJ, HEAP_ARRAY, 1, node)
        self.assertEqual(events, [("delete_buffer", 16),
                                  ("delete_node", NODE_SIZE),
                                  ("memset", HEAP_ARRAY, 8),
                                  ("delete_array", 8)])

    def test_node_size_is_0x78(self):
        self.assertEqual(NODE_SIZE, 0x78)

    def test_chain_order_is_node_order_with_next_saved_first(self):
        # A -> B -> C: buffer/node deletes interleave per node, in
        # list order, because next is saved before each node's frees.
        c = Node(StrField(inline=True))
        b = Node(StrField(inline=False, capacity=7), next=c)
        a = Node(StrField(inline=False, capacity=3), next=b)
        events, _, _ = list_teardown(OBJ, HEAP_ARRAY, 2, a)
        self.assertEqual(events, [("delete_buffer", 4),
                                  ("delete_node", NODE_SIZE),
                                  ("delete_buffer", 8),
                                  ("delete_node", NODE_SIZE),
                                  ("delete_node", NODE_SIZE),
                                  ("memset", HEAP_ARRAY, 16),
                                  ("delete_array", 16)])

    def test_capacity_plus_one_wraps_at_64_bits(self):
        node = Node(StrField(inline=False, capacity=(1 << 64) - 1))
        events, _, _ = list_teardown(OBJ, HEAP_ARRAY, 0, node)
        self.assertEqual(events[0], ("delete_buffer", 0))


class ArrayPhaseTests(unittest.TestCase):
    def test_inline_array_skips_delete(self):
        events, _, _ = list_teardown(OBJ, OBJ + 0x30, 4, None)
        self.assertEqual(events, [("memset", OBJ + 0x30, 32),
                                  ("array_inline",)])

    def test_heap_array_deleted_with_count_times_eight(self):
        events, _, _ = list_teardown(OBJ, HEAP_ARRAY, 5, None)
        self.assertEqual(events, [("memset", HEAP_ARRAY, 40),
                                  ("delete_array", 40)])

    def test_count_zero_still_deletes_heap_array_with_size_zero(self):
        # The bytes compare the pointer, not the count, before the
        # tail delete: a heap array is deleted even for count 0.
        events, _, _ = list_teardown(OBJ, HEAP_ARRAY, 0, None)
        self.assertEqual(events, [("memset", HEAP_ARRAY, 0),
                                  ("delete_array", 0)])

    def test_count_times_eight_wraps_at_64_bits(self):
        events, _, _ = list_teardown(OBJ, HEAP_ARRAY, 1 << 61, None)
        self.assertEqual(events, [("memset", HEAP_ARRAY, 0),
                                  ("delete_array", 0)])

    def test_both_fields_cleared_even_with_null_head(self):
        _, head, tail = list_teardown(OBJ, HEAP_ARRAY, 0, None)
        self.assertTrue(head)
        self.assertTrue(tail)


class PacketTests(unittest.TestCase):
    def test_packet_verifies_against_real_binary(self):
        self.assertEqual(check_packet(PACKET_DIR, BINARY), [])

    def test_packet_verify_script_passes(self):
        result = subprocess.run(
            [sys.executable,
             os.path.join(PACKET_DIR, "verify.py"),
             "--binary", BINARY],
            capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("ALL CHECKS PASSED", result.stdout)

    def test_excerpt_regeneration_is_byte_identical(self):
        import hashlib
        import tempfile
        names = ("window.objdump.txt", "plt.objdump.txt")
        before = {}
        for name in names:
            with open(os.path.join(PACKET_DIR, name), "rb") as f:
                before[name] = hashlib.sha256(f.read()).hexdigest()
        with tempfile.TemporaryDirectory() as tmp:
            script = os.path.join(PACKET_DIR, "export_excerpts.py")
            code = open(script).read()
            # Run the exporter against a scratch packet dir by
            # rewriting its PACKET_DIR constant for this test only.
            code = code.replace(
                'PACKET_DIR = os.path.dirname(os.path.abspath(__file__))',
                'PACKET_DIR = %r' % tmp)
            scratch = os.path.join(tmp, "export_excerpts.py")
            with open(scratch, "w") as f:
                f.write(code)
            result = subprocess.run(
                [sys.executable, scratch, "--binary", BINARY],
                capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            for name in names:
                with open(os.path.join(tmp, name), "rb") as f:
                    self.assertEqual(
                        hashlib.sha256(f.read()).hexdigest(), before[name],
                        "%s regenerated differently" % name)

    def test_sampled_instructions_match_fresh_objdump(self):
        # Pre-submit self-check samples, from the raw excerpts only.
        import re
        excerpts = {}
        for name in ("window.objdump.txt", "plt.objdump.txt"):
            with open(os.path.join(PACKET_DIR, name)) as f:
                excerpts[name] = f.read()
        samples = [("window.objdump.txt", "514bd40"),
                   ("window.objdump.txt", "514bd7b"),
                   ("window.objdump.txt", "514bda9")]
        result = subprocess.run(
            ["objdump", "-d", "--start-address=0x514bd40",
             "--stop-address=0x514bdf0", BINARY],
            capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        fresh = result.stdout
        for name, addr in samples:
            line = [ln for ln in excerpts[name].splitlines()
                    if ln.strip().startswith(addr + ":")]
            self.assertEqual(len(line), 1, (name, addr))
            m = re.match(r"^\s*[0-9a-f]+:\t([0-9a-f ]+?)\t(.*)$",
                         line[0])
            self.assertIsNotNone(m, line[0])
            self.assertIn(line[0].split("\t")[-1].strip(),
                          fresh)
            self.assertIn(addr, fresh)

    def test_corruption_controls(self):
        # Tamper a COPY of the packet (never the shipped packet):
        # a wrong function SHA must fail, and a changed excerpt byte
        # must fail the byte check.
        import copy
        import json
        import re
        import shutil
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            copy_dir = os.path.join(tmp, "packet")
            shutil.copytree(PACKET_DIR, copy_dir)
            rec_path = os.path.join(copy_dir, "records.json")
            with open(rec_path) as f:
                rec = json.load(f)
            rec["function"]["sha256"] = "0" * 64
            with open(rec_path, "w") as f:
                json.dump(rec, f)
            self.assertTrue(check_packet(copy_dir, BINARY),
                            "tampered SHA must fail")
            shutil.rmtree(copy_dir)
            shutil.copytree(PACKET_DIR, copy_dir)
            excerpt = os.path.join(copy_dir, "window.objdump.txt")
            text = open(excerpt).read()
            # Change one hex byte token on the first instruction line.
            m = re.search(r"^(\s*514bd40:\t)([0-9a-f]{2})",
                          text, re.MULTILINE)
            self.assertIsNotNone(m)
            bad = "ff" if m.group(2) != "ff" else "fe"
            text = text[:m.start(2)] + bad + text[m.end(2):]
            with open(excerpt, "w") as f:
                f.write(text)
            self.assertTrue(check_packet(copy_dir, BINARY),
                            "tampered excerpt byte must fail")


def main():
    global BINARY
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", default=BINARY)
    args = ap.parse_args()
    BINARY = args.binary
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
