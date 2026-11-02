#!/usr/bin/env python3
"""Tests for the node #94 BlockCache chain lookup model (RE-001).

The model is tools/foundation_blockcache_chain_lookup.py; the packet
is research/work-items/RE-001-blockcache-chain-lookup-94/.
"""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

from foundation_blockcache_chain_lookup import (  # noqa: E402
    KEY,
    ChainNode,
    NullHeadError,
    blockcache_lookup,
    build_chain,
    helper_trial,
    walker,
)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET = os.path.join(
    REPO, "research", "work-items", "RE-001-blockcache-chain-lookup-94")
BINARY = os.path.join(REPO, "work", "hl-node-94.bin")


def sentinel_chain(payload_positions, length=10, handler_positions=()):
    """A chain of sentinel nodes; payload_positions maps a node index
    to a payload stored under the key 'BlockCache' on that node."""
    specs = []
    for i in range(length):
        records = []
        if i in payload_positions:
            records = [(KEY, payload_positions[i])]
        handler = None
        if i in handler_positions:
            handler = handler_positions[i]
        specs.append((records, handler))
    return build_chain(specs)


class TestKey(unittest.TestCase):
    def test_key_bytes(self):
        self.assertEqual(KEY, b"BlockCache")
        self.assertEqual(len(KEY), 10)


class TestHelper(unittest.TestCase):
    def test_hit(self):
        node = ChainNode(records=[(b"other", "no"), (KEY, "yes")])
        self.assertEqual(helper_trial(node), "yes")

    def test_miss(self):
        node = ChainNode(records=[(b"BlockCach", "short"),
                                  (b"BlockCacheX", "long")])
        self.assertIsNone(helper_trial(node))

    def test_empty_key_matches_by_length(self):
        node = ChainNode(records=[(b"", "empty")])
        self.assertEqual(helper_trial(node, b""), "empty")


class TestInlineTrials(unittest.TestCase):
    def test_hit_at_each_inline_position(self):
        for pos in range(8):
            head = sentinel_chain({pos: "hit-%d" % pos})
            self.assertEqual(blockcache_lookup(head), "hit-%d" % pos)

    def test_handler_at_each_inline_position(self):
        for pos in range(8):
            def handler(node, key, pos=pos):
                return "handled-%d" % pos
            head = sentinel_chain({}, handler_positions={pos: handler})
            self.assertEqual(blockcache_lookup(head), "handled-%d" % pos)

    def test_handler_beats_later_helper_hit(self):
        def handler(node, key):
            return "handled"
        head = sentinel_chain({3: "late"}, handler_positions={1: handler})
        self.assertEqual(blockcache_lookup(head), "handled")

    def test_null_next_before_eighth_returns_none(self):
        head = sentinel_chain({}, length=3)
        self.assertIsNone(blockcache_lookup(head))

    def test_null_head_raises(self):
        with self.assertRaises(NullHeadError):
            blockcache_lookup(None)


class TestDelegation(unittest.TestCase):
    def test_walker_hit_at_ninth_node(self):
        head = sentinel_chain({8: "ninth"}, length=10)
        self.assertEqual(blockcache_lookup(head), "ninth")

    def test_walker_hit_deep(self):
        head = sentinel_chain({25: "deep"}, length=30)
        self.assertEqual(blockcache_lookup(head), "deep")

    def test_walker_handler_dispatch(self):
        def handler(node, key):
            return "walker-handled"
        head = sentinel_chain({}, length=14,
                               handler_positions={12: handler})
        self.assertEqual(blockcache_lookup(head), "walker-handled")

    def test_walker_exhaustion_returns_none(self):
        head = sentinel_chain({}, length=12)
        self.assertIsNone(blockcache_lookup(head))

    def test_eight_misses_then_null_walker_chain(self):
        # Eight inline nodes, then the walker sees a null next node.
        head = sentinel_chain({}, length=8)
        self.assertIsNone(blockcache_lookup(head))


class TestPacket(unittest.TestCase):
    def test_verify_passes(self):
        result = subprocess.run(
            [sys.executable, os.path.join(PACKET, "verify.py"),
             "--binary", BINARY],
            capture_output=True, text=True)
        self.assertEqual(result.stdout.strip(), "ALL CHECKS PASSED",
                         result.stdout + result.stderr)

    def test_excerpt_matches_binary(self):
        # The excerpts were generated with the repo-relative binary
        # path, which objdump echoes in its header; match that
        # spelling. Three sampled instructions, byte-for-byte against
        # a fresh objdump run: the entry endbr64, a helper call, and
        # the walker delegation call.
        fresh = subprocess.run(
            ["objdump", "-d", "--start-address=0x514e550",
             "--stop-address=0x514e7e0", "work/hl-node-94.bin"],
            capture_output=True, text=True, check=True, cwd=REPO).stdout
        with open(os.path.join(PACKET, "window.objdump.txt")) as f:
            stored = f.read()
        self.assertEqual(stored, fresh)
        for addr in ("514e550:", "514e5c7:", "514e7bb:"):
            self.assertIn(addr, stored)

    def test_excerpt_regeneration(self):
        with tempfile.TemporaryDirectory() as tmp:
            copy = os.path.join(tmp, "packet")
            shutil.copytree(PACKET, copy)
            result = subprocess.run(
                [sys.executable, os.path.join(copy, "export_excerpts.py"),
                 "--binary", "work/hl-node-94.bin"],
                capture_output=True, text=True, cwd=REPO)
            self.assertEqual(result.returncode, 0, result.stderr)
            for name in ("window.objdump.txt", "walker.objdump.txt",
                         "helper.objdump.txt", "cleanup.objdump.txt",
                         "caller.objdump.txt", "plt.objdump.txt"):
                with open(os.path.join(PACKET, name), "rb") as f:
                    orig = f.read()
                with open(os.path.join(copy, name), "rb") as f:
                    regen = f.read()
                self.assertEqual(orig, regen, name)

    def test_corrupt_records_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            dst = os.path.join(tmp, "packet")
            shutil.copytree(PACKET, dst)
            with open(os.path.join(dst, "records.json"), "r+") as f:
                text = f.read().replace("BlockCache", "BlockCachf")
                f.seek(0)
                f.write(text)
                f.truncate()
            result = subprocess.run(
                [sys.executable, os.path.join(dst, "verify.py"),
                 "--binary", BINARY],
                capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("FAILED", result.stdout)

    def test_corrupt_binary_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = os.path.join(tmp, "bad.bin")
            shutil.copy(BINARY, bad)
            with open(bad, "r+b") as f:
                # Flip one byte inside the window carve range.
                f.seek(0x514e550 - 0x1000 + 0x10)
                byte = f.read(1)
                f.seek(0x514e550 - 0x1000 + 0x10)
                f.write(bytes([byte[0] ^ 0xFF]))
            result = subprocess.run(
                [sys.executable, os.path.join(PACKET, "verify.py"),
                 "--binary", bad],
                capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("FAILED", result.stdout)


if __name__ == "__main__":
    unittest.main()
