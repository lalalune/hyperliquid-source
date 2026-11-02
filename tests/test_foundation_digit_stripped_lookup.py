#!/usr/bin/env python3
"""Tests for node #94 digit-stripped table lookup at 0x514e160 (RE-001).

Covers the model in tools/foundation_digit_stripped_lookup.py, the
packet verifier, and the independent excerpt checker, including
corruption controls that must make the checkers fail.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET_DIR = os.path.join(
    REPO_ROOT, "research", "work-items", "RE-001-digit-stripped-lookup-94")
WORK_BINARY = os.path.join(REPO_ROOT, "work", "hl-node-94.bin")
ARTIFACT_BINARY = os.path.join(REPO_ROOT, "artifacts", "node", "94", "hl-node")

sys.path.insert(0, REPO_ROOT)

from tools.foundation_digit_stripped_lookup import (  # noqa: E402
    HASH_SEED, Node, Table, check_packet, excerpt_matches, hash_bytes,
    lookup, strip_trailing_digits)


def binary_path():
    """Prefer the digest-verified work copy over the LFS pointer."""
    if os.path.getsize(WORK_BINARY) > 1000000:
        return WORK_BINARY
    return ARTIFACT_BINARY


def load_records():
    with open(os.path.join(PACKET_DIR, "records.json")) as f:
        return json.load(f)


def hash_table(nodes, bucket_count):
    """Build a hash-path table snapshot from nodes via the real hash."""
    buckets = {}
    for node in nodes:
        buckets.setdefault(node.cached_hash % bucket_count, []).append(node)
    return Table(buckets, list(nodes), 21, bucket_count)


class StripTests(unittest.TestCase):
    def test_no_trailing_digits(self):
        self.assertEqual(strip_trailing_digits(b"ETHUSD"), b"ETHUSD")

    def test_some_trailing_digits(self):
        self.assertEqual(strip_trailing_digits(b"BTC123"), b"BTC")

    def test_all_digits(self):
        self.assertEqual(strip_trailing_digits(b"123"), b"")

    def test_empty(self):
        self.assertEqual(strip_trailing_digits(b""), b"")

    def test_digits_in_middle_kept(self):
        self.assertEqual(strip_trailing_digits(b"a1b2"), b"a1b")

    def test_digit_boundaries(self):
        # 0x2f ('/') and 0x3a (':') are not digits; 0x30 and 0x39 are.
        self.assertEqual(strip_trailing_digits(b"AB/"), b"AB/")
        self.assertEqual(strip_trailing_digits(b"AB:"), b"AB:")
        self.assertEqual(strip_trailing_digits(b"AB0"), b"AB")
        self.assertEqual(strip_trailing_digits(b"AB9"), b"AB")


class LinearPathTests(unittest.TestCase):
    def setUp(self):
        self.nodes = [
            Node(b"AAA", 111, "first"),
            Node(b"BTC", 222, "second"),
            Node(b"", 333, "empty-key"),
        ]
        self.table = Table({}, list(self.nodes), 20, 8)

    def test_hit_middle(self):
        self.assertEqual(lookup(b"BTC", self.table), "second")

    def test_trailing_digits_stripped_before_lookup(self):
        self.assertEqual(lookup(b"BTC99", self.table), "second")

    def test_all_digits_find_empty_key(self):
        self.assertEqual(lookup(b"777", self.table), "empty-key")

    def test_miss(self):
        self.assertIsNone(lookup(b"ETH", self.table))

    def test_size_20_stays_linear(self):
        def boom(data):
            raise AssertionError("hash must not be called on the linear path")
        self.assertEqual(lookup(b"AAA", self.table, hash_fn=boom), "first")


class HashPathTests(unittest.TestCase):
    def setUp(self):
        self.bucket_count = 8
        self.nodes = [
            Node(b"BTC", hash_bytes(b"BTC"), "btc"),
            Node(b"ETH", hash_bytes(b"ETH"), "eth"),
            Node(b"", hash_bytes(b""), "empty"),
        ]
        self.table = hash_table(self.nodes, self.bucket_count)

    def test_hit(self):
        self.assertEqual(lookup(b"BTC", self.table), "btc")

    def test_trailing_digits_stripped_before_hash(self):
        self.assertEqual(lookup(b"ETH42", self.table), "eth")

    def test_empty_key_via_hash(self):
        self.assertEqual(lookup(b"123", self.table), "empty")

    def test_wrong_cached_hash_misses_despite_same_key(self):
        wrong = Node(b"BTC", hash_bytes(b"BTC") + 1, "wrong")
        # Place it in BTC's bucket explicitly: the walk examines it
        # (its cached hash differs from the computed hash) and misses.
        bucket = hash_bytes(b"BTC") % self.bucket_count
        table = Table({bucket: [wrong]}, [wrong], 21, self.bucket_count)
        self.assertIsNone(lookup(b"BTC", table))

    def test_key_mismatch_misses(self):
        self.assertIsNone(lookup(b"ETC", self.table))

    def test_bucket_guard_ends_chain(self):
        bucket = hash_bytes(b"BTC") % self.bucket_count
        # A foreign hash that provably falls in a different bucket.
        foreign_hash = hash_bytes(b"BTC") + 1
        while foreign_hash % self.bucket_count == bucket:
            foreign_hash += 1
        foreign = Node(b"XXX", foreign_hash, "foreign")
        later = Node(b"BTC", hash_bytes(b"BTC"), "later")
        # Foreign first: it is examined (hash mismatch) and the walk
        # continues to `later`, which matches.
        table = Table({bucket: [foreign, later]}, [foreign, later],
                      21, self.bucket_count)
        self.assertEqual(lookup(b"BTC", table), "later")
        # Foreign after a non-matching same-bucket node: the guard
        # must stop the walk before `later`.
        first = Node(b"AAA", hash_bytes(b"BTC"), "first")
        table = Table({bucket: [first, foreign, later]},
                      [first, foreign, later], 21, self.bucket_count)
        self.assertIsNone(lookup(b"BTC", table))

    def test_empty_bucket_misses(self):
        self.assertIsNone(lookup(b"NOPE", self.table))


class HashVectorTests(unittest.TestCase):
    def test_vectors_from_packet(self):
        rec = load_records()
        seed = int(rec["hash_vectors"]["seed"], 16)
        self.assertEqual(seed, HASH_SEED)
        for vec in rec["hash_vectors"]["vectors"]:
            self.assertEqual(hash_bytes(vec["input"].encode(), seed),
                             int(vec["hash"], 16))


class PacketTests(unittest.TestCase):
    def test_verify_passes(self):
        result = check_packet(PACKET_DIR, binary_path())
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("ALL CHECKS PASSED", result.stdout)

    def test_excerpt_matches_binary(self):
        # The excerpts were generated with the repo-relative binary
        # path, which objdump echoes in its header; match that spelling.
        self.assertTrue(excerpt_matches(
            "work/hl-node-94.bin", 0x514E160, 0x514E3C0,
            os.path.join(PACKET_DIR, "window.objdump.txt"),
            cwd=REPO_ROOT))
        self.assertTrue(excerpt_matches(
            "work/hl-node-94.bin", 0x5427800, 0x5427990,
            os.path.join(PACKET_DIR, "callee.objdump.txt"),
            cwd=REPO_ROOT))

    def test_excerpt_regeneration(self):
        with tempfile.TemporaryDirectory() as tmp:
            copy = os.path.join(tmp, "packet")
            shutil.copytree(PACKET_DIR, copy)
            result = subprocess.run(
                [sys.executable, os.path.join(copy, "export_excerpts.py"),
                 "--binary", "work/hl-node-94.bin"],
                capture_output=True, text=True, cwd=REPO_ROOT)
            self.assertEqual(result.returncode, 0, result.stderr)
            for name in ("window.objdump.txt", "callee.objdump.txt",
                         "helper.objdump.txt", "caller.objdump.txt",
                         "plt.objdump.txt"):
                with open(os.path.join(PACKET_DIR, name), "rb") as f:
                    orig = f.read()
                with open(os.path.join(copy, name), "rb") as f:
                    regen = f.read()
                self.assertEqual(orig, regen, name)

    def test_corrupt_records_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            copy = os.path.join(tmp, "packet")
            shutil.copytree(PACKET_DIR, copy)
            path = os.path.join(copy, "records.json")
            with open(path) as f:
                rec = json.load(f)
            rec["window"]["sha256"] = "0" * 64
            with open(path, "w") as f:
                json.dump(rec, f)
            result = check_packet(copy, binary_path())
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("FAILED", result.stdout)

    def test_corrupt_binary_fails(self):
        binary = binary_path()
        with tempfile.TemporaryDirectory() as tmp:
            tampered = os.path.join(tmp, "hl-node-94.bin")
            shutil.copyfile(binary, tampered)
            # Flip one byte inside the window carve range (file offset
            # for VA 0x514e160); the tamper itself must fail the check.
            with open(tampered, "r+b") as f:
                f.seek(0x514D160)
                byte = f.read(1)
                f.seek(0x514D160)
                f.write(bytes([byte[0] ^ 0xFF]))
            result = check_packet(PACKET_DIR, tampered)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("FAILED", result.stdout)


if __name__ == "__main__":
    unittest.main()
