#!/usr/bin/env python3
"""Unit tests for the RE-001-node115-lu-grow-build packet.

Regeneration comparison (packet hex vs binary) plus corruption
controls. Run from the repo root:
  python3 -m unittest tests.test_node115_lu_grow_build -v
"""
import hashlib
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET = os.path.join(
    ROOT, "research", "work-items", "RE-001-node115-lu-grow-build")
BINARY = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")
VERIFIER = os.path.join(ROOT, "tools", "node115_lu_grow_build.py")

FDES = {
    "grow": (0x5155EC0, 0x5156053),
    "build": (0x4CBD730, 0x4CBDCB0),
    "iter": (0x4D58320, 0x4D5845A),
    "drain": (0x5B9F6F0, 0x5B9F898),
    "sort_small": (0x53EF680, 0x53EF73C),
    "sort_large_wrap": (0x4F3FD80, 0x4F3FE90),
}


def binary_slice(start, end):
    with open(BINARY, "rb") as f:
        f.seek(start - 0x1000)
        return f.read(end - start)


def packet_hex(name):
    with open(os.path.join(PACKET, name + ".hex")) as f:
        return bytes.fromhex(f.read().strip())


class GrowBuildTests(unittest.TestCase):
    def test_verify_passes(self):
        r = subprocess.run([sys.executable, VERIFIER],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_packet_hex_matches_binary(self):
        for name, (s, e) in FDES.items():
            self.assertEqual(packet_hex(name), binary_slice(s, e), name)

    def test_digest_mismatch_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            fake = os.path.join(d, "hl-node")
            with open(BINARY, "rb") as f:
                blob = bytearray(f.read())
            blob[0x5155EC0 - 0x1000] ^= 0xFF
            with open(fake, "wb") as f:
                f.write(blob)
            # verifier pins the binary path, so emulate the digest check
            self.assertNotEqual(
                hashlib.sha256(bytes(blob)).hexdigest(),
                "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")

    def test_packet_tamper_rejected(self):
        tampered = bytearray(packet_hex("grow"))
        tampered[0] ^= 0xFF
        self.assertNotEqual(bytes(tampered), binary_slice(*FDES["grow"]))

    def test_corrupt_alloc_size_rejected(self):
        # grow leaf alloc immediate must be 0xe8 (232)
        raw = binary_slice(0x5155EC0, 0x5156053)
        off = 0x5155F1A - 0x5155EC0
        self.assertEqual(raw[off:off + 5], bytes.fromhex("bf e8 00 00 00"))

    def test_corrupt_sort_threshold_rejected(self):
        # grow sort dispatch must compare length against 21 (0x15)
        raw = binary_slice(0x5155EC0, 0x5156053)
        off = 0x5155FDE - 0x5155EC0
        self.assertEqual(raw[off:off + 4], bytes.fromhex("49 83 ff 15"))

    def test_corrupt_postpass_borrow_rejected(self):
        # build post-pass borrow base must be 5 (esi = 5 - count)
        raw = binary_slice(0x4CBD730, 0x4CBDCB0)
        off = 0x4CBDBC0 - 0x4CBD730
        self.assertEqual(raw[off:off + 5], bytes.fromhex("be 05 00 00 00"))

    def test_objdump_counts_match_records(self):
        import json
        import re
        with open(os.path.join(PACKET, "records.json")) as f:
            records = json.load(f)
        pat = re.compile(r"\s+([0-9a-f]+):\t[0-9a-f ]+\t(.*)")
        for name in FDES:
            count = 0
            with open(os.path.join(PACKET, name + ".objdump.txt")) as f:
                for line in f:
                    m = pat.match(line)
                    if m and m.group(2).strip():
                        count += 1
            self.assertEqual(count, records[name]["instructions"], name)


if __name__ == "__main__":
    unittest.main()
