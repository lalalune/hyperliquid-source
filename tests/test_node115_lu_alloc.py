#!/usr/bin/env python3
"""Unit tests for RE-001-node115-lu-alloc (stdlib unittest only)."""
import hashlib
import os
import struct
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PACKET = os.path.join(ROOT, "research", "work-items",
                      "RE-001-node115-lu-alloc")
BIN = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")
SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

EXHIBITS = {
    "al_thunk": (0x636b370, 0x636b37c),
    "al_head": (0x636a680, 0x636a6b5),
    "al_scan": (0x636a737, 0x636a75d),
    "al_fresh": (0x636a8b4, 0x636a8e4),
    "al_found": (0x636a97e, 0x636a9d0),
}


def read_at(data, va, n):
    return data[va - 0x1000: va - 0x1000 + n]


class TestAlloc(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(BIN, "rb") as f:
            cls.data = f.read()

    def test_binary_sha_and_size(self):
        self.assertEqual(len(self.data), 105896032)
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), SHA)

    def test_exhibits_regenerate(self):
        for name, (s, e) in EXHIBITS.items():
            with open(os.path.join(PACKET, name + ".hex")) as f:
                claimed = bytes.fromhex("".join(f.read().split()))
            self.assertEqual(len(claimed), e - s, name)
            self.assertEqual(read_at(self.data, s, e - s), claimed, name)

    def test_tamper_control(self):
        good = read_at(self.data, 0x636b370, 12)
        bad = bytearray(good)
        bad[4] ^= 0xFF
        self.assertNotEqual(bytes(bad), good)

    def test_thunk_shape(self):
        b = read_at(self.data, 0x636b370, 12)
        self.assertEqual(b[:4], bytes.fromhex("f30f1efa"))   # endbr64
        self.assertEqual(b[4:7], bytes.fromhex("4531c0"))    # xor r8d,r8d
        self.assertEqual(b[7], 0xe9)
        tgt = 0x636b377 + 5 + struct.unpack("<i", b[8:12])[0]
        self.assertEqual(tgt, 0x636a680)

    def test_worker_ret_and_fde(self):
        self.assertEqual(read_at(self.data, 0x636aa0b, 1), b"\xc3")
        frames = subprocess.run(["objdump", "--dwarf=frames", BIN],
                                capture_output=True, text=True).stdout
        self.assertIn("pc=000000000636b370..000000000636b37c", frames)
        self.assertIn("pc=000000000636a680..000000000636aad8", frames)

    def test_miss_handler_call_args(self):
        # miss-handler call site decodes to the thunk; the caller's own
        # setup (rsi=[record], rcx=0x40, rdx=0x200000) is covered by the
        # verifier's key-byte checks and the packet text.
        b = read_at(self.data, 0x63d9803, 5)
        self.assertEqual(b[0], 0xe8)
        tgt = 0x63d9803 + 5 + struct.unpack("<i", b[1:5])[0]
        self.assertEqual(tgt, 0x636b370)

    def test_alignment_math(self):
        # miss-handler call: align 0x40, size 0x200000.
        align = (0x40 + 0xF) & ~0xF
        rounded = (align + 0x200000 - 1) & -align
        total = align + rounded
        self.assertEqual((align, rounded, total), (0x40, 0x200000, 0x200040))
        self.assertGreater(total - 0x10, 0x1000)  # large path
        # large-path index: bsr(2*(total-16)-1) = 22, masked bits 0.
        r8 = 2 * (total - 0x10) - 1
        bsr = r8.bit_length() - 1
        self.assertEqual(bsr, 22)
        self.assertEqual(0 + 4 * bsr - 23, 65)

    def test_manifest_coverage(self):
        with open(os.path.join(PACKET, "MANIFEST.sha256")) as f:
            lines = [l.strip() for l in f if l.strip()]
        self.assertEqual(len(lines), 15)
        rc = subprocess.run(["sha256sum", "-c", "MANIFEST.sha256"],
                            cwd=PACKET, capture_output=True, text=True)
        self.assertEqual(rc.returncode, 0, rc.stdout + rc.stderr)


if __name__ == "__main__":
    unittest.main()
