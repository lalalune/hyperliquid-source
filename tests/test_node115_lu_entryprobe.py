#!/usr/bin/env python3
"""Unit tests for the RE-001-node115-lu-entryprobe packet.

Regeneration comparison + tamper control. The objdump header embeds the
invoked path, so the header line is stripped before comparison.
"""
import hashlib
import json
import re
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research/work-items/RE-001-node115-lu-entryprobe"
BIN = ROOT / "artifacts/node/115/hl-node"
TARGET_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"


def objdump_lines(start, end):
    out = subprocess.run(
        ["objdump", "-d", f"--start-address={hex(start)}",
         f"--stop-address={hex(end)}", str(BIN)],
        capture_output=True, text=True, check=True).stdout
    return [l for l in out.splitlines() if re.match(r"^\s*[0-9a-f]+:\t", l)]


def strict_count(lines):
    n = 0
    for l in lines:
        parts = l.split("\t")
        if len(parts) >= 3 and parts[2].strip() \
                and not re.fullmatch(r"[0-9a-f ]+", parts[2].strip()):
            n += 1
    return n


class TestEntryProbe(unittest.TestCase):
    def test_binary_identity(self):
        self.assertEqual(hashlib.sha256(BIN.read_bytes()).hexdigest(), TARGET_SHA)
        self.assertEqual(BIN.stat().st_size, 105896032)

    def test_records_shape(self):
        rec = json.loads((PACKET / "records.json").read_text())
        self.assertEqual(rec["target"]["upstream_main"], "05bc2de30")
        spec = rec["exhibits"]["pb_probe"]
        self.assertEqual(spec["range"], ["0x63b9680", "0x63b968c"])
        self.assertEqual(spec["bytes"], 12)
        self.assertEqual(spec["strict"], 4)
        self.assertEqual(rec["fde"]["rets"], ["0x63b968b"])
        self.assertEqual(rec["census"]["E8"], ["0x63d8717", "0x63d8874"])
        self.assertEqual(rec["census"]["rela_dyn_entries"], 60723)

    def test_exhibit_bytes(self):
        raw = bytes.fromhex((PACKET / "pb_probe.hex").read_text().split()[0])
        self.assertEqual(raw.hex(), "f30f1efa48833f000f94c0c3")
        data = BIN.read_bytes()
        self.assertEqual(data[0x63B9680 - 0x1000:0x63B968C - 0x1000], raw)

    def test_objdump_regeneration(self):
        saved = (PACKET / "pb_probe.objdump.txt").read_text().splitlines()
        self.assertEqual(objdump_lines(0x63B9680, 0x63B968C), saved)
        self.assertEqual(strict_count(saved), 4)

    def test_tamper_control(self):
        raw = bytearray(bytes.fromhex((PACKET / "pb_probe.hex").read_text().split()[0]))
        raw[5] ^= 0xFF
        data = BIN.read_bytes()
        self.assertNotEqual(data[0x63B9680 - 0x1000:0x63B968C - 0x1000], bytes(raw))

    def test_single_ret_and_no_call(self):
        raw = bytes.fromhex((PACKET / "pb_probe.hex").read_text().split()[0])
        self.assertEqual(raw[-1], 0xC3)
        self.assertNotIn(0xE8, raw)

    def test_padding(self):
        data = BIN.read_bytes()
        self.assertEqual(data[0x63B9674 - 0x1000:0x63B9680 - 0x1000], b"\xcc" * 12)
        self.assertEqual(data[0x63B968C - 0x1000:0x63B9690 - 0x1000], b"\xcc" * 4)

    def test_caller_sites(self):
        import struct
        data = BIN.read_bytes()
        for site in (0x63D8717, 0x63D8874):
            o = 0x1418300 + (site - 0x1419300)
            self.assertEqual(data[o], 0xE8)
            self.assertEqual(site + 5 + struct.unpack("<i", data[o + 1:o + 5])[0], 0x63B9680)
            self.assertEqual(data[o + 5:o + 7], b"\x84\xc0")

    def test_manifest_covers_packet(self):
        manifest = (PACKET / "MANIFEST.sha256").read_text()
        self.assertIn("pb_probe.hex", manifest)
        self.assertIn("pb_probe.objdump.txt", manifest)
        self.assertIn("records.json", manifest)
        self.assertIn("tools/node115_lu_entryprobe.py", manifest)
        self.assertIn("tests/test_node115_lu_entryprobe.py", manifest)

    def test_readme_counts_match(self):
        readme = (PACKET / "README.md").read_text()
        self.assertIn("0x63b9680..0x63b968c", readme)
        self.assertIn("12 bytes", readme)
        self.assertIn("4 strict", readme)


if __name__ == "__main__":
    sys.exit(0 if unittest.main(verbosity=1, exit=False).result.wasSuccessful() else 1)
