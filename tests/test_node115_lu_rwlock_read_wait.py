#!/usr/bin/env python3
"""Unit tests for the node #115 lu RwLock read-wait packet (RE-001).

All tests run the packet verifier; corruption controls invoke the
verifier against temp copies, never the originals.
"""
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research" / "work-items" / "RE-001-node115-lu-rwlock-read-wait"
TOOL = ROOT / "tools" / "node115_lu_rwlock_read_wait.py"
BINARY = ROOT / "artifacts" / "node" / "115" / "hl-node"


def run_verifier(binary, hexpath, records):
    return subprocess.run(
        [sys.executable, str(TOOL), "--binary", str(binary),
         "--hex", str(hexpath), "--records", str(records)],
        capture_output=True, text=True)


def temp_copy():
    tmp = Path(tempfile.mkdtemp())
    hexpath = tmp / "fde1a60.hex"
    records = tmp / "records.json"
    shutil.copy(PACKET / "fde1a60.hex", hexpath)
    shutil.copy(PACKET / "records.json", records)
    return tmp, hexpath, records


class TestRwlockReadWait(unittest.TestCase):
    def test_verifier_passes(self):
        r = run_verifier(BINARY, PACKET / "fde1a60.hex", PACKET / "records.json")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("127 GOT sites", r.stdout)

    def test_body_hex_matches_binary(self):
        data = BINARY.read_bytes()
        body = data[0x5BB1A60 - 0x1000:0x5BB210A - 0x1000]
        hexbody = bytes.fromhex((PACKET / "fde1a60.hex").read_text().strip())
        self.assertEqual(hexbody, body)
        self.assertEqual(len(body), 1706)
        self.assertEqual(hashlib.sha256(body).hexdigest(),
                         "95d9b142970398a722b871c66eb3d77a3b06ae45a55333dc5c668b3773f96aac")

    def test_single_ret_inside_fde(self):
        text = (PACKET / "fde1a60.objdump.txt").read_text()
        rets = [l for l in text.splitlines() if l.strip().endswith("\tret")]
        self.assertEqual(len(rets), 1)
        self.assertIn("5bb20a2", rets[0])

    def test_corrupt_body_hex_rejected(self):
        tmp, hexpath, records = temp_copy()
        raw = bytearray(bytes.fromhex(hexpath.read_text().strip()))
        raw[100] ^= 0xFF
        hexpath.write_text(raw.hex() + "\n")
        r = run_verifier(BINARY, hexpath, records)
        self.assertNotEqual(r.returncode, 0)

    def test_corrupt_futex_nr_rejected(self):
        # Corrupting the binary copy must be rejected (the pinned
        # digest check fires first on any binary change, before the
        # site checks would even run).
        tmp, hexpath, records = temp_copy()
        binpath = tmp / "hl-node"
        shutil.copy(BINARY, binpath)
        raw = bytearray(binpath.read_bytes())
        # mov edi,0xca at 0x5bb1dd0: file offset VA-0x1000; opcode bytes
        # bf ca 00 00 00 -> change 0xca to 0xcb (futex nr 203)
        off = 0x5BB1DD0 - 0x1000
        self.assertEqual(raw[off + 1], 0xCA)
        raw[off + 1] = 0xCB
        binpath.write_bytes(raw)
        r = run_verifier(binpath, hexpath, records)
        self.assertNotEqual(r.returncode, 0)

    def test_corrupt_records_byte_count_rejected(self):
        tmp, hexpath, records = temp_copy()
        rec = json.loads(records.read_text())
        rec["bodies"]["wait"]["bytes"] = 1705
        records.write_text(json.dumps(rec))
        r = run_verifier(BINARY, hexpath, records)
        self.assertNotEqual(r.returncode, 0)

    def test_corrupt_golden_ratio_rejected(self):
        # As above: any binary change is rejected at the digest check.
        tmp, hexpath, records = temp_copy()
        binpath = tmp / "hl-node"
        shutil.copy(BINARY, binpath)
        raw = bytearray(binpath.read_bytes())
        # movabs rbx,0x9e3779b97f4a7c15 at 0x5bb1a98: bytes
        # 48 bb 15 7c 4a 7f b9 79 37 9e; flip one immediate byte
        off = 0x5BB1A98 - 0x1000
        self.assertEqual(raw[off:off + 2], b"\x48\xbb")
        raw[off + 2] ^= 0x01
        binpath.write_bytes(raw)
        r = run_verifier(binpath, hexpath, records)
        self.assertNotEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main()
