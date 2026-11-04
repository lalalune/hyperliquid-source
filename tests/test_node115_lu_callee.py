#!/usr/bin/env python3
"""Unit tests for RE-001-node115-lu-callee evidence.

Regeneration, tamper control, strict counts, key bytes, FDE
boundaries, .rela.dyn GOT absence, census spot checks, and
MANIFEST coverage. Static byte reads only; never executes the node.
"""

import hashlib
import json
import re
import struct
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "artifacts/node/115/hl-node"
PACKET = ROOT / "research/work-items/RE-001-node115-lu-callee"
RECORDS = json.loads((PACKET / "records.json").read_text())
DATA = BIN.read_bytes()


def read(va, n):
    return DATA[va - 0x1000:va - 0x1000 + n]


def e8_target(call_va):
    b = read(call_va, 5)
    assert b[0] == 0xE8, hex(call_va)
    return call_va + 5 + struct.unpack("<i", b[1:5])[0]


def strict_lines(s, e):
    out = subprocess.run(
        ["objdump", "-d", f"--start-address={hex(s)}",
         f"--stop-address={hex(e)}", str(BIN)],
        capture_output=True, text=True).stdout
    return [ln for ln in out.splitlines()
            if re.match(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t\S", ln)]


class TestCalleeEvidence(unittest.TestCase):
    def test_binary_sha(self):
        self.assertEqual(hashlib.sha256(DATA).hexdigest(),
                         RECORDS["binary_sha256"])
        self.assertEqual(len(DATA), 105896032)

    def test_exhibits_regenerate(self):
        for ex in RECORDS["exhibits"]:
            s, e = int(ex["start"], 16), int(ex["end"], 16)
            raw = read(s, e - s)
            self.assertEqual(len(raw), ex["bytes"])
            self.assertEqual(raw.hex(),
                             (PACKET / f"{ex['name']}.hex")
                             .read_text().strip())
            self.assertEqual(
                [ln.strip() for ln in strict_lines(s, e)],
                [ln.strip() for ln in
                 (PACKET / f"{ex['name']}.objdump.txt")
                 .read_text().splitlines() if ln.strip()])

    def test_tamper_control(self):
        # Flipping one exhibit byte must break the stored hex match.
        ex = RECORDS["exhibits"][0]
        s = int(ex["start"], 16)
        raw = bytearray(read(s, ex["bytes"]))
        raw[0] ^= 0xFF
        self.assertNotEqual(
            bytes(raw).hex(),
            (PACKET / f"{ex['name']}.hex").read_text().strip())

    def test_strict_counts(self):
        total = 0
        for ex in RECORDS["exhibits"]:
            s, e = int(ex["start"], 16), int(ex["end"], 16)
            n = len(strict_lines(s, e))
            self.assertEqual(n, ex["strict_instrs"], ex["name"])
            total += n
        self.assertEqual(total, RECORDS["total_strict_instrs"])
        self.assertEqual(sum(e["bytes"] for e in RECORDS["exhibits"]),
                         RECORDS["total_exhibit_bytes"])

    def test_key_bytes(self):
        self.assertEqual(read(0x63C1340, 7).hex(), "4c8bbd88ec0000")
        self.assertEqual(read(0x63C134D, 4).hex(), "410f95c3")
        self.assertEqual(read(0x63B26B0, 8).hex(), "498b9c2410260000")
        self.assertEqual(e8_target(0x63C10BD), 0x63B2630)
        self.assertEqual(e8_target(0x63C1CAD), 0x63B2630)
        self.assertEqual(e8_target(0x63C1989), 0x63C1030)
        self.assertEqual(e8_target(0x63C1A89), 0x63C1030)
        self.assertEqual(e8_target(0x63C1AE1), 0x63C1030)

    def test_fde_boundaries(self):
        frames = subprocess.run(["objdump", "--dwarf=frames", str(BIN)],
                                capture_output=True, text=True).stdout
        self.assertIn("pc=00000000063c1030..00000000063c1360", frames)
        self.assertIn("pc=00000000063b2630..00000000063b2850", frames)

    def test_got_absence(self):
        out = subprocess.run(["readelf", "-SW", str(BIN)],
                             capture_output=True, text=True).stdout
        secs = {}
        for line in out.splitlines():
            m = re.match(r"\s*\[\s*\d+\]\s+(\S+)\s+(\S+)\s+([0-9a-f]+)\s+"
                         r"([0-9a-f]+)\s+([0-9a-f]+)", line)
            if m:
                secs[m.group(1)] = (int(m.group(3), 16),
                                    int(m.group(4), 16),
                                    int(m.group(5), 16))
        _, roff, rsize = secs[".rela.dyn"]
        hits = []
        for j in range(0, rsize, 24):
            _, _, add = struct.unpack("<QQq", DATA[roff + j:roff + j + 24])
            if add in (0x63C1030, 0x63B2630):
                hits.append(add)
        self.assertEqual(hits, [])

    def test_manifest_coverage(self):
        out = subprocess.run(["sha256sum", "-c", "MANIFEST.sha256"],
                             cwd=PACKET, capture_output=True,
                             text=True).stdout
        self.assertNotIn("FAILED", out)
        self.assertEqual(out.count(": OK"), 15)


if __name__ == "__main__":
    unittest.main()
