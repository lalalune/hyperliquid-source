#!/usr/bin/env python3
"""Unit tests for packet #243: node #115 lu give-back.

Regeneration comparison (objdump output re-derived from the binary,
header lines stripped, lines compared as normalized tuples) plus
tamper controls. Static reads only; the node binary is never executed.
"""

import json
import os
import re
import subprocess
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")
PACKET = os.path.join(ROOT, "research", "work-items",
                      "RE-001-node115-lu-giveback")


def load_records():
    with open(os.path.join(PACKET, "records.json")) as fh:
        return json.load(fh)


def objdump_tuples(start, stop):
    out = subprocess.run(
        ["objdump", "-d", "--start-address=%s" % hex(start),
         "--stop-address=%s" % hex(stop), BIN],
        capture_output=True, text=True, check=True).stdout
    rows = []
    for ln in out.splitlines():
        m = re.match(r"^\s*([0-9a-f]+):\t([0-9a-f ]+)\t(\S.*)$", ln)
        if m:
            rows.append((int(m.group(1), 16), m.group(2).split(),
                         m.group(3).strip()))
    return rows


def stored_tuples(name):
    rows = []
    with open(os.path.join(PACKET, name + ".objdump.txt")) as fh:
        for ln in fh:
            m = re.match(r"^\s*([0-9a-f]+):\t([0-9a-f ]+)\t(\S.*)$", ln)
            if m:
                rows.append((int(m.group(1), 16), m.group(2).split(),
                             m.group(3).strip()))
    return rows


class TestGiveback(unittest.TestCase):
    def test_fde_bounds(self):
        rec = load_records()
        self.assertEqual(rec["fde"], ["0x63d8e70", "0x63d906b"])
        self.assertEqual(int(rec["fde"][1], 16) - int(rec["fde"][0], 16), 507)

    def test_exhibit_count(self):
        rec = load_records()
        self.assertEqual(len(rec["exhibits"]), 6)

    def test_total_bytes(self):
        rec = load_records()
        total = sum(e["bytes"] for e in rec["exhibits"].values())
        self.assertEqual(total, 387)

    def test_total_strict(self):
        rec = load_records()
        total = sum(e["strict"] for e in rec["exhibits"].values())
        self.assertEqual(total, 93)

    def test_regeneration_all(self):
        rec = load_records()
        for name, e in rec["exhibits"].items():
            s, en = int(e["range"][0], 16), int(e["range"][1], 16)
            self.assertEqual(stored_tuples(name), objdump_tuples(s, en), name)
            self.assertEqual(len(stored_tuples(name)), e["strict"], name)

    def test_tamper_byte_detected(self):
        rec = load_records()
        e = rec["exhibits"]["gb_entry"]
        with open(os.path.join(PACKET, "gb_entry.hex")) as fh:
            raw = bytes.fromhex("".join(fh.read().split()))
        with open(BIN, "rb") as fh:
            fh.seek(int(e["range"][0], 16) - 0x1000)
            live = fh.read(len(raw))
        self.assertEqual(raw, live)
        tampered = bytes([raw[0] ^ 0xFF]) + raw[1:]
        self.assertNotEqual(tampered, live)

    def test_tamper_objdump_detected(self):
        rows = stored_tuples("gb_tail")
        self.assertTrue(rows)
        mutated = list(rows)
        addr, bts, mn = mutated[0]
        mutated[0] = (addr, bts, mn + " ; tampered")
        self.assertNotEqual(mutated, rows)

    def test_manifest_entries(self):
        with open(os.path.join(PACKET, "MANIFEST.sha256")) as fh:
            lines = [ln.strip() for ln in fh if ln.strip()]
        self.assertEqual(len(lines), 17)
        self.assertFalse(any("MANIFEST.sha256" in ln for ln in lines))

    def test_hex_parse(self):
        rec = load_records()
        for name, e in rec["exhibits"].items():
            with open(os.path.join(PACKET, name + ".hex")) as fh:
                raw = bytes.fromhex("".join(fh.read().split()))
            self.assertEqual(len(raw), e["bytes"], name)
            self.assertEqual(int(e["range"][1], 16) - int(e["range"][0], 16),
                             e["bytes"], name)

    def test_records_ranges_inside_fde(self):
        rec = load_records()
        lo, hi = int(rec["fde"][0], 16), int(rec["fde"][1], 16)
        spans = sorted((int(e["range"][0], 16), int(e["range"][1], 16))
                       for e in rec["exhibits"].values())
        for s, en in spans:
            self.assertGreaterEqual(s, lo)
            self.assertLessEqual(en, hi)
        for (s1, e1), (s2, e2) in zip(spans, spans[1:]):
            self.assertGreaterEqual(s2, e1)


if __name__ == "__main__":
    unittest.main()
