#!/usr/bin/env python3
"""Unit tests for the node #94 binary-search-16 evidence checker.

The tests run the checker against a copy of the pinned target and against
corrupted copies, plus the decoded lower-bound rule on synthetic tables.
They never execute the captured binary.
"""

import hashlib
import shutil
import struct
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

from foundation_binary_search_16 import (  # noqa: E402
    BODY, CIE0, CIE2, END, FDE, NEXT, PAD_END, START, analyze, inspect,
    lower_bound,
)

TARGET = ROOT / 'artifacts/node/94/hl-node'
EVIDENCE = ROOT / 'research/work-items/foundation-binary-search-16-94/evidence.json'


def load():
    return bytearray(TARGET.read_bytes())


def sections_of(data):
    from elf_index import sections
    return {s['name']: s for s in sections(bytes(data))}


def write_va(data, va, raw):
    secs = sections_of(data)
    for s in secs.values():
        if s['type'] != 8 and s['address'] <= va < s['address'] + s['size']:
            off = s['offset'] + va - s['address']
            data[off:off + len(raw)] = raw
            return
    raise ValueError(f'unmapped VA {hex(va)}')


def table(keys):
    """Synthetic table: entries at 0x2000+i*16, key cells at 0x1000+i*8."""
    entries = {0x2000 + i * 16: 0x1000 + i * 8 for i in range(len(keys))}
    cells = {0x1000 + i * 8: k for i, k in enumerate(keys)}
    return entries, cells


def search(keys, rsi, span_bytes=None):
    entries, cells = table(keys)
    hi = 0x2000 + (len(keys) * 16 if span_bytes is None else span_bytes)
    return lower_bound(entries, cells, 0x2000, hi, rsi) - 0x2000


class TestBinarySearch16(unittest.TestCase):
    def test_check_reproduces(self):
        result = inspect(str(TARGET))
        self.assertEqual(result['window'], (START, END))
        self.assertEqual(result['body_sha256'], hashlib.sha256(BODY).hexdigest())
        self.assertEqual(len(result['direct_callers']), 14)
        self.assertEqual(result['relocation_slots'], [])

    def test_body_hash(self):
        data = load()
        secs = sections_of(data)
        text = secs['.text']
        off = text['offset'] + START - text['address']
        self.assertEqual(bytes(data[off:off + len(BODY)]), BODY)

    def test_rule_edges(self):
        self.assertEqual(search([10, 20, 30], 20), 16)
        self.assertEqual(search([10, 20, 30], 25), 32)
        self.assertEqual(search([10, 20, 30], 5), 0)
        self.assertEqual(search([10, 20, 30], 10), 0)
        self.assertEqual(search([10, 20, 30], 30), 32)
        self.assertEqual(search([10, 20, 30], 31), 48)
        self.assertEqual(search([7], 7), 0)
        self.assertEqual(search([7], 8), 16)
        self.assertEqual(search([], 1), 0)
        self.assertEqual(search([1 << 63], 1), 0)
        self.assertEqual(search([7], 7, span_bytes=8), 0)
        self.assertEqual(search([7], 8, span_bytes=8), 16)
        self.assertEqual(search([7], 1, span_bytes=-16), 0)

    def test_corrupt_window_byte(self):
        data = load()
        write_va(data, START + 4, b'\x00')
        with self.assertRaises(ValueError):
            analyze(bytes(data))

    def test_corrupt_padding_byte(self):
        data = load()
        write_va(data, END, b'\x00')
        with self.assertRaises(ValueError):
            analyze(bytes(data))

    def test_corrupt_branch_target(self):
        data = load()
        # jae rel8 at body offset 66 (0x51cb5b1 + 2 - 1 = displacement byte).
        write_va(data, START + 66, b'\x00')
        with self.assertRaises(ValueError):
            analyze(bytes(data))

    def test_corrupt_call_site(self):
        data = load()
        write_va(data, 0x51a5dce + 1, b'\x00\x00\x00\x00')
        with self.assertRaises(ValueError):
            analyze(bytes(data))

    def test_corrupt_caller_setup(self):
        data = load()
        # Byte immediately before the first call site (lea tail byte, 0x00).
        write_va(data, 0x51a5dce - 1, b'\x01')
        with self.assertRaises(ValueError):
            analyze(bytes(data))

    def test_corrupt_window_fde(self):
        data = load()
        secs = sections_of(data)
        eh = secs['.eh_frame']
        off = eh['offset'] + 0x2a1170
        data[off + 12:off + 16] = struct.pack('<I', 0x6B)
        with self.assertRaises(ValueError):
            analyze(bytes(data))

    def test_corrupt_cie(self):
        data = load()
        secs = sections_of(data)
        eh = secs['.eh_frame']
        off = eh['offset'] + 0x6205d0
        data[off + 8] ^= 0x01
        with self.assertRaises(ValueError):
            analyze(bytes(data))

    def test_naming_relocation_added(self):
        data = load()
        secs = sections_of(data)
        rela = secs['.rela.dyn']
        # Overwrite the first entry's addend with the window start.
        off = rela['offset']
        data[off + 16:off + 24] = struct.pack('<q', START)
        with self.assertRaises(ValueError):
            analyze(bytes(data))

    def test_evidence_matches(self):
        import json
        retained = json.loads(EVIDENCE.read_text())
        result = inspect(str(TARGET))
        self.assertEqual(retained['target_sha256'],
                         '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f')
        self.assertEqual(retained['function']['start_va'], hex(START))
        self.assertEqual(retained['function']['end_va_exclusive'], hex(END))
        self.assertEqual(retained['function']['bytes'], END - START)
        self.assertEqual(retained['function']['sha256'], result['body_sha256'])
        self.assertEqual(retained['function']['padding_bytes'], 6)
        self.assertEqual(retained['incoming_pattern_scan']['e8_candidates'],
                         [hex(c) for c in result['direct_callers']])
        self.assertEqual(retained['incoming_pattern_scan']['relocation_slots'],
                         result['relocation_slots'])

    def test_temp_copy_check(self):
        with tempfile.TemporaryDirectory() as tmp:
            copy = Path(tmp) / 'hl-node'
            shutil.copyfile(TARGET, copy)
            self.assertEqual(inspect(str(copy))['body_sha256'],
                             hashlib.sha256(BODY).hexdigest())


if __name__ == '__main__':
    unittest.main()
