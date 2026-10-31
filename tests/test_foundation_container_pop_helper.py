#!/usr/bin/env python3
"""Unit tests for the node #94 container-pop-helper evidence checker.

The tests run the checker against a copy of the pinned target and against
corrupted copies, plus the decoded pop-helper rule on synthetic inputs.
They never execute the captured binary.
"""

import hashlib
import struct
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

from foundation_container_pop_helper import (  # noqa: E402
    BODY, END, START, MASK, inspect, pop_rule,
)

TARGET = ROOT / 'artifacts/node/94/hl-node'
EVIDENCE = ROOT / 'research/work-items/foundation-container-pop-helper-94/evidence.json'


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


class TestContainerPopHelper(unittest.TestCase):
    def test_check_reproduces(self):
        result = inspect(str(TARGET))
        self.assertEqual(result['window'], (START, END))
        self.assertEqual(result['body_sha256'], hashlib.sha256(BODY).hexdigest())
        self.assertEqual(len(result['direct_callers']), 1)
        self.assertEqual(result['relocation_slots'], [])

    def test_body_hash(self):
        data = load()
        secs = sections_of(data)
        text = secs['.text']
        off = text['offset'] + START - text['address']
        self.assertEqual(bytes(data[off:off + len(BODY)]), BODY)

    def test_rule_edges(self):
        self.assertEqual(pop_rule(100, 100, 1000, 7), (0x1e7, 7, 0x207, 992, -0x10))
        self.assertEqual(pop_rule(100, 50, 1000, 7), (68, None, None, None, -0x10))
        self.assertEqual(pop_rule(100, 100, 1000, 0), (0x1e0, 0, 0x200, 992, -0x10))
        self.assertEqual(pop_rule(0x20, 0, 1000, 7), (0, None, None, None, -0x10))
        self.assertEqual(pop_rule(100, 100, 1000, MASK),
                         (0x1df, MASK, 0x1ff, 992, -0x10))

    def corrupted(self, mutator):
        data = load()
        mutator(data)
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(bytes(data))
            path = tmp.name
        try:
            with self.assertRaises(ValueError):
                inspect(path)
        finally:
            Path(path).unlink(missing_ok=True)

    def test_corrupt_body_byte(self):
        def flip(data):
            write_va(data, START + 4, b'\x00')
        self.corrupted(flip)

    def test_corrupt_padding(self):
        def flip(data):
            write_va(data, END, b'\x90')
        self.corrupted(flip)

    def test_corrupt_fde(self):
        def flip(data):
            secs = sections_of(data)
            eh = secs['.eh_frame']
            off = eh['offset'] + 0x29c8c0 + 12
            data[off] ^= 0x01
        self.corrupted(flip)

    def test_corrupt_call_site(self):
        def flip(data):
            write_va(data, 0x508f33e + 1, b'\x00')
        self.corrupted(flip)

    def test_corrupt_caller_setup(self):
        def flip(data):
            write_va(data, 0x508f33e - 7, b'\x00')
        self.corrupted(flip)


if __name__ == '__main__':
    unittest.main()
