#!/usr/bin/env python3
"""Unit tests for the node #94 three-digit ASCII parse evidence checker.

The tests run the checker against a copy of the pinned target and against
corrupted copies, plus the decoded parse rule on synthetic inputs.
They never execute the captured binary. Each temporary target copy is
unlinked after use, so repeated runs do not fill /tmp with 91 MB copies.
"""

import hashlib
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

from foundation_three_digit_ascii_parse import (  # noqa: E402
    BODY, CALL_SITE, END, START, inspect, parse,
)

TARGET = ROOT / 'artifacts/node/94/hl-node'
EVIDENCE = ROOT / 'research/work-items/foundation-three-digit-ascii-parse-94/evidence.json'


def load_bytes():
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


def check_bytes(data):
    fd, tmp = tempfile.mkstemp()
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(bytes(data))
        return inspect(tmp)
    finally:
        os.unlink(tmp)


class TestThreeDigitAsciiParse(unittest.TestCase):
    def test_check_reproduces(self):
        result = inspect(str(TARGET))
        self.assertEqual(result['window'], (START, END))
        self.assertEqual(result['body_sha256'], hashlib.sha256(BODY).hexdigest())
        self.assertEqual(result['direct_callers'], [CALL_SITE])
        self.assertEqual(result['relocation_slots'], [])

    def test_body_hash(self):
        data = load_bytes()
        secs = sections_of(data)
        text = secs['.text']
        off = text['offset'] + START - text['address']
        self.assertEqual(bytes(data[off:off + len(BODY)]), BODY)

    def test_rule_edges(self):
        self.assertEqual(parse(b'', 0), 0)
        self.assertEqual(parse(b'12', 2), 0)
        self.assertEqual(parse(b'1234', 4), 0)
        self.assertEqual(parse(b'123', 3), 123)
        self.assertEqual(parse(b'100', 3), 100)
        self.assertEqual(parse(b'999', 3), 999)
        self.assertEqual(parse(b'523', 3), 523)
        self.assertEqual(parse(b'012', 3), 0)
        self.assertEqual(parse(b'12a', 3), 0)
        self.assertEqual(parse(b'1:3', 3), 0)
        self.assertEqual(parse(b':23', 3), 0)
        self.assertEqual(parse(b' 23', 3), 0)

    def test_body_corruption_fails(self):
        data = load_bytes()
        write_va(data, START + 25, b'\x90')
        with self.assertRaises(ValueError):
            check_bytes(data)

    def test_padding_corruption_fails(self):
        data = load_bytes()
        write_va(data, END, b'\x90')
        with self.assertRaises(ValueError):
            check_bytes(data)

    def test_caller_corruption_fails(self):
        data = load_bytes()
        write_va(data, CALL_SITE, b'\x90')
        with self.assertRaises(ValueError):
            check_bytes(data)

    def test_fde_corruption_fails(self):
        data = load_bytes()
        secs = sections_of(data)
        eh = secs['.eh_frame']
        off = eh['offset'] + 0x24804 + 12
        data[off:off + 4] = (0x56).to_bytes(4, 'little')
        with self.assertRaises(ValueError):
            check_bytes(data)

    def test_digest_corruption_fails(self):
        data = load_bytes()
        data[0] ^= 0xff
        with self.assertRaises(ValueError):
            check_bytes(data)


if __name__ == '__main__':
    unittest.main()
