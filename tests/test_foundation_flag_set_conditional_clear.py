#!/usr/bin/env python3
"""Unit tests for the node #94 flag-set plus conditional clear evidence checker.

The tests run the checker against the pinned target bytes and against
corrupted in-memory copies, plus the decoded flag-set plus conditional clear
rule on synthetic inputs. They never execute the captured binary, and they
write no 91 MB temporary target copies: corruption checks run in memory.
"""

import hashlib
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

from foundation_flag_set_conditional_clear import (  # noqa: E402
    BODY, CALLERS, END, START, analyze, parse,
)

TARGET = ROOT / 'artifacts/node/94/hl-node'


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


class TestFlagSetConditionalClear(unittest.TestCase):
    def test_check_reproduces(self):
        result = analyze(bytes(load_bytes()))
        self.assertEqual(result['window'], (START, END))
        self.assertEqual(result['body_sha256'], hashlib.sha256(BODY).hexdigest())
        self.assertEqual(result['direct_callers'],
                         [site for site, _, _, _ in CALLERS])
        self.assertEqual(result['relocation_slots'], [])

    def test_body_hash(self):
        data = load_bytes()
        secs = sections_of(data)
        text = secs['.text']
        off = text['offset'] + START - text['address']
        self.assertEqual(bytes(data[off:off + len(BODY)]), BODY)

    def test_rule_edges(self):
        self.assertEqual(parse(True), (True, False))
        self.assertEqual(parse(False), (True, True))

    def test_corrupt_body_fails(self):
        data = load_bytes()
        write_va(data, START + 11, b'\x02')
        with self.assertRaises(ValueError):
            analyze(bytes(data))

    def test_corrupt_flag_store_fails(self):
        data = load_bytes()
        write_va(data, START + 17, b'\x02')
        with self.assertRaises(ValueError):
            analyze(bytes(data))

    def test_corrupt_branch_fails(self):
        data = load_bytes()
        write_va(data, START + 25, b'\x04')
        with self.assertRaises(ValueError):
            analyze(bytes(data))

    def test_corrupt_padding_fails(self):
        data = load_bytes()
        write_va(data, END, b'\x90')
        with self.assertRaises(ValueError):
            analyze(bytes(data))

    def test_corrupt_caller_bytes_fails(self):
        data = load_bytes()
        site = CALLERS[0][0]
        write_va(data, site + 1, b'\x00')
        with self.assertRaises(ValueError):
            analyze(bytes(data))


if __name__ == '__main__':
    unittest.main()
