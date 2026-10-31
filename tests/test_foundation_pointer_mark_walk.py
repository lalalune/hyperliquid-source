#!/usr/bin/env python3
"""Unit tests for the node #94 pointer-mark walk evidence checker.

The tests run the checker against a copy of the pinned target and against
corrupted copies, plus the decoded walk rule on synthetic inputs.
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

from foundation_pointer_mark_walk import (  # noqa: E402
    BODY, CALLERS, END, START, inspect, layout, walk,
)

TARGET = ROOT / 'artifacts/node/94/hl-node'
EVIDENCE = ROOT / 'research/work-items/foundation-pointer-mark-walk-94/evidence.json'


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


class TestPointerMarkWalk(unittest.TestCase):
    def test_check_reproduces(self):
        result = inspect(str(TARGET))
        self.assertEqual(result['window'], (START, END))
        self.assertEqual(result['body_sha256'], hashlib.sha256(BODY).hexdigest())
        self.assertEqual(result['direct_callers'], [c[0] for c in CALLERS])
        self.assertEqual(result['relocation_slots'], [])

    def test_body_hash(self):
        data = load_bytes()
        secs = sections_of(data)
        text = secs['.text']
        off = text['offset'] + START - text['address']
        self.assertEqual(bytes(data[off:off + len(BODY)]), BODY)

    def test_rule_edges(self):
        mem, rdi_obj, s, _ = layout([])
        self.assertEqual(walk(mem, rdi_obj, s), mem)
        mem, rdi_obj, s, _ = layout(['empty'])
        self.assertEqual(walk(mem, rdi_obj, s), mem)
        mem, rdi_obj, s, nodes = layout([['mask']])
        out = walk(mem, rdi_obj, s)
        self.assertEqual(out[nodes[0] + 0xcc8], 0x4242424242424242)
        mem, rdi_obj, s, nodes = layout([['other']])
        out = walk(mem, rdi_obj, s)
        self.assertEqual(out[nodes[0] + 0xcc8], 0x1111)
        mem, rdi_obj, s, nodes = layout([['mask', 'mask', 'other']])
        out = walk(mem, rdi_obj, s)
        self.assertEqual(out[nodes[0] + 0xcc8], 0x4242424242424242)
        self.assertEqual(out[nodes[1] + 0xcc8], 0x4242424242424242)
        self.assertEqual(out[nodes[2] + 0xcc8], 0x1111)
        mem, rdi_obj, s, nodes = layout([['mask']] * 9)
        out = walk(mem, rdi_obj, s)
        self.assertEqual(len(nodes), 9)
        for n in nodes:
            self.assertEqual(out[n + 0xcc8], 0x4242424242424242)
        # Five-entry walk marks all five chains.
        mem, rdi_obj, s, nodes = layout([['mask']] * 5)
        out = walk(mem, rdi_obj, s)
        self.assertEqual(len(nodes), 5)
        for n in nodes:
            self.assertEqual(out[n + 0xcc8], 0x4242424242424242)

    def test_body_corruption_fails(self):
        data = load_bytes()
        write_va(data, START + 4, b'\x90')
        with self.assertRaises(ValueError):
            check_bytes(data)

    def test_padding_corruption_fails(self):
        data = load_bytes()
        write_va(data, END, b'\x90')
        with self.assertRaises(ValueError):
            check_bytes(data)

    def test_caller_call_corruption_fails(self):
        data = load_bytes()
        write_va(data, CALLERS[0][0] + 1, b'\x00')
        with self.assertRaises(ValueError):
            check_bytes(data)

    def test_fde_corruption_fails(self):
        data = load_bytes()
        secs = sections_of(data)
        eh = secs['.eh_frame']
        off = eh['offset'] + 0x297df0 + 12
        data[off:off + 4] = (0x91).to_bytes(4, 'little')
        with self.assertRaises(ValueError):
            check_bytes(data)

    def test_digest_corruption_fails(self):
        data = load_bytes()
        write_va(data, START + 145, b'\x90')
        with self.assertRaises(ValueError):
            check_bytes(data)


if __name__ == '__main__':
    unittest.main()
