import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check
from short_string_alias import (MASK, MAGIC, RANGES, TARGET, Transfers, alias,
                                alias_transfers, decode, evaluate, feed_transfers,
                                hash_words, instructions, read_va, stream_state)


class IntegerEquationControls(unittest.TestCase):
    def test_register_widths_and_wrapping_flags(self):
        t = Transfers({})
        t.put('rax', MASK)
        t.put('al', 0x41)
        self.assertEqual(t.get('rax'), 0xFFFFFFFFFFFFFF41)
        t.put('eax', 7)
        self.assertEqual(t.get('rax'), 7)
        t.flags(0xFFFFFFFF, 1, 0x100000000, 32)
        self.assertTrue(t.cf and t.zf)
        self.assertFalse(t.of)
        t.flags(0x80000000, 1, 0x7FFFFFFF, 32, True)
        self.assertTrue(t.of)
        self.assertFalse(t.cf or t.sf)

    def test_region_boundaries_and_unknown_equations_fail(self):
        t = Transfers({1: (b'\x90', 'syscall')})
        t.map(0x10000, b'abc')
        self.assertEqual(t.load(0x10001, 16), 0x6362)
        with self.assertRaisesRegex(ValueError, 'Out-of-region read'):
            t.load(0x10001, 32)
        with self.assertRaisesRegex(ValueError, 'read-only'):
            t.store(0x10000, 8, 0)
        with self.assertRaisesRegex(ValueError, 'Unsupported equation'):
            t.run(1)
        flags = Transfers({1: (b'\x74\x00', 'je 3')})
        with self.assertRaisesRegex(ValueError, 'unmodeled flags'):
            flags.run(1)

    def test_byte_decoder_records_reject_duplicate_addresses(self):
        line = ' 13daa30: 53                   push rbx\n'
        self.assertEqual(instructions(line), {0x13DAA30: (b'\x53', 'push rbx')})
        with self.assertRaisesRegex(ValueError, 'Duplicate instruction'):
            instructions(line+line)

    def test_reciprocal_inequality_and_low_byte_truncation(self):
        # For h=26q+r, h*M=q*2^67 + 2q + r*M. The second term lies
        # in [0,2^67), so floor(h*M/2^67)=q for EVERY unsigned u64 h.
        self.assertEqual(26*MAGIC-(1 << 67), 2)
        self.assertLess(2*(MASK//26)+25*MAGIC, 1 << 67)
        for h in [0, 1, 25, 26, 27, (1 << 32)-1, 1 << 32, (1 << 63)-1, 1 << 63, MASK]:
            high = (h*MAGIC) >> 64
            q_target = (high & 0xFFFFFFFF) >> 3
            byte = ((h & 0xFFFFFFFF)-26*q_target+65) & 255
            self.assertEqual(byte, h % 26+65)


class Node94AliasEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = ROOT/'artifacts/node/94/hl-node'
        cls.data = cls.binary.read_bytes()
        identity = next(x for x in json.loads((ROOT/'provenance/artifacts.json').read_text())['files']
                        if x['path'] == 'artifacts/node/94/hl-node')
        check(cls.binary, identity)
        cls.code, cls.raw = decode(cls.binary, cls.data)

    def test_whole_target_fdes_and_dual_decode(self):
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), TARGET)
        self.assertEqual(len(self.code), 292)
        for begin, end in RANGES.values():
            self.assertEqual(sum(len(b) for v, (b, _) in self.code.items() if begin <= v < end), end-begin)
        self.assertEqual(len(self.raw), 5)

    def test_target_transfers_match_stream_equations_and_retained_record(self):
        result = evaluate(self.code)
        self.assertEqual(result['alias_comparisons'], 78)
        self.assertEqual(result['per_write_state_comparisons'], 1056)
        retained = ROOT/'research/work-items/RE-001-short-string-alias-94/observed/records.json'
        stored = json.loads(retained.read_text())
        for key, value in result.items():
            self.assertEqual(stored[key], value, key)
        # All feed instructions are visited; only eight producer growth-path
        # instructions are outside this preallocated-output scope.
        visited = {int(v, 16) for v in result['instruction_visits']}
        self.assertTrue({v for v in self.code if RANGES['feed'][0] <= v < RANGES['feed'][1]} <= visited)
        self.assertEqual(len(visited), 284)

    def test_growth_is_a_real_excluded_callee_not_a_stub(self):
        with self.assertRaisesRegex(ValueError, 'Unclosed callee'):
            alias_transfers(self.code, b'fictional-long-identifier', capacity=0)

    def test_split_feeds_and_counter_boundary_are_not_interchangeable(self):
        message = b'fictional-identifier-with-tail'
        chunks = [message, b'\xff', b'\x09\0\0\0']
        states, _ = feed_transfers(self.code, chunks)
        self.assertEqual(states[-1], stream_state([b''.join(chunks)]))
        self.assertNotEqual(hash_words(b''.join(chunks)), hash_words(message+b'\x09\0\0\0'))
        self.assertNotEqual(hash_words(b''.join(chunks)), hash_words(message+b'\xff\0\0\0\x09'))
        self.assertEqual(alias_transfers(self.code, message)[0], alias(message))

    def test_actual_elf_instruction_mutations_disagree_below_digest_gate(self):
        # Change real instruction bytes, then independently re-decode with BOTH
        # native decoders. Do not alter the high-level equations or reject only
        # because the whole-file digest changed.
        mutations = [
            ('delimiter', 0x13C6109, 0xFF, 0xFE),
            ('counter-width', 0x13C6124, 0x04, 0x03),
            ('initial-state', 0x13C60A2, 0x75, 0x74),
            ('partial-word-round', 0x13DAAEC, 0x0D, 0x0C),
            ('full-word-round', 0x13DAB5D, 0x0D, 0x0C),
            ('finalization-domain', 0x13C618E, 0xFF, 0xFE),
            ('output-offset', 0x13C6252, 0x41, 0x42),
        ]
        with tempfile.TemporaryDirectory(prefix='alias-byte-controls-') as directory:
            path = Path(directory)/'mutated-node94-data'
            for name, va, before, after in mutations:
                with self.subTest(name=name):
                    offset, body = read_va(self.data, va, 1)
                    self.assertEqual(body, bytes([before]))
                    changed = bytearray(self.data)
                    changed[offset] = after
                    path.write_bytes(changed)
                    os.chmod(path, 0o600)
                    code, _ = decode(path, changed)
                    with self.assertRaisesRegex(ValueError, '(Alias|Feed state|Counter hash) mismatch'):
                        evaluate(code)


if __name__ == '__main__':
    unittest.main()
