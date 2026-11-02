"""Static controls for the node #115 insertion leaf; never execute the target."""
import itertools
import json
import mmap
from pathlib import Path
import re
import runpy
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import node115_record_insertion as bind


def records_for(keys):
    return [key.to_bytes(8, 'little') + bytes([i]) * 32 for i, key in enumerate(keys)]


class RecordInsertionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.handle = bind.TARGET.open('rb')
        cls.data = mmap.mmap(cls.handle.fileno(), 0, access=mmap.ACCESS_READ)
        cls.records = bind.build_records(cls.data)
        cls.body = bytes.fromhex(cls.records['function']['body_hex'])

    @classmethod
    def tearDownClass(cls):
        cls.data.close()
        cls.handle.close()

    def patched(self, offset, raw, callback):
        # Private copy-on-write pages, not a bytearray copy of the whole ELF.
        with mmap.mmap(self.handle.fileno(), 0, access=mmap.ACCESS_COPY) as data:
            data[offset:offset + len(raw)] = raw
            return callback(data)

    def test_regeneration_byte_identical(self):
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp) / 'packet'
            bind.generate(bind.TARGET, out)
            for name in ('records.json', 'README.md', 'verify.py', 'MANIFEST.sha256'):
                self.assertEqual((out / name).read_bytes(), (bind.PACKET / name).read_bytes(), name)
        self.assertEqual(self.records, json.loads((bind.PACKET / 'records.json').read_text()))

    def test_readme_counts_equal_json(self):
        text = (bind.PACKET / 'README.md').read_text()
        self.assertEqual(text, bind.readme_text(self.records))
        m = self.records['metrics']
        checks = {
            'Complete leaf bytes': [m['function_bytes']],
            'Decoded leaf instructions, including in-body NOPs': [m['instructions']],
            'INT3 bytes before / after, outside the body': [m['padding_before_bytes'], m['padding_after_bytes']],
            'Direct callees / indirect transfers': [m['direct_callees'], m['indirect_transfers']],
            'Direct call sites / owning FDEs / tail-jump sites': [m['direct_call_sites'], m['direct_caller_fdes'], m['tail_jump_sites']],
            'Caller instructions decoded for boundary validation': [m['caller_instructions']],
            'First-party Location bindings in that caller': [m['source_locations']],
            'Instruction-grounded vectors / trap vectors': [m['vectors'], m['trap_vectors']],
        }
        for label, expected in checks.items():
            actual = re.search(r'^\| ' + re.escape(label) + r' \| (.*?) \|$', text, re.M)
            self.assertIsNotNone(actual, label)
            self.assertEqual([int(x) for x in re.findall(r'\d+', actual[1])], expected, label)

    def test_full_leaf_extent_and_control_flow(self):
        f = self.records['function']
        rows = f['instructions']
        self.assertEqual(sum(r['size'] for r in rows), bind.END - bind.START)
        self.assertEqual(''.join(r['bytes'] for r in rows), self.body.hex())
        for a, b in zip(rows, rows[1:]):
            self.assertEqual(a['va'] + a['size'], b['va'])
        boundaries = {r['va'] for r in rows}
        self.assertTrue(all(r['target'] in boundaries for r in rows if 'target' in r))
        self.assertEqual([r['va'] for r in rows if r['op'] == 'ret'], [0x26cf382])
        self.assertEqual([r['va'] for r in rows if r['op'] == 'ud2'], [0x26cf42d])
        self.assertFalse(f['direct_callees'] or f['indirect_transfers'] or f['external_branches'])
        self.assertIsNone(f['frame']['lsda'])

    def test_every_leaf_byte_corruption_rejected_below_digest_gate(self):
        for i in range(len(self.body)):
            body = bytearray(self.body)
            body[i] ^= 1
            with self.subTest(offset=i), self.assertRaises(ValueError):
                bind.validate_leaf(bytes(body))

    def test_semantic_counterfacts_change_decoded_rule(self):
        original = bind.relation_from_decode(bind.decode_leaf(self.body))
        for va, byte, key in [(0x26cf3ce, 0x72, 'initial_skip_condition'),
                              (0x26cf423, 0x73, 'backward_shift_condition'),
                              (0x26cf3bd, 41, 'record_bytes')]:
            body = bytearray(self.body)
            body[va - bind.START] = byte
            rows = bind.decode_leaf(bytes(body))
            self.assertNotEqual(bind.relation_from_decode(rows)[key], original[key])
            with self.assertRaisesRegex(ValueError, 'relation changed'):
                bind.check_relation(rows)

    def test_strict_decoder_rejects_nonboundary_and_unknown_forms(self):
        cases = [b'\x90', b'\xf0\x48\x89\xf8', b'\x48\x8d\xc0', b'\xc3\x48',
                 b'\xe8\x00\x00\x00\x00', self.body[:-1]]
        changed = bytearray(self.body)
        changed[0x26cf378 - bind.START] ^= 1  # JAE middle of final UD2.
        cases.append(bytes(changed))
        for body in cases:
            with self.subTest(body=body[:8].hex()), self.assertRaises(ValueError):
                bind.decode_leaf(body)

    def test_explicit_instruction_grounded_vectors(self):
        for case in self.records['vectors']:
            with self.subTest(name=case['name']):
                rows = records_for(case['keys'])
                if 'expected_trap' in case:
                    with self.assertRaisesRegex(ValueError, 'UD2'):
                        bind.insertion_model(rows, case['start_index'])
                else:
                    actual = bind.insertion_model(rows, case['start_index'])
                    self.assertEqual(actual, [rows[i] for i in case['expected_order']])

    def test_stable_sort_and_sorted_prefixes(self):
        # Independent stable-sort oracle, including the unsigned extreme.
        key = lambda r: int.from_bytes(r[:8], 'little')
        for n in range(1, 6):
            for keys in itertools.product((0, 1, bind.U64), repeat=n):
                original = records_for(keys)
                for k in range(1, n + 1):
                    rows = sorted(original[:k], key=key) + original[k:]
                    self.assertEqual(bind.insertion_model(rows, k), sorted(rows, key=key))

    def test_unsorted_prefix_is_not_a_full_sort(self):
        rows = records_for([9, 1, 5])
        self.assertEqual(bind.insertion_model(rows, 2), rows)
        self.assertNotEqual(bind.insertion_model(rows, 2), sorted(rows))
        self.assertEqual(bind.insertion_model(rows, 3), rows)

    def test_entry_guard_boundaries(self):
        for n in range(6):
            rows = records_for([0] * n)
            for k in (0, n + 1, bind.U64):
                with self.subTest(n=n, k=k), self.assertRaisesRegex(ValueError, 'UD2'):
                    bind.insertion_model(rows, k)
            if n:
                self.assertEqual(bind.insertion_model(rows, n), rows)
        for k in (-1, 1 << 64, True):
            with self.assertRaisesRegex(ValueError, 'invalid index'):
                bind.insertion_model(records_for([1]), k)

    def test_digest_and_truncation_fail_before_output(self):
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            self.patched(0, b'X', bind.build_records)
        with tempfile.TemporaryDirectory() as temp:
            bad = Path(temp) / 'bad'
            bad.write_bytes(b'not the node')
            out = Path(temp) / 'output'
            with self.assertRaisesRegex(ValueError, 'SHA-256'):
                bind.generate(bad, out)
            self.assertFalse(out.exists())

    def test_shifted_fde_start_extent_and_cie_rejected(self):
        frame = self.records['function']['frame']
        for off in (frame['fde_file_offset'] + 8, frame['fde_file_offset'] + 12,
                    frame['fde_file_offset'] + 4, frame['cie_file_offset'] + 17):
            raw = bytes([self.data[off] ^ 1])
            with self.subTest(offset=off), self.assertRaises(ValueError):
                self.patched(off, raw, bind._observe)

    def test_padding_corruption_rejected(self):
        off = self.records['function']['file_offset']
        for at in (off - 1, off + len(self.body)):
            with self.subTest(offset=at), self.assertRaisesRegex(ValueError, 'padding'):
                self.patched(at, b'\x90', bind._observe)

    def test_wrong_incoming_call_target_rejected(self):
        hit = self.records['caller_census']['hits'][0]
        raw = struct.pack('<i', hit['displacement'] + 1)
        with self.assertRaisesRegex(ValueError, 'caller census'):
            self.patched(hit['file_offset'] + 1, raw, bind._observe)

    def test_source_location_and_relocation_corruption_rejected(self):
        src = self.records['caller_context']['sources'][0]
        for off in (src['slot_file_offset'] + 8, src['relocation_file_offset'] + 16):
            with self.subTest(offset=off), self.assertRaises(ValueError):
                self.patched(off, bytes([self.data[off] ^ 1]), bind._observe)

    def test_manifest_whitelist_and_hash_controls(self):
        verifier = runpy.run_path(str(bind.PACKET / 'verify.py'))
        parse = verifier['parse_manifest']
        text = (bind.PACKET / 'MANIFEST.sha256').read_text()
        self.assertEqual(set(parse(text)), set(bind.MANIFEST_PATHS))
        lines = text.splitlines(keepends=True)
        for mutated in (''.join(lines[1:]), text + lines[0],
                        text + '0' * 64 + '  ../escape\n',
                        text.replace('README.md', '/README.md'), text + '\n'):
            with self.assertRaises(ValueError):
                parse(mutated)
        with tempfile.TemporaryDirectory(dir=ROOT / 'work') as temp:
            packet = Path(temp)
            for name in ('README.md', 'records.json', 'verify.py', 'MANIFEST.sha256'):
                (packet / name).write_bytes((bind.PACKET / name).read_bytes())
            (packet / 'records.json').write_text('{}\n')
            with self.assertRaisesRegex(ValueError, 'digest mismatch'):
                verifier['verify'](packet)
            (packet / 'extra').write_text('x')
            with self.assertRaisesRegex(ValueError, 'packet file'):
                verifier['verify'](packet)


if __name__ == '__main__':
    unittest.main()
