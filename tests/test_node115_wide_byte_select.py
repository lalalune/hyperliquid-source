"""Static target-byte and semantic controls for the RE-001 wide byte leaf."""
import copy
import json
import mmap
from pathlib import Path
import re
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import node115_wide_byte_select as subject


class WideByteSelectTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.stream = subject.TARGET.open('rb')
        cls.data = mmap.mmap(cls.stream.fileno(), 0, access=mmap.ACCESS_READ)
        cls.record = subject.inspect(cls.data)
        cls.body = bytes.fromhex(cls.record['window']['body_hex'])

    @classmethod
    def tearDownClass(cls):
        cls.data.close()
        cls.stream.close()

    def mutant(self):
        # Private copy-on-write mapping; only touched pages are copied. Never
        # alter the capture or allocate another full binary in Python memory.
        return mmap.mmap(self.stream.fileno(), 0, access=mmap.ACCESS_COPY)

    def test_authenticated_extent_and_full_walk(self):
        r = self.record
        self.assertEqual(r['target']['sha256'], subject.SHA)
        self.assertEqual((r['window']['start'], r['window']['end']),
                         (0x43352f0, 0x4335379))
        self.assertEqual(r['window']['body_sha256'], subject.BODY_SHA)
        self.assertEqual(r['window']['frame']['cie_fields']['augmentation'], 'zR')
        self.assertIsNone(r['window']['frame']['lsda'])
        self.assertEqual(''.join(row['bytes'] for row in r['instructions']), self.body.hex())
        self.assertEqual(sum(row['size'] for row in r['instructions']), 137)
        self.assertEqual(r['callees'], [])
        self.assertEqual(r['direct_rel32_candidates'], [])

    def test_regenerate_byte_identically(self):
        expected = subject.packet_bytes(self.record)
        with tempfile.TemporaryDirectory() as folder:
            out = Path(folder) / 'packet'
            result = subject.generate(subject.TARGET, out)
            self.assertEqual(result, self.record)
            for name, content in expected.items():
                self.assertEqual((out / name).read_bytes(), content, name)
                self.assertEqual((subject.PACKET / name).read_bytes(), content, name)
            subject.verify_manifest(out)

    def test_readme_counts_equal_json_and_data(self):
        r = json.loads((subject.PACKET / 'records.json').read_text())
        c = r['counts']
        self.assertEqual(c, {
            'body_bytes': len(bytes.fromhex(r['window']['body_hex'])),
            'instructions': len(r['instructions']),
            'branches': sum('branch' in row for row in r['instructions']),
            'returns': sum(row['instruction'] == 'ret' for row in r['instructions']),
            'callees': len(r['callees']),
            'caller_candidates': len(r['direct_rel32_candidates']),
            'padding_bytes': len(bytes.fromhex(r['window']['padding_hex'])),
            'pointer_relocations': len(r['function_pointer_relocations']),
            'vectors': len(r['vectors']),
        })
        labels = dict(zip(('Body bytes', 'Decoded instructions',
                           'Internal branch instructions', 'Return instructions',
                           'Direct or indirect callees', 'Direct rel32 caller candidates',
                           'Following padding bytes', 'Relocated function pointers',
                           'Instruction-grounded model vectors'),
                          ('body_bytes', 'instructions', 'branches', 'returns',
                           'callees', 'caller_candidates', 'padding_bytes',
                           'pointer_relocations', 'vectors')))
        readme = (subject.PACKET / 'README.md').read_text()
        rows = re.findall(r'^\| ([^|]+?) \| (\d+) \|$', readme, re.MULTILINE)
        self.assertEqual(len(rows), len(labels))
        for label, value in rows:
            self.assertEqual(int(value), c[labels[label]])
        # Changing a JSON count also changes the rendered count, preventing a
        # hard-coded README count from passing through equality by coincidence.
        for label, key in labels.items():
            changed = copy.deepcopy(r)
            changed['counts'][key] += 1
            self.assertIn(f'| {label} | {c[key] + 1} |', subject.readme(changed))

    def test_all_byte_positions_with_asymmetric_word(self):
        word = int.from_bytes(bytes(range(1, 33)), 'little')
        for index in range(32):
            with self.subTest(index=index):
                expected = 32 - index
                result = subject.model([word, index])
                self.assertEqual(result, {'depth': 1, 'slots': [expected, index], 'rax': 0})
                self.assertEqual(subject.byte_address_rule(index, word, self.record['facts']),
                                 expected)

    def test_wide_indices_and_unsigned_bound(self):
        # Every high-limb bit must reject even with an in-range low limb. A
        # low64-only or signed compare would incorrectly select 0xff here.
        indices = [32, 33, (1 << 63), subject.U64, subject.U256]
        indices += [(1 << bit) | low for bit in range(64, 256) for low in (0, 31)]
        for index in indices:
            with self.subTest(index=index):
                self.assertEqual(subject.model([subject.U256, index])['slots'][0], 0)
                self.assertEqual(subject.byte_address_rule(index, subject.U256,
                                                          self.record['facts']), 0)

    def test_underflow_preserves_memory_and_upper_rax(self):
        for depth in (0, 1):
            for entry in (0, subject.U64, 0x123456789abcdef0):
                slots = [subject.U256, 99]
                before = slots[:]
                self.assertEqual(subject.model(slots, depth, entry),
                                 {'depth': depth, 'slots': before,
                                  'rax': (entry & ~255) | 0x2c})
                self.assertEqual(slots, before)

    def test_only_result_slot_changes_and_operand_order(self):
        slots = [0x123456, 1 << 255, 0, 0xabcdef]
        before = slots[:]
        self.assertEqual(subject.model(slots, 3, subject.U64),
                         {'depth': 2, 'slots': [0x123456, 128, 0, 0xabcdef], 'rax': 0})
        self.assertEqual(slots, before)
        self.assertEqual(subject.model([0, 1 << 255])['slots'][0], 0)

    def test_all_retained_vectors(self):
        for vector in self.record['vectors']:
            with self.subTest(label=vector['label']):
                self.assertEqual(subject.model(vector['slots'], vector['depth'],
                                               vector['entry_rax']), vector['expected'])

    def test_model_rejects_out_of_domain_inputs(self):
        for slots, depth, rax in (([-1], 1, 0), ([1 << 256], 1, 0),
                                  ([True], 1, 0), ([0], 2, 0), ([0], -1, 0),
                                  ([0], 1, -1), ([0], 1, 1 << 64)):
            with self.subTest(slots=slots, depth=depth, rax=rax):
                with self.assertRaises(ValueError):
                    subject.model(slots, depth, rax)

    def test_wrong_digest_and_no_output(self):
        with self.assertRaisesRegex(ValueError, 'digest mismatch'):
            subject.inspect(b'not the authenticated node')
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            bad = root / 'bad'
            out = root / 'must-not-exist'
            for content in (b'', b'wrong binary'):
                bad.write_bytes(content)
                with self.assertRaisesRegex(ValueError, 'digest mismatch'):
                    subject.generate(bad, out)
                self.assertFalse(out.exists())

    def test_actual_window_mutation_rejected_at_two_layers(self):
        with self.mutant() as data:
            off = self.record['window']['file_offset']
            data[off] ^= 1
            with self.assertRaisesRegex(ValueError, 'digest mismatch'):
                subject.inspect(data)
            with self.assertRaisesRegex(ValueError, 'unsupported instruction'):
                subject.inspect(data, authenticate=False)

    def test_shifted_fde_rejected_without_digest_shortcut(self):
        with self.mutant() as data:
            old = struct.unpack_from('<i', data, subject.FDE + 8)[0]
            struct.pack_into('<i', data, subject.FDE + 8, old + 1)
            with self.assertRaisesRegex(ValueError, 'FDE extent'):
                subject.inspect(data, authenticate=False)

    def test_cie_index_and_padding_corruption(self):
        with self.mutant() as data:
            data[subject.CIE + 20] ^= 1
            with self.assertRaisesRegex(ValueError, 'CIE bytes'):
                subject.inspect(data, authenticate=False)
        with self.mutant() as data:
            secs = subject.validate_sections(data)
            header = next(s for s in secs if s['name'] == '.eh_frame_hdr')
            i = self.record['window']['frame']['index']['index']
            pos = header['offset'] + 12 + 8 * i
            old = struct.unpack_from('<i', data, pos)[0]
            struct.pack_into('<i', data, pos, old + 1)
            with self.assertRaisesRegex(ValueError, 'unwind index'):
                subject.inspect(data, authenticate=False)
        with self.mutant() as data:
            data[subject.END - 0x1000] = 0x90
            with self.assertRaisesRegex(ValueError, 'padding changed'):
                subject.inspect(data, authenticate=False)

    def test_wrong_branch_target_and_condition(self):
        for pos, value in ((9, 0x7b), (8, 0x74), (0x3f, 0x19)):
            body = bytearray(self.body)
            body[pos] = value
            with self.subTest(pos=pos):
                with self.assertRaisesRegex(ValueError, 'branch target or condition'):
                    subject.validate_walk(body)

    def test_semantic_operand_mutation_changes_fact_then_rejects(self):
        for va, value, fact in ((0x43352f7, 1, 'minimum_depth'),
                                 (0x4335308, 4, 'slot_shift'),
                                 (0x4335326, 31, 'index_limit'),
                                 (0x4335377, 0x2d, 'underflow_al')):
            body = bytearray(self.body)
            body[va - subject.START] = value
            rows = subject.decode(body)
            facts = {r['fact']: r['value'] for r in rows if 'fact' in r}
            self.assertEqual(facts[fact], value)
            with self.assertRaisesRegex(ValueError, 'semantic immediate'):
                subject.validate_walk(body)
        altered = dict(self.record['facts'], index_limit=31)
        self.assertEqual(subject.byte_address_rule(31, 255, self.record['facts']), 255)
        self.assertEqual(subject.byte_address_rule(31, 255, altered), 0)

    def test_every_window_byte_and_truncation_rejected(self):
        for pos in range(len(self.body)):
            body = bytearray(self.body)
            body[pos] ^= 1
            with self.subTest(pos=pos):
                with self.assertRaises(ValueError):
                    subject.validate_walk(body)
        for size in range(len(self.body)):
            with self.subTest(size=size):
                with self.assertRaises(ValueError):
                    subject.validate_walk(self.body[:size])
        with self.assertRaises(ValueError):
            subject.validate_walk(self.body + b'\xc3')

    def test_injected_call_cannot_expand_leaf_closure(self):
        body = bytearray(self.body)
        body[:5] = b'\xe8' + struct.pack('<i', 0x1000)
        with self.assertRaisesRegex(ValueError, 'unsupported instruction'):
            subject.validate_walk(body)

    def test_full_text_rel32_scan_and_wrong_destination(self):
        self.assertEqual(subject.direct_candidates(self.data), [])
        start_off = subject.TEXT_OFFSET + 0x100
        last_off = subject.TEXT_OFFSET + subject.TEXT_END - subject.TEXT_START - 5
        # Include the last possible complete encoding in .text, and both e8/e9.
        for off in (start_off, last_off):
            for opcode in (0xe8, 0xe9):
                with self.subTest(off=off, opcode=opcode), self.mutant() as data:
                    va = off + 0x1000
                    data[off:off + 5] = bytes([opcode]) + struct.pack('<i', subject.START - va - 5)
                    hits = subject.direct_candidates(data)
                    self.assertEqual([(h['address'], h['target']) for h in hits],
                                     [(va, subject.START)])
                    with self.assertRaisesRegex(ValueError, 'caller census'):
                        subject.inspect(data, authenticate=False)
                    struct.pack_into('<i', data, off + 1, subject.START + 1 - va - 5)
                    self.assertEqual(subject.direct_candidates(data), [])

    def test_wrong_function_pointer_target_and_type_rejected(self):
        self.assertEqual([r['slot'] for r in self.record['function_pointer_relocations']],
                         [0x6485fc8, 0x6486d30])
        for off in (0xb3dc0, 0xb5bf0):
            with self.subTest(off=off), self.mutant() as data:
                struct.pack_into('<q', data, off + 16, subject.START + 1)
                with self.assertRaisesRegex(ValueError, 'pointer references'):
                    subject.inspect(data, authenticate=False)
        with self.mutant() as data:
            struct.pack_into('<Q', data, 0xb3dc0 + 8, 7)
            with self.assertRaisesRegex(ValueError, 'pointer relocation type'):
                subject.inspect(data, authenticate=False)

    def test_manifest_whitelist_and_hash_controls(self):
        expected = subject.packet_bytes(self.record)
        with tempfile.TemporaryDirectory() as folder:
            out = Path(folder)
            for name, content in expected.items():
                (out / name).write_bytes(content)
            subject.verify_manifest(out)
            (out / 'extra').write_text('unlisted')
            with self.assertRaisesRegex(ValueError, 'file whitelist'):
                subject.verify_manifest(out)
            (out / 'extra').unlink()
            (out / 'records.json').write_text('{}\n')
            with self.assertRaisesRegex(ValueError, 'hash mismatch'):
                subject.verify_manifest(out)
            (out / 'records.json').write_bytes(expected['records.json'])
            original = expected['MANIFEST.sha256'].decode()
            for manifest in (original + original.splitlines()[0] + '\n',
                             original.replace('README.md', '../README.md'),
                             '\n'.join(original.splitlines()[:-1]) + '\n'):
                (out / 'MANIFEST.sha256').write_text(manifest)
                with self.assertRaises(ValueError):
                    subject.verify_manifest(out)


if __name__ == '__main__':
    unittest.main()
