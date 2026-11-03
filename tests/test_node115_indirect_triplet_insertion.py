"""Target-grounded static and semantic controls; never launch the captured node. MIT."""
import copy
import itertools
import json
import mmap
from pathlib import Path
import random
import re
import runpy
import shutil
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import node115_indirect_triplet_insertion as subject


class IndirectTripletInsertionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.handle = subject.TARGET.open('rb')
        cls.data = mmap.mmap(cls.handle.fileno(), 0, access=mmap.ACCESS_READ)
        cls.record = subject.analyze(cls.data)
        cls.verify = staticmethod(runpy.run_path(str(subject.PACKET / 'verify.py'))['verify'])

    @classmethod
    def tearDownClass(cls):
        cls.data.close()
        cls.handle.close()

    def mutation(self, offset, replacement, message=None):
        with mmap.mmap(self.handle.fileno(), 0, access=mmap.ACCESS_COPY) as changed:
            changed[offset:offset + len(replacement)] = replacement
            with self.assertRaisesRegex(ValueError, message or '.'):
                subject._analyze(changed)

    def test_retained_evidence_and_whitelist(self):
        self.assertEqual(self.verify(), self.record)
        self.assertEqual(json.loads((subject.PACKET / 'records.json').read_text()), self.record)

    def test_regeneration_is_byte_identical(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / 'packet'
            subject.generate(subject.TARGET, output)
            self.assertEqual({p.name for p in output.iterdir()},
                             {'README.md', 'records.json', 'verify.py', 'MANIFEST.sha256'})
            for p in output.iterdir():
                self.assertEqual(p.read_bytes(), (subject.PACKET / p.name).read_bytes(), p.name)

    def test_readme_counts_equal_json(self):
        text = (subject.PACKET / 'README.md').read_text()
        metrics = text.split('<!-- metrics derived from records.json; checked by the targeted tests -->\n')[1]
        metrics = metrics.split('<!-- end metrics -->')[0]
        actual = {name: int(n) for name, n in re.findall(r'^\| ([^|]+) \| (\d+) \|$', metrics, re.M)}
        record = json.loads((subject.PACKET / 'records.json').read_text())
        f = record['function']
        self.assertEqual(actual, {
            'Bound function bodies': len([f]),
            'Function bytes (including internal NOP)': len(bytes.fromhex(f['bytes'])),
            'Decoded function instructions (including internal NOP)': len(f['instructions']),
            'Reachable function instructions': len(f['instructions']) - len(f['control_flow']['unreachable']),
            'Internal unreachable NOP bytes': sum(len(bytes.fromhex(p['bytes'])) for p in f['internal_padding']),
            'Post-FDE INT3 bytes (excluded from body)': len(bytes.fromhex(f['post_fde_padding']['bytes'])),
            'Callees': len(f['callees']),
            'Indirect transfers': len(f['indirect_transfers']),
            'Raw full-text E8/E9 matches': len(record['direct_references']['matches']),
            'Distinct direct caller FDEs': len({r['owner']['fde'] for r in record['direct_references']['matches']}),
            'Frozen semantic vectors': len(record['vectors']),
        })

    def test_complete_decode_geometry_and_leaf_closure(self):
        f = self.record['function']
        self.assertEqual(f['fde'], subject.FDE)
        self.assertEqual(f['body_sha256'], subject.BODY_SHA)
        self.assertEqual(f['size'], 246)
        self.assertEqual(len(f['instructions']), 74)
        raw = bytes.fromhex(f['bytes'])
        self.assertEqual(b''.join(bytes.fromhex(r['bytes']) for r in f['instructions']), raw)
        cursor = subject.START
        for row in f['instructions']:
            self.assertEqual(row['va'], cursor)
            self.assertEqual(subject.decode(bytes.fromhex(row['bytes']), cursor), [row])
            cursor += len(bytes.fromhex(row['bytes']))
        self.assertEqual(cursor, subject.END)
        self.assertEqual(f['callees'], [])
        self.assertEqual(f['indirect_transfers'], [])
        self.assertEqual(f['control_flow']['unreachable'], [0x26d42f6])
        self.assertEqual(f['control_flow']['terminals'],
                         [{'va': 0x26d4373, 'kind': 'ret'}, {'va': 0x26d4374, 'kind': 'ud2'}])
        self.assertFalse(any('rip_target' in r for r in f['instructions']))

    def test_frozen_instruction_grounded_vectors(self):
        for row in self.record['vectors']:
            with self.subTest(row['name']):
                if row['expected'] == 'ud2':
                    with self.assertRaisesRegex(ValueError, 'UD2'):
                        subject.insertion_order(row['keys'], row['start_index'])
                else:
                    self.assertEqual(subject.insertion_order(row['keys'], row['start_index']), row['expected'])

    def test_guard_unsigned_extremes_without_memory(self):
        values = [0, 1, 2, (1 << 63) - 1, 1 << 63, subject.MASK64 - 1, subject.MASK64]
        for n, k in itertools.product(values, repeat=2):
            expected = 'ud2' if not 1 <= k <= n else 'return' if k == n else 'insert'
            self.assertEqual(subject.entry_action(n, k), expected, (n, k))
        for bad in (-1, 1 << 64, True, 1.5):
            with self.assertRaises(ValueError):
                subject.entry_action(bad, 1)

    def test_stable_model_against_independent_sorting(self):
        rng = random.Random(0x26d4280)
        boundary = [0, 1, 0x7fffffff, 0x80000000, 0xfffffffe, 0xffffffff]
        def native_key(k):
            return (struct.unpack('<i', struct.pack('<I', k[0]))[0], k[1], k[2])
        for n in range(1, 21):
            for _ in range(12):
                keys = [tuple(rng.choice(boundary) for _ in range(3)) for _ in range(n)]
                # Deliberate duplicate keys expose accidental equality reordering.
                if n > 2:
                    keys[-1] = keys[0]
                expected = sorted(range(n), key=lambda i: native_key(keys[i]))
                self.assertEqual(subject.insertion_order(keys, 1), expected)
                k = rng.randint(1, n)
                keys[:k] = sorted(keys[:k], key=native_key)
                expected = sorted(range(n), key=lambda i: native_key(keys[i]))
                self.assertEqual(subject.insertion_order(keys, k), expected)

    def test_wrong_identity_rejected_before_analysis_or_output(self):
        with patch.object(subject, '_analyze', side_effect=AssertionError('must not analyze')):
            for data in (b'wrong artifact', b''):
                with self.assertRaisesRegex(ValueError, 'size/SHA-256'):
                    subject.analyze(data)
            with mmap.mmap(self.handle.fileno(), 0, access=mmap.ACCESS_COPY) as changed:
                changed[subject.START - 0x1000] ^= 1
                with self.assertRaisesRegex(ValueError, 'size/SHA-256'):
                    subject.analyze(changed)
        with tempfile.TemporaryDirectory() as tmp:
            wrong = Path(tmp) / 'wrong'
            wrong.write_bytes(b'wrong artifact')
            output = Path(tmp) / 'must-not-exist'
            with self.assertRaisesRegex(ValueError, 'size/SHA-256'):
                subject.generate(wrong, output)
            self.assertFalse(output.exists())

    def test_actual_body_mutations_below_digest(self):
        # Width/stride, load displacement, full-row copy and return corruption.
        for va in (0x26d429b, 0x26d42ba, 0x26d42cb, 0x26d430f, 0x26d4373):
            p = va - 0x1000
            with self.subTest(va=hex(va)):
                self.mutation(p, bytes([self.data[p] ^ 1]))

    def test_signedness_counterfacts_change_decoded_rule(self):
        original = bytes.fromhex(self.record['function']['bytes'])
        for va in (0x26d42d8, 0x26d4351):
            changed = bytearray(original)
            self.assertEqual(changed[va - subject.START], 0x9c)
            changed[va - subject.START] = 0x92  # SETL -> SETB, actual opcode.
            conditions = subject.comparison_conditions(subject.decode(changed, subject.START))
            self.assertNotEqual(conditions, self.record['rule']['comparison_conditions'])
            self.mutation(va - 0x1000, b'\x92', 'Changed comparison conditions')
        # The concrete counterexample flips the first-word ordering.
        self.assertLess(subject.key_value([0x80000000, 0, 0]), subject.key_value([0, 0, 0]))
        self.assertGreater(0x80000000, 0)

    def test_third_word_strict_branch_counterfact(self):
        changed = bytearray.fromhex(self.record['function']['bytes'])
        changed[0x26d4367 - subject.START] = 0x76  # Unsupported JBE must fail closed.
        with self.assertRaisesRegex(ValueError, 'Unsupported condition'):
            subject.decode(changed, subject.START)
        changed[0x26d4367 - subject.START] = 0x73  # JB -> JAE is supported but wrong.
        self.assertNotEqual(subject.comparison_conditions(subject.decode(changed, subject.START)),
                            self.record['rule']['comparison_conditions'])
        self.mutation(0x26d4367 - 0x1000, b'\x73', 'Changed comparison conditions')

    def test_shifted_fde_and_corrupt_cie_rejected(self):
        p = subject.FDE['fde'] + 8
        raw = struct.unpack_from('<i', self.data, p)[0]
        self.mutation(p, struct.pack('<i', raw + 1), 'Selected FDE extent')
        self.mutation(subject.FDE['cie'] + 13, b'\x79', 'FDE/CIE bytes')
        p = self.record['function']['unwind_index']['file_offset'] + 4
        raw = struct.unpack_from('<i', self.data, p)[0]
        self.mutation(p, struct.pack('<i', raw + 4), 'Unwind header disagrees')

    def test_wrong_incoming_call_target_rejected(self):
        p = subject.CALL_SITE - 0x1000 + 1
        delta = struct.unpack_from('<i', self.data, p)[0]
        self.mutation(p, struct.pack('<i', delta + 16), 'Caller target changed')

    def test_unexpected_callee_and_misaligned_branch_rejected(self):
        # A CALL replacing the same-sized final JMP adds a callee below the hash gate.
        self.mutation(0x26d436c - 0x1000, b'\xe8', 'Unexpected callee')
        # Branch into the second byte of MOV R9,RAX rather than its start.
        p = 0x26d42f5 - 0x1000
        self.mutation(p, bytes([self.data[p] + 1]), 'instruction boundaries')

    def test_padding_and_source_association_controls(self):
        self.mutation(subject.END - 0x1000, b'\x90', 'padding')
        source = self.record['caller_context']['source_association']
        self.mutation(source['location_file_offset'] + 16, b'\x27', 'Location metadata')
        self.mutation(source['path_file_offset'], b'N', 'First-party path')
        self.mutation(subject.LOCATION_RELOC + 16, struct.pack('<q', subject.PATH_VA + 1), 'Location relocation')
        p = subject.LOCATION_LEA - 0x1000 + 3
        raw = struct.unpack_from('<i', self.data, p)[0]
        self.mutation(p, struct.pack('<i', raw + 8), 'Location LEA')

    def test_changed_executable_section_rejected(self):
        shoff = struct.unpack_from('<Q', self.data, 40)[0]
        size, count = struct.unpack_from('<HH', self.data, 58)
        for i in range(count):
            p = shoff + i * size
            if struct.unpack_from('<Q', self.data, p + 16)[0] == 0x1419300:
                self.mutation(p + 8, struct.pack('<Q', 2), '.text geometry or flags')
                break
        else:
            self.fail('No .text section header')

    def test_decoder_unknown_and_truncated_forms(self):
        for row in self.record['function']['instructions']:
            raw = bytes.fromhex(row['bytes'])
            if len(raw) > 1:
                with self.subTest(va=hex(row['va'])):
                    with self.assertRaises(ValueError):
                        subject.decode(raw[:-1], row['va'])
        for raw in (b'\xff\xd0', b'\xcc', b'\x66\x90', b'\x48', b'\x0f', b'\x8d\xc0'):
            with self.assertRaises(ValueError):
                subject.decode(raw, subject.START)

    def test_scan_full_bounds_and_both_opcodes(self):
        target, base = 0x11223344, 0x1000
        raw = bytearray(b'\xcc' * 17)
        for pos, opcode in ((0, 0xe8), (12, 0xe9)):
            raw[pos] = opcode
            struct.pack_into('<i', raw, pos + 1, target - (base + pos + 5))
        self.assertEqual([r['site'] for r in subject.scan_rel32(raw, 0, base, len(raw), target)],
                         [base, base + 12])
        self.assertEqual([r['kind'] for r in subject.scan_rel32(raw, 0, base, len(raw), target)],
                         ['call', 'jmp'])
        self.assertEqual(subject.scan_rel32(raw, 0, base, len(raw) - 1, target)[-1]['site'], base)
        # A matching encoding starts inside another E8's immediate: scan must not skip it.
        raw = bytearray(b'\xe8\xe8\0\0\0\0')
        struct.pack_into('<i', raw, 2, target - (base + 1 + 5))
        self.assertEqual([r['site'] for r in subject.scan_rel32(raw, 0, base, len(raw), target)], [base + 1])

    def test_full_text_census_and_caller_source(self):
        refs = self.record['direct_references']
        self.assertEqual(refs['scan']['start'], 0x1419300)
        self.assertEqual(refs['scan']['end'], 0x63f0a00)
        self.assertEqual([(r['site'], r['kind']) for r in refs['matches']], [(subject.CALL_SITE, 'call')])
        context = self.record['caller_context']
        self.assertEqual(context['fde'], subject.CALLER)
        self.assertEqual(context['source_association']['path'], 'node/src/consensus/state.rs')
        self.assertEqual(context['source_association']['line'], 550)
        self.assertEqual(context['instructions'][0]['operands'], ['rsi', '21'])
        self.assertEqual(context['instructions'][3]['operands'], ['edx', '1'])

    def test_manifest_whitelist_attacks(self):
        original = (subject.PACKET / 'MANIFEST.sha256').read_text()
        with tempfile.TemporaryDirectory() as tmp:
            packet = Path(tmp) / 'packet'
            shutil.copytree(subject.PACKET, packet)
            manifest = packet / 'MANIFEST.sha256'
            variants = [original + original.splitlines(keepends=True)[0],
                        '\n'.join(original.splitlines()[:-1]) + '\n',
                        original.replace('  records.json', '  ../records.json'),
                        original.replace('  records.json', '  /records.json'),
                        original.replace('  records.json', '  unexpected.json'),
                        original.replace(original[:64], '0' * 64, 1)]
            for changed in variants:
                manifest.write_text(changed)
                with self.assertRaises(ValueError):
                    self.verify(packet)
            manifest.write_text(original)
            (packet / 'extra').write_text('not whitelisted')
            with self.assertRaisesRegex(ValueError, 'file whitelist'):
                self.verify(packet)
            (packet / 'extra').unlink()
            (packet / 'records.json').unlink()
            (packet / 'records.json').symlink_to(subject.PACKET / 'records.json')
            with self.assertRaisesRegex(ValueError, 'symlinked'):
                self.verify(packet)

    def test_rehashed_semantic_and_readme_drift_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            packet = Path(tmp) / 'packet'
            shutil.copytree(subject.PACKET, packet)
            record = copy.deepcopy(self.record)
            record['rule']['key_order'][0] = 'unsigned'
            (packet / 'records.json').write_bytes(subject.json_bytes(record))
            (packet / 'MANIFEST.sha256').write_bytes(subject.manifest_bytes(packet))
            with self.assertRaisesRegex(ValueError, 'Regenerated semantic records'):
                self.verify(packet)
            (packet / 'records.json').write_bytes(subject.json_bytes(self.record))
            with (packet / 'README.md').open('a') as handle:
                handle.write('\nUnproved extra claim.\n')
            (packet / 'MANIFEST.sha256').write_bytes(subject.manifest_bytes(packet))
            with self.assertRaisesRegex(ValueError, 'Regenerated README'):
                self.verify(packet)


if __name__ == '__main__':
    unittest.main()
