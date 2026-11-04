"""Target-grounded static checks, independent scalar fixtures and controls (MIT)."""
import copy
import hashlib
import mmap
from pathlib import Path
import random
import shutil
import struct
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import node115_tuple_threshold as subject
from elf_index import sections
from fde_extents import eh_frame_records


class TupleThresholdTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.file = subject.TARGET.open('rb')
        # Read-only until a control dirties a private page; no full image copies.
        cls.data = mmap.mmap(cls.file.fileno(), 0, access=mmap.ACCESS_COPY)
        cls.record = subject.collect(cls.data)
        cls.secs = sections(cls.data)
        cls.cies, cls.fdes = eh_frame_records(cls.data, cls.secs)
        cls.body = bytes.fromhex(cls.record['window']['body_hex'])
        cls.rule = cls.record['rule']
        cls.verifier = types.ModuleType('tuple_threshold_verifier')
        source = subject.PACKET / 'verify.py'
        cls.verifier.__file__ = str(source)
        exec(compile(source.read_bytes(), str(source), 'exec'), cls.verifier.__dict__)

    @classmethod
    def tearDownClass(cls):
        cls.data.close()
        cls.file.close()

    def mutate(self, offset, replacement, operation):
        before = self.data[offset:offset + len(replacement)]
        self.data[offset:offset + len(replacement)] = replacement
        try:
            return operation()
        finally:
            self.data[offset:offset + len(replacement)] = before

    def test_regeneration_all_packet_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp) / 'packet'
            # A native disassembler is not available to the generation path.
            with patch('subprocess.run', side_effect=AssertionError('native subprocess forbidden')):
                subject.generate(subject.TARGET, out)
            self.assertEqual({p.name: p.read_bytes() for p in out.iterdir()},
                             {p.name: p.read_bytes() for p in subject.PACKET.iterdir()})
            self.verifier.verify_manifest(out, ROOT)

    def test_full_instruction_partition_and_callee_closure(self):
        rows, graph, rule = subject.certify_body(self.body)
        self.assertEqual(b''.join(bytes.fromhex(r['hex']) for r in rows), self.body)
        self.assertEqual([r['address'] for r in rows], [r['address'] for r in graph])
        self.assertEqual([r['address'] for r in rows if r['mnemonic'] == 'ret'], [subject.END - 1])
        self.assertFalse(any(r['mnemonic'] == 'call' for r in rows))
        self.assertEqual(self.record['callees'], [])
        self.assertEqual(rule, self.rule)
        self.assertEqual(self.record['window']['fde'], subject.EXPECTED_FDE)

    def test_frozen_instruction_grounded_vectors(self):
        for vector in self.record['vectors']:
            args = [vector[k] for k in ('left', 'right', 'current', 'reference', 'base')]
            with self.subTest(case=vector['name']):
                self.assertEqual(subject.model(*args), vector['al'])
                self.assertEqual(subject.model(*args, rule=self.rule), vector['al'])
        self.assertEqual({v['al'] for v in self.record['vectors']}, {0, 1, 2})

    def test_saturation_sub_borrow_and_add_carry_boundaries(self):
        delta, maximum = self.rule['add_immediate'], subject.U64
        boundary = (1 << self.rule['word_bits']) - delta
        values = {0, 1, maximum, boundary - 2, boundary - 1, boundary, boundary + 1,
                  (1 << 63) - 1, 1 << 63}
        rng = random.Random(0x2c6f290)
        values.update(rng.getrandbits(64) for _ in range(2048))
        for base in values:
            self.assertEqual(subject.saturation_operands(base, self.rule), min(maximum, base + delta))
        self.assertEqual(subject.saturation_operands(boundary - 1, self.rule), maximum)
        self.assertEqual(subject.saturation_operands(boundary, self.rule), maximum)

    def test_mixed_signedness_and_priority_over_tail_fields(self):
        # Independent ordered signed values, converted to raw input bit patterns.
        signed = [-2147483648, -1, 0, 1, 2147483647]
        for a in signed:
            for b in signed:
                expected = 2 if a >= b else 0
                self.assertEqual(subject.model([a & 0xffffffff, 0, 0],
                                               [b & 0xffffffff, 0, 0], 0, 0, subject.U64), expected)
        for a, b in ((0x80000000, 0x7fffffff), (0xffffffff, 0), (1, 0)):
            self.assertEqual(subject.model([0, a, 0], [0, b, 0xffffffff], 0, 0, 0), 2)
            self.assertEqual(subject.model([0, 0, a], [0, 0, b], 0, 0, 0), 2)

    def test_wrong_digest_and_truncation_before_output(self):
        with tempfile.TemporaryDirectory() as temp:
            bad, out = Path(temp) / 'bad', Path(temp) / 'output'
            for payload in (b'', b'wrong capture', self.body):
                bad.write_bytes(payload)
                with self.assertRaisesRegex(ValueError, 'digest mismatch'):
                    subject.generate(bad, out)
                self.assertFalse(out.exists())
        offset = self.record['window']['file_offset']
        with self.assertRaisesRegex(ValueError, 'digest mismatch'):
            self.mutate(offset, bytes([self.data[offset] ^ 1]), lambda: subject.collect(self.data))
        with self.assertRaisesRegex(ValueError, 'digest mismatch'):
            self.mutate(0, b'X', lambda: subject.collect(self.data))

    def test_every_body_byte_corruption_rejected_below_digest(self):
        for offset in range(len(self.body)):
            mutant = bytearray(self.body)
            mutant[offset] ^= 1
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                subject.certify_body(mutant)

    def test_unknown_and_truncated_encodings_fail_closed(self):
        with self.assertRaisesRegex(ValueError, 'Unsupported opcode'):
            subject.decode(b'\x90', subject.START)
        for row in self.record['instructions']:
            raw = bytes.fromhex(row['hex'])
            for size in range(1, len(raw)):
                with self.subTest(address=row['address'], size=size), self.assertRaises(ValueError):
                    subject.decode(raw[:size], row['address'])
        with self.assertRaisesRegex(ValueError, 'Unsupported MOV ModRM'):
            subject.decode(b'\x8b\x46\x60', subject.START)

    def test_semantic_signedness_and_threshold_mutants_change_result(self):
        for offset, replacement, vector_name, changed_result in (
                (14, 0x92, 'signed-negative-first', 2),
                (97, 0x92, 'threshold-equal', 0)):
            mutant = bytearray(self.body)
            mutant[offset] = replacement
            rule = subject.rule_from_instructions(subject.decode(mutant, subject.START))
            vector = next(v for v in self.record['vectors'] if v['name'] == vector_name)
            args = [vector[k] for k in ('left', 'right', 'current', 'reference', 'base')]
            self.assertNotEqual(rule, self.rule)
            self.assertNotEqual(vector['al'], changed_result)
            self.assertEqual(subject.model(*args, rule=rule), changed_result)
            with self.assertRaisesRegex(ValueError, 'Decoded body contract'):
                subject.certify_body(mutant)

    def test_paired_delta_mutant_changes_threshold(self):
        mutant = bytearray(self.body)
        struct.pack_into('<i', mutant, 70, -5001)
        struct.pack_into('<i', mutant, 78, 5001)
        rule = subject.rule_from_instructions(subject.decode(mutant, subject.START))
        args = ([0xffffffff, 0, 0], [0, 0, 0], 5000, 0, 0)
        self.assertEqual(subject.model(*args), 1)
        self.assertEqual(subject.model(*args, rule=rule), 0)
        with self.assertRaisesRegex(ValueError, 'Decoded body contract'):
            subject.certify_body(mutant)

    def test_shifted_fde_start_and_extent_fail_below_digest(self):
        base = self.record['window']['fde_record']['file_offset']
        for field in (8, 12):
            offset = base + field
            old = struct.unpack_from('<i', self.data, offset)[0]
            def check():
                cies, fdes = eh_frame_records(self.data, self.secs)
                subject.check_window(self.data, self.secs, cies, fdes)
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'FDE identity/extent'):
                self.mutate(offset, struct.pack('<i', old + 1), check)
        with self.assertRaisesRegex(ValueError, 'FDE identity/extent'):
            subject.check_window(self.data, self.secs, self.cies,
                                 self.fdes + [dict(subject.EXPECTED_FDE)])

    def test_cie_and_padding_corruption_fail_below_digest(self):
        cies = copy.deepcopy(self.cies)
        cies[subject.EXPECTED_FDE['cie']]['data_align'] = -4
        with self.assertRaisesRegex(ValueError, 'CIE interpretation'):
            subject.check_window(self.data, self.secs, cies, self.fdes)
        offset = subject.file_offset(self.secs, subject.END, 1)
        with self.assertRaisesRegex(ValueError, 'Padding changed'):
            self.mutate(offset, b'\x90', lambda: subject.check_window(
                self.data, self.secs, self.cies, self.fdes))

    def test_full_text_scan_and_wrong_call_target(self):
        hits = subject.direct_scan(self.data, self.secs, {subject.START})
        self.assertEqual(tuple(h['address'] for h in hits), subject.CALL_SITES)
        self.assertTrue(all(h['mnemonic'] == 'call' for h in hits))
        for site, (start, end) in zip(subject.CALL_SITES, subject.CONTEXTS):
            offset = subject.file_offset(self.secs, site + 1, 4)
            raw = struct.unpack_from('<i', self.data, offset)[0]
            with self.subTest(site=site), self.assertRaisesRegex(ValueError, 'Caller target mismatch'):
                self.mutate(offset, struct.pack('<i', raw + 1), lambda: subject.check_context(
                    self.data, self.secs, start, end, site))

    def test_scan_includes_both_text_endpoints(self):
        # Real .text coordinates with tiny synthetic file geometry, no target claim.
        secs = [{'name': '.text', 'address': subject.TEXT_START, 'offset': 0,
                 'size': subject.TEXT_END - subject.TEXT_START, 'flags': 6}]
        # Sparse file avoids allocating a second image in Python memory.
        with tempfile.TemporaryFile() as f:
            f.truncate(secs[0]['size'])
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_WRITE) as data:
                for offset, opcode in ((0, 0xe8), (len(data) - 5, 0xe9)):
                    va = subject.TEXT_START + offset
                    data[offset:offset + 5] = bytes([opcode]) + struct.pack('<i', subject.START - va - 5)
                hits = subject.direct_scan(data, secs, {subject.START})
                self.assertEqual([h['address'] for h in hits], [subject.TEXT_START, subject.TEXT_END - 5])
                self.assertEqual([h['mnemonic'] for h in hits], ['call', 'jmp'])

    def test_source_location_and_relocation_corruptions(self):
        source = self.record['source_association']
        offsets = [source['relocation']['record_file_offset'] + 8,
                   source['relocation']['record_file_offset'] + 16,
                   source['location_file_offset'] + 8,
                   source['location_file_offset'] + 16,
                   subject.file_offset(self.secs, source['relocation']['addend'], 1),
                   subject.file_offset(self.secs, subject.SOURCE_LEA + 3, 1)]
        for offset in offsets:
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                self.mutate(offset, bytes([self.data[offset] ^ 1]), lambda: subject.source_association(
                    self.data, self.secs, self.fdes))
        p = source['relocation']['record_file_offset']
        with self.assertRaisesRegex(ValueError, 'relocation missing/duplicate'):
            self.mutate(p + 24, self.data[p:p + 24], lambda: subject.source_association(
                self.data, self.secs, self.fdes))

    def test_readme_counts_equal_json_and_semantic_arrays(self):
        r, c = self.record, self.record['counts']
        self.assertEqual((subject.PACKET / 'README.md').read_bytes(), subject.render_readme(r))
        self.assertEqual(c['functions_bound'], 1)
        self.assertEqual(c['body_bytes'], r['window']['end'] - r['window']['start'])
        self.assertEqual(c['instructions'], len(r['instructions']))
        self.assertEqual(c['callees'], len(r['callees']))
        hits = r['caller_census']['hits']
        self.assertEqual(c['direct_call_candidates'], sum(h['mnemonic'] == 'call' for h in hits))
        self.assertEqual(c['direct_jump_candidates'], sum(h['mnemonic'] == 'jmp' for h in hits))
        self.assertEqual(c['caller_fdes'], len({h['containing_fde']['fde'] for h in hits}))
        self.assertEqual(c['vectors'], len(r['vectors']))
        text = (subject.PACKET / 'README.md').read_text()
        for key, value in c.items():
            self.assertIn(f'| {key} | {value} |', text)
        bad = copy.deepcopy(r)
        bad['counts']['instructions'] += 1
        self.assertNotEqual(subject.render_readme(bad), subject.render_readme(r))

    def test_manifest_whitelist_digest_missing_and_duplicates(self):
        self.verifier.verify_manifest()
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp) / 'packet'
            shutil.copytree(subject.PACKET, out)
            manifest = out / 'MANIFEST.sha256'
            saved = manifest.read_bytes()
            for content in (saved + saved.splitlines(keepends=True)[0],
                            b'0' * 64 + b'  ../../../../outside\n',
                            b'\n'.join(saved.splitlines()[1:]) + b'\n',
                            b'0' * 64 + saved[64:]):
                manifest.write_bytes(content)
                with self.assertRaises(ValueError):
                    self.verifier.verify_manifest(out, ROOT)
            manifest.write_bytes(saved)
            (out / 'unlisted').write_text('unlisted')
            with self.assertRaisesRegex(ValueError, 'whitelist'):
                self.verifier.verify_manifest(out, ROOT)
            (out / 'unlisted').unlink()
            (out / 'records.json').unlink()
            with self.assertRaisesRegex(ValueError, 'whitelist'):
                self.verifier.verify_manifest(out, ROOT)

    def test_scalar_model_rejects_out_of_domain_values(self):
        for field, value in (('second_less_condition', 'setl'),
                             ('sub_branch', 'jae'), ('saturation_select', 'cmovb')):
            rule = dict(self.rule, **{field: value})
            with self.assertRaisesRegex(ValueError, 'Unsupported model instruction contract'):
                subject.model([0, 0, 0], [0, 0, 0], 0, 0, 0, rule=rule)
        for args in (([0, 0], [0, 0, 0], 0, 0, 0),
                     ([-1, 0, 0], [0, 0, 0], 0, 0, 0),
                     ([0, 0, 0], [0, 0, 0], 1 << 64, 0, 0),
                     ([True, 0, 0], [0, 0, 0], 0, 0, 0)):
            with self.assertRaises(ValueError):
                subject.model(*args)


if __name__ == '__main__':
    unittest.main()
