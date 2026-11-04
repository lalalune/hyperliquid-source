"""Target-byte controls for the complete node #115 subtraction leaf."""
from contextlib import contextmanager
import importlib.util
import json
import mmap
from pathlib import Path
import random
import re
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import node115_sub256_borrow as subject


class Sub256BorrowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.stream = subject.TARGET.open('rb')
        # One private mapping; only changed pages consume copy-on-write memory.
        cls.data = mmap.mmap(cls.stream.fileno(), 0, access=mmap.ACCESS_COPY)
        cls.record = subject.build_records(cls.data)
        cls.secs = subject.sections(cls.data)
        spec = importlib.util.spec_from_file_location('sub256_packet_verify', subject.PACKET / 'verify.py')
        cls.verifier = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.verifier)

    @classmethod
    def tearDownClass(cls):
        cls.data.close()
        cls.stream.close()

    @contextmanager
    def mutated(self, offset, replacement):
        original = self.data[offset:offset + len(replacement)]
        self.assertNotEqual(original, replacement)
        self.data[offset:offset + len(replacement)] = replacement
        try:
            yield self.data
        finally:
            self.data[offset:offset + len(original)] = original

    def at_va(self, va, size=1):
        return subject.file_offset(self.secs, va, size)

    def test_regeneration_is_byte_identical_without_native_tools(self):
        with tempfile.TemporaryDirectory() as folder:
            out = Path(folder) / 'evidence'
            with patch('subprocess.run', side_effect=AssertionError('native command forbidden')):
                record = subject.generate(subject.TARGET, out)
            self.assertEqual(record, self.record)
            for name in ('records.json', 'README.md'):
                self.assertEqual((out / name).read_bytes(), (subject.PACKET / name).read_bytes())

    def test_complete_body_extent_and_empty_callee_closure(self):
        row = self.record['window']
        self.assertEqual((row['start'], row['end'], row['size']), (0x2ccdd80, 0x2ccddb1, 49))
        self.assertEqual(row['frame']['fde_record']['file_offset'], 0xd8b2b8)
        self.assertEqual(row['frame']['cie_record']['file_offset'], 0xca6ed8)
        self.assertIsNone(row['frame']['lsda'])
        decoded = row['instructions']
        self.assertEqual(len(decoded), 14)
        self.assertEqual(bytes.fromhex(''.join(r['hex'] for r in decoded)), bytes.fromhex(row['body_hex']))
        self.assertEqual(decoded[-1]['mnemonic'], 'ret')
        self.assertFalse(any(r['mnemonic'] in ('call', 'jmp') for r in decoded))
        self.assertEqual(self.record['callees'], [])
        self.assertEqual(row['padding']['hex'], 'cc' * 15)

    def test_readme_counts_equal_json_and_all_prose_regenerates(self):
        text = (subject.PACKET / 'README.md').read_text()
        counts = {key: int(value) for key, value in re.findall(r'^\| ([a-z_]+) \| (\d+) \|$', text, re.M)}
        self.assertEqual(counts, self.record['metrics'])
        self.assertEqual(text, subject.render_readme(self.record))
        self.assertEqual(counts['vectors'], len(self.record['vectors']))
        self.assertEqual(counts['body_bytes'], len(bytes.fromhex(self.record['window']['body_hex'])))
        self.assertEqual(counts['direct_call_sites'], len(self.record['caller_census']['hits']))
        self.assertEqual(counts['caller_fdes'], len({r['owner_start'] for r in self.record['caller_census']['hits']}))

    def test_all_recorded_vectors_match_independent_scalar_arithmetic(self):
        rows = self.record['window']['instructions']
        for vector in self.record['vectors']:
            left, right, result = (int(vector[key], 16) for key in ('left_hex', 'right_hex', 'result_hex'))
            with self.subTest(left=vector['left_hex'], right=vector['right_hex']):
                self.assertEqual((result, vector['borrow']), subject.model(left, right))
                self.assertEqual((result, vector['borrow']), subject.instruction_equations(rows, left, right))

    def test_borrow_chain_maximal_limb_and_signed_unsigned_boundaries(self):
        word, modulus = 1 << 64, 1 << 256
        cases = [
            (0, 0, 0, 0), (0, 1, modulus - 1, 1), (modulus - 1, 1, modulus - 2, 0),
            # The middle limb is MAX with incoming borrow, so b_i+c_i == W.
            (word**3, word**2 - 1, word**3 - word**2 + 1, 0),
            (0, word**2 - 1, modulus - word**2 + 1, 1),
            (word**3, 1, word**3 - 1, 0),
            (1 << 255, (1 << 255) - 1, 1, 0),
            ((1 << 255) - 1, 1 << 255, modulus - 1, 1),
        ]
        for left, right, result, borrow in cases:
            self.assertEqual(subject.instruction_equations(self.record['window']['instructions'], left, right),
                             (result, borrow))
            self.assertEqual(subject.model(left, right), (result, borrow))
        rng = random.Random(0x2ccdd80)
        for _ in range(1000):
            left, right = rng.getrandbits(256), rng.getrandbits(256)
            self.assertEqual(subject.instruction_equations(self.record['window']['instructions'], left, right),
                             subject.model(left, right))
        for bad in (-1, modulus, 0.5, True):
            with self.assertRaisesRegex(ValueError, 'unsigned domain'):
                subject.model(bad, 0)

    def test_real_sbb_and_setb_counterfacts_change_equations(self):
        raw = bytearray.fromhex(self.record['window']['body_hex'])
        # At +11, change the second limb's SBB opcode to SUB.
        self.assertEqual(raw[11], 0x19)
        raw[11] = 0x29
        decoded = subject.decode_leaf(raw)
        self.assertEqual(subject.instruction_equations(decoded, 1 << 64, 1), ((1 << 65) - 1, 0))
        self.assertEqual(subject.model(1 << 64, 1), ((1 << 64) - 1, 0))
        with self.assertRaisesRegex(ValueError, 'semantic certificate'):
            subject.certify_leaf(decoded)
        raw[11] = 0x19
        self.assertEqual(raw[45], 0x92)
        raw[45] = 0x93
        decoded = subject.decode_leaf(raw)
        self.assertEqual(subject.instruction_equations(decoded, 0, 1), ((1 << 256) - 1, 0))
        with self.assertRaisesRegex(ValueError, 'semantic certificate'):
            subject.certify_leaf(decoded)

    def test_every_window_byte_flip_rejects_below_digest_gate(self):
        body = bytes.fromhex(self.record['window']['body_hex'])
        for offset in range(len(body)):
            mutant = bytearray(body)
            mutant[offset] ^= 1
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                subject.certify_leaf(subject.decode_leaf(mutant))
        for length in range(len(body)):
            with self.subTest(truncated=length), self.assertRaises(ValueError):
                subject.certify_leaf(subject.decode_leaf(body[:length]))
        with self.assertRaises(ValueError):
            subject.certify_leaf(subject.decode_leaf(body + b'\xc3'))

    def test_wrong_digest_truncation_and_changed_window_fail_before_output(self):
        with tempfile.TemporaryDirectory() as folder:
            path, out = Path(folder) / 'wrong-node', Path(folder) / 'must-not-exist'
            for wrong in (b'', b'wrong-release', self.data[:4096]):
                path.write_bytes(wrong)
                with self.assertRaisesRegex(ValueError, 'digest mismatch'):
                    subject.generate(path, out)
                self.assertFalse(out.exists())
        off = self.at_va(subject.START)
        with self.mutated(off, b'\x49') as changed:
            with self.assertRaisesRegex(ValueError, 'digest mismatch'):
                subject.build_records(changed)

    def test_shifted_fde_start_range_and_cie_bytes_reject_below_digest_gate(self):
        fde = self.record['window']['frame']['fde_record']['file_offset']
        for offset in (fde + 8, fde + 12):
            original = struct.unpack_from('<i', self.data, offset)[0]
            with self.subTest(offset=offset), self.mutated(offset, struct.pack('<i', original + 1)):
                with self.assertRaisesRegex(ValueError, 'FDE extent'):
                    subject.check_frames(self.data, self.secs)
        # CIE's final DW_CFA_nop: decoded fields remain valid, raw CIE must reject.
        cie = self.record['window']['frame']['cie_record']
        offset = cie['file_offset'] + len(bytes.fromhex(cie['hex'])) - 1
        with self.mutated(offset, b'\x01'):
            with self.assertRaisesRegex(ValueError, 'frame record bytes'):
                subject.check_frames(self.data, self.secs)

    def test_wrong_unwind_header_link_rejects(self):
        hdr = next(s for s in self.secs if s['name'] == '.eh_frame_hdr')
        index = self.record['window']['frame']['unwind_index']['index']
        off = hdr['offset'] + 12 + index * 8 + 4
        old = struct.unpack_from('<i', self.data, off)[0]
        with self.mutated(off, struct.pack('<i', old + 4)):
            with self.assertRaisesRegex(ValueError, 'FDE/index disagreement'):
                subject.check_frames(self.data, self.secs)

    def test_complete_text_scan_and_focused_caller_contexts(self):
        census = self.record['caller_census']
        hits = subject.scan_rel32(self.data, census['section'], subject.START)
        self.assertEqual([h['site'] for h in hits], [0x2c70e23, 0x2c70e87, 0x2c70eca])
        self.assertTrue(all(h['mnemonic'] == 'call' for h in hits))
        self.assertEqual(census['section']['size'], 0x63f0a00 - 0x1419300)
        for index, hit in enumerate(census['hits']):
            context = hit['context']
            decoded = subject.decode_context(bytes.fromhex(context['hex']), context['start'])
            self.assertEqual(decoded, context['instructions'])
            self.assertEqual(subject.certify_context(decoded, index), context['argument_relation'])
            ranges = [(context['argument_relation'][key], width) for key, width in
                      [('output_stack_offset', 33), ('left_stack_offset', 32), ('right_stack_offset', 32)]]
            for i, (start, width) in enumerate(ranges):
                for other, other_width in ranges[i + 1:]:
                    self.assertTrue(start + width <= other or other + other_width <= start)

    def test_wrong_callee_target_argument_and_borrow_edge_reject(self):
        for index, hit in enumerate(self.record['caller_census']['hits']):
            context = hit['context']
            for label, offset in [('callee', hit['site'] - context['start'] + 1),
                                  ('argument', 4), ('borrow test', 29), ('borrow edge', 33)]:
                mutant = bytearray.fromhex(context['hex'])
                mutant[offset] ^= 1
                with self.subTest(index=index, label=label), self.assertRaises(ValueError):
                    subject.certify_context(subject.decode_context(mutant, context['start']), index)
            raw = bytes.fromhex(context['hex'])
            for n in range(1, len(raw)):
                with self.subTest(index=index, truncated=n), self.assertRaises(ValueError):
                    subject.certify_context(subject.decode_context(raw[:n], context['start']), index)

    def test_scan_includes_final_complete_instruction_and_labels_raw_hits(self):
        # Deliberately unaligned E8/E9 bytes demonstrate raw-scan limits.
        target, start = 0x3000000, 0x2800000
        blob = bytearray(b'\x90' * 31)
        for off, opcode in ((1, 0xe8), (26, 0xe9)):
            blob[off:off + 5] = bytes([opcode]) + struct.pack('<i', target - (start + off + 5))
        section = {'offset': 0, 'address': start, 'size': len(blob)}
        hits = subject.scan_rel32(blob, section, target)
        self.assertEqual([h['site'] for h in hits], [start + 1, start + 26])
        self.assertEqual([h['mnemonic'] for h in hits], ['call', 'jmp'])
        section['size'] -= 1
        self.assertEqual(len(subject.scan_rel32(blob, section, target)), 1)

    def test_source_location_relocation_path_and_lea_corruptions(self):
        source = self.record['source_context']
        self.assertEqual(subject.source_context(self.data, self.secs), source)
        self.assertEqual((source['path'], source['line'], source['column']), ('l1/src/qtys/impl_wei.rs', 6, 1))
        offsets = [self.at_va(subject.SOURCE_SITE) + 3,
                   self.at_va(subject.LOCATION) + 8,
                   self.at_va(subject.LOCATION) + 16,
                   source['relocation']['file_offset'] + 8,
                   source['relocation']['file_offset'] + 16,
                   self.at_va(source['path_va'])]
        for off in offsets:
            with self.subTest(offset=off), self.mutated(off, bytes([self.data[off] ^ 1])):
                with self.assertRaises(ValueError):
                    subject.source_context(self.data, self.secs)

    def test_manifest_whitelist_and_regenerated_packet(self):
        self.assertEqual(self.verifier.verify(), len(self.verifier.WHITELIST))

    def test_manifest_missing_duplicate_unlisted_and_corrupt_files_reject(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for relative in self.verifier.WHITELIST:
                dest = root / relative
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes((ROOT / relative).read_bytes())
            manifest = root / self.verifier.PACKET_REL / 'MANIFEST.sha256'
            original = (subject.PACKET / 'MANIFEST.sha256').read_text()
            manifest.write_text(original)
            self.assertEqual(self.verifier.verify_manifest(root), len(self.verifier.WHITELIST))
            lines = original.splitlines()
            variants = ['\n'.join(lines[:-1]) + '\n', original + lines[0] + '\n',
                        original + '0' * 64 + '  ../../escape\n',
                        original + '0' * 64 + '  unexpected.txt\n',
                        original.replace(lines[0][:64], '0' * 64, 1), 'not a manifest\n']
            for variant in variants:
                manifest.write_text(variant)
                with self.assertRaises(ValueError):
                    self.verifier.verify_manifest(root)
            manifest.write_text(original)
            readme = root / self.verifier.PACKET_REL / 'README.md'
            readme.write_text(readme.read_text() + 'tamper\n')
            with self.assertRaisesRegex(ValueError, 'digest mismatch'):
                self.verifier.verify_manifest(root)
            readme.unlink()
            with self.assertRaisesRegex(ValueError, 'missing or unsafe'):
                self.verifier.verify_manifest(root)


if __name__ == '__main__':
    unittest.main()
