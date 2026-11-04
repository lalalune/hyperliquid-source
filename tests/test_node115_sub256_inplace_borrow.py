"""Static target-grounded controls. Never execute the captured node."""
import hashlib
import importlib.util
import json
import mmap
from pathlib import Path
import random
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import node115_sub256_inplace_borrow as s

# Loading the packet verifier must not introduce extra files into its whitelist.
spec = importlib.util.spec_from_file_location('sub256_packet_verify', s.PACKET / 'verify.py')
verifier = importlib.util.module_from_spec(spec)
old_bytecode = sys.dont_write_bytecode
sys.dont_write_bytecode = True
spec.loader.exec_module(verifier)
sys.dont_write_bytecode = old_bytecode


class Sub256BorrowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.handle = s.TARGET.open('rb')
        # One private mapping, with only mutated pages copied for controls.
        cls.data = mmap.mmap(cls.handle.fileno(), 0, access=mmap.ACCESS_COPY)
        cls.record = s.collect(cls.data)
        cls.secs = s.sections(cls.data)
        cls.body = bytes.fromhex(cls.record['function']['body_hex'])

    @classmethod
    def tearDownClass(cls):
        cls.data.close()
        cls.handle.close()

    def mutate(self, offset, replacement, operation):
        saved = self.data[offset:offset + len(replacement)]
        self.assertNotEqual(saved, replacement)
        self.data[offset:offset + len(replacement)] = replacement
        try:
            return operation(self.data)
        finally:
            self.data[offset:offset + len(replacement)] = saved

    def test_records_regenerate_byte_identically(self):
        self.assertEqual(s.encoded(self.record), (s.PACKET / 'records.json').read_bytes())
        with tempfile.TemporaryDirectory() as folder:
            s.generate(s.TARGET, Path(folder))
            self.assertEqual((Path(folder) / 'records.json').read_bytes(), s.encoded(self.record))

    def test_complete_instruction_walk_and_leaf_effects(self):
        rows, rule = s.check_leaf(self.body)
        self.assertEqual(b''.join(bytes.fromhex(r['hex']) for r in rows), self.body)
        self.assertEqual(rows[-1]['va'] + rows[-1]['size'], s.END)
        self.assertEqual([r['op'] for r in rows].count('sbb'), 3)
        self.assertEqual([r['op'] for r in rows].count('sub'), 1)
        self.assertFalse(any(r['op'] in ('call', 'jmp') for r in rows))
        self.assertEqual(rule['flag_destination'], s.mem('rdi', 32, 8))
        self.assertEqual([r['op'] for r in rows[8:12]], ['movups'] * 4)
        self.assertEqual(rows[6]['operands'], ['rax', s.mem('rdx', 24)])

    def test_actual_fde_cie_padding_and_exec_extent(self):
        f = self.record['function']
        self.assertEqual((f['start'], f['end'], f['size']), (0x43be060, 0x43be091, 49))
        self.assertEqual(f['body_sha256'], hashlib.sha256(self.body).hexdigest())
        self.assertEqual(f['frame']['fde_file_offset'], 0xea5568)
        self.assertEqual(f['frame']['cie_file_offset'], 0xca6ed8)
        self.assertIsNone(f['frame']['lsda'])
        self.assertEqual(f['padding']['hex'], 'cc' * 15)
        self.assertTrue(0x3c00000 <= f['start'] < 0x5000000)

    def test_callers_boundary_source_and_stack_buffers(self):
        c = self.record['caller_context']
        rows = s.decode(bytes.fromhex(c['body_hex']), c['start'])
        by = {r['va']: r for r in rows}
        hits = self.record['caller_scan']['hits']
        self.assertEqual([h['site'] for h in hits], [0x4353cf6, 0x4353db7])
        self.assertTrue(all(by[h['site']]['target'] == s.START for h in hits))
        self.assertEqual(c['source_location']['path'], 'l1/src/spot_meta.rs')
        self.assertEqual((c['source_location']['line'], c['source_location']['column']), (119, 33))
        for left, right in [(0xe0, 0xb0), (0xb0, 0x160)]:
            areas = [set(range(0x30, 0x51)), set(range(left, left + 32)), set(range(right, right + 32))]
            self.assertTrue(all(not a & b for i, a in enumerate(areas) for b in areas[i + 1:]))

    def test_scan_checks_all_positions_e8_e9_signed_and_edges(self):
        data = bytearray(40)
        text = {'offset': 2, 'address': 100, 'size': 34}
        for p, op in [(2, 0xe8), (9, 0xe9), (31, 0xe8)]:
            data[p] = op
            struct.pack_into('<i', data, p + 1, 50 - (100 + p - 2 + 5))
        # An incomplete trailing e8 is not a decodable rel32.
        data[35] = 0xe8
        hits = s.scan_rel32(data, text, 50)
        self.assertEqual([h['site'] for h in hits], [100, 107])
        data[35] = 0xff  # Restores -86's high byte for the last complete call.
        self.assertEqual([h['site'] for h in s.scan_rel32(data, text, 50)], [100, 107, 129])

    def test_integer_model_known_carries_and_unsigned_extremes(self):
        fixtures = [(0, 0, 0, 0), (0, 1, s.U256 - 1, 1),
                    (1 << 192, 1, (1 << 192) - 1, 0),
                    ((1 << 192) - 1, 1 << 192, s.U256 - 1, 1),
                    (s.U256 - 1, s.U256 - 1, 0, 0)]
        for a, b, result, borrow in fixtures:
            self.assertEqual(s.model(a, b), {'difference': result, 'borrow': borrow, 'rax': b >> 192})
        for v in self.record['vectors']:
            self.assertEqual(s.model(int(v['left'], 16), int(v['right'], 16)),
                             {'difference': int(v['difference'], 16), 'borrow': v['borrow'],
                              'rax': int(v['rax'], 16)})

    def test_extracted_limb_relation_against_unbounded_arithmetic(self):
        rng = random.Random(0x43be060)
        pairs = [(rng.getrandbits(256), rng.getrandbits(256)) for _ in range(1000)]
        pairs += [(1 << n, 1) for n in range(256)]
        for a, b in pairs:
            self.assertEqual(s.limb_relation(self.record['rule'], a, b), s.model(a, b))

    def test_model_rejects_out_of_domain_values(self):
        for a, b in [(-1, 0), (0, -1), (s.U256, 0), (0, s.U256), (True, 0), (0, 1.5)]:
            with self.assertRaisesRegex(ValueError, 'unsigned 256'):
                s.model(a, b)

    def test_actual_sbb_mutant_changes_borrow_chain_before_rejection(self):
        mutant = bytearray(self.body)
        mutant[0x43be06b - s.START] = 0x29  # SBB -> SUB for limb at +8.
        rule = s.derive_rule(s.decode(mutant, s.START))
        self.assertNotEqual(s.limb_relation(rule, 1 << 64, 1), s.model(1 << 64, 1))
        with self.assertRaisesRegex(ValueError, 'semantic contract'):
            s.check_leaf(mutant)

    def test_actual_setae_mutant_inverts_flag_before_rejection(self):
        mutant = bytearray(self.body)
        mutant[0x43be08d - s.START] = 0x93
        rule = s.derive_rule(s.decode(mutant, s.START))
        self.assertEqual(s.limb_relation(rule, 0, 0)['borrow'], 1)
        with self.assertRaisesRegex(ValueError, 'semantic contract'):
            s.check_leaf(mutant)

    def test_actual_limb_offset_mutant_changes_relation_before_rejection(self):
        mutant = bytearray(self.body)
        mutant[0x43be069 - s.START] = 16  # Load right limb +16 instead of +8.
        rule = s.derive_rule(s.decode(mutant, s.START))
        self.assertNotEqual(s.limb_relation(rule, 0, 1 << 64), s.model(0, 1 << 64))
        with self.assertRaisesRegex(ValueError, 'semantic contract'):
            s.check_leaf(mutant)

    def test_every_window_byte_rejected_below_digest(self):
        for p in range(len(self.body)):
            with self.subTest(offset=p):
                mutant = bytearray(self.body)
                mutant[p] ^= 1
                with self.assertRaises(ValueError):
                    s.check_leaf(mutant)

    def test_unknown_truncated_and_overprefixed_encodings_rejected(self):
        for body in [b'\x90', b'\x48', b'\x0f', b'\x48\x8b', b'\x66\x66\xc3',
                     b'\x48\x8d\xc0', b'\x0f\x92\xc8']:
            with self.subTest(body=body), self.assertRaises(ValueError):
                s.decode(body, s.START)
        for length in range(len(self.body)):
            with self.assertRaises(ValueError):
                s.check_leaf(self.body[:length])

    def test_wrong_digest_rejected_before_output_or_parser(self):
        with tempfile.TemporaryDirectory() as folder:
            path, out = Path(folder) / 'bad', Path(folder) / 'out'
            path.write_bytes(b'not the capture')
            with patch.object(s, 'collect_static', side_effect=AssertionError('parser reached')):
                with self.assertRaisesRegex(ValueError, 'digest mismatch'):
                    s.generate(path, out)
            self.assertFalse(out.exists())
        def check(data):
            with self.assertRaisesRegex(ValueError, 'digest mismatch'):
                s.collect(data)
        self.mutate(s.offset(self.secs, s.START), b'\x49', check)

    def test_shifted_fde_and_length_rejected_below_digest(self):
        p = self.record['function']['frame']['fde_file_offset']
        for field in (8, 12):
            value = struct.unpack_from('<i', self.data, p + field)[0]
            def check(data):
                with self.assertRaisesRegex(ValueError, 'FDE extent'):
                    s.collect_static(data)
            self.mutate(p + field, struct.pack('<i', value + 1), check)

    def test_cie_corruption_rejected_below_digest(self):
        p = self.record['function']['frame']['cie_file_offset']
        def check(data):
            with self.assertRaisesRegex(ValueError, 'CIE bytes'):
                s.collect_static(data)
        self.mutate(p + 12, b'\x02', check)  # code alignment 1 -> 2.

    def test_wrong_call_target_rejected_below_digest(self):
        p = s.offset(self.secs, 0x4353cf7)
        value = struct.unpack_from('<i', self.data, p)[0]
        def check(data):
            with self.assertRaisesRegex(ValueError, 'direct-caller census'):
                s.collect_static(data)
        self.mutate(p, struct.pack('<i', value + 16), check)

    def test_wrong_source_relocation_and_location_rejected(self):
        loc = self.record['caller_context']['source_location']
        for p, replacement, reason in [
            (loc['relocation_file_offset'] + 16, struct.pack('<q', loc['path_va'] + 1), 'relocation'),
            (loc['location_file_offset'] + 16, struct.pack('<I', 120), 'Location fields'),
            (s.offset(self.secs, loc['path_va']), b'L', 'source path')]:
            def check(data):
                with self.assertRaisesRegex(ValueError, reason):
                    s.collect_static(data)
            self.mutate(p, replacement, check)

    def test_padding_and_false_caller_rejected(self):
        def padding(data):
            with self.assertRaisesRegex(ValueError, 'padding'):
                s.collect_static(data)
        self.mutate(s.offset(self.secs, s.END), b'\x90', padding)
        # Add an e8-shaped candidate outside the measured bodies. It must not be
        # silently ignored, even when it was originally data/instruction interior.
        site = 0x5001000
        fake = b'\xe8' + struct.pack('<i', s.START - site - 5)
        def census(data):
            with self.assertRaisesRegex(ValueError, 'direct-caller census'):
                s.collect_static(data)
        self.mutate(s.offset(self.secs, site), fake, census)

    def test_readme_counts_equal_json_and_drift_rejected(self):
        readme = (s.PACKET / 'README.md').read_text()
        verifier.check_readme_counts(self.record, readme)
        with self.assertRaisesRegex(ValueError, 'counts differ'):
            verifier.check_readme_counts(self.record, readme.replace('| instructions | 14 |', '| instructions | 15 |'))
        c = self.record['counts']
        self.assertEqual(c['instructions'], len(self.record['function']['instructions']))
        self.assertEqual(c['vectors'], len(self.record['vectors']))
        self.assertEqual(c['direct_call_sites'], len(self.record['caller_scan']['hits']))
        self.assertEqual(c['caller_owners'], len({h['owner_start'] for h in self.record['caller_scan']['hits']}))
        self.assertEqual(c['function_bytes'], len(self.body))

    def test_manifest_whitelist_and_corruption_controls(self):
        text = (s.PACKET / 'MANIFEST.sha256').read_text()
        verifier.check_manifest(text)
        rows = text.splitlines()
        for changed in ['\n'.join(rows[:-1]), text + rows[0] + '\n',
                        text + '0' * 64 + '  ../outside\n',
                        ('0' if text[0] != '0' else '1') + text[1:]]:
            with self.assertRaises(ValueError):
                verifier.check_manifest(changed)


if __name__ == '__main__':
    unittest.main()
