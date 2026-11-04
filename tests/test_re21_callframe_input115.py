"""Digest-bound static checks and synthetic negative controls for the CALL path."""
import csv
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import re21_callframe_input115 as re21


class CallFrameStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = re21.verified_bytes(re21.ROOT / re21.TARGET, re21.TARGET_SHA256)
        cls.sec = re21.sections(cls.data)
        cls.scratch = tempfile.TemporaryDirectory()
        cls.generated = Path(cls.scratch.name) / 'generated'
        cls.summary = re21.generate(cls.data, cls.generated)

    @classmethod
    def tearDownClass(cls):
        cls.scratch.cleanup()

    @staticmethod
    def fake_code(raw, base=0x1000):
        return [dict(name='.text', type=1, flags=4, address=base, offset=0, size=len(raw))]

    def test_generated_evidence_matches_checked_in_files(self):
        expected = re21.ROOT / 'research/work-items/RE-021-callframe-input-115'
        names = {'windows.tsv', 'edges.tsv', 'relocations.tsv', 'functions.tsv',
                 'literals.tsv', 'exceptions.tsv', 'sources.tsv', 'bodies.json', 'lineage.json', 'summary.json'}
        self.assertEqual({p.name for p in self.generated.iterdir()}, names)
        for name in sorted(names):
            with self.subTest(name=name):
                self.assertEqual((self.generated / name).read_bytes(), (expected / name).read_bytes())

    def test_summary_is_bounded_to_selected_records(self):
        self.assertEqual(self.summary['target_sha256'], re21.TARGET_SHA256)
        self.assertEqual(self.summary['selected_function_fdes'], 8)
        self.assertEqual(self.summary['selected_fde_body_bytes'], 5422)
        self.assertEqual(self.summary['selected_fdes_with_lsda'], 6)
        self.assertEqual(self.summary['selected_exception_sites'], 37)
        self.assertEqual(self.summary['selected_source_descriptors'], 15)
        self.assertEqual(self.summary['selected_source_suffixes'], 3)
        self.assertEqual(self.summary['selected_relocations'], 10)
        self.assertGreater(self.summary['selected_relative_branches'], 50)
        self.assertEqual(len({start for _, start in re21.FUNCTIONS}), 8)

    def test_body_hashes_and_fde_extents_are_consistent(self):
        bodies = json.loads((self.generated / 'bodies.json').read_text())
        with (self.generated / 'functions.tsv').open(newline='') as f:
            rows = list(csv.DictReader(f, delimiter='\t'))
        self.assertEqual(len(rows), len(bodies))
        for body, row in zip(bodies, rows):
            raw = bytes.fromhex(body['hex'])
            self.assertEqual(row['label'], body['label'])
            self.assertEqual(len(raw), int(body['end_va'], 16) - int(body['start_va'], 16))
            self.assertEqual(hashlib.sha256(raw).hexdigest(), row['body_sha256'])
            self.assertEqual(raw, self.data[int(body['file_offset'], 16):int(body['file_offset'], 16) + len(raw)])

    def test_hash_rejection_precedes_parsing(self):
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            re21.generate(self.data[:64], self.generated)
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory) / 'changed'
            fixture.write_bytes(b'not the captured artifact')
            with self.assertRaisesRegex(ValueError, 'SHA-256'):
                re21.verified_bytes(fixture, re21.TARGET_SHA256)
            with self.assertRaisesRegex(ValueError, 'SHA-256'):
                re21.check_legacy(fixture, self.data)

    def test_missing_target_is_an_error(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(FileNotFoundError):
                re21.verified_bytes(Path(directory) / 'missing', re21.TARGET_SHA256)

    def test_corrupt_instruction_is_rejected(self):
        _, va, expected = re21.PINS[0]
        corrupted = bytearray(self.data)
        _, off = re21.file_offset(self.sec, va, 1, True)
        corrupted[off] ^= 1
        with self.assertRaisesRegex(ValueError, 'instruction window mismatch'):
            re21.check_pin(corrupted, self.sec, va, expected)

    def test_corrupt_address_key_cannot_match(self):
        observed = re21.read_va(self.data, self.sec, 0x64c0750, 20)
        self.assertEqual(observed, re21.project_address(9))
        mutated = bytearray(observed)
        mutated[-1] ^= 1
        self.assertNotEqual(bytes(mutated), re21.project_address(9))

    def test_frame_lineage_checks_real_displacements_and_rejects_mutation(self):
        observed = re21.lineage(self.data, self.sec)
        self.assertEqual(observed['frame_key_field'], 0x90)
        self.assertEqual(observed['frame_input_start_field'], 0x58)
        self.assertEqual(observed['frame_input_end_field'], 0x60)
        self.assertEqual(observed['frame_output_start_field'], 0x70)
        self.assertEqual(observed['frame_second_key_field'], 0xa4)
        corrupted = bytearray(self.data)
        _, off = re21.file_offset(self.sec, 0x299b241, 8, True)
        corrupted[off + 4] ^= 8
        with self.assertRaisesRegex(ValueError, 'lineage displacement'):
            re21.lineage(corrupted, self.sec)

    def test_section_reads_reject_nobits_absent_crossing_and_ambiguity(self):
        bss = next(x for x in self.sec if x['name'] == '.bss')
        text = next(x for x in self.sec if x['name'] == '.text')
        for va, size in [(bss['address'], 1), (-1, 1), (0, 0), (0xffffffffffffffff, 1),
                         (text['address'] + text['size'] - 1, 2)]:
            with self.subTest(va=va, size=size), self.assertRaises(ValueError):
                re21.read_va(self.data, self.sec, va, size, True)
        with self.assertRaisesRegex(ValueError, 'unique'):
            re21.read_va(self.data, self.sec + [dict(text)], text['address'], 1, True)

    def test_relative_branch_shapes_and_corruption(self):
        for raw, target in [(b'\x74\x02', 0x1004),
                            (b'\xeb\xfc', 0x0ffe),
                            (b'\xe8\xfb\xff\xff\xff', 0x1000),
                            (b'\x0f\x85\xfa\xff\xff\xff', 0x1000)]:
            with self.subTest(raw=raw):
                self.assertEqual(re21.relative_branch(raw, self.fake_code(raw), 0x1000)[1], target)
        raw = b'\x90\x90'
        with self.assertRaisesRegex(ValueError, 'unsupported'):
            re21.relative_branch(raw, self.fake_code(raw), 0x1000)
        with self.assertRaises(ValueError):
            re21.relative_branch(b'\xe8\x00', self.fake_code(b'\xe8\x00'), 0x1000)

    def test_indirect_call_requires_exact_opcode_and_signed_displacement(self):
        raw = b'\xff\x15\xfa\xff\xff\xff'
        self.assertEqual(re21.indirect_slot(raw, self.fake_code(raw), 0x1000)[1], 0x1000)
        bad = b'\xff\x10\xfa\xff\xff\xff'
        with self.assertRaisesRegex(ValueError, 'indirect call'):
            re21.indirect_slot(bad, self.fake_code(bad), 0x1000)

    def test_missing_duplicate_and_wrong_relative_relocations(self):
        record = struct.pack('<QQq', 0x2000, 8, 0x4000)
        data = record * 2
        sec = [dict(name='.rela.dyn', type=4, offset=0, size=len(data)),
               dict(name='.dynsym', type=11, offset=len(data), size=0),
               dict(name='.dynstr', type=3, offset=len(data), size=0)]
        with self.assertRaisesRegex(ValueError, 'ambiguous relocation'):
            re21.relocation_rows(data, sec, [('x', 0x2000, 8, 0x4000)])
        sec[0]['size'] = len(record)
        with self.assertRaisesRegex(ValueError, 'missing relocation'):
            re21.relocation_rows(data, sec, [('x', 0x2008, 8, 0x4000)])
        with self.assertRaisesRegex(ValueError, 'target mismatch'):
            re21.relocation_rows(data, sec, [('x', 0x2000, 8, 0x4001)])
        with self.assertRaisesRegex(ValueError, 'type mismatch'):
            re21.relocation_rows(data, sec, [('x', 0x2000, 6, 'symbol')])
        with self.assertRaisesRegex(ValueError, 'duplicate relocation request'):
            re21.relocation_rows(data, sec, [('x', 0x2000, 8, 0x4000), ('y', 0x2000, 8, 0x4000)])

    def test_lsda_parser_rejects_wrong_encodings_bounds_and_truncation(self):
        fde = dict(start=0x1000, end=0x1010, lsda=0x2000)
        good = bytes.fromhex('ffff010400010000')
        def section(data):
            return [dict(name='.gcc_except_table', type=1, address=0x2000, offset=0, size=len(data))]
        rows = re21.lsda_sites(good, section(good), 'x', fde)
        self.assertEqual(rows[0][3:7], ['0x1000', '0x1001', '', '0'])
        for bad in (bytes.fromhex('00ff010400010000'), bytes.fromhex('ffff030400010000'),
                    bytes.fromhex('ffff017f00010000'), bytes.fromhex('ffff010400110000'),
                    bytes.fromhex('ffff010400011000'), bytes.fromhex('ffff010480'),
                    bytes.fromhex('ff9b7f010400010000'), bytes.fromhex('ff9b01010400010000')):
            with self.subTest(bad=bad.hex()), self.assertRaises(ValueError):
                re21.lsda_sites(bad, section(bad), 'x', fde)

    def test_source_suffixes_are_sanitized_and_reference_target_checked(self):
        self.assertEqual(re21.sanitize_source_path(b'prefix/z_vendor/a/b.rs'), 'z_vendor/a/b.rs')
        for invalid in (b'unknown/a.rs', b'z_vendor/a/../b.rs', b'z_vendor/a\x00b',
                        b'z_vendor/z_vendor/b.rs'):
            with self.subTest(raw=invalid), self.assertRaises(ValueError):
                re21.sanitize_source_path(invalid)
        with (self.generated / 'sources.tsv').open(newline='') as stream:
            rows = list(csv.DictReader(stream, delimiter='\t'))
        self.assertEqual(len(rows), 15)
        self.assertTrue(all(row['sanitized_path_suffix'].startswith('z_vendor/') for row in rows))
        self.assertEqual(len({row['sanitized_path_suffix'] for row in rows}), 3)
        corrupt = bytearray(self.data)
        _, off = re21.file_offset(self.sec, 0x2999af0, 7, True)
        corrupt[off + 3] ^= 1
        with self.assertRaisesRegex(ValueError, 'source descriptor reference'):
            re21.source_locations(corrupt, self.sec)

    def test_u256_target_is_low_160_bits_big_endian(self):
        self.assertEqual(re21.project_address(9), bytes(19) + b'\x09')
        value = int.from_bytes(bytes(range(32)), 'big')
        self.assertEqual(re21.project_address(value), bytes(range(12, 32)))
        self.assertEqual(re21.project_address((1 << 255) | 9), re21.project_address(9))
        for value in (-1, 1 << 256):
            with self.subTest(value=value), self.assertRaises(ValueError):
                re21.project_address(value)

    def test_each_target_key_bit_changes_the_projected_key(self):
        baseline = re21.project_address(9)
        for bit in range(160):
            with self.subTest(bit=bit):
                self.assertNotEqual(re21.project_address(9 ^ (1 << bit)), baseline)
        for bit in range(160, 256):
            with self.subTest(bit=bit):
                self.assertEqual(re21.project_address(9 ^ (1 << bit)), baseline)

    def test_copy_direct_success_prefix_and_zero_padding(self):
        source = b'abcdef'
        self.assertEqual(re21.copy_result(source, 1, 3), b'bcd')
        self.assertEqual(re21.copy_result(source, 4, 5), b'ef\x00\x00\x00')
        self.assertEqual(re21.copy_result(source, 6, 3), bytes(3))
        self.assertEqual(re21.copy_result(source, re21.MAX_U64, 0), b'')
        self.assertEqual(re21.copy_result(source, re21.MAX_U64, 1), b'\x00')
        with self.assertRaises(ValueError):
            re21.copy_result(source, -1, 1)
        with self.assertRaises(ValueError):
            re21.copy_result(source, 0, 65537)

    def test_copy_213_byte_hypothesis_and_short_input_control(self):
        source = bytes(212) + b'\x01'
        self.assertEqual(re21.copy_result(source, 0, 213), source)
        shorter = source[:-1]
        self.assertEqual(re21.copy_result(shorter, 0, 213), bytes(213))
        self.assertNotEqual(re21.copy_result(shorter, 0, 213), source)

    def test_call_stack_error_precedence_and_consumption(self):
        self.assertEqual(re21.call_stack_gate(2, 1, 1), (0x2c, 2, 'first_pop'))
        self.assertEqual(re21.call_stack_gate(3, 1, 1), (0x27, 0, 'static_value'))
        self.assertEqual(re21.call_stack_gate(3, 0, 1), (0x2c, 0, 'ranges_pop'))
        self.assertEqual(re21.call_stack_gate(6, 0, 0), (0x2c, 3, 'ranges_pop'))
        self.assertEqual(re21.call_stack_gate(7, 0, 1), (0, 0, 'ranges_ready'))
        self.assertEqual(re21.call_stack_gate(7, 1, 2), (0, 0, 'ranges_ready'))
        with self.assertRaises(ValueError):
            re21.call_stack_gate(7, -1, 0)

    def test_range_high_limb_empty_and_carry_boundaries(self):
        high = 1 << 64
        self.assertEqual(re21.range_check(high, 0), 'empty')
        self.assertEqual(re21.range_check(0, high), 'size_high')
        self.assertEqual(re21.range_check(high, 1), 'offset_high')
        self.assertEqual(re21.range_check(re21.MAX_U64 - 1, 1), 'accepted')
        self.assertEqual(re21.range_check(re21.MAX_U64, 1), 'end_carry')
        self.assertEqual(re21.range_check(0, 213), 'accepted')
        with self.assertRaises(ValueError):
            re21.range_check(1 << 256, 0)

    def test_word_rounding_around_32_and_u64_boundary(self):
        for n, expected in [(0, 0), (1, 1), (31, 1), (32, 1), (33, 2), (212, 7),
                            (213, 7), (224, 7), (225, 8), (re21.MAX_U64, 1 << 59)]:
            with self.subTest(n=n):
                self.assertEqual(re21.words_for_bytes(n), expected)
        with self.assertRaises(ValueError):
            re21.words_for_bytes(re21.MAX_U64 + 1)

    def test_memory_cost_and_failed_charge_metadata(self):
        self.assertEqual(re21.memory_cost(7, 3, 512), 21)
        self.assertEqual(re21.expand_metadata(7, 0, 20, 3, 512), (0x21, 7, 21, 20))
        self.assertEqual(re21.expand_metadata(7, 0, 21, 3, 512), (0, 7, 21, 0))
        self.assertEqual(re21.expand_metadata(7, 3, 18, 3, 512), (0, 7, 21, 0))
        self.assertEqual(re21.memory_cost(re21.MAX_U64, 3, 512), re21.MAX_U64)
        with self.assertRaises(ValueError):
            re21.expand_metadata(7, 22, 100, 3, 512)
        with self.assertRaises(ValueError):
            re21.memory_cost(1, 3, 0)

    def test_base_charge_writes_wrapped_subtraction_before_failure(self):
        self.assertEqual(re21.base_charge(3, 3), (0, 0))
        self.assertEqual(re21.base_charge(2, 3), (0x20, re21.MAX_U64))
        self.assertEqual(re21.base_charge(0, 0), (0, 0))
        with self.assertRaises(ValueError):
            re21.base_charge(-1, 3)

    def test_copy_charge_saturates_and_does_not_store_failed_subtraction(self):
        self.assertEqual(re21.copy_charge(20, 213, 3), (0x20, 20))
        self.assertEqual(re21.copy_charge(21, 213, 3), (0, 0))
        self.assertEqual(re21.copy_charge(re21.MAX_U64 - 1, re21.MAX_U64, 64),
                         (0x20, re21.MAX_U64 - 1))
        self.assertEqual(re21.copy_charge(re21.MAX_U64, re21.MAX_U64, 64), (0, 0))
        with self.assertRaises(ValueError):
            re21.copy_charge(1, 1, -1)

    def test_forwarded_gas_cap_stipend_and_invalid_divisor(self):
        self.assertEqual(re21.forwarded_gas(6400, 10000, 64), (100, 6300))
        self.assertEqual(re21.forwarded_gas(6400, 100, 64), (6300, 100))
        self.assertEqual(re21.forwarded_gas(6400, 10000, 64, 2300), (100, 8600))
        self.assertEqual(re21.forwarded_gas(1, re21.MAX_U64, 64, re21.MAX_U64), (0, re21.MAX_U64))
        with self.assertRaises(ValueError):
            re21.forwarded_gas(1, 1, 0)
        with self.assertRaises(ValueError):
            re21.forwarded_gas(1, -1, 64)


if __name__ == '__main__':
    unittest.main()
