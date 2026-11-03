import csv
import io
import struct
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

from tools import abci_greeting_115 as m


class GreetingEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = m.INPUT.read_bytes()
        m.verify_digest(cls.data)
        cls.secs = m.sections(cls.data)
        cls.read = staticmethod(lambda a, n: m.read_va(cls.data, cls.secs, a, n))
        cls.windows = m.read_windows(cls.read)
        cls.reports = m.build_reports(cls.data)

    @staticmethod
    def rows(data):
        return list(csv.DictReader(io.StringIO(data.decode()), delimiter='\t'))

    def corrupt(self, position, replacement=None):
        def read(addr, size):
            result = bytearray(self.read(addr, size))
            if addr <= position < addr + size:
                index = position - addr
                result[index] = result[index] ^ 1 if replacement is None else replacement
            return bytes(result)
        return read

    def test_target_digest_and_wrong_digest(self):
        m.verify_digest(self.data)
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            m.verify_digest(b'wrong binary')

    def test_bad_digest_fails_before_elf_parsing(self):
        with patch.object(m, 'sections') as parser:
            with self.assertRaisesRegex(ValueError, 'SHA-256'):
                m.build_reports(b'bad')
            parser.assert_not_called()

    def test_bad_digest_creates_no_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / 'bad.bin'
            binary.write_bytes(b'invalid')
            out = root / 'reports'
            with patch.object(m, 'INPUT', binary):
                with self.assertRaisesRegex(ValueError, 'SHA-256'):
                    m.main(['--out', str(out)])
            self.assertFalse(out.exists())

    def test_bad_historical_digest(self):
        with self.assertRaisesRegex(ValueError, 'node 94 SHA-256'):
            m.validate_historical(b'not the historical node')

    def test_every_fixed_window_rejects_corruption(self):
        self.assertGreater(len(m.WINDOWS), 90)
        for name, address, raw in m.WINDOWS:
            with self.subTest(window=name):
                with self.assertRaisesRegex(ValueError, 'instruction window differs'):
                    m.read_windows(self.corrupt(address + len(bytes.fromhex(raw)) // 2))

    def test_every_transfer_displacement_is_checked(self):
        for name, site, target in m.TRANSFERS:
            with self.subTest(transfer=name):
                kind, actual, raw = m.direct_transfer(self.read, site)
                self.assertEqual(actual, target)
                _, mutated_target, _ = m.direct_transfer(self.corrupt(site + len(raw) - 1), site)
                self.assertNotEqual(mutated_target, target)
                self.assertIn(kind, ('call', 'jmp', 'jo', 'jb', 'jae', 'je', 'jne', 'jbe', 'ja', 'js', 'jns', 'jle', 'jg'))

    def test_transfer_rejects_invalid_opcode(self):
        with self.assertRaisesRegex(ValueError, 'unsupported'):
            m.direct_transfer(self.corrupt(0x2acecde, 0x90), 0x2acecde)

    def test_location_reference_rejects_wrong_opcode(self):
        target, _ = m.location_reference(self.read, 0x3c1352f, bytes.fromhex('488d15'))
        self.assertEqual(target, 0x64767a8)
        with self.assertRaisesRegex(ValueError, 'encoding'):
            m.location_reference(self.corrupt(0x3c1352f), 0x3c1352f, bytes.fromhex('488d15'))

    def test_relative_table_targets_and_bound(self):
        values = m.decode_rel_table(self.read, 0x60be64, 6, 0x2cd6de0, 0x2cd72f9)
        self.assertEqual([value[1] for value in values],
                         [0x2cd6e20, 0x2cd6fa3, 0x2cd6f6d, 0x2cd6f88, 0x2cd6f52, 0x2cd7031])
        with self.assertRaisesRegex(ValueError, 'outside'):
            m.decode_rel_table(lambda a, n: bytes(n), 0x60be64, 6, 0x2cd6de0, 0x2cd72f9)

    def test_relative_table_rejects_bad_lengths(self):
        for count in (0, 257):
            with self.subTest(count=count), self.assertRaises(ValueError):
                m.decode_rel_table(self.read, 0x60be64, count, 0, 1)
        with self.assertRaisesRegex(ValueError, 'truncated'):
            m.decode_rel_table(lambda a, n: b'\x00', 0x60be64, 6, 0, 1)

    def test_corrupted_discriminant_marker_fails(self):
        with self.assertRaisesRegex(ValueError, 'marker'):
            m.derive_constants(self.corrupt(0x2cd6f82))

    def test_corrupted_integer_threshold_fails(self):
        with self.assertRaisesRegex(ValueError, 'pattern'):
            m.derive_constants(self.corrupt(0x2935e3e))

    def test_nobits_cannot_supply_file_bytes(self):
        sec = dict(name='fake', type=8, flags=6, address=0x1000, size=32, offset=0)
        with self.assertRaisesRegex(ValueError, 'file-backed'):
            m.mapping([sec], 0x1000, 1)

    def test_overlapping_file_sections_rejected(self):
        sec = dict(name='one', type=1, flags=6, address=0x1000, size=32, offset=0)
        other = dict(sec, name='two', offset=100)
        with self.assertRaisesRegex(ValueError, 'unique'):
            m.mapping([sec, other], 0x1001, 1)

    def test_invalid_addresses_and_nonexecutable_section(self):
        sec = dict(name='data', type=1, flags=2, address=0x1000, size=32, offset=0)
        for address, size in ((-1, 1), (0x1000, 0), (0x101f, 2)):
            with self.subTest(address=address, size=size), self.assertRaises(ValueError):
                m.mapping([sec], address, size)
        with self.assertRaises(ValueError):
            m.mapping([sec], 0x1000, 1, executable=True)

    def test_relocation_exact_and_corrupted(self):
        sec = dict(name='.rela.dyn', type=4, offset=0, size=24)
        record = struct.pack('<QQq', 0x2000, 8, 0x1234)
        self.assertEqual(m.relative_relocations(record, [sec], [0x2000]), {0x2000: 0x1234})
        for bad in (struct.pack('<QQq', 0x2000, 7, 0x1234),
                    struct.pack('<QQq', 0x2001, 8, 0x1234)):
            with self.subTest(raw=bad.hex()), self.assertRaises(ValueError):
                m.relative_relocations(bad, [sec], [0x2000])
        with self.assertRaises(ValueError):
            m.relative_relocations(record, [sec, sec], [0x2000])

    def test_duplicate_relocation_rejected(self):
        record = struct.pack('<QQq', 0x2000, 8, 0x1234)
        sec = dict(name='.rela.dyn', type=4, offset=0, size=48)
        with self.assertRaisesRegex(ValueError, 'ambiguous'):
            m.relative_relocations(record * 2, [sec], [0x2000])

    def test_truncated_relocation_section_is_rejected(self):
        sec = dict(name='.rela.dyn', type=4, offset=0, size=24)
        with self.assertRaisesRegex(ValueError, 'outside file'):
            m.relative_relocations(bytes(23), [sec], [0x2000])

    def test_lsda_selected_row(self):
        raw = bytes.fromhex('ffff010400050100')
        sec = dict(name='.gcc_except_table', type=1, flags=2, address=0x2000, size=len(raw), offset=0)
        fde = dict(lsda=0x2000, start=0x1000, end=0x1020)
        rows = m.parse_lsda(raw, [sec], fde)
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0]['start'], rows[0]['end'], rows[0]['landing'], rows[0]['action']),
                         (0x1000, 0x1005, 0x1001, 0))

    def test_lsda_rejects_truncated_and_outside_rows(self):
        fde = dict(lsda=0x2000, start=0x1000, end=0x1020)
        for raw in (bytes.fromhex('ffff010500050100'), bytes.fromhex('ffff010400210100'),
                    bytes.fromhex('ffff010400052000'), bytes.fromhex('00ff010400050100'),
                    bytes.fromhex('ffff010400058000')):
            sec = dict(name='.gcc_except_table', type=1, flags=2, address=0x2000, size=len(raw), offset=0)
            with self.subTest(raw=raw.hex()), self.assertRaises(ValueError):
                m.parse_lsda(raw, [sec], fde)

    def test_lsda_absence_and_outside_pointer(self):
        self.assertEqual(m.parse_lsda(b'', [], dict(lsda=None)), [])
        sec = dict(name='.gcc_except_table', type=1, flags=2, address=0x2000, size=8, offset=0)
        with self.assertRaisesRegex(ValueError, 'outside'):
            m.parse_lsda(bytes(8), [sec], dict(lsda=0x3000, start=0, end=1))
        with self.assertRaisesRegex(ValueError, 'outside file'):
            m.parse_lsda(bytes(7), [sec], dict(lsda=0x2000, start=0, end=1))

    def test_lsda_must_cover_the_entire_call(self):
        row = dict(start=0x100, end=0x105)
        self.assertEqual(m.callsite_witness([row], 0x100, 5), row)
        self.assertIsNone(m.callsite_witness([row], 0x106, 5))
        with self.assertRaisesRegex(ValueError, 'crosses'):
            m.callsite_witness([row], 0x101, 5)
        with self.assertRaisesRegex(ValueError, 'crosses'):
            m.callsite_witness([row], 0xff, 2)
        with self.assertRaisesRegex(ValueError, 'ambiguous'):
            m.callsite_witness([row, row], 0x100, 5)
        with self.assertRaises(ValueError):
            m.callsite_witness([row], 0x100, 0)

    def test_copy_boundaries(self):
        self.assertEqual(m.map_copy(12, 10, 100, 10), 102)
        for pos in (9, 13, 20):
            with self.subTest(pos=pos), self.assertRaises(ValueError):
                m.map_copy(pos, 10, 100, 10)
        with self.assertRaises(ValueError):
            m.map_copy(10, 10, 100, 10, width=0)
        with self.assertRaises(ValueError):
            m.map_copy(10, 10, -1, 10)

    def test_flow_contains_both_critical_joins(self):
        rows = {row['step']: row for row in self.rows(self.reports['flow.tsv'])}
        self.assertEqual(rows['owner_body']['tracked_after'], '0xb00')
        self.assertEqual(rows['parent_stage_4']['tracked_after'], '0x840')
        self.assertEqual(rows['executor_a_body']['tracked_after'], '0x138')
        self.assertEqual(rows['executor_b_body']['tracked_after'], '0x138')
        self.assertEqual(rows['future_copy_7']['tracked_after'], '0x11d0')
        self.assertEqual(rows['mode_copy_7']['tracked_after'], '0x1278')
        self.assertEqual(rows['future_copy_7']['tracked_width'], '0x8')
        self.assertEqual(rows['mode_copy_7']['tracked_width'], '0x1')

    def test_flow_rejects_corrupted_copy_size(self):
        with self.assertRaises(ValueError):
            m.flow_rows(self.corrupt(0x2cd1120, 0), self.windows)

    def test_flow_rejects_corrupted_snapshot_slot(self):
        with self.assertRaisesRegex(ValueError, 'snapshot argument'):
            m.flow_rows(self.corrupt(0x2ace97d), self.windows)

    def test_flow_rejects_corrupted_mode_slot(self):
        with self.assertRaisesRegex(ValueError, 'snapshot mode'):
            m.flow_rows(self.corrupt(0x2ace96f), self.windows)

    def test_flow_rejects_corrupted_prior_snapshot_offset(self):
        with self.assertRaisesRegex(ValueError, 'owner body'):
            m.flow_rows(self.corrupt(0x5444fc9), self.windows)

    def test_selected_preflight_sentinel_returns_to_repack_copy(self):
        for site, opcode, target in ((0x5a07f01, 'jb', 0x5a07f25),
                                     (0x5a07f2c, 'jne', 0x5a07f48),
                                     (0x5a07f3b, 'jmp', 0x5a08551),
                                     (0x5a09032, 'jo', 0x5a09063)):
            with self.subTest(site=site):
                kind, actual, _ = m.direct_transfer(self.read, site)
                self.assertEqual((kind, actual), (opcode, target))
        self.assertEqual(self.read(0x5a07f2e, 13), bytes.fromhex('48b80000000000000080488903'))
        self.assertEqual(m.preflight_witness(self.read), {
            'saved_pointer_stack_offset': 0x460, 'output_stack_offset': 0x480,
            'selected_input_tag': 2, 'sentinel': 1 << 63})

    def test_preflight_witness_rejects_overlapping_output(self):
        with self.assertRaisesRegex(ValueError, 'overlaps'):
            m.preflight_witness(self.corrupt(0x5a09018, 0x60))

    def test_parent_pointer_is_not_in_the_copied_prefix(self):
        self.assertEqual(m.parent_result_witness(self.read), {
            'result_stack_offset': 0x730, 'copied_prefix_length': 0x380,
            'pointer_stack_offset': 0xab0, 'pointer_result_offset': 0x380})
        with self.assertRaisesRegex(ValueError, 'not just past'):
            m.parent_result_witness(self.corrupt(0x2cb779a))

    def test_varuint_boundary_vectors(self):
        small, wide, shift, tags, *_ = m.derive_constants(self.read)
        vectors = {0: '00', 250: 'fa', 251: 'fbfb00', 65535: 'fbffff',
                   65536: 'fc00000100', (1 << 32) - 1: 'fcffffffff',
                   1 << 32: 'fd0000000001000000', (1 << 64) - 1: 'fdffffffffffffffff'}
        for value, expected in vectors.items():
            with self.subTest(value=value):
                self.assertEqual(m.unsigned_model(value, small, wide, shift, tags).hex(), expected)

    def test_varuint_rejects_invalid_inputs(self):
        for value in (-1, 1 << 64, '1'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                m.unsigned_model(value, 251, 65536, 32, [251, 252, 253])
        with self.assertRaises(ValueError):
            m.unsigned_model(0, 1, 1, 32, [251, 252, 253])

    def test_counter_saturation_and_bucket_advance(self):
        maximum = (1 << 64) - 1
        self.assertEqual(m.bucket_model(12, 4, 12, maximum), (12, 5))
        self.assertEqual(m.bucket_model(12, maximum, 12, maximum), (12, maximum))
        self.assertEqual(m.bucket_model(12, maximum, 13, maximum), (13, 1))
        self.assertEqual(m.bucket_model(12, 0, 11, maximum), (12, 1))
        with self.assertRaises(ValueError):
            m.bucket_model(0, -1, 0, maximum)

    def test_context_boundaries_are_not_selected_fdes(self):
        owned = {start for _, start in m.FUNCTIONS}
        for boundary in (0x3c13520, 0x2cb6500, 0x5a6bfb0, 0x5648a30, 0x2b7a290, 0x5a07ec0):
            with self.subTest(boundary=boundary):
                self.assertNotIn(boundary, owned)

    def test_generated_unwind_has_guarded_send_call(self):
        rows = {row['call']: row for row in self.rows(self.reports['unwind_links.tsv'])}
        self.assertEqual(rows['greeting_send']['status'], 'covered')
        self.assertEqual(rows['greeting_send']['landing_va'], '0x2acfbb2')
        self.assertEqual(rows['zero_length_write']['status'], 'no_lsda')

    def test_target_location_and_artifact_identity_in_report(self):
        import json
        loc = json.loads(self.reports['location.json'])
        self.assertEqual(loc['binary_sha256'], m.TARGET)
        self.assertEqual((loc['file_name'], loc['line'], loc['column']), ('l1/src/abci/state.rs', 123, 37))


if __name__ == '__main__':
    unittest.main()
