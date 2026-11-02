"""Static, target-bound and corruption controls for the nested map collector."""
import struct
import tempfile
import unittest
from pathlib import Path

from tools import config_nested_map94 as m


class NestedMapEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Absence of the required artifact is an error, never a skip.
        cls.data = m.TARGET.read_bytes()
        cls.result = m.inspect(cls.data)
        cls.view = cls.result['view']

    def changed(self, va):
        result = bytearray(self.data)
        result[self.view.offset(va, 1)] ^= 1
        return result

    def test_digest_and_size(self):
        m.verify_identity(self.data)
        self.assertEqual(len(self.data), m.SIZE)

    def test_short_artifact_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
            m.verify_identity(self.data[:-1])

    def test_same_size_changed_artifact_is_rejected(self):
        corrupted = self.changed(0x14bc870)
        with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
            m.verify_identity(corrupted)

    def test_selected_body_corruption_is_rejected(self):
        corrupted = self.changed(0x14bc8ed)
        with self.assertRaisesRegex(ValueError, 'selected FDE bytes changed'):
            m.inspect(corrupted, authenticate=False)

    def test_prior_boundary_corruption_is_rejected(self):
        corrupted = self.changed(0x14bc53c)
        with self.assertRaisesRegex(ValueError, 'boundary changed'):
            m.inspect(corrupted, authenticate=False)

    def test_literal_corruption_is_rejected(self):
        corrupted = self.changed(0x21bb6c)
        with self.assertRaisesRegex(ValueError, 'field spelling changed'):
            m.inspect(corrupted, authenticate=False)

    def test_dispatch_cell_corruption_is_rejected(self):
        corrupted = self.changed(0x20fabc)
        with self.assertRaisesRegex(ValueError, 'dispatch boundary changed'):
            m.inspect(corrupted, authenticate=False)

    def test_jump_table_corruption_is_rejected(self):
        corrupted = self.changed(0x2137bc)
        with self.assertRaisesRegex(ValueError, 'jump-table target'):
            m.inspect(corrupted, authenticate=False)

    def test_wrong_but_valid_jump_target_is_rejected(self):
        corrupted = bytearray(self.data)
        first = self.view.offset(0x213b88 + 0x1e * 4, 4)
        second = self.view.offset(0x213b88 + 0x1f * 4, 4)
        corrupted[first:first + 4] = corrupted[second:second + 4]
        with self.assertRaisesRegex(ValueError, 'map-prefix route changed'):
            m.inspect(corrupted, authenticate=False)

    def test_lsda_header_corruption_is_rejected(self):
        lsda = next(row['lsda'] for row in self.result['functions'] if row['lsda'] is not None)
        corrupted = self.changed(lsda)
        with self.assertRaisesRegex(ValueError, 'LSDA header'):
            m.inspect(corrupted, authenticate=False)

    def test_landing_outside_function_is_rejected(self):
        function = dict(next(row for row in self.result['functions'] if row['lsda'] is not None))
        function['lsda'] = 0
        with self.assertRaisesRegex(ValueError, 'outside exception table'):
            m.exception_sites(self.view, [], [function], set(), [])

    def test_relocation_symbol_corruption_is_rejected(self):
        slot = 0x576e488
        record = self.result['relocations'][slot]
        corrupted = bytearray(self.data)
        struct.pack_into('<Q', corrupted, record[1] + 8, (0xffffffff << 32) | 6)
        with self.assertRaisesRegex(ValueError, 'dynamic symbol out of range'):
            m.relocation_rows(m.View(corrupted), {slot})

    def test_file_mapping_rejects_invalid_ranges(self):
        for va, size in [(-1, 1), (0, 0), (1 << 64, 1), ((1 << 64) - 1, 2)]:
            with self.subTest(va=va, size=size), self.assertRaises(ValueError):
                self.view.offset(va, size)

    def test_nobits_has_no_file_bytes(self):
        section = next(s for s in self.view.sections if s['name'] == '.bss' and s['type'] == 8)
        with self.assertRaisesRegex(ValueError, 'file-backed'):
            self.view.read(section['address'], 1)

    def test_overlapping_nobits_never_supplies_file_bytes(self):
        sections = [dict(type=8, flags=2, size=1, address=0x1000, offset=0),
                    dict(type=1, flags=2, size=1, address=0x1000, offset=0)]
        self.assertEqual(m.View(b'X', sections).read(0x1000, 1), b'X')
        with self.assertRaisesRegex(ValueError, 'file-backed'):
            m.View(b'X', sections[:1]).read(0x1000, 1)

    def test_outside_section_and_cross_section_rejected(self):
        with self.assertRaises(ValueError):
            self.view.read((1 << 63) - 1, 1)
        section = next(s for s in self.view.sections if s['name'] == '.text')
        with self.assertRaises(ValueError):
            self.view.read(section['address'] + section['size'] - 1, 2)

    def test_unrecognized_or_truncated_instructions_fail_closed(self):
        for raw in (b'\x62', b'\x0f', b'\xe8\x01', b'\x48\x8b'):
            with self.subTest(raw=raw.hex()), self.assertRaises(ValueError):
                m.decode_body(raw, 0x1000)

    def test_branch_into_instruction_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'branch into an instruction'):
            m.decode_body(bytes.fromhex('eb01b800000000c3'), 0x1000)

    def test_relative_call_target_is_signed(self):
        row = m.decode_one(bytes.fromhex('e8f6ffffff'), 0, 0x1000)
        self.assertEqual((row['kind'], row['target']), ('call', 0xffb))

    def test_jump_table_range_and_target_checks(self):
        view = m.View(struct.pack('<i', 4), [{'type': 1, 'flags': 2, 'size': 4,
                                             'address': 0x1000, 'offset': 0}])
        self.assertEqual(m.jump_table(view, 0x1000, 1, {0x1004})[0][-1], 0x1004)
        with self.assertRaisesRegex(ValueError, 'target'):
            m.jump_table(view, 0x1000, 1, {0x1005})
        for count in (0, 257):
            with self.subTest(count=count), self.assertRaisesRegex(ValueError, 'count'):
                m.jump_table(view, 0x1000, count, set())

    def test_selected_fdes_and_instruction_counts(self):
        self.assertEqual(len(self.result['functions']), 10)
        self.assertEqual(sum(f['size'] for f in self.result['functions']), 8226)
        self.assertEqual(len(self.result['instructions']), 1974)
        self.assertEqual(len(self.result['witnesses']), 165)

    def test_dispatch_field_and_neighboring_controls(self):
        self.assertEqual(self.result['field'], b'eth_chain_to_rpc_provider_to_keys')
        self.assertEqual((self.result['field_tag'], self.result['tag_bias']), (0x1d, 0x16))
        self.assertEqual([(r[0], r[3]) for r in self.result['dispatch']],
                         [(6, 0x13ad46c), (7, 0x13ad0d1), (8, 0x13ad5da)])

    def test_binary_marker_table_boundaries(self):
        rows = {(name, i): dst for name, i, _, _, _, dst in self.result['tables']}
        self.assertEqual(len(rows), 275)
        self.assertEqual(rows['cached_class', 0x80], 0x13bce37)
        self.assertEqual(rows['cached_class', 0xde], 0x13bcc28)
        self.assertEqual(rows['cached_class', 0xdf], 0x13bcbcd)
        self.assertNotEqual(rows['cached_class', 0x81], rows['cached_class', 0x80])
        self.assertNotEqual(rows['cached_class', 0xdd], rows['cached_class', 0xde])

    def test_selected_import_and_relocation_type(self):
        row = self.result['relocations'][0x576e488]
        self.assertEqual((row[2], row[4]), (6, 'memcmp'))
        self.assertEqual(len(self.result['relocations']), 15)

    def test_exception_records_and_cfg_propositions(self):
        self.assertEqual(len(self.result['lsda_headers']), 6)
        self.assertEqual(len(self.result['exceptions']), 48)
        claims = {r[0]: r[-1] for r in self.result['cfg']}
        self.assertEqual(len(claims), 18)
        self.assertEqual(claims['inner_replace_skips_count_increment'], 'false')
        self.assertEqual(claims['outer_replace_skips_count_increment'], 'false')
        self.assertEqual(claims['binary_value_failure_to_drop'], 'true')

    def test_cfg_forbidden_and_unknown_addresses(self):
        rows = m.decode_body(bytes.fromhex('7502eb00c3'), 0x1000)
        self.assertTrue(m.reachable(rows, 0x1000, 0x1004))
        self.assertFalse(m.reachable(rows, 0x1000, 0x1004, forbidden=(0x1004,)))
        with self.assertRaisesRegex(ValueError, 'instruction boundary'):
            m.reachable(rows, 0x1001, 0x1004)

    def test_uleb_truncation_is_rejected(self):
        with self.assertRaises(ValueError):
            m.uleb(b'\x80', 0, 1)

    def test_object_delimiters_and_negative_controls(self):
        cases = [
            (True, b'', ('error', 3, 0)),
            (True, b' }', ('end', None, 1)),
            (False, b'}', ('end', None, 0)),
            (True, b'"p"', ('quoted_key_boundary', None, 1)),
            (False, b', "p"', ('quoted_key_boundary', None, 3)),
            (True, b',"p"', ('error', 17, 0)),
            (False, b'"p"', ('error', 8, 0)),
            (False, b', ', ('error', 5, 2)),
            (False, b', }', ('error', 21, 2)),
            (True, b'\x0b', ('error', 17, 0)),
        ]
        for first, data, expected in cases:
            with self.subTest(first=first, data=data):
                self.assertEqual(m.delimiter_probe('object', first, data, self.result['mask']), expected)

    def test_array_delimiters_and_negative_controls(self):
        cases = [
            (True, b'', ('error', 2, 0)),
            (True, b' ]', ('end', None, 1)),
            (True, b'"v"', ('string_value_boundary', None, 0)),
            (False, b', "v"', ('string_value_boundary', None, 2)),
            (True, b',"v"', ('string_value_boundary', None, 0)),
            (False, b'"v"', ('error', 7, 0)),
            (False, b', ', ('error', 5, 2)),
            (False, b', ]', ('error', 21, 2)),
        ]
        for first, data, expected in cases:
            with self.subTest(first=first, data=data):
                self.assertEqual(m.delimiter_probe('array', first, data, self.result['mask']), expected)

    def test_key_order_model_and_negative_controls(self):
        cases = [
            (b'', b'', ('equal', 0, None)),
            (b'', b'a', ('less', 0, None)),
            (b'a', b'', ('greater', 0, None)),
            (b'alpha', b'alpha', ('equal', 5, None)),
            (b'alpha', b'alphabet', ('less', 5, None)),
            (b'alphabet', b'alpha', ('greater', 5, None)),
            (b'Alpha', b'alpha', ('less', 5, 0)),
            (b'a\x00b', b'a\x00c', ('less', 3, 2)),
            (b'\xff', b'\x7f', ('greater', 1, 0)),
        ]
        for left, right, expected in cases:
            with self.subTest(left=left, right=right):
                self.assertEqual(m.key_order_probe(left, right), expected)
        with self.assertRaises(ValueError):
            m.key_order_probe('text', b'text')

    def test_binary_map_prefix_boundaries(self):
        cases = [
            (b'', ('need_marker', None, 0)),
            (bytes.fromhex('7f'), ('external_boundary', None, 1)),
            (bytes.fromhex('80'), ('map_count', 0, 1)),
            (bytes.fromhex('8f'), ('map_count', 15, 1)),
            (bytes.fromhex('90'), ('external_boundary', None, 1)),
            (bytes.fromhex('de'), ('truncated_length', None, 1)),
            (bytes.fromhex('de01'), ('truncated_length', None, 2)),
            (bytes.fromhex('de0102'), ('map_count', 258, 3)),
            (bytes.fromhex('deffffaa'), ('map_count', 65535, 3)),
            (bytes.fromhex('df010203'), ('truncated_length', None, 4)),
            (bytes.fromhex('df01020304'), ('map_count', 16909060, 5)),
            (bytes.fromhex('dfffffffff'), ('map_count', 4294967295, 5)),
            (bytes.fromhex('e0'), ('external_boundary', None, 1)),
        ]
        for data, expected in cases:
            with self.subTest(data=data.hex()):
                self.assertEqual(m.map_prefix_probe(data), expected)
        with self.assertRaises(ValueError):
            m.map_prefix_probe('not bytes')

    def test_probe_invalid_parameters_fail(self):
        for kind, first, payload in [('other', True, b''), ('object', 1, b''), ('object', True, '')]:
            with self.subTest(kind=kind, first=first), self.assertRaises(ValueError):
                m.delimiter_probe(kind, first, payload, self.result['mask'])

    def test_writes_only_declared_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            summary = m.generate(self.data, Path(directory))
            self.assertEqual(summary['delimiter_probes'], 23)
            self.assertEqual({p.name for p in Path(directory).iterdir()}, {
                'functions.tsv', 'instructions.tsv', 'branches.tsv', 'calls.tsv', 'witnesses.tsv',
                'prior-boundaries.tsv', 'binary-jump-tables.tsv', 'field-dispatch-boundary.tsv',
                'relocations.tsv', 'lsda-headers.tsv', 'exceptions.tsv', 'cfg-propositions.tsv',
                'delimiter-probes.tsv', 'binary-prefix-probes.tsv', 'key-order-probes.tsv', 'evidence.json'})


if __name__ == '__main__':
    unittest.main()
