import hashlib
from pathlib import Path
import struct
import tempfile
import unittest

from tools import config_address_query94 as m


class AddressQueryEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = m.ARTIFACT.read_bytes()
        m.checked_digest(cls.data)
        cls.secs = m.sections(cls.data)
        cls.meta, cls.windows, cls.edges = m.collect(cls.data)

    def test_digest_and_size_reject_changed_input(self):
        self.assertEqual(m.checked_digest(self.data), m.SHA256)
        altered = bytearray(self.data)
        altered[0x100] ^= 1
        with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
            m.checked_digest(altered)
        with self.assertRaises(ValueError):
            m.checked_digest(memoryview(self.data)[:-1])

    def test_fde_extents_and_raw_body_hashes(self):
        self.assertEqual(len(self.meta['fdes']), 11)
        for row, (label, start, end) in zip(self.meta['fdes'], m.SELECTED):
            self.assertEqual((row['label'], row['start_va'], row['end_va_exclusive']),
                             (label, hex(start), hex(end)))
            raw = bytes.fromhex(row['body_bytes_hex'])
            self.assertEqual(len(raw), end - start)
            self.assertEqual(hashlib.sha256(raw).hexdigest(), row['body_sha256'])
            self.assertEqual(raw, m.at(self.data, self.secs, start, end - start))

    def test_route_vtable_and_global_are_relocation_linked(self):
        relocs = {r['slot_va']: r for r in self.meta['relocations']}
        self.assertEqual(relocs['0x5691978']['addend'], '0x1f9a950')
        self.assertEqual(relocs['0x5691980']['addend'], '0x1f6f830')
        self.assertEqual(relocs['0x5691988']['addend'], '0x1f6f830')
        self.assertEqual(relocs['0x576e928']['addend'], '0x577b288')
        self.assertEqual(relocs['0x5773960']['addend'], '0x5786388')
        self.assertEqual(self.meta['comparison_dynamic_symbol'], 'memcmp')
        self.assertEqual(self.meta['copy_dynamic_symbol'], 'memcpy')
        self.assertEqual((self.meta['vtable_size'], self.meta['vtable_alignment']), (8, 8))
        rip = {row['label']: row['target_va'] for row in self.meta['rip_targets']}
        self.assertEqual(rip['method_literal'], '0x3f078c')
        self.assertEqual(rip['constructor_vtable'], '0x5691960')
        self.assertEqual(rip['name_cell_slot'], '0x576e928')

    def test_transfer_directions_and_jump_no_fallthrough(self):
        edges = {row[0]: row for row in self.edges}
        self.assertEqual(edges['wrapper_to_callback'][4], '0x1f6f830')
        self.assertEqual(edges['callback_to_lookup'][4], '0x27baca0')
        self.assertEqual(edges['required_address_missing'][4], '0x1ca403c')
        self.assertEqual(edges['object_to_lookup_path'][2], 'jump')
        self.assertEqual(edges['object_to_lookup_path'][5], '')
        self.assertEqual(edges['name_above_mask_range'][4], '0x27bafba')
        self.assertEqual(edges['builder_to_serializer'][4], '0x29769c0')
        self.assertEqual(edges['serializer_boolean_to_writer'][4], '0x25acd00')
        self.assertEqual(edges['registration_to_entry_helper'][4], '0x2a48ad0')
        self.assertEqual(edges['writer_needs_growth'][4], '0x25acea9')

    def test_name_gate_all_byte_values_and_boundary(self):
        mask = int(self.meta['name_mask_u32'], 16)
        expected = {13, 14, 18, 19, 20, 21, 31}
        self.assertEqual({n for n in range(256) if m.name_selected(n, mask)}, expected)
        self.assertTrue(m.name_selected(31, mask))
        self.assertFalse(m.name_selected(32, mask))
        # x86 bit-test masks the bit index, but the preceding range check
        # prevents byte 45 from aliasing selected bit 13.
        self.assertFalse(m.name_selected(45, mask))
        self.assertFalse(m.name_selected(255, mask))
        for invalid in (-1, 256):
            with self.assertRaises(ValueError):
                m.name_selected(invalid, mask)
        names = {r['discriminant']: r for r in self.meta['name_descriptors']}
        self.assertEqual(names[31]['name'], 'SoloSandbox')
        self.assertEqual(names[32]['name'], 'NvTestnet')
        self.assertFalse(names[32]['mask_selected'])

    def test_overlapping_key_comparison_has_seven_byte_coverage(self):
        key = b'address'
        self.assertTrue(m.key_matches(key, key))
        self.assertFalse(m.key_matches(key[:-1], key))
        self.assertFalse(m.key_matches(key + b'x', key))
        for i in range(len(key)):
            altered = key[:i] + bytes([key[i] ^ 1]) + key[i + 1:]
            self.assertFalse(m.key_matches(altered, key), i)
        self.assertEqual([r['matches'] for r in self.meta['key_comparison_controls']],
                         [True] + [False] * 7)
        with self.assertRaises(ValueError):
            m.key_matches(key, b'bad')

    def test_constants_and_empty_argument_error_evidence(self):
        constants = self.meta['literals_and_constants']
        self.assertEqual(constants['method'], 'eth_usingBigBlocks')
        self.assertEqual(constants['field'], 'address')
        self.assertEqual(constants['diagnostic_field'], 'address')
        self.assertEqual(constants['empty_array'], '[]')
        self.assertEqual(constants['threshold_f64'], 3.0)
        self.assertEqual(constants['whitespace_mask_u64'], '0x100002600')
        self.assertEqual(constants['no_more_params'], 'No more params')
        self.assertEqual(constants['invalid_params_text'], 'Invalid params')
        self.assertEqual(constants['positional_error_code'], -32602)
        self.assertEqual(constants['jsonrpc_field'], 'jsonrpc')
        self.assertEqual(constants['jsonrpc_version'], '2.0')
        self.assertEqual(constants['id_field'], 'id')
        self.assertEqual(constants['result_field'], 'result')
        self.assertEqual(constants['bool_false'], 'false')
        self.assertEqual(constants['bool_true'], 'true')

    def test_serialized_boolean_selection(self):
        self.assertEqual(m.boolean_selection(0), ('false', 5))
        self.assertEqual(m.boolean_selection(1), ('true', 4))
        for invalid in (-1, 256):
            with self.assertRaises(ValueError):
                m.boolean_selection(invalid)

    def test_timing_branch_ordered_boundary(self):
        threshold = self.meta['literals_and_constants']['threshold_f64']
        self.assertFalse(m.exceeds_threshold(2.999, threshold))
        self.assertFalse(m.exceeds_threshold(threshold, threshold))
        self.assertTrue(m.exceeds_threshold(3.001, threshold))
        self.assertFalse(m.exceeds_threshold(float('nan'), threshold))
        self.assertTrue(m.exceeds_threshold(float('inf'), threshold))
        self.assertEqual([r['enters_name_check'] for r in self.meta['timing_controls']],
                         [False, False, True, False])

    def test_code_window_corruption_rejected_even_without_digest_gate(self):
        altered = bytearray(self.data)
        offset, _ = m.va_offset(self.secs, 0x27bafa3, 1)
        altered[offset] ^= 1
        with self.assertRaisesRegex(ValueError, 'window mismatch'):
            m.collect(altered)

    def test_branch_corruption_and_unknown_opcode_rejected(self):
        altered = bytearray(self.data)
        offset, _ = m.va_offset(self.secs, 0x1f6f993, 5)
        altered[offset + 1] ^= 1
        _, _, target = m.rel_target(altered, self.secs, 0x1f6f993)
        self.assertNotEqual(target, 0x27baca0)
        with self.assertRaisesRegex(ValueError, 'window mismatch'):
            m.collect(altered)
        altered[offset] = 0x90
        with self.assertRaisesRegex(ValueError, 'unsupported transfer opcode'):
            m.rel_target(altered, self.secs, 0x1f6f993)

    def test_relocation_corruption_rejected_even_without_digest_gate(self):
        altered = bytearray(self.data)
        section = next(s for s in self.secs if s['name'] == '.rela.dyn')
        slot = 0x5691978
        matches = [pos for pos in range(section['offset'], section['offset'] + section['size'], 24)
                   if struct.unpack_from('<Q', altered, pos)[0] == slot]
        self.assertEqual(len(matches), 1)
        altered[matches[0] + 16] ^= 1
        with self.assertRaisesRegex(ValueError, 'relocation mismatch'):
            m.collect(altered)

    def test_address_mapping_rejects_nobits_ambiguity_and_crossing(self):
        file_section = {'type': 1, 'flags': 2, 'address': 0x100, 'offset': 0x20, 'size': 8, 'name': 'file'}
        bss = {'type': 8, 'flags': 2, 'address': 0x200, 'offset': 0x28, 'size': 8, 'name': 'bss'}
        self.assertEqual(m.va_offset([file_section, bss], 0x107, 1), (0x27, 'file'))
        for address, size in ((0x107, 2), (0x108, 1), (0x200, 1), (-1, 1), (0x100, 0)):
            with self.subTest(address=address, size=size):
                with self.assertRaises(ValueError):
                    m.va_offset([file_section, bss], address, size)
        with self.assertRaises(ValueError):
            m.va_offset([file_section, dict(file_section)], 0x100, 1)

    def test_relocation_and_rip_negative_controls(self):
        with self.assertRaisesRegex(ValueError, 'absent'):
            m.relocation_map(self.data, self.secs, {0x7fffffffffffffff})
        with self.assertRaisesRegex(ValueError, 'opcode mismatch'):
            m.rip_target(self.data, self.secs, 0x27baf85, '488d05')
        with self.assertRaisesRegex(ValueError, 'symbol table index'):
            m.dynsym_name(self.data, self.secs, 100000)

    def test_generate_is_deterministic_and_digest_failure_has_no_output(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            m.generate(self.data, base / 'one')
            m.generate(self.data, base / 'two')
            for name in ('path.json', 'windows.tsv', 'transfers.tsv'):
                self.assertEqual((base / 'one' / name).read_bytes(), (base / 'two' / name).read_bytes())
            with self.assertRaises(ValueError):
                m.generate(b'not an ELF', base / 'bad')
            self.assertFalse((base / 'bad').exists())


if __name__ == '__main__':
    unittest.main()
