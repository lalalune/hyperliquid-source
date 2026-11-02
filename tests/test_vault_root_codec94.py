"""Target-grounded and corruption controls for the selected Vault codec."""
import hashlib
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import vault_root_codec94 as v
from elf_index import sections


class VaultRootCodec94Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = v.BINARY.read_bytes()
        cls.secs = sections(cls.data)
        cls.result = v.analyze(cls.data)

    def mutated(self, va):
        _, off = v.location(self.secs, va, 1)
        data = bytearray(self.data)
        data[off] ^= 1
        return data

    def test_original_digest_and_bad_digest(self):
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), v.DIGEST)
        with self.assertRaisesRegex(ValueError, 'digest'):
            v.check_digest(self.data, '0' * 64)

    def test_fields_order_and_distinct_names(self):
        fields = self.result['fields']
        self.assertEqual([x['name'] for x in fields], [
            'name', 'description', 'create_time', 'vault_user', 'leader',
            'user_states', 'leader_commission', 'is_closed', 'lockup_duration',
            'allow_deposits', 'relationship', 'always_close_on_withdraw', 's'])
        self.assertEqual([x['input_offset'] for x in fields],
                         [40, 64, 120, 132, 152, 80, 104, 172, 112, 173, 0, 174, 175])
        self.assertEqual(len({x['name'] for x in fields}), 13)
        self.assertTrue(all(int(x['failure_target_va'], 16) for x in fields))
        self.assertTrue(all(int(x['direct_failure_target_va'], 16) for x in fields))
        self.assertTrue(all(int(x['direct_copy_input_site_va'], 16) -
                            int(x['direct_input_site_va'], 16) == 0x3953470 - 0x23406d0
                            for x in fields))

    def test_missing_and_duplicate_names(self):
        all_names = {row['name'] for row in self.result['fields']}
        missing = {row['name'] for row in self.result['missing_diagnostics']}
        duplicate = {row['name'] for row in self.result['duplicate_diagnostics']}
        self.assertEqual(len(missing), 10)
        self.assertEqual(duplicate, all_names)
        self.assertEqual(all_names - missing,
                         {'allow_deposits', 'always_close_on_withdraw', 's'})
        self.assertEqual(len(self.result['duplicate_diagnostics']), 13)

    def test_marker_modes_and_bounded_defaults(self):
        self.assertEqual(self.result['direct_markers'], [
            {'mode': 0, 'marker': '0x9d'}, {'mode': 1, 'marker': '0x8d'}])
        self.assertEqual([v.allow_default(i) for i in (0, 1, 2)], [0, 1, 1])
        self.assertEqual([v.bit_default(i) for i in (0, 1, 2)], [0, 1, 0])
        for bad in (-1, 3, 255):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    v.allow_default(bad)
                with self.assertRaises(ValueError):
                    v.bit_default(bad)
        self.assertEqual((self.result['s_bit_zero'], self.result['s_bit_one']), ('D', 'U'))

    def test_root_bridge_chain(self):
        calls = {row['name']: row['target_va'] for row in self.result['calls']}
        self.assertEqual(calls['existing_root_closure_context'], '0x25dbd30')
        self.assertEqual(calls['bridge_to_collector'], '0x257b7e0')
        self.assertEqual(calls['bridge_to_sequence'], '0x1e45bc0')
        self.assertEqual(calls['outer_reader_entries'], '0x2641c60')
        self.assertEqual(calls['reader_key'], '0x16a54a0')
        self.assertEqual(calls['pair_buffered_key'], '0x1e11630')
        self.assertEqual(calls['pair_direct_key'], '0x1e10fb0')
        self.assertEqual(calls['sequence_to_loop_pair'], '0x1de2ea0')
        self.assertEqual(calls['pair_buffered'], '0x2340f40')
        self.assertEqual(calls['pair_direct'], '0x23406d0')
        self.assertEqual(self.result['root_closure_context']['serializer_mode_byte'], 1)

    def test_outer_fixmap_boundary(self):
        self.assertIsNone(v.fixmap_count(0x7f))
        self.assertEqual(v.fixmap_count(0x80), 0)
        self.assertEqual(v.fixmap_count(0x8f), 15)
        self.assertIsNone(v.fixmap_count(0x90))
        for bad in (-1, 256):
            with self.assertRaises(ValueError):
                v.fixmap_count(bad)

    def test_pair_layout_and_key_helper_relocation(self):
        pair = self.result['pair_layout']
        self.assertEqual((pair['key_array_offset'], pair['key_stride'], pair['value_stride'],
                          pair['pair_stride']), (0x798, 20, 176, 16))
        self.assertEqual((pair['key_input_bytes'], pair['key_buffer_bytes']), (20, 42))
        self.assertEqual(pair['hex_alphabet'], '0123456789abcdef')
        self.assertEqual(pair['reader_label'], 'Address')
        self.assertEqual(self.result['duplicate_key_diagnostic'], 'duplicate key')
        self.assertEqual(pair['hex_relocation']['addend_va'], '0x29ed380')
        self.assertEqual((pair['hex_relocation']['type'], pair['hex_relocation']['symbol_index']), (8, 0))

    def test_allocation_guard_boundary(self):
        self.assertEqual(self.result['empty_collector_pointer'], 8)
        limit = self.result['allocation_limit']
        last = limit // 16
        self.assertTrue(v.allocation_precheck(last)['passes'])
        self.assertFalse(v.allocation_precheck(last + 1)['passes'])
        self.assertTrue(v.allocation_precheck(1 << 60)['high_bits_nonzero'])
        self.assertFalse(v.allocation_precheck((1 << 64) - 1)['passes'])
        for bad in (-1, 1 << 64):
            with self.assertRaises(ValueError):
                v.allocation_precheck(bad)

    def test_relocation_corruption_after_rehash(self):
        off = int(self.result['pair_layout']['hex_relocation']['file_offset'], 16)
        data = bytearray(self.data)
        data[off + 16] ^= 1
        with self.assertRaisesRegex(ValueError, 'helper relocation changed'):
            v.analyze(data, v.sha(data))

    def test_fde_ranges_and_copy_sites(self):
        f = {row['name']: row for row in self.result['functions']}
        self.assertEqual(len(f), 20)
        self.assertEqual((f['map_reader']['start_va'], f['map_reader']['end_va_exclusive']),
                         ('0x19f9a50', '0x19fe747'))
        self.assertTrue(all(row['section'] == '.text' for row in f.values()))
        for row in self.result['fields']:
            self.assertEqual(int(row['copy_input_site_va'], 16) - int(row['input_site_va'], 16),
                             0x3953130 - 0x2340f40)

    def test_direct_call_corruption(self):
        data = self.mutated(0x25dbda8)
        with self.assertRaises(ValueError):
            v.call_target(data, self.secs, 0x25dbda8)
        with self.assertRaisesRegex(ValueError, 'body differs'):
            v.analyze(data, v.sha(data))

    def test_root_context_call_corruption_after_rehash(self):
        data = self.mutated(0x2818841)
        with self.assertRaisesRegex(ValueError, 'call target changed'):
            v.analyze(data, v.sha(data))

    def test_selected_branch_corruption(self):
        data = self.mutated(0x19fd962)
        with self.assertRaises(ValueError):
            v.branch_target(data, self.secs, 0x19fd962, '0f85')
        with self.assertRaisesRegex(ValueError, 'body differs'):
            v.analyze(data, v.sha(data))

    def test_name_byte_corruption_after_rehash(self):
        data = self.mutated(0x3dfa18)
        with self.assertRaisesRegex(ValueError, 'field label changed'):
            v.analyze(data, v.sha(data))

    def test_root_mode_corruption_after_rehash(self):
        data = self.mutated(0x281882c)
        with self.assertRaisesRegex(ValueError, 'root closure call context changed'):
            v.analyze(data, v.sha(data))

    def test_s_literal_corruption_after_rehash(self):
        data = self.mutated(0x3dfbdb)
        with self.assertRaisesRegex(ValueError, 's alternatives changed'):
            v.analyze(data, v.sha(data))

    def test_default_instruction_corruption_after_rehash(self):
        data = self.mutated(0x19f9e70)
        with self.assertRaisesRegex(ValueError, 'body differs'):
            v.analyze(data, v.sha(data))

    def test_range_and_nonfile_backed_rejected(self):
        for va, size in ((-1, 1), (0, 0), (1 << 62, 8)):
            with self.subTest(va=va, size=size):
                with self.assertRaises(ValueError):
                    v.va_bytes(self.data, self.secs, va, size)
        nobits = next(s for s in self.secs if s['type'] == 8 and s['size'] > 0)
        with self.assertRaises(ValueError):
            v.va_bytes(self.data, [nobits], nobits['address'], 1)
        text = next(s for s in self.secs if s['name'] == '.text')
        with self.assertRaisesRegex(ValueError, 'beyond input'):
            v.va_bytes(self.data[:16], [text], text['address'], 1)
        with self.assertRaises(ValueError):
            v.va_bytes(self.data, [text, text], text['address'], 1)

    def test_length_and_opcode_controls(self):
        data = self.mutated(0x2340fca)
        with self.assertRaises(ValueError):
            v.field_label(data, self.secs, 0x2340fc3)
        data = self.mutated(0x2340fb4)
        with self.assertRaises(ValueError):
            v.input_offset(data, self.secs, 0x2340fb4, '4d8b67', 1)


if __name__ == '__main__':
    unittest.main()
