"""Static and corruption controls for the selected node-94 key envelope."""
import csv
import io
import json
import unittest

from tools import aws_key_unit94 as m


class KeyEnvelopeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        data = (m.ROOT / m.ARTIFACT).read_bytes()
        cls.image = m.Image(data)
        # Keep mutations in process memory; never write the captured ELF.
        cls.image.data = bytearray(data)
        cls.selection = m.decode_selection(cls.image)
        cls.p = cls.selection['parameters']

    def with_byte(self, va, value, operation):
        pos = self.image.offset(va)
        original = self.image.data[pos]
        self.image.data[pos] = value
        try:
            return operation()
        finally:
            self.image.data[pos] = original

    def test_four_fdes_and_bytes(self):
        rows = self.selection['functions']
        self.assertEqual(len(rows), 4)
        self.assertEqual(sum(r['byte_count'] for r in rows), 776)
        self.assertEqual(sum(r['instruction_count'] for r in rows), 242)
        self.assertEqual({r['start'] for r in rows}, set(m.FUNCTIONS))

    def test_selected_calls_reach_the_expected_bodies(self):
        rows = {r['va']: r for r in self.selection['instructions']}
        self.assertEqual(rows[0x13aa226]['target'], 0x13f4250)
        self.assertEqual(rows[0x13aa27d]['target'], 0x13f4300)
        self.assertEqual(rows[0x13f4294]['target'], 0x1409860)
        self.assertEqual(rows[0x13f4266]['target'], rows[0x13f4310]['target'])

    def test_table_run_not_duplicated_name_table(self):
        table = self.selection['table']
        self.assertEqual(table['same_target_entries'], 76)
        self.assertEqual(table['target_va'], 0x13f428e)
        self.assertNotEqual(table['target_va'], table['following_target_va'])

    def test_all_direct_branches_land_on_instruction_starts(self):
        by_owner = {}
        for row in self.selection['instructions']:
            by_owner.setdefault(row['owner'], set()).add(row['va'])
        for row in self.selection['instructions']:
            if row['kind'] in ('branch', 'jump'):
                self.assertIn(row['target'], by_owner[row['owner']])

    def test_lsda_covers_both_delegations(self):
        rows = self.selection['lsda_records']
        self.assertEqual(len(rows), 4)
        entry = next(r for r in rows if 0x13aa226 in r['transfer_sites'])
        self.assertIn(0x13aa27d, entry['transfer_sites'])
        self.assertEqual(entry['landing'], 0x13aa2c1)
        self.assertEqual(entry['action'], 0)

    def test_structural_paths_cover_success_and_local_failures(self):
        paths = {r['label']:r for r in self.selection['cfg_paths']}
        self.assertEqual(len(paths), 15)
        for label in ('entry_to_map_call', 'entry_to_direct_call', 'entry_to_count_error',
                      'map_wrapper_to_unit_call', 'unit_call_to_key_write',
                      'unit_call_to_error_copy'):
            self.assertTrue(paths[label]['reachable'], label)
            self.assertEqual(paths[label]['witness'][0], paths[label]['start'])
            self.assertEqual(paths[label]['witness'][-1], paths[label]['goal'])
        self.assertFalse(paths['map_call_to_direct_call']['reachable'])
        self.assertFalse(paths['key_write_to_error_copy']['reachable'])

    def test_valid_but_redirected_branch_changes_structural_path(self):
        def check():
            decoded = [dict(row, owner=start) for start in m.FUNCTIONS
                       for row in m.walk(self.image, start)]
            with self.assertRaisesRegex(ValueError, 'unexpected structural path'):
                m.normal_flow(decoded, self.selection['table'])
        # Redirect an existing short jump to another valid instruction start.
        self.with_byte(0x13aa22c, 0x4d, check)

    def test_wrong_digest_fails_before_parsing(self):
        with self.assertRaisesRegex(ValueError, 'digest'):
            m.Image(b'not the authenticated ELF')
        def check():
            with self.assertRaisesRegex(ValueError, 'digest'):
                m.Image(self.image.data)
        self.with_byte(0x14098b4, 0x90, check)

    def test_modified_opcode_fails_body_contract(self):
        def check():
            with self.assertRaisesRegex(ValueError, 'FDE bytes'):
                m.decode_selection(self.image)
        self.with_byte(0x14098b4, 0x90, check)

    def test_changed_operand_fails_byte_contract(self):
        def check():
            with self.assertRaisesRegex(ValueError, 'byte contract'):
                self.image.pin(0x13aa1f9, m.PINS[0x13aa1f9])
        self.with_byte(0x13aa213 + 2, 2, check)

    def test_branch_into_an_operand_is_rejected(self):
        def check():
            with self.assertRaisesRegex(ValueError, 'instruction start'):
                m.walk(self.image, 0x1409860)
        self.with_byte(0x1409868, 0xff, check)

    def test_table_corruption_is_rejected(self):
        def check():
            with self.assertRaisesRegex(ValueError, 'table run'):
                m.decode_selection(self.image)
        self.with_byte(self.selection['table']['base_va'] + 4, 0, check)

    def test_lsda_encoding_corruption_is_rejected(self):
        addr = self.selection['lsda_header']['lsda_va'] + 3
        def check():
            with self.assertRaisesRegex(ValueError, 'call-site encoding'):
                m.decode_lsda(self.image, self.selection['functions'], self.selection['instructions'])
        self.with_byte(addr, 2, check)

    def test_cleanup_relocation_corruption_is_rejected(self):
        slot = 0x576e128
        old = self.image.relocations[slot]
        self.image.relocations[slot] = (old[0] + 1, old[1])
        try:
            with self.assertRaisesRegex(ValueError, 'relocation changed'):
                m.decode_selection(self.image)
        finally:
            self.image.relocations[slot] = old

    def test_relative_relocation_symbol_is_rejected(self):
        record_offset = self.image.relocations[0x576e128][1]
        position = record_offset + 12
        old = self.image.data[position]
        self.image.data[position] = 1
        try:
            with self.assertRaisesRegex(ValueError, 'relative relocation has a symbol'):
                m.Image(self.image.data, authenticate=False)
        finally:
            self.image.data[position] = old

    def test_unmapped_and_nobits_addresses_are_rejected(self):
        with self.assertRaisesRegex(ValueError, 'file-backed'):
            self.image.read((1 << 64) - 1, 1)
        section = next(s for s in self.image.sections if s['name'] == '.bss' and s['type'] == 8)
        with self.assertRaisesRegex(ValueError, 'file-backed'):
            self.image.read(section['address'], 1)
        with self.assertRaisesRegex(ValueError, 'range'):
            self.image.offset(0, 0)

    def test_all_marker_classes_and_boundary_points(self):
        p = self.p
        examples = {0x00:(0,0), 0x7f:(0,0x7f), 0x80:(0x80,0),
                    0x8f:(0x80,15), 0x90:(0x90,0), 0x9f:(0x90,15),
                    0xa0:(0xa0,0), 0xbf:(0xa0,31), 0xc0:(0xc0,0),
                    0xde:(0xde,30), 0xdf:(0xdf,31), 0xe0:(0xe0,0xe0),
                    0xff:(0xe0,0xff)}
        for marker, expected in examples.items():
            with self.subTest(marker=marker):
                self.assertEqual(m.normalize(marker,p), expected)
        for marker in range(256):
            cls, payload = m.normalize(marker,p)
            self.assertTrue(0 <= cls < 256 and 0 <= payload < 256)

    def test_invalid_model_input_rejected(self):
        for marker in (-1, 256, 1.5, None):
            with self.subTest(marker=marker), self.assertRaises(ValueError):
                m.normalize(marker, self.p)
        with self.assertRaises(ValueError):
            m.envelope_model('not bytes', self.p)
        with self.assertRaises(ValueError):
            m.envelope_model(b'', self.p, cached_class=256)

    def test_empty_marker_is_local_error(self):
        got = m.envelope_model(b'', self.p)
        self.assertEqual((got['route'], got['result_tag'], got['consumed']), ('no_marker',0,0))

    def test_fixed_map_only_one_entry_reaches_map_wrapper(self):
        for count in range(16):
            result = m.envelope_model(bytes([0x80 + count]), self.p)
            self.assertEqual(result['consumed'], 1)
            self.assertEqual(result['count'], count)
            self.assertEqual(result['route'], 'map_key_delegate' if count == 1 else 'count_error')
            if count != 1:
                self.assertEqual(result['result_tag'], 4)

    def test_non_map_marker_delegates_without_interpretation(self):
        for marker in (0, 31, 32, 0x7f, 0x90, 0xa0, 0xc0, 0xe0, 0xff):
            got = m.envelope_model(bytes([marker, 0xaa]), self.p)
            self.assertEqual((got['route'], got['consumed']), ('direct_delegate',1))
            self.assertIsNone(got['result_tag'])

    def test_map16_big_endian_count_and_remaining_byte(self):
        for count in (0, 1, 2, 255, 256, 65535):
            data = b'\xde' + count.to_bytes(2, 'big') + b'\xaa'
            got = m.envelope_model(data, self.p)
            self.assertEqual(got['count'], count)
            self.assertEqual(got['consumed'], 3)
            self.assertEqual(got['route'], 'map_key_delegate' if count == 1 else 'count_error')

    def test_map32_big_endian_count(self):
        for count in (0, 1, 2, 65535, 65536, (1 << 32) - 1):
            data = b'\xdf' + count.to_bytes(4, 'big')
            got = m.envelope_model(data, self.p)
            self.assertEqual(got['count'], count)
            self.assertEqual(got['consumed'], 5)
            self.assertEqual(got['route'], 'map_key_delegate' if count == 1 else 'count_error')

    def test_short_headers_exhaust_then_delegate(self):
        for marker, width in ((0xde, 2), (0xdf, 4)):
            for size in range(width):
                data = bytes([marker]) + bytes([0x7f] * size)
                got = m.envelope_model(data, self.p)
                self.assertEqual(got['route'], 'truncated_prefix_delegate')
                self.assertEqual(got['consumed'], len(data))
                self.assertIsNone(got['result_tag'])

    def test_cached_and_fresh_header_consumption(self):
        fresh = m.envelope_model(b'\xde\x00\x01\xff', self.p)
        cached = m.envelope_model(b'\x00\x01\xff', self.p,
                                  cached_class=0xde, cached_payload=30)
        self.assertEqual(fresh['route'], 'map_key_delegate')
        self.assertEqual(cached['route'], fresh['route'])
        self.assertEqual((fresh['consumed'], cached['consumed']), (3,2))
        self.assertEqual((fresh['cache_class'], cached['cache_class']), (1,1))

    def test_one_unit_marker_succeeds(self):
        outcomes = [m.unit_model(i,self.p)['result_tag'] for i in range(256)]
        self.assertEqual([i for i, tag in enumerate(outcomes) if tag == 9], [0xc0])
        self.assertEqual(outcomes.count(2), 255)

    def test_unit_eof_consumes_nothing_and_fields_are_unknown(self):
        got = m.unit_model(None,self.p)
        self.assertEqual(got, {'result_tag':0, 'consumed':0, 'class':None, 'payload':None})

    def test_unit_error_classification(self):
        for marker, pair in ((0x01,(0,1)), (0x8f,(0x80,15)),
                             (0x9f,(0x90,15)), (0xbf,(0xa0,31)),
                             (0xc1,(0xc1,0xc1)), (0xdf,(0xdf,0xdf)),
                             (0xff,(0xe0,0xff))):
            got = m.unit_model(marker,self.p)
            self.assertEqual((got['class'],got['payload']),pair)
            self.assertEqual(got['consumed'],1)
            self.assertEqual(got['result_tag'],2)

    def test_key_success_preserves_index_and_unit_failure_is_copied(self):
        count = self.selection['table']['same_target_entries']
        for index in (0, 31, 32, 33, count - 1):
            self.assertEqual(m.map_result_model(9,index,9,self.p,count),
                             {'route':'write_key','result_tag':9,'index':index})
            self.assertEqual(m.map_result_model(9,index,2,self.p,count)['route'], 'copy_unit_error')

    def test_name_error_returns_without_unit(self):
        for tag in (0,1,2,4,6,8):
            self.assertEqual(m.map_result_model(tag,None,None,self.p,76),
                             {'route':'copy_name_error','result_tag':tag,'index':None})

    def test_out_of_range_index_is_not_modeled_as_valid(self):
        for index in (-1,76,255):
            with self.assertRaisesRegex(ValueError, 'outside checked'):
                m.map_result_model(9,index,9,self.p,76)

    def test_outputs_have_expected_complete_cases(self):
        files = m.outputs(self.image)
        summary = json.loads(files['summary.json'])
        self.assertEqual(summary['target_sha256'], m.DIGEST)
        self.assertEqual(summary['metrics']['lsda_records'], 4)
        self.assertEqual(summary['metrics']['cfg_queries'], 15)
        for name, expected in (('marker-cases.tsv',256),('unit-cases.tsv',257),
                               ('prefix-cases.tsv',69),('wrapper-cases.tsv',21)):
            rows = list(csv.DictReader(io.StringIO(files[name]),delimiter='\t'))
            self.assertEqual(len(rows),expected)


if __name__ == '__main__':
    unittest.main()
