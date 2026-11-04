"""Controls for the digest-bound node #115 configuration trace."""
from pathlib import Path
import hashlib
import tempfile
import unittest
from unittest import mock

from tools import node115_config_trace as trace


class ConfigTraceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.blob = (trace.ROOT / 'artifacts/node/115/hl-node').read_bytes()
        cls.image = trace.Image(cls.blob)
        cls.record = trace.collect(cls.image)

    def test_complete_selected_extents_and_independent_partitions(self):
        metrics = self.record['metrics']
        self.assertEqual(metrics['selected_fde_bodies'], 23)
        self.assertEqual(metrics['selected_body_bytes'], 23939)
        self.assertEqual(metrics['structurally_decoded_instructions'], 5831)
        self.assertEqual(metrics['plain_matcher_bytes'], 2246)
        self.assertEqual(metrics['quoted_matcher_bytes'], 2785)
        self.assertEqual(metrics['renderer_bytes'], 1681)
        self.assertEqual(sum(row['size'] for body in self.record['instructions'].values()
                             for row in body), metrics['selected_body_bytes'])
        self.assertEqual(metrics['lsda_tables'], 12)
        self.assertEqual(metrics['lsda_callsite_ranges'], 77)
        for table in self.record['exceptions']:
            for site in table['sites']:
                self.assertLess(int(site['start_va'], 16), int(site['end_va'], 16))

    def test_three_independent_name_paths_and_list(self):
        names = self.record['names']
        self.assertEqual(len(names), 79)
        self.assertEqual([row['tag'] for row in names], list(range(79)))
        self.assertEqual(len({row['name'] for row in names}), 79)
        self.assertEqual(self.record['metrics']['renderer_and_error_list_same_pointer'], 79)
        by_name = {row['name']:row for row in names}
        for name, tag in (('EaTx', 13), ('SoloSandbox', 32), ('NvTestnet', 33),
                          ('NvTestnet2', 34), ('NvMainnet3', 37),
                          ('JoinMainnet', 38), ('DummyNv', 39), ('FBinSpot', 40),
                          ('EbHlPerp', 78)):
            with self.subTest(name=name):
                self.assertEqual(by_name[name]['tag'], tag)
        self.assertEqual(self.record['plain']['failure_value'], 79)
        self.assertEqual(self.record['metrics']['config_default_tag'], 33)
        self.assertEqual(self.record['quoted']['failure_va'], '0x1774946')
        self.assertEqual(self.record['metrics']['envelope_paths_agree'], 79)
        self.assertEqual(by_name['NvTestnet']['quoted_envelope_arm_va'], '0x1773284')
        self.assertEqual(by_name['NvTestnet']['object_envelope_arm_va'], '0x1773736')

    def test_exact_input_contract_negative_cases(self):
        # This is a model of the extracted static predicates, not target execution.
        names = {row['name'].encode('ascii'):row['tag'] for row in self.record['names']}
        for name, tag in names.items():
            with self.subTest(name=name):
                self.assertEqual(names.get(name), tag)
                self.assertNotIn(name+b'\x00', names)
                changed = bytes([0])+name[1:]
                self.assertNotIn(changed, names)
        for value in (b'', b'E', b'Nvtestnet', b'NvTestnet ', b' NvTestnet', b'\"NvTestnet\"'):
            self.assertNotIn(value, names)
        self.assertEqual(self.record['plain']['minimum_length'], 2)
        self.assertEqual(self.record['plain']['maximum_length'], 13)
        by_len = {x['length']:x['accepted'] for x in self.record['plain']['buckets']}
        self.assertEqual((by_len[5], by_len[6]), (0, 0))

    def test_templates_reference_entry_headers(self):
        entries = {x['name']:x for x in self.record['templates']}
        for name, literal in (('cham','/cham'), ('hl','/hl'), ('code','/code'),
                              ('static_config','/static_config'), ('aws_name','/aws_name')):
            item = entries[name]
            raw = bytes.fromhex(item['entry_bytes'])
            self.assertEqual(raw[0], 0xc0)
            self.assertEqual(raw[1], len(literal))
            self.assertEqual(raw[2:-1], literal.encode('ascii'))
            self.assertEqual(raw[-1], 0)
            self.assertEqual(int(item['literal_va'],16), int(item['entry_va'],16)+2)

    def test_dynamic_symbol_and_result_landmarks(self):
        by_name = {x['name']:x for x in self.record['landmarks']}
        for key, symbol in (('open64_slot','open64'), ('read_slot','read'),
                            ('read_close_slot','close'), ('read_fstat_slot','fstat64'),
                            ('create_first_mkdir','mkdir'), ('stat64_slot','stat64'),
                            ('open64_errno_slot','__errno_location')):
            self.assertEqual(by_name[key]['dynamic_symbol'], symbol)
        self.assertEqual(by_name['read_interrupted_retry']['target_or_slot_va'], '0x5c756c0')
        self.assertEqual(by_name['fallback_plain_matcher']['relative_addend_va'], '0x1775500')
        self.assertEqual(by_name['select_creation_mode']['immediate'], 511)
        self.assertEqual(by_name['select_recursive_flag']['immediate'], 1)
        self.assertEqual(by_name['config_read_error_default']['immediate'], 33)
        self.assertEqual(by_name['config_parse_error_default']['immediate'], 33)
        self.assertEqual(self.record['trailing_whitespace_bytes'], [9, 10, 13, 32])
        self.assertNotIn(11, self.record['trailing_whitespace_bytes'])
        self.assertNotIn(12, self.record['trailing_whitespace_bytes'])

    def test_selected_open_case(self):
        case = self.record['open_case']
        self.assertEqual(case['short_path_max_bytes'], 383)
        self.assertEqual(case['option_bytes'], '00000000b6010000010000000000')
        self.assertEqual(case['open64_flags'], '0x80000')
        self.assertEqual(case['open64_mode_argument'], '0x1b6')
        self.assertEqual(case['access_flag_masked_value'], 0)

    def test_changed_open_options_rejected(self):
        index = {r['va']:dict(r) for body in self.record['instructions'].values() for r in body}
        index[0x5ca4975]['bytes'] = 'c645b800'
        index[0x5ca4975]['immediate'] = 0
        with self.assertRaisesRegex(ValueError, 'open-option instruction changed'):
            trace.read_only_open_case(index)

    def test_authentication_rejects_truncated_and_corrupt_capture(self):
        with self.assertRaisesRegex(ValueError, 'size or SHA-256'):
            trace.verify_digest(memoryview(self.blob)[:-1])
        altered = bytearray(self.blob)
        altered[0] ^= 1
        with self.assertRaisesRegex(ValueError, 'size or SHA-256'):
            trace.Image(altered)

    def test_unbacked_and_ambiguous_addresses_fail(self):
        bss = next(s for s in self.image.sections if s['name'] == '.bss')
        self.assertEqual(bss['type'], 8)
        for address, size in ((-1, 1), (0x10000000000000000, 1), (bss['address'], 1)):
            with self.subTest(address=address), self.assertRaises(ValueError):
                self.image.offset(address, size)
        with self.assertRaises(ValueError):
            self.image.offset(trace.PARSER, 0)
        sec = next(s for s in self.image.sections if s['name'] == '.text')
        self.image.sections.append(dict(sec))
        try:
            with self.assertRaisesRegex(ValueError, 'unique'):
                self.image.offset(trace.PARSER, 1)
        finally:
            self.image.sections.pop()

    def test_instruction_reader_rejects_truncation(self):
        with self.assertRaisesRegex(ValueError, 'truncated'):
            trace.decode(bytes.fromhex('0f850000'), trace.PARSER)
        with self.assertRaisesRegex(ValueError, 'unsupported'):
            trace.decode(b'\x60', trace.PARSER)

    def test_branch_to_instruction_interior_is_rejected(self):
        start = 0x17783e0
        fde = self.image.fdes[start]
        body = bytearray(self.image.read(start, fde['end']-start))
        branch = 0x1778452-start
        self.assertEqual(body[branch:branch+2], bytes.fromhex('712f'))
        body[branch+1] += 1
        with self.assertRaisesRegex(ValueError, 'instruction interior'):
            trace.decode(body, start)

    def test_body_hash_rejects_unpinned_instruction_corruption(self):
        image = self.image
        start = 0x17783e0
        original = image.read
        def read(va, size):
            result = original(va, size)
            if va == start and size == image.fdes[start]['end']-start:
                changed = bytearray(result)
                changed[-1] ^= 1
                return bytes(changed)
            return result
        with mock.patch.object(image, 'read', side_effect=read):
            with self.assertRaisesRegex(ValueError, 'body changed'):
                trace.collect(image)

    def test_fde_shortening_rejected(self):
        row = self.image.fdes[0x17780c0]
        old = row['end']
        row['end'] -= 1
        try:
            with self.assertRaisesRegex(ValueError, 'extent changed'):
                trace.collect(self.image)
        finally:
            row['end'] = old

    def test_unwind_index_fde_mismatch_rejected(self):
        row = self.image.index_entries[0x17783e0]
        old = row['fde']
        row['fde'] += 1
        try:
            with self.assertRaisesRegex(ValueError, 'unwind index and FDE disagree'):
                trace.collect(self.image)
        finally:
            row['fde'] = old

    def test_parser_length_table_outside_extent_rejected(self):
        table = int(self.record['plain']['table'], 16)
        original = self.image.s32
        def altered(address):
            if address == table:
                return 0x7fffffff
            return original(address)
        with mock.patch.object(self.image, 's32', side_effect=altered):
            with self.assertRaisesRegex(ValueError, 'outside FDE'):
                trace.parser(self.image)

    def test_renderer_shifted_arm_rejected(self):
        table = int(self.record['renderer']['table'], 16)
        original = self.image.s32
        def altered(address):
            result = original(address)
            return result+1 if address == table+33*4 else result
        with mock.patch.object(self.image, 's32', side_effect=altered):
            with self.assertRaises(ValueError):
                trace.renderer(self.image)

    def test_envelope_object_table_corruption_rejected(self):
        slot = 0x481a64 + 33*4
        original = self.image.s32
        def altered(address):
            result = original(address)
            return result+1 if address == slot else result
        with mock.patch.object(self.image, 's32', side_effect=altered):
            with self.assertRaisesRegex(ValueError, 'not an instruction start'):
                trace.collect(self.image)

    def test_json_error_branch_corruption_rejected(self):
        original = self.image.read
        def altered(va, size):
            data = original(va, size)
            if va == 0x1774946:
                data = bytes([data[0]^1])+data[1:]
            return data
        with mock.patch.object(self.image, 'read', side_effect=altered):
            with self.assertRaisesRegex(ValueError, 'encoding mismatch'):
                trace.json_parser(self.image)

    def test_input_constraint_out_of_range_rejected(self):
        chain = trace.Chain(self.image, self.image.fdes[trace.PARSER]['end'], 9)
        with self.assertRaisesRegex(ValueError, 'outside length bucket'):
            chain.memory(8, 2, trace.PARSER)
        with self.assertRaisesRegex(ValueError, 'does not constrain every input byte'):
            trace.constraints(trace.constant(0, 1), 1)
        conflict = [frozenset({('input', 0), ord('A')}),
                    frozenset({('input', 0), ord('B')})]
        with self.assertRaises(ValueError):
            trace.constraints(['or', tuple(conflict[:1]), tuple(conflict[1:])], 1)

    def test_relative_target_corruption_rejected(self):
        slot = 0x64e2400
        old = self.image.relocations[slot]
        self.image.relocations[slot] = (old[0], old[1]+1)
        try:
            with self.assertRaisesRegex(ValueError, 'RELATIVE addend changed'):
                trace.collect(self.image)
        finally:
            self.image.relocations[slot] = old

    def test_name_list_pointer_corruption_rejected(self):
        row = next(x for x in self.record['names'] if x['name'] == 'NvTestnet')
        slot = int(row['list_slot_va'], 16)
        old = self.image.relocations[slot]
        self.image.relocations[slot] = (old[0], old[1]+1)
        try:
            with self.assertRaisesRegex(ValueError, 'name list disagrees'):
                trace.collect(self.image)
        finally:
            self.image.relocations[slot] = old

    def test_dynamic_symbol_corruption_rejected(self):
        slot = 0x64e2310
        old = self.image.symbols[slot]
        self.image.symbols[slot] = (old[0], old[1], 'unrelated_symbol')
        try:
            with self.assertRaisesRegex(ValueError, 'dynamic symbol binding changed'):
                trace.collect(self.image)
        finally:
            self.image.symbols[slot] = old

    def test_template_terminator_corruption_rejected(self):
        item = next(x for x in self.record['templates'] if x['name'] == 'static_config')
        terminator = int(item['literal_va'],16) + item['length']
        original = self.image.read
        def altered(va, size):
            return b'\x01' if va == terminator and size == 1 else original(va, size)
        with mock.patch.object(self.image, 'read', side_effect=altered):
            with self.assertRaisesRegex(ValueError, 'template entry changed'):
                trace.collect(self.image)

    def test_lsda_header_corruption_rejected(self):
        fde = self.image.fdes[0x17783e0]
        offset = self.image.offset(fde['lsda'], 1)
        blob = self.image.blob
        class Altered:
            def __getitem__(self, key):
                if isinstance(key, int) and key == offset:
                    return blob[key] ^ 1
                return blob[key]
        with mock.patch.object(self.image, 'blob', Altered()):
            with self.assertRaisesRegex(ValueError, 'unsupported LSDA header'):
                trace.exception_table(self.image, fde)

    def test_repeat_writes_are_byte_identical(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            left, right = root/'one', root/'two'
            trace.write_outputs(self.record, left)
            trace.write_outputs(self.record, right)
            self.assertEqual(sorted(p.name for p in left.iterdir()), sorted(p.name for p in right.iterdir()))
            for first in left.iterdir():
                second = right / first.name
                self.assertEqual(hashlib.sha256(first.read_bytes()).digest(),
                                 hashlib.sha256(second.read_bytes()).digest())


if __name__ == '__main__':
    unittest.main()
