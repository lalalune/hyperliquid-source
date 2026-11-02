"""Offline byte, corruption and boundary controls for node 94 configuration timing."""
import copy
import hashlib
from pathlib import Path
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import config_agent_prune94 as subject


class ConfigAgentPruneTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = subject.Image(subject.TARGET.read_bytes())
        cls.result = subject.collect(cls.image)
        cls.rows = {r['va']: r for r in cls.result['instructions']}
        cls.summary = cls.result['summary']

    def mutate(self, offset, data, action):
        original = self.image.data
        altered = bytearray(original)
        altered[offset:offset + len(data)] = data
        self.image.data = altered
        try:
            action()
        finally:
            self.image.data = original

    def test_digest_and_selected_extents(self):
        self.assertEqual(hashlib.sha256(self.image.data).hexdigest(), subject.DIGEST)
        self.assertEqual(len(self.result['functions']), 11)
        self.assertEqual(sum(f['byte_count'] for f in self.result['functions']), 6696)
        for fde in self.result['functions']:
            with self.subTest(entry=fde['entry']):
                body = self.image.read(fde['entry'], fde['byte_count'])
                self.assertEqual(hashlib.sha256(body).hexdigest(), fde['sha256'])
                self.assertEqual(fde['entry'] + len(body), fde['end'])

    def test_wrong_digest_is_rejected(self):
        with self.assertRaisesRegex(subject.EvidenceError, 'digest mismatch'):
            subject.Image(b'corrupt artifact')

    def test_instruction_partition_and_branch_targets(self):
        self.assertEqual(len(self.result['instructions']), 1489)
        self.assertEqual(len(self.result['branches']), 120)
        for fde in self.result['functions']:
            selected = [r for r in self.result['instructions'] if r['function'] == fde['entry']]
            self.assertEqual(selected[0]['va'], fde['entry'])
            self.assertEqual(selected[-1]['va'] + selected[-1]['size'], fde['end'])
            self.assertEqual(sum(r['size'] for r in selected), fde['byte_count'])
            for row in selected:
                self.assertEqual(self.image.read(row['va'], row['size']).hex(), row['bytes'])
        for row in self.result['branches']:
            if row['within_fde']:
                self.assertIn(row['target'], self.rows)

    def test_descriptors_for_only_selected_names(self):
        self.assertEqual([(r['tag'], r['name']) for r in self.result['names']], [
            (10, 'Ea2'), (18, 'SoloTestnet'), (19, 'SoloMainnet'),
            (20, 'LockerTestnet'), (21, 'LockerMainnet'), (22, 'RpcTestnet'),
            (23, 'RpcSandbox'), (24, 'RpcMainnet'), (25, 'RpcMainnet2'),
            (31, 'SoloSandbox')])
        default = self.summary['name_guard']['default_context']
        self.assertEqual((default['tag'], default['name'], default['text_va']), (32, 'NvTestnet', '0x2180ff'))
        self.assertEqual(self.summary['name_guard']['name_domain_bound'], 76)

    def test_name_predicate_all_byte_values(self):
        guard = self.summary['name_guard']
        selected = {10, 18, 19, 20, 21, 22, 23, 24, 25, 31}
        minus_one = struct.unpack('<Q', struct.pack('<d', -1.0))[0]
        plus_one = struct.unpack('<Q', struct.pack('<d', 1.0))[0]
        for tag in range(256):
            expected = 'assertion' if tag in selected else 'clock_path'
            self.assertEqual(subject.timer_guard(tag, minus_one, guard['range_start'], guard['range_width'], guard['extra_tags']), expected)
            self.assertEqual(subject.timer_guard(tag, plus_one, guard['range_start'], guard['range_width'], guard['extra_tags']), 'clock_path')
        with self.assertRaises(subject.EvidenceError):
            subject.timer_guard(256, plus_one, 18, 8, [10, 31])

    def test_float_class_boundaries_masked_exceptions(self):
        cases = ((0x0000000000000000, 'clock_path'),
                 (0x8000000000000000, 'clock_path'),
                 (0x3ff0000000000000, 'clock_path'),
                 (0xbff0000000000000, 'assertion'),
                 (0x7ff0000000000000, 'clock_path'),
                 (0xfff0000000000000, 'assertion'),
                 (0x7ff8000000000001, 'assertion'),
                 (0xfff8000000000001, 'assertion'))
        for bits, expected in cases:
            with self.subTest(bits=hex(bits)):
                self.assertEqual(subject.timer_guard(18, bits, 18, 8, [10, 31]), expected)
                self.assertEqual(subject.timer_guard(32, bits, 18, 8, [10, 31]), 'clock_path')
        with self.assertRaises(subject.EvidenceError):
            subject.timer_guard(18, 1 << 64, 18, 8, [10, 31])

    def test_timing_branch_and_lazy_reload(self):
        self.assertEqual(self.rows[0x13cbddc]['target'], 0x13cbeb3)
        self.assertEqual(self.rows[0x13cbdea]['target'], 0x13cbeca)
        self.assertEqual(self.rows[0x13cbead]['target'], 0x13cbde2)
        self.assertEqual(self.rows[0x13cbeb6]['target'], 0x13cbde2)
        self.assertEqual(self.rows[0x13cbebf]['target'], 0x13cbde2)
        self.assertEqual(self.rows[0x13cbec5]['target'], 0x13cbdf0)
        self.assertEqual(self.rows[0x13cbe26]['target'], 0x13cbe5e)

    def test_each_driver_passes_positive_constants(self):
        for row in self.result['drivers']:
            self.assertEqual((row['zero_flag_seconds'], row['nonzero_flag_seconds']), ('5.0', '1.0'))
            self.assertEqual((row['zero_flag_bytes'], row['nonzero_flag_bytes']),
                             ('0000000000001440', '000000000000f03f'))
            self.assertEqual(row['metric'], 'prune agents')
            for address in (row['zero_flag_va'], row['nonzero_flag_va']):
                bits = struct.unpack('<Q', self.image.read(address, 8))[0]
                for tag in range(256):
                    self.assertEqual(subject.timer_guard(tag, bits, 18, 8, [10, 31]), 'clock_path')
        for address in (0x26fb98f, 0x4ce153f, 0x4ce189f):
            self.assertEqual(self.rows[address]['memory_va'], 0x576e9b0)
            self.assertEqual(self.rows[address + self.rows[address]['size']]['kind'], 'mov_load')

    def test_no_second_float_compare_in_selected_timing_body(self):
        later = [r for r in self.result['instructions'] if r['function'] == 0x13cbdb0 and r['va'] > 0x13cbdf5]
        self.assertFalse(any(r.get('opcode2') == 0x2e for r in later))

    def test_hour_magic_for_complete_bounded_domain(self):
        config = self.summary['hour']
        magic, shift, bound = int(config['magic'], 16), config['shift'], config['bound']
        self.assertEqual((magic, shift, bound, config['divisor']), (0x91a2b3c5, 43, 90000, 3600))
        for value in range(bound):
            self.assertEqual(subject.hour_bucket(value, magic, shift), value // 3600)
        with self.assertRaises(subject.EvidenceError):
            subject.hour_bucket(-1, magic, shift)

    def test_counter_unsigned_boundaries_and_saturation(self):
        d = self.result['drivers'][0]
        maximum = (1 << 64) - 1
        for old in (0, 1, 18, 19, 20, 21, maximum - 2, maximum - 1, maximum):
            actual = subject.counter_step(old, d['counter_magic'], d['counter_shift'], d['counter_mask'], d['counter_scale'])
            self.assertEqual(actual, min(old + 1, maximum) % 20)
        self.assertEqual(subject.counter_step(maximum, d['counter_magic'], d['counter_shift'], d['counter_mask'], d['counter_scale']), 15)
        with self.assertRaises(subject.EvidenceError):
            subject.counter_step(1 << 64, d['counter_magic'], d['counter_shift'], d['counter_mask'], d['counter_scale'])

    def test_counter_deterministic_wide_control(self):
        d = self.result['drivers'][0]
        maximum = (1 << 64) - 1
        value = 0
        for _ in range(10000):
            value = (value * 6364136223846793005 + 1442695040888963407) & maximum
            actual = subject.counter_step(value, d['counter_magic'], d['counter_shift'], d['counter_mask'], d['counter_scale'])
            self.assertEqual(actual, min(value + 1, maximum) % 20)

    def test_driver_field_offsets_and_order(self):
        self.assertEqual([(r['role'], r['counter_offset'], r['state_offset']) for r in self.result['drivers']],
                         [('main', 0x39c0, 0x36d0), ('first', 0x4440, 0x4150), ('second', 0x39c0, 0x36d0)])
        for start in (0x26fb750, 0x4ce1300, 0x4ce1660):
            self.assertEqual(self.rows[start + 0x1b5]['kind'], 'mov_store')
            self.assertEqual(self.rows[start + 0x1d0]['kind'], 'call')
            self.assertEqual(self.rows[start + 0x208]['memory_va'], 0x57748f0)
            self.assertLess(start + 0x1b5, start + 0x1d0)
            self.assertLess(start + 0x208, start + 0x23f)

    def test_relocation_edges_connect_selected_functions(self):
        slots = {r['slot']: r for r in self.result['relocations']}
        self.assertEqual(slots[0x576e928]['addend'], 0x577b288)
        self.assertEqual(slots[0x576e9b0]['addend'], 0x13cbdb0)
        self.assertEqual(slots[0x57748e8]['addend'], 0x3987ad0)
        self.assertEqual(slots[0x57748f0]['addend'], 0x34227e0)
        expected = {(0x26fb920, 0x1f84e00), (0x4ce14d0, 0x47dbf50), (0x4ce1830, 0x47dc080)}
        actual = {(r['va'], r['target']) for r in self.result['calls'] if r['target'] is not None}
        self.assertTrue(expected <= actual)

    def test_handoff_loop_and_failure_edges(self):
        self.assertEqual(self.rows[0x3422998]['target'], 0x3422aba)
        self.assertEqual(self.rows[0x3422ab5]['target'], 0x3422980)
        self.assertEqual(self.rows[0x3422a43]['target'], 0x3422c15)
        self.assertEqual(self.rows[0x3422a75]['target'], 0x3422c15)
        self.assertEqual(self.rows[0x3422c2e]['kind'], 'trap')
        self.assertEqual(self.rows[0x3422cc3]['target'], 0x5660110)

    def test_exception_and_cfg_records(self):
        self.assertEqual(len(self.result['lsda_headers']), 7)
        self.assertEqual(len(self.result['exception_sites']), 44)
        self.assertEqual(len(self.result['cfg_claims']), 27)
        checks = {r['label']: r['reachable'] for r in self.result['cfg_claims']}
        self.assertEqual(checks['main_equal_hour_skips_counter'], 0)
        self.assertEqual(checks['main_counter_reaches_builder'], 1)
        self.assertEqual(checks['name_bypass_skips_float_check'], 0)
        self.assertEqual(checks['handoff_record_loop'], 1)
        self.assertEqual(checks['insert_duplicate_skips_count'], 0)
        self.assertEqual(checks['insert_empty_root_reaches_allocation'], 1)
        self.assertEqual(checks['cleanup_empty_return_skips_stores'], 0)
        self.assertEqual(checks['cleanup_remove_reaches_count'], 1)

    def test_handoff_reaches_insert_and_cleanup(self):
        self.assertEqual(self.rows[0x3422ab0]['target'], 0x33a51f0)
        self.assertEqual(self.rows[0x3422af5]['target'], 0x379fb00)
        self.assertEqual(self.rows[0x33a5236]['memory_va'], 0x576e488)
        slots = {r['slot']: r for r in self.result['relocations']}
        self.assertEqual((slots[0x576e488]['relocation_type'], slots[0x576e488]['symbol']), (6, 'memcmp'))

    def test_state_properties_are_instruction_derived(self):
        properties = {(r['scope'], r['property']): r['value'] for r in self.result['state_properties']}
        self.assertEqual(properties, {
            ('index', 'key_prefix_bytes'): 20,
            ('index', 'node_entry_stride_bytes'): 32,
            ('index', 'node_count_offset'): 0x16a,
            ('index', 'new_allocation_bytes'): 0x170,
            ('index', 'node_limit'): 11,
            ('index', 'owner_count_offset'): 0x10,
            ('cleanup', 'entry_count_offset'): 0x18,
            ('cleanup', 'growth_counter_offset'): 0x10,
            ('cleanup', 'empty_control_byte'): 0xff,
            ('cleanup', 'deleted_control_byte'): 0x80,
            ('cleanup', 'mirror_bias'): 0x10,
            ('cleanup', 'predicate_bit_mask'): 1,
            ('cleanup', 'current_pointer_delta'): -8,
        })

    def test_insert_duplicate_and_cleanup_branch_destinations(self):
        expected = {
            0x33a520a: 0x33a531d, 0x33a52e2: 0x33a52f5,
            0x33a5318: 0x33a5422, 0x33a535b: 0x33a53bc,
            0x33a53cd: 0x33a543e, 0x33a53f9: 0x33a544e,
            0x379fb22: 0x379fd36, 0x379fbb8: 0x379fd36,
            0x379fcb2: 0x379fca0, 0x379fcbd: 0x379fbb2,
            0x379fd26: 0x379fb73,
        }
        for address, target in expected.items():
            with self.subTest(address=hex(address)):
                self.assertEqual(self.rows[address]['target'], target)

    def test_state_branch_corruption_is_rejected(self):
        pos = self.image.offset(0x379fcbd, 6)
        def check():
            with self.assertRaisesRegex(subject.EvidenceError, 'byte contract changed'):
                subject.collect(self.image, check_body_hashes=False)
        self.mutate(pos + 1, b'\x84', check)

    def test_state_literal_corruption_is_rejected(self):
        pos = self.image.offset(0x33a526d, 5)
        def check():
            with self.assertRaisesRegex(subject.EvidenceError, 'byte contract changed'):
                subject.collect(self.image, check_body_hashes=False)
        self.mutate(pos + 1, b'\x13', check)

    def test_state_comparison_relocation_corruption_is_rejected(self):
        pos = self.image.symbol_offsets[0x576e488] + 8
        def check():
            with self.assertRaisesRegex(subject.EvidenceError, 'dynamic symbol changed'):
                subject.check_slots(self.image)
        self.mutate(pos, struct.pack('<Q', 8), check)

    def test_modeled_record_order_signed_and_unsigned_boundaries(self):
        def record(prefix, signed, middle, final):
            return prefix + struct.pack('<iII', signed, middle, final)
        zero = bytes(20)
        examples = (
            (record(zero, -1, 0, 0), record(zero, 0, 0, 0), -1),
            (record(zero, -(1 << 31), 0, 0), record(zero, (1 << 31) - 1, 0, 0), -1),
            (record(zero, 0, 1 << 31, 0), record(zero, 0, (1 << 31) - 1, 0), 1),
            (record(zero, 0, 0, 1 << 31), record(zero, 0, 0, (1 << 31) - 1), 1),
            (record(b'\x01' + bytes(19), -1, 0, 0), record(zero, 1, 0, 0), 1),
            (record(zero, 1, 0, 0), record(zero, 0, (1 << 32) - 1, (1 << 32) - 1), 1),
        )
        for left, right, expected in examples:
            with self.subTest(left=left.hex(), right=right.hex()):
                self.assertEqual(subject.record_compare(left, right), expected)
                self.assertEqual(subject.record_compare(right, left), -expected)
                self.assertEqual(subject.record_compare(left, left), 0)
        self.assertEqual(len(self.result['comparison_cases']), 11)

    def test_modeled_record_order_rejects_invalid_lengths(self):
        for length in (0, 19, 20, 31, 33):
            with self.subTest(length=length), self.assertRaisesRegex(subject.EvidenceError, '32-byte records'):
                subject.record_compare(bytes(length), bytes(32))

    def test_extended_instruction_encodings(self):
        expected = ((b'\x1c\x00', 'sbb'), (b'\xa8\x01', 'test'),
                    (b'\x48\x2b\x44\x24\x10', 'sub'),
                    (b'\x66\x0f\x76\xc9', 'sse_0x76'),
                    (b'\x66\x0f\xbd\xfa', 'bsr'))
        for raw, kind in expected:
            with self.subTest(raw=raw.hex()):
                rows = subject.decode(raw, 0x1000)
                self.assertEqual(len(rows), 1)
                self.assertEqual((rows[0]['kind'], rows[0]['size']), (kind, len(raw)))

    def test_cfg_control_rejects_wrong_but_valid_target(self):
        changed = copy.deepcopy(self.result)
        row = next(r for r in changed['instructions'] if r['va'] == 0x26fb9e0)
        row['kind'], row['target'] = 'jump', 0x26fb905
        with self.assertRaisesRegex(subject.EvidenceError, 'CFG proposition changed'):
            subject.control_flow(changed)

    def test_body_digest_rejects_corrupted_name_bound(self):
        pos = self.image.offset(0x13cbdd9, 3)
        def check():
            with self.assertRaisesRegex(subject.EvidenceError, 'FDE bytes changed'):
                subject.collect(self.image)
        self.mutate(pos + 2, b'\x09', check)

    def test_instruction_contract_rejects_corrupted_bound_below_hash(self):
        pos = self.image.offset(0x13cbdd9, 3)
        def check():
            with self.assertRaisesRegex(subject.EvidenceError, 'byte contract changed'):
                subject.collect(self.image, check_body_hashes=False)
        self.mutate(pos + 2, b'\x09', check)

    def test_instruction_contract_rejects_branch_direction_change(self):
        pos = self.image.offset(0x13cbdea, 6)
        def check():
            with self.assertRaisesRegex(subject.EvidenceError, 'byte contract changed'):
                subject.collect(self.image, check_body_hashes=False)
        self.mutate(pos + 1, b'\x83', check)

    def test_relocation_corruption(self):
        pos = self.image.relocation_offsets[0x57748f0] + 16
        original = struct.unpack_from('<q', self.image.data, pos)[0]
        def check():
            with self.assertRaisesRegex(subject.EvidenceError, 'RELATIVE target changed'):
                subject.check_slots(self.image)
        self.mutate(pos, struct.pack('<q', original + 1), check)

    def test_selected_name_relocation_corruption(self):
        pos = self.image.relocation_offsets[0x5668328] + 16
        original = struct.unpack_from('<q', self.image.data, pos)[0]
        def check():
            with self.assertRaises(subject.EvidenceError):
                subject.name_entries(self.image, [10, *range(18, 26), 31])
        self.mutate(pos, struct.pack('<q', original + 1), check)

    def test_float_literal_corruption(self):
        pos = self.image.offset(0x20a890, 8)
        def check():
            with self.assertRaisesRegex(subject.EvidenceError, 'threshold constants changed'):
                subject.collect(self.image, check_body_hashes=False)
        self.mutate(pos, struct.pack('<d', -5.0), check)

    def test_failure_literal_corruption(self):
        pos = self.image.offset(0x219f59, 1)
        def check():
            with self.assertRaisesRegex(subject.EvidenceError, 'failure text changed'):
                subject.collect(self.image, check_body_hashes=False)
        self.mutate(pos, b'X', check)

    def test_counter_reciprocal_relation(self):
        magic = self.result['drivers'][0]['counter_magic']
        self.assertEqual(5 * magic - (1 << 66), 1)
        self.assertEqual(self.result['drivers'][0]['counter_divisor'], 20)

    def test_lsda_corruption(self):
        location = self.result['lsda_headers'][0]['lsda']
        pos = self.image.offset(location, 1)
        def check():
            with self.assertRaisesRegex(subject.EvidenceError, 'unsupported LSDA'):
                subject.exception_sites(self.image, self.result)
        self.mutate(pos, b'\xfe', check)

    def test_nobits_unmapped_and_ambiguous_ranges(self):
        bss = next(s for s in self.image.sections if s['name'] == '.bss')
        self.assertEqual(bss['type'], 8)
        with self.assertRaises(subject.EvidenceError):
            self.image.offset(bss['address'], 1)
        with self.assertRaises(subject.EvidenceError):
            self.image.offset(0xfffffffffffff000, 4)
        self.image.sections.append(dict(next(s for s in self.image.sections if s['name'] == '.text')))
        try:
            with self.assertRaises(subject.EvidenceError):
                self.image.offset(0x13cbdb0, 1)
        finally:
            self.image.sections.pop()

    def test_fde_missing_and_ambiguous(self):
        duplicate = dict(self.image.fde(0x13cbdb0))
        self.image.fdes.append(duplicate)
        try:
            with self.assertRaisesRegex(subject.EvidenceError, 'missing or ambiguous'):
                self.image.fde(0x13cbdb0)
        finally:
            self.image.fdes.pop()
        with self.assertRaises(subject.EvidenceError):
            self.image.fde(0xfffffffffffff000)

    def test_decoder_rejects_truncation_unknown_opcode_and_interior_target(self):
        for raw in (b'\x0f\x84\x00', b'\x48\x8b\x05\x00', b'\xf1', b'\xeb\xff'):
            with self.subTest(raw=raw.hex()), self.assertRaises(subject.EvidenceError):
                subject.decode(raw, 0x1000)

    def test_identical_output_writes(self):
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            a, b = Path(first), Path(second)
            subject.write_outputs(self.result, a)
            subject.write_outputs(self.result, b)
            left = {p.name: p.read_bytes() for p in a.iterdir()}
            right = {p.name: p.read_bytes() for p in b.iterdir()}
            self.assertEqual(left, right)
            self.assertEqual(len(left), 18)
            self.assertIn('summary.json', left)
            self.assertIn('exception-sites.tsv', left)


if __name__ == '__main__':
    unittest.main()
