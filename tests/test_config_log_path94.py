"""Static, target-bound positive and negative controls for config log evidence."""
import contextlib
import hashlib
import itertools
import unittest
from unittest import mock

from tools import config_log_path94 as log


class ConfigLogEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = bytearray(log.TARGET.read_bytes())
        cls.view = log.View(cls.data)
        cls.result = log.collect(cls.data)
        cls.edge_by_name = {row['label']: row for row in cls.result['edges']}
        cls.contract_by_name = {row['label']: row for row in cls.result['contracts']}

    @contextlib.contextmanager
    def changed(self, offset, replacement):
        original = self.data[offset:offset + len(replacement)]
        self.data[offset:offset + len(replacement)] = replacement
        try:
            yield
        finally:
            self.data[offset:offset + len(replacement)] = original

    def test_artifact_identity(self):
        log.verify_identity(self.data)
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), log.DIGEST)
        self.assertEqual(len(self.data), log.SIZE)

    def test_wrong_hash_is_rejected(self):
        offset = self.view.offset(0x13e28c0, 1)
        with self.changed(offset, bytes([self.data[offset] ^ 1])):
            with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
                log.verify_identity(self.data)
        log.verify_identity(self.data)

    def test_configuration_cell_is_file_backed_data(self):
        cell = self.result['summary']['global_config_cell']
        self.assertEqual(cell['section'], '.data')
        self.assertEqual(cell['section_type'], 1)
        self.assertEqual(int(cell['file_offset'],16), self.view.offset(int(cell['va'],16), 1))

    def test_wrong_length_is_rejected(self):
        with self.assertRaises(ValueError):
            log.verify_identity(b'')

    def test_ranges_and_fde_hashes(self):
        rows = self.result['functions']
        self.assertEqual(len(rows), 10)
        self.assertEqual(sum(row['size'] for row in rows), 13468)
        self.assertTrue(all(int(row['end_va'], 16) - int(row['start_va'], 16) == row['size'] for row in rows))

    def test_corrupt_body_rejected_after_identity_gate(self):
        offset = self.view.offset(0x13e2c83, 1)
        with self.changed(offset, b'\x75'):
            with mock.patch.object(log, 'verify_identity'):
                with self.assertRaisesRegex(ValueError, 'FDE body changed'):
                    log.collect(self.data)

    def test_contract_detects_changed_condition(self):
        label, va, expected = next(x for x in log.CONTRACTS if x[0] == 'warn_custom_live_guard')
        offset = self.view.offset(va, len(bytes.fromhex(expected)))
        with self.changed(offset + 3, b'\x84'):
            with self.assertRaisesRegex(ValueError, 'instruction contract changed'):
                log.require(self.view, label, va, expected)

    def test_operand_and_short_edge_controls(self):
        site = 0x13e2c83
        raw = bytes(self.view.read(site, 2))
        self.assertEqual(log.edge_target(site, raw, '74'), 0x13e2cf9)
        self.assertNotEqual(log.edge_target(site, raw[:1] + b'\x00', '74'), 0x13e2cf9)
        with self.assertRaises(ValueError):
            log.edge_target(site, b'\x75' + raw[1:], '74')
        with self.assertRaises(ValueError):
            log.edge_target(site, b'\x74', '74')

    def test_direct_and_indirect_edges_are_distinct(self):
        direct = self.edge_by_name['warn_path_insert']
        indirect = self.edge_by_name['file_builder']
        self.assertEqual(direct['destination_kind'], 'direct_va')
        self.assertEqual(direct['destination'], '0x14cad30')
        self.assertEqual(indirect['destination_kind'], 'relative_slot')
        self.assertEqual(indirect['destination'], '0x576eba8')
        with self.assertRaises(ValueError):
            log.edge_target(0, b'\xff\x15\x00', 'ff15')

    def test_changed_edge_target_fails_selected_validation(self):
        offset = self.view.offset(0x13e2c83, 2)
        with self.changed(offset + 1, b'\x00'):
            with self.assertRaisesRegex(ValueError, 'edge target changed'):
                log.selected_edges(self.view)

    def test_rip_operand_controls(self):
        raw = bytes(self.view.read(0x13e2acb, 7))
        self.assertEqual(log.rip_target(0x13e2acb, raw), 0x1fbef2)
        self.assertNotEqual(log.rip_target(0x13e2acb, raw[:-1] + bytes([raw[-1] ^ 1])), 0x1fbef2)
        with self.assertRaises(ValueError):
            log.rip_target(0x13e2acb, raw[:-1])
        with self.assertRaises(ValueError):
            log.rip_target(0x13e2acb, b'\x48\x8d\x00' + raw[3:])

    def test_closed_decoder_spans_every_selected_fde(self):
        rows = self.result['instructions']
        self.assertEqual(len(rows), 2760)
        for fn in self.result['functions']:
            selected = [r for r in rows if r['function'] == fn['start_va']]
            self.assertEqual(sum(r['size'] for r in selected), fn['size'])
            self.assertEqual(selected[0]['va'], fn['start_va'])
            for first, second in zip(selected, selected[1:]):
                self.assertEqual(int(first['va'],16) + first['size'], int(second['va'],16))

    def test_decoder_handles_selected_sse_immediates(self):
        self.assertEqual(log.decode_one(bytes.fromhex('f20f70c000'), 0, 0x100)['end'], 0x105)
        self.assertEqual(log.decode_one(bytes.fromhex('660f60c0'), 0, 0x100)['end'], 0x104)
        self.assertEqual(log.decode_one(bytes.fromhex('660f6ec0'), 0, 0x100)['end'], 0x104)
        with self.assertRaises(ValueError):
            log.decode_one(bytes.fromhex('f20f70c0'), 0, 0x100)

    def test_decoder_handles_locked_compare_exchange(self):
        raw = bytes.fromhex('f00fb04c2468')
        self.assertEqual(log.decode_one(raw, 0, 0x100)['end'], 0x106)
        with self.assertRaises(ValueError):
            log.decode_one(raw[:-1], 0, 0x100)

    def test_decoder_rejects_unknown_truncation_and_mid_instruction_branch(self):
        for raw in (b'\xff', b'\x0f\x38', b'\xe8\x00', b'\x66' * 10):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                log.decode_one(raw, 0, 0x100)
        with self.assertRaisesRegex(ValueError, 'branch into an instruction'):
            log.decode_body(bytes.fromhex('b800000000ebfb'), 0x100)

    def test_actual_branch_retargeted_into_operand_rejected(self):
        start, end = 0x13e28c0, 0x13e4cd4
        body = bytearray(self.view.read(start, end-start))
        body[0x13e2c84-start] = 0x73
        with self.assertRaisesRegex(ValueError, 'branch into an instruction'):
            log.decode_body(body, start)

    def test_cfg_queries_are_boundary_checked_and_overapproximate(self):
        start, end = 0x14cad30, 0x14caf32
        decoded = log.decode_body(self.view.read(start, end-start), start)
        self.assertTrue(log.reachable(decoded, 0x14cadc3, 0x14caec8))
        self.assertFalse(log.reachable(decoded, 0x14cadc3, 0x14caeb7))
        self.assertFalse(log.reachable(decoded, 0x14cadc3, 0x14caec8, (0x14caec8,)))
        with self.assertRaises(ValueError):
            log.reachable(decoded, start+2, 0x14caec8)
        self.assertTrue(all(row['reachable'] in (0,1) for row in self.result['cfg_claims']))

    def test_no_file_bytes_for_nobits_and_unmapped(self):
        sections = [dict(name='bss', type=8, flags=0, address=0x100, size=4, offset=0)]
        view = log.View(b'abcd', sections)
        for address in (0x100, 0xff, 0x104, -1):
            with self.subTest(address=address), self.assertRaises(ValueError):
                view.read(address, 1)

    def test_ambiguous_and_cross_boundary_ranges_are_rejected(self):
        one = dict(name='one', type=1, flags=0, address=0x100, size=4, offset=0)
        two = dict(name='two', type=1, flags=0, address=0x100, size=4, offset=4)
        with self.assertRaises(ValueError):
            log.View(b'abcdefgh', [one, two]).read(0x100, 1)
        view = log.View(b'abcd', [one])
        self.assertEqual(view.read(0x101, 3), b'bcd')
        with self.assertRaises(ValueError):
            view.read(0x101, 4)
        with self.assertRaises(ValueError):
            view.read(0x100, 0)
        with self.assertRaises(ValueError):
            view.read((1 << 64)-1, 2)

    def test_nobits_cannot_shadow_a_file_section(self):
        secs = [dict(name='bss', type=8, flags=0, address=100, size=4, offset=0),
                dict(name='file', type=1, flags=0, address=100, size=4, offset=0)]
        self.assertEqual(log.View(b'ABCD', secs).read(101, 2), b'BC')

    def test_templates_are_complete_and_distinct(self):
        templates = self.result['templates']
        self.assertEqual([x.get('literal') for x in templates['warn']['tokens'] if 'literal' in x], ['/data/log/', '/warn/'])
        self.assertEqual([x.get('literal') for x in templates['error']['tokens'] if 'literal' in x], ['/data/log/', '/error/'])
        self.assertEqual(sum('argument' in x for x in templates['warn']['tokens']), 3)
        self.assertEqual(templates['seed_static_config']['bytes'], 'c00e2f7374617469635f636f6e66696700')

    def test_template_corrupt_terminator_and_length(self):
        va = 0x1fbef2
        expected = 'c00a2f646174612f6c6f672fc0062f7761726e2fc000'
        for relative, replacement in ((21, b'\x80'), (1, b'\x0b'), (0, b'\xc1')):
            with self.subTest(relative=relative):
                offset = self.view.offset(va + relative, 1)
                with self.changed(offset, replacement):
                    with self.assertRaises(ValueError):
                        log.template(self.view, va, expected)

    def test_category_values_and_selection(self):
        rows = self.result['categories']
        self.assertEqual(len(rows), 13)
        self.assertEqual([r['index'] for r in rows if r['formatter_slice'] == 'trade'], [5])
        self.assertEqual(sum(r['formatter_slice'] == 'infra' for r in rows), 12)
        self.assertEqual(self.result['summary']['context_nv_name']['text'], 'NvTestnet')

    def test_severity_table_decodes_two_admitted_keys(self):
        rows = log.severity_names(self.view)
        self.assertEqual([(r['key'], r['text']) for r in rows], [(0, 'Error'), (1, 'Warn')])
        self.assertEqual(self.edge_by_name['severity_adapter_sink']['destination'], '0x576e008')

    def test_severity_table_rejects_length_and_offset_corruption(self):
        for va, replacement in ((0x20c4c0, b'\x06'), (0x21a098, b'\x00')):
            offset = self.view.offset(va, 1)
            with self.subTest(va=va), self.changed(offset, replacement):
                with self.assertRaises(ValueError):
                    log.severity_names(self.view)

    def test_prefix_helper_uses_fresh_three_argument_array(self):
        setup = self.contract_by_name['prefix_three_arguments']
        self.assertEqual(setup['va'], '0x13ecf8f')
        self.assertEqual(self.edge_by_name['prefix_three_part_format']['destination'], '0x576e040')
        self.assertEqual(self.edge_by_name['prefix_candidate_free']['destination'], '0x576e010')
        self.assertEqual(self.edge_by_name['prefix_absent']['destination'], '0x13ed023')

    def test_prefix_argument_setup_corruption_is_rejected(self):
        label, va, expected = next(x for x in log.CONTRACTS if x[0] == 'prefix_three_arguments')
        offset = self.view.offset(va, len(bytes.fromhex(expected)))
        with self.changed(offset, b'\x49'):
            with self.assertRaisesRegex(ValueError, 'instruction contract changed'):
                log.require(self.view, label, va, expected)

    def test_rolling_suffix_and_error_messages(self):
        suffix = self.result['templates']['rolling_suffix']['tokens']
        self.assertEqual(suffix, [{'argument': True}, {'literal': '_overflow{}'}])
        messages = self.result['diagnostics']
        self.assertEqual(messages['pattern_missing']['text'], 'pattern does not contain `{}`')
        self.assertEqual(messages['gzip_feature_missing']['text'], 'gzip compression requires the `gzip` feature')

    def test_rolling_scalar_against_independent_byte_search(self):
        alphabet = (ord('x'), ord('{'), ord('}'))
        for size in range(9):
            for seq in itertools.product(alphabet, repeat=size):
                data = bytes(seq)
                self.assertEqual(log.scalar_pair_search(data), b'{}' in data)
        with self.assertRaises(ValueError):
            log.scalar_pair_search(b'x'*17)

    def test_rolling_tail_vector_all_lanes(self):
        for size in range(17, 66):
            for lane in range(16):
                data = bytearray(b'x'*size)
                at = size-17+lane
                data[at:at+2] = b'{}'
                self.assertEqual(log.trailing_pair_mask(bytes(data),0x7b,0x7d),1 << lane)
        with self.assertRaises(ValueError):
            log.trailing_pair_mask(b'x'*16,0x7b,0x7d)

    def test_rolling_fixed_suffix_at_length_boundaries(self):
        for size in range(11, 513):
            pattern = b'x'*(size-11)+b'_overflow{}'
            if size <= 16:
                self.assertTrue(log.scalar_pair_search(pattern))
                self.assertFalse(log.scalar_pair_search(pattern[:-1]+b'|'))
            else:
                self.assertTrue(log.trailing_pair_mask(pattern,0x7b,0x7d) & 0x8000)
                self.assertEqual(log.trailing_pair_mask(pattern[:-1]+b'|',0x7b,0x7d),0)

    def test_rolling_constants_and_thresholds_detect_corruption(self):
        constants = log.rolling_constants(self.view)
        self.assertEqual((constants['short_max'],constants['unrolled_min']),(16,66))
        for va in (0x2054c0,0x206f70,0x3ccdc79,0x3ccdd0a):
            offset = self.view.offset(va, 1)
            with self.subTest(va=va), self.changed(offset, bytes([self.data[offset]^1])):
                with self.assertRaises(ValueError):
                    log.rolling_constants(self.view)

    def test_extension_gate_boundary_and_tag(self):
        cases = ((9,b'x.gz','gzip_feature_error'),(9,b'x.tar.gz','gzip_feature_error'),
                 (9,b'.gz','continue'),(9,b'..','continue'),(9,b'x.GZ','continue'),
                 (9,b'x.gz.tmp','continue'),(9,b'','continue'),(8,b'x.gz','continue'))
        for tag, component, expected in cases:
            with self.subTest(tag=tag,component=component):
                self.assertEqual(log.extension_decision(tag,component),expected)
        with self.assertRaises(ValueError):
            log.extension_decision(256,b'x.gz')

    def test_appender_tag_gate_exhaustive(self):
        constants = log.appender_tag_constants(self.view)
        actual = [tag for tag in range(256) if log.appender_tag_enters(tag, constants)]
        self.assertEqual(actual, [7, 8, 9])
        rows = self.result['appender_tag_cases']
        self.assertEqual([row['tag'] for row in rows if row['enters_two_call_gate']], actual)
        for tag in (-1, 256, True):
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                log.appender_tag_enters(tag, constants)

    def test_appender_tag_gate_rejects_corrupt_immediates(self):
        for va in (0x147165b, 0x147165d):
            offset = self.view.offset(va, 1)
            with self.subTest(va=va), self.changed(offset, bytes([self.data[offset] ^ 1])):
                with self.assertRaisesRegex(ValueError, 'appender tag gate changed'):
                    log.appender_tag_constants(self.view)

    def test_appender_operation_flags_reject_corruption(self):
        label, va, expected = next(x for x in log.CONTRACTS if x[0] == 'appender_operation_flags')
        offset = self.view.offset(va, len(bytes.fromhex(expected)))
        with self.changed(offset + 7, b'\xfe'):
            with self.assertRaisesRegex(ValueError, 'instruction contract changed'):
                log.require(self.view, label, va, expected)

    def test_appender_result_paths_and_lock_edges(self):
        claims = {row['label']: row['reachable'] for row in self.result['cfg_claims']}
        self.assertEqual(claims['appender_operation_error_bypasses_copy'], 0)
        self.assertEqual(claims['appender_call_error_reaches_sentinel'], 1)
        self.assertEqual(claims['appender_call_error_bypasses_copy'], 0)
        self.assertEqual(claims['appender_call_ok_reaches_copy'], 1)
        self.assertEqual(claims['appender_call_ok_bypasses_error_store'], 0)
        self.assertEqual(self.edge_by_name['appender_lock_contended']['destination'], '0x1471792')
        self.assertEqual(self.edge_by_name['appender_unlock_ok_contended']['destination'], '0x14717b5')

    def test_rolling_failure_and_success_cfg(self):
        claims = {r['label']:r['reachable'] for r in self.result['cfg_claims']}
        self.assertEqual(claims['rolling_short_no_match_is_error'],1)
        self.assertEqual(claims['rolling_short_error_bypasses_success'],0)
        self.assertEqual(claims['rolling_gzip_bypasses_success'],0)
        self.assertEqual(claims['rolling_success_reaches_return'],1)

    def test_live_predicate_exhaustive_over_byte_inputs(self):
        for mode in range(256):
            for flag in range(256):
                actual, _ = log.classify(mode, flag, False, False, False)
                self.assertEqual(actual, mode in (1, 2) and bool(flag & 1))

    def test_custom_path_in_live_mode_is_rejected(self):
        for channel in ('warn', 'error'):
            rows = [r for r in self.result['scenarios'] if r['channel'] == channel and
                    r['derived_live_bit'] == 1 and r['custom_present'] == 1]
            self.assertTrue(rows)
            self.assertTrue(all(r['local_selection'] == 'assertion' for r in rows))

    def test_custom_path_nonlive_bypasses_default_prefix_helper(self):
        for disabled in (False, True):
            for prefix in (False, True):
                self.assertEqual(log.classify(0, 1, disabled, True, prefix), (False, 'clone_custom'))

    def test_missing_path_default_and_helper_boundaries(self):
        self.assertEqual(log.classify(1, 1, False, False, False), (True, 'move_default'))
        self.assertEqual(log.classify(1, 1, True, False, False), (True, 'move_absent'))
        self.assertEqual(log.classify(0, 1, False, False, True), (False, 'prefix_helper_absent'))
        self.assertEqual(log.classify(2, 1, False, False, True), (True, 'prefix_helper_default'))

    def test_invalid_scenario_inputs_rejected(self):
        for values in ((-1, 1, False, False, False), (256, 1, False, False, False),
                       (1, 256, False, False, False), (1, 1, 1, False, False)):
            with self.subTest(values=values), self.assertRaises(ValueError):
                log.classify(*values)

    def test_map_duplicate_bypasses_length_increment(self):
        self.assertEqual(self.edge_by_name['path_map_equal']['destination'], '0x14cadc3')
        self.assertEqual(self.edge_by_name['path_map_replacement_return']['destination'], '0x14caec8')
        self.assertEqual(self.contract_by_name['path_map_new_length_and_sentinel']['va'], '0x14caeb7')
        self.assertEqual(self.edge_by_name['appender_map_equal']['destination'], '0x14cba07')
        self.assertEqual(self.edge_by_name['appender_map_replacement_return']['destination'], '0x14cbaab')
        self.assertEqual(self.contract_by_name['appender_map_new_length']['va'], '0x14cbaa5')

    def test_selected_relocations_resolve_and_are_unique(self):
        rows = log.parse_relocations(self.view)
        self.assertEqual(len(rows), len(log.RELOCS))
        self.assertEqual(len({r['slot_va'] for r in rows}), len(rows))
        self.assertEqual(next(r['addend'] for r in rows if r['slot_va'] == '0x576e928'), '0x577b288')

    def test_changed_relocation_addend_rejected(self):
        row = next(r for r in self.result['relocations'] if r['slot_va'] == '0x576e928')
        offset = int(row['relocation_file_offset'], 16) + 16
        replacement = bytes([self.data[offset] ^ 1])
        with self.changed(offset, replacement):
            with self.assertRaisesRegex(ValueError, 'relocation changed'):
                log.parse_relocations(self.view)

    def test_duplicate_relocation_slot_rejected(self):
        row = next(r for r in self.result['relocations'] if r['slot_va'] == '0x576e928')
        offset = int(row['relocation_file_offset'], 16)
        following = offset + 24
        with self.changed(following, self.data[offset:offset+8]):
            with self.assertRaisesRegex(ValueError, 'duplicate selected relocation'):
                log.parse_relocations(self.view)

    def test_lsda_rows_cover_selected_call_sites(self):
        rows = self.result['lsda_sites']
        self.assertEqual(len(rows), 122)
        cases = {0x13e2ad5: '0x13e45e8', 0x13e2d90: '0x13e45c4',
                 0x13e333a: '0x13e460b', 0x13ecfd6: '0x13ed041'}
        for site, landing in cases.items():
            hits = [r for r in rows if int(r['start_va'],16) <= site < int(r['end_va'],16)]
            self.assertEqual(len(hits), 1)
            self.assertEqual(hits[0]['landing_va'], landing)

    def test_lsda_rejects_changed_header_and_table_length(self):
        offset = self.view.offset(0x91fc80, 7)
        for relative, replacement in ((0,b'\x00'), (1,b'\x01'), (4,b'\x03'), (5,b'\xff')):
            with self.subTest(relative=relative):
                with self.changed(offset + relative, replacement):
                    with self.assertRaises(ValueError):
                        log.parse_lsda(self.view, 0x13e28c0, 0x13e4cd4, 0x91fc80)

    def test_lsda_rejects_nobits_and_out_of_range(self):
        with self.assertRaises(ValueError):
            log.parse_lsda(self.view, 0x13e28c0, 0x13e4cd4, 0x577b288)
        with self.assertRaises(ValueError):
            log.parse_lsda(self.view, 0x13e28c0, 0x13e28d0, 0x91fc80)

    def test_diagnostic_lengths_and_identity(self):
        diag = self.result['diagnostics']
        self.assertEqual(diag['custom_live_assertion']['text'], 'assertion failed: !is_live')
        self.assertEqual(len(diag['builder_unwrap']['text']), diag['builder_unwrap']['length'])
        self.assertEqual(self.edge_by_name['final_builder_error']['destination'], '0x13e42d3')


if __name__ == '__main__':
    unittest.main()
