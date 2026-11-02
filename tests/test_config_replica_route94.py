"""Digest-bound static and synthetic controls for the replica data route."""
import hashlib
import unittest

from tools import config_replica_route94 as route


class Overlay:
    """Replace a byte only in VA reads, leaving the ELF section map intact."""
    def __init__(self, view, target):
        self.view = view
        self.target = target

    def offset(self, va, size):
        return self.view.offset(va, size)

    def read(self, va, size):
        result = bytearray(self.view.read(va, size))
        if va <= self.target < va + size:
            result[self.target - va] ^= 1
        return bytes(result)


class RawView:
    def __init__(self, raw):
        self.raw = raw

    def read(self, va, size):
        if va != 0 or size > len(self.raw):
            raise ValueError('range')
        return self.raw[:size]

    def offset(self, va, size):
        self.read(va, size)
        return 0


class ReplicaRouteControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = route.TARGET.read_bytes()
        cls.view = route.View(cls.data)
        cls.rows = route.collect(cls.data)

    def test_full_binary_identity_and_corruption(self):
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), route.DIGEST)
        route.verify_identity(self.data)
        damaged = bytearray(self.data)
        damaged[self.view.offset(0x474bd90, 1)] ^= 1
        with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
            route.verify_identity(damaged)
        with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
            route.verify_identity(self.data[:-1])

    def test_each_selected_body_matches_the_digest_and_fde(self):
        rows = self.rows['fnrows']
        self.assertEqual(len(rows), 12)
        self.assertEqual(len({r['start_va'] for r in rows}), 12)
        for row in rows:
            start = int(row['start_va'], 16)
            end = int(row['end_va'], 16)
            self.assertEqual(end - start, row['size'])
            self.assertEqual(hashlib.sha256(self.view.read(start, end-start)).hexdigest(),
                             row['sha256'])

    def test_unwind_index_duplicate_and_missing_start_rejected(self):
        index = [{'start': 1, 'fde': 10}, {'start': 2, 'fde': 20}]
        self.assertEqual(route.selected_unwind_index(index, [2])[2]['fde'], 20)
        with self.assertRaisesRegex(ValueError, 'duplicate selected unwind-index start'):
            route.selected_unwind_index(index + [{'start': 1, 'fde': 99}], [1])
        with self.assertRaisesRegex(ValueError, 'missing selected unwind-index start'):
            route.selected_unwind_index(index, [3])

    def test_selected_function_corruption_rejected_beyond_image_gate(self):
        damaged = bytearray(self.data)
        damaged[self.view.offset(0x474bd90, 1)] ^= 1
        with self.assertRaisesRegex(ValueError, 'selected body digest changed'):
            route.collect(damaged, check_identity=False)

    def test_virtual_mapping_rejects_unbacked_ambiguous_and_overflow(self):
        bss = next(s for s in self.view.sections if s['name'] == '.bss')
        with self.assertRaises(ValueError):
            self.view.offset(bss['address'] + bss['size'] - 1, 1)
        section = {'type': 1, 'address': 8, 'size': 4, 'offset': 0}
        overlapping = route.View(b'abcd', [section, dict(section)])
        with self.assertRaises(ValueError):
            overlapping.offset(8, 1)
        for va, size in ((-1, 1), (1 << 64, 1), (1, 0), (1, -1)):
            with self.subTest(va=va, size=size), self.assertRaises(ValueError):
                self.view.offset(va, size)

    def test_fixed_contract_and_byte_mutation(self):
        label, va, expected = next(c for c in route.CONTRACTS if c[0] == 'name_gate')
        self.assertEqual(route.require(self.view, label, va, expected)['bytes'], expected)
        with self.assertRaisesRegex(ValueError, 'byte contract changed'):
            route.require(Overlay(self.view, va + 5), label, va, expected)

    def test_instruction_decoder_rejects_bad_inputs_and_interior_branch(self):
        self.assertEqual(route.decode_one(bytes.fromhex('e801000000'), 0, 0x1000)['target'], 0x1006)
        with self.assertRaisesRegex(ValueError, 'truncated'):
            route.decode_one(bytes.fromhex('e8ff'), 0, 0x1000)
        with self.assertRaisesRegex(ValueError, 'unsupported'):
            route.decode_one(bytes.fromhex('0f0f'), 0, 0x1000)
        with self.assertRaisesRegex(ValueError, 'branch into an instruction'):
            route.decode_body(bytes.fromhex('eb014889c0c3'), 0x1000)

    def test_direct_and_rip_operands_and_corrupt_opcodes(self):
        self.assertEqual(route.direct(self.view, 0x474bec6), 0x4b307c0)
        self.assertEqual(route.rip(self.view, 0x474beb4), 0x6fb7c5)
        with self.assertRaises(ValueError):
            route.direct(Overlay(self.view, 0x474bec6), 0x474bec6)
        with self.assertRaises(ValueError):
            route.rip(Overlay(self.view, 0x474beb4), 0x474beb4)

    def test_selected_bindings_and_mismatched_addend(self):
        bindings = {int(row['slot_va'], 16): row for row in self.rows['relocations']}
        self.assertEqual(len(bindings), 26)
        self.assertEqual(bindings[0x5773b28]['addend'], '0x474bd90')
        self.assertEqual(bindings[0x576eb88]['symbol'], 'write')
        self.assertEqual(bindings[0x5668488]['addend'], '0x2180ff')
        with self.assertRaisesRegex(ValueError, 'selected relocation changed'):
            route.parse_bindings(self.view, {0x5773b28: (8, 0, '')})
        with self.assertRaisesRegex(ValueError, 'missing selected relocation'):
            route.parse_bindings(self.view, {0: (8, 0, '')})

    def test_lsda_header_corruption_is_not_accepted(self):
        first = self.rows['lsda_headers'][0]
        damaged = bytearray(self.data)
        damaged[int(first['header_file_offset'], 16)] = 0
        changed = route.View(damaged, self.view.sections)
        start = int(first['function'], 16)
        end = next(end for _, fn, end, _ in route.FUNCTIONS if fn == start)
        with self.assertRaisesRegex(ValueError, 'unsupported LSDA header'):
            route.parse_lsda(changed, start, end, int(first['lsda_va'], 16))

    def test_literal_lengths_and_failure_anchors_are_checked(self):
        slices = {item['label']: item for item in self.rows['data_rows']}
        self.assertEqual(slices['local_operation']['bytes'], b'remove_dir'.hex())
        self.assertEqual(slices['time_failure']['length'], 43)
        self.assertEqual(slices['entry_failure']['length'], 55)
        self.assertEqual(slices['child_time_pattern']['length'], 22)
        self.assertEqual(route.immediate32(self.view, 0x4b30869, 'ba'), 10)
        with self.assertRaisesRegex(ValueError, 'immediate instruction changed'):
            route.immediate32(Overlay(self.view, 0x4b30869), 0x4b30869, 'ba')
        with self.assertRaisesRegex(ValueError, 'data slice changed'):
            route.selected_slice(Overlay(self.view, 0x219c46), 'operation',
                                 0x219c46, 10, b'remove_dir')

    def test_parent_finalizer_calls_pending_and_has_cleanup(self):
        ins = {row['va']: row for row in self.rows['instructions']}
        self.assertEqual(ins['0x1d3aa7c']['kind'], 'indirect_call')
        self.assertEqual(ins['0x1d3aa7c']['target_va'], '0x5773038')
        bindings = {row['slot_va']: row for row in self.rows['relocations']}
        self.assertEqual(bindings['0x5773038']['addend'], '0x4760b00')
        cfg = {row['label']: row['reachable'] for row in self.rows['cfg']}
        self.assertEqual(cfg['parent_start_reaches_pending'], 1)
        self.assertEqual(cfg['parent_unwind_reaches_field_cleanup'], 1)
        label, va, expected = next(c for c in route.CONTRACTS if c[0] == 'finalize_entry')
        with self.assertRaisesRegex(ValueError, 'byte contract changed'):
            route.require(Overlay(self.view, 0x1d3aa7c), label, va, expected)

    def test_boundary_call_targets_use_checked_relocations(self):
        edges = {row['site_va']: row for row in self.rows['boundary_edges']}
        self.assertEqual(edges['0x226edfb']['operand_va'], '0x5773b28')
        self.assertEqual(edges['0x226edfb']['resolved_va'], '0x474bd90')
        self.assertEqual(edges['0x4b306eb']['resolved_va'], '0x45ba470')
        self.assertEqual(edges['0x4b30694']['resolved_va'], '0x4b20250')
        label, va, expected = next(c for c in route.BOUNDARIES if c[0] == 'handoff_write')
        with self.assertRaisesRegex(ValueError, 'byte contract changed'):
            route.require(Overlay(self.view, 0x4b306eb), label, va, expected)

    def test_handoff_is_contiguous_and_covered_by_subsequent_copy(self):
        row = self.rows['handoff']
        moves = row['moves']
        self.assertEqual(sorted((int(m['object_relative_offset'], 16), m['width']) for m in moves),
                         [(0, 16), (16, 16), (32, 16), (48, 16), (64, 16),
                          (80, 16), (96, 16), (112, 8)])
        self.assertEqual(row['object_field_offset'], '0x540')
        self.assertEqual(row['pending_state_offset'], '0x5b8')
        self.assertEqual(row['pending_sentinel'], '0x8000000000000000')
        label, va, expected = next(c for c in route.BOUNDARIES if c[0] == 'caller_pending_init')
        with self.assertRaisesRegex(ValueError, 'byte contract changed'):
            route.require(Overlay(self.view, va + 2), label, va, expected)
        self.assertGreaterEqual(row['subsequent_copy_bytes'], 0x540 + 120)
        self.assertIn('identity', row['limitation'])

    def test_cfg_queries_and_invalid_endpoints(self):
        by_label = {row['label']: row['reachable'] for row in self.rows['cfg']}
        self.assertEqual(by_label['entry_format_error_bypasses_constructor'], 0)
        self.assertEqual(by_label['entry_present_reaches_constructor'], 1)
        body = route.decode_body(bytes.fromhex('7402eb01c3c3'), 0x1000)
        self.assertTrue(route.reachable(body, 0x1000, 0x1005))
        self.assertFalse(route.reachable(body, 0x1000, 0x1005, forbidden=(0x1002, 0x1004)))
        with self.assertRaisesRegex(ValueError, 'instruction boundary'):
            route.reachable(body, 0x1001, 0x1005)

    def test_templates_render_literal_and_argument_bytes(self):
        templates = self.rows['templates']
        self.assertEqual(route.render_template(templates['configured'], [b'R', b'K', b'V']),
                         bytes.fromhex('522f646174612f4b2f56'))
        self.assertEqual(route.render_template(templates['child'], [b'A', b'B', b'C']),
                         bytes.fromhex('412f422f43'))
        self.assertEqual(route.render_template(templates['local'], [b'replica_cmds']).hex(),
                         self.rows['summary']['rendered_examples_hex']['local'])
        with self.assertRaisesRegex(ValueError, 'missing format argument'):
            route.render_template(templates['child'], [b'A'])
        with self.assertRaisesRegex(ValueError, 'extra format argument'):
            route.render_template(templates['child'], [b'A', b'B', b'C', b'D'])

    def test_template_corruption_truncation_and_trailing_bytes(self):
        item = self.rows['templates']['configured']
        va = int(item['va'], 16)
        with self.assertRaisesRegex(ValueError, 'template bytes changed'):
            route.template(Overlay(self.view, va + 1), va, item['bytes'])
        for raw in (bytes.fromhex('05616263'), bytes.fromhex('0161'), bytes.fromhex('0001')):
            with self.subTest(raw=raw.hex()), self.assertRaises(ValueError):
                route.template(RawView(raw), 0, raw.hex())

    def test_name_gate_all_bytes_and_boundaries(self):
        admitted = {13, 14, 18, 19, 20, 21, 31}
        for value in range(256):
            self.assertEqual(route.name_admitted(value, 0x803c6000, 31), value in admitted)
        self.assertEqual(self.rows['summary']['default_name']['table_index'], 32)
        self.assertFalse(route.name_admitted(32, 0x803c6000, 31))
        for value in (-1, 256, 0x100000000):
            with self.subTest(value=value), self.assertRaises(ValueError):
                route.name_admitted(value, 0x803c6000, 31)
        with self.assertRaises(ValueError):
            route.name_admitted(1, 0x803c6000, 32)

    def test_entry_mode_boundary_and_sentinel(self):
        rows = {(r['first_flag'], r['mode_byte']): r for r in self.rows['modes']}
        self.assertEqual(len(rows), 512)
        for flag in (0, 1):
            for mode, expected in ((0, 1), (1, 1), (2, 0), (255, 0)):
                self.assertEqual(rows[flag, mode]['mode_le_one'], expected)
                self.assertEqual(rows[flag, mode]['forwarded_low_byte'], expected)
            self.assertEqual(rows[flag, 0]['initial_value'], 'time_format' if flag else 'sentinel')

    def test_responses_null_boundary(self):
        rows = {r['byte']: r['local_result'] for r in self.rows['response_tags']}
        self.assertEqual([i for i in range(256) if rows[i] == 'literal_null'], [2])
        self.assertEqual(rows[1], 'external_value_helper')
        self.assertEqual(rows[3], 'external_value_helper')
        label, va, expected = next(c for c in route.CONTRACTS if c[0] == 'resps_null')
        with self.assertRaisesRegex(ValueError, 'byte contract changed'):
            route.require(Overlay(self.view, va + 2), label, va, expected)

    def test_saturating_increment_boundary(self):
        high = (1 << 64) - 1
        for value, expected in ((0, 1), (1, 2), (high-1, high), (high, high)):
            self.assertEqual(route.counter_increment(value), expected)
        for value in (-1, 1 << 64):
            with self.subTest(value=value), self.assertRaises(ValueError):
                route.counter_increment(value)

    def test_duration_strict_boundaries_and_unordered(self):
        f = route.duration_gate
        self.assertFalse(f(float('-inf'), 3.0))
        self.assertFalse(f(float.fromhex('0x1.7ffffffffffffp+1'), 3.0))
        self.assertFalse(f(3.0, 3.0))
        self.assertTrue(f(float.fromhex('0x1.8000000000001p+1'), 3.0))
        self.assertTrue(f(float('inf'), 3.0))
        self.assertFalse(f(float('nan'), 3.0))
        with self.assertRaises(ValueError):
            f(3, 3.0)

    def test_buffer_partial_retry_guard_and_errors(self):
        f = route.classify_drain
        self.assertEqual(f(0, b'abcdef', [(2, 0), (-1, 4), (4, 0)]), (b'', 3, 'finished'))
        self.assertEqual(f(0, b'abcdef', [(2, 0), (0, 0)]), (b'cdef', 2, 'stopped'))
        self.assertEqual(f(0, b'abcdef', [(3, 0), (-1, 5)]), (b'def', 2, 'stopped'))
        self.assertEqual(f(0, b'abcdef', [(-1, 4)]), (b'abcdef', 1, 'next_write_pending'))
        self.assertEqual(f(1, b'abcdef', [(6, 0)]), (b'abcdef', 0, 'guard_return'))
        self.assertEqual(f(0, b'', []), (b'', 0, 'guard_return'))
        self.assertEqual(f(0, b'ab', [(-1, 4)], retry_error=5), (b'ab', 1, 'stopped'))
        for result in (-2, 7):
            with self.subTest(result=result), self.assertRaises(ValueError):
                f(0, b'abcdef', [(result, 0)])


if __name__ == '__main__':
    unittest.main()
