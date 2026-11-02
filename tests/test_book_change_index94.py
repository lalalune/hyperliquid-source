"""Offline controls for the node 94 change-index evidence collector."""
import copy
import json
import tempfile
import unittest
from pathlib import Path

from tools import book_change_index94 as m


class Node:
    def __init__(self, keys=None, children=None):
        self.keys = list(keys or ())
        self.children = list(children or ())


def synthetic_insert(root, key):
    """A standalone tree model using the pinned pivot rule, not target code."""
    def descend(node):
        at = 0
        while at < len(node.keys) and node.keys[at] < key:
            at += 1
        if at < len(node.keys) and node.keys[at] == key:
            return None, False
        promoted = key
        new_child = None
        if node.children:
            child_result, added = descend(node.children[at])
            if not added:
                return None, False
            if child_result is None:
                return None, True
            promoted, new_child = child_result
        if len(node.keys) < 11:
            node.keys.insert(at, promoted)
            if node.children:
                node.children.insert(at + 1, new_child)
            return None, True
        rule = m.split_projection(at)
        pivot = rule['old_pivot_index']
        old_keys = node.keys
        left = old_keys[:pivot]
        middle = old_keys[pivot]
        right = old_keys[pivot + 1:]
        old_children = node.children
        left_children = old_children[:pivot + 1] if old_children else []
        right_children = old_children[pivot + 1:] if old_children else []
        if rule['insert_side'] == 'left':
            left.insert(at, promoted)
            if old_children:
                left_children.insert(at + 1, new_child)
        else:
            right_pos = at - pivot - 1
            right.insert(right_pos, promoted)
            if old_children:
                right_children.insert(right_pos + 1, new_child)
        node.keys = left
        node.children = left_children
        sibling = Node(right, right_children)
        return (middle, sibling), True

    if root is None:
        return Node([key]), True
    split, added = descend(root)
    if split:
        return Node([split[0]], [root, split[1]]), added
    return root, added


def inspect_tree(root):
    """Check structural invariants independently of insertion history."""
    levels = set()
    def walk(node, lower, upper, depth, is_root):
        if not (1 if is_root else 5) <= len(node.keys) <= 11:
            raise AssertionError('invalid key count')
        if node.keys != sorted(set(node.keys)):
            raise AssertionError('unsorted or repeated keys')
        if any((lower is not None and k <= lower) or (upper is not None and k >= upper)
               for k in node.keys):
            raise AssertionError('key outside ancestor bounds')
        if not node.children:
            levels.add(depth)
            return list(node.keys)
        if len(node.children) != len(node.keys) + 1:
            raise AssertionError('incorrect child count')
        out = []
        borders = [lower] + node.keys + [upper]
        for index, child in enumerate(node.children):
            out.extend(walk(child, borders[index], borders[index + 1], depth + 1, False))
            if index < len(node.keys):
                out.append(node.keys[index])
        return out
    result = walk(root, None, None, 0, True)
    if len(levels) != 1:
        raise AssertionError('leaves have unequal depth')
    return result, next(iter(levels))


class EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = m.TARGET.read_bytes()
        cls.evidence = m.collect(cls.data)
        cls.secs = m.sections(cls.data)

    def test_target_digest(self):
        self.assertEqual(m.sha256(self.data), m.TARGET_SHA256)
        m.authenticate(self.data)

    def test_reject_wrong_digest_and_modified_content(self):
        with self.assertRaises(m.EvidenceError):
            m.authenticate(self.data, '0' * 64)
        with self.assertRaises(m.EvidenceError):
            m.authenticate(self.data[:-1] + bytes([self.data[-1] ^ 1]))

    def test_five_unique_fdes_and_raw_bodies(self):
        rows = self.evidence['functions']
        self.assertEqual(len(rows), 5)
        for row, (_, start, end, digest) in zip(rows, m.FUNCTIONS):
            self.assertEqual((int(row['start_va'], 16), int(row['end_va'], 16)), (start, end))
            self.assertEqual(row['size'], end - start)
            self.assertEqual(m.sha256(bytes.fromhex(row['raw_hex'])), digest)
            if row['role'] in ('inner_entry_counterpart', 'change_map_text_field'):
                self.assertIsNone(row['lsda_va'])
            else:
                self.assertIsNotNone(row['lsda_va'])
        self.assertEqual(sum(r['size'] for r in rows), 7079)

    def test_bad_fde_extent_and_index_are_rejected(self):
        row = self.evidence['functions'][0]
        start, end = int(row['start_va'], 16), int(row['end_va'], 16)
        fde = int(row['fde_va'], 16)
        record = {'start': start, 'end': end, 'fde': fde}
        self.assertEqual(m.checked_fde({start: [record]}, {start: fde}, start, end), record)
        for records, index in (({}, {start: fde}),
                               ({start: [record, record]}, {start: fde}),
                               ({start: [{**record, 'end': end + 1}]}, {start: fde}),
                               ({start: [record]}, {start: fde + 1})):
            with self.assertRaises(m.EvidenceError):
                m.checked_fde(records, index, start, end)

    def test_every_function_rejects_corruption(self):
        for row in self.evidence['functions']:
            body = bytearray.fromhex(row['raw_hex'])
            for index in (0, len(body) // 2, len(body) - 1):
                changed = bytearray(body)
                changed[index] ^= 1
                with self.subTest(row=row['role'], index=index):
                    with self.assertRaises(m.EvidenceError):
                        m.verify_window(changed, row['sha256'])

    def test_lsda_ranges_and_selected_landing_pads(self):
        headers = self.evidence['lsda_headers']
        rows = self.evidence['lsda_entries']
        self.assertEqual(len(headers), 3)
        self.assertEqual(len(rows), 36)
        def covering(site):
            return [r for r in rows if int(r['range_start_va'], 16) <= site < int(r['range_end_va'], 16)]
        for site in (0x49599ab, 0x4205b15, 0x4223766):
            self.assertEqual(len(covering(site)), 1)
            self.assertIsNone(covering(site)[0]['landing_va'])
        for site, pad in ((0x4959a6f, 0x4959aa5),
                          (0x4206650, 0x4206714),
                          (0x4206662, 0x42066f9),
                          (0x4223ed9, 0x4223f65)):
            self.assertEqual(covering(site)[0]['landing_va'], hex(pad))

    def test_lsda_rejects_bad_headers_truncation_and_ranges(self):
        hdr = self.evidence['lsda_headers'][0]
        func = next(f for f in self.evidence['functions'] if f['start_va'] == hdr['function_start_va'])
        off = int(hdr['file_offset'], 16)
        raw = bytearray(self.data[off:off + hdr['span_size'] + 16])
        start, end, va = int(func['start_va'], 16), int(func['end_va'], 16), int(hdr['lsda_va'], 16)
        m.parse_lsda(raw, start, end, va)
        for index in (0, 1, 3):
            altered = bytearray(raw)
            altered[index] = 0
            with self.subTest(index=index):
                with self.assertRaises(m.EvidenceError):
                    m.parse_lsda(altered, start, end, va)
        with self.assertRaises(m.EvidenceError):
            m.parse_lsda(raw[:hdr['span_size'] - 1], start, end, va)
        with self.assertRaises(m.EvidenceError):
            m.parse_lsda(raw, start, start + 1, va)
        with self.assertRaises(m.EvidenceError):
            m.parse_lsda(bytes.fromhex('ffff01808080808080808080808080'), start, end, va)

    def test_all_windows_reject_corruption(self):
        self.assertEqual(len(self.evidence['windows']), len(m.WINDOWS))
        for row in self.evidence['windows']:
            raw = bytearray.fromhex(row['raw_hex'])
            m.verify_window(raw, row['sha256'])
            raw[len(raw) // 2] ^= 1
            with self.subTest(row=row['label']):
                with self.assertRaises(m.EvidenceError):
                    m.verify_window(raw, row['sha256'])

    def test_mapping_rejects_nobits_and_unbacked_ranges(self):
        bss = next(s for s in self.secs if s['name'] == '.bss')
        self.assertEqual(bss['type'], 8)
        for address, size in ((bss['address'], 1), (0, 1), (-1, 1), (0x42f7d84, 0)):
            with self.subTest(address=address, size=size):
                with self.assertRaises(m.EvidenceError):
                    m.map_va(self.secs, address, size, executable=True)
        with self.assertRaises(m.EvidenceError):
            m.map_va(self.secs, bss['address'], 1)

    def test_all_conditional_sites_decode_and_targets_stay_in_fde(self):
        selected = [(a, b) for _, a, b, _ in m.FUNCTIONS]
        for row in self.evidence['branches']:
            site = int(row['site_va'], 16)
            raw = m.read_va(self.data, self.secs, site, 6, True)
            self.assertEqual(m.decode_branch(raw, site)['raw_hex'], row['raw_hex'])
            extent = next(((a, b) for a, b in selected if a <= site < b), None)
            if extent is not None:
                self.assertTrue(extent[0] <= int(row['target_va'], 16) < extent[1])

    def test_branch_negative_controls(self):
        for row in self.evidence['branches']:
            site = int(row['site_va'], 16)
            raw = bytearray(m.read_va(self.data, self.secs, site, 6, True))
            raw[0] = 0x90
            with self.subTest(site=site):
                with self.assertRaises(m.EvidenceError):
                    m.decode_branch(raw, site)
        r = m.decode_branch(bytes.fromhex('0f840f020000'), 0x42f82a4)
        self.assertEqual(r['target_va'], '0x42f84b9')
        altered = m.decode_branch(bytes.fromhex('0f840e020000'), 0x42f82a4)
        self.assertNotEqual(altered['target_va'], r['target_va'])

    def test_all_direct_call_targets_and_corruption(self):
        for label, site, target in m.DIRECT_CALLS:
            raw = bytearray(m.read_va(self.data, self.secs, site, 5, True))
            self.assertEqual(m.decode_rel32(raw, site, target), target)
            raw[1] ^= 1
            with self.subTest(label=label):
                with self.assertRaises(m.EvidenceError):
                    m.decode_rel32(raw, site, target)
            raw[0] = 0x90
            with self.assertRaises(m.EvidenceError):
                m.decode_rel32(raw, site, target)

    def test_indirect_call_opcode_corruption(self):
        for label, site in m.INDIRECT_CALLS:
            raw = bytearray(m.read_va(self.data, self.secs, site, 6, True))
            slot = m.decode_indirect(raw, site)
            self.assertIn(slot, m.EXPECTED_RELOCATIONS)
            raw[0] ^= 1
            with self.subTest(label=label):
                with self.assertRaises(m.EvidenceError):
                    m.decode_indirect(raw, site)

    def test_change_field_key_and_formatter_edges(self):
        literal = next(r for r in self.evidence['literals'] if r['label'] == 'change_map_text_key')
        self.assertEqual(literal['text'], 'uaR')
        edges = {r['label']: r['target_va'] for r in self.evidence['direct_calls']}
        self.assertEqual(edges['text_caller_to_field'], '0x47abcf0')
        self.assertEqual(edges['text_field_to_key_writer'], '0x4ab04c0')
        self.assertEqual(edges['text_field_to_value_writer'], '0x460e280')
        branches = {r['site_va']: r['target_va'] for r in self.evidence['branches']}
        self.assertEqual(branches['0x47abcfc'], '0x47abd65')
        self.assertEqual(branches['0x47abd19'], '0x47abd7f')
        self.assertEqual(branches['0x47abd30'], '0x47abd98')

    def test_diagnostic_literals_and_corruption(self):
        for label, address, expected in m.LITERALS:
            raw = bytearray(m.read_va(self.data, self.secs, address, len(expected)))
            m.check_literal(raw, expected)
            raw[0] ^= 1
            with self.subTest(label=label):
                with self.assertRaises(m.EvidenceError):
                    m.check_literal(raw, expected)

    def test_comparison_table_and_corruption(self):
        base = 0x70046c
        raw = bytearray(m.read_va(self.data, self.secs, base, 16))
        rows = m.decode_jump_table(raw, base, (0x4935c71,) * 4)
        self.assertEqual([r['index'] for r in rows], [0, 1, 2, 3])
        for index in range(4):
            altered = bytearray(raw)
            altered[index * 4] ^= 1
            with self.subTest(index=index):
                with self.assertRaises(m.EvidenceError):
                    m.decode_jump_table(altered, base, (0x4935c71,) * 4)
        with self.assertRaises(m.EvidenceError):
            m.decode_jump_table(raw[:-1], base, (0x4935c71,) * 4)
        other_base = 0x58a480
        other = m.read_va(self.data, self.secs, other_base, 16)
        rows = m.decode_jump_table(other, other_base, (0x33a0811,) * 4)
        self.assertEqual([int(x['target_va'], 16) - 0x33a0780 for x in rows], [0x91] * 4)


    def test_counterpart_comparison_and_corruption(self):
        first = bytearray(m.read_va(self.data, self.secs, 0x4935be0, 0x1cd, True))
        second = bytearray(m.read_va(self.data, self.secs, 0x33a0780, 0x1cd, True))
        result = m.compare_counterpart(first, second)
        self.assertEqual(result['raw_different_bytes'], 27)
        self.assertEqual(result['mask_bytes'], 28)
        self.assertEqual(len(result['operands']), 7)
        self.assertEqual(result['masked_sha256'], 'fe7b4cc80d95b79e8654de9d7bf89fa51d85cd16d2c1cef1ef374fa7132e9c12')
        for offset in (0, 0x23, 0x12c, 0x141, 0x1b0, 0x1b7, 0x1be, 0x1c9):
            bad = bytearray(second)
            bad[offset] ^= 1
            with self.subTest(offset=offset):
                with self.assertRaises(m.EvidenceError):
                    m.compare_counterpart(first, bad)
        with self.assertRaises(m.EvidenceError):
            m.compare_counterpart(first, second[:-1])
        for offset, disp, size, target_a, target_b in m.COPY_OPERANDS:
            self.assertEqual(m.checked_copy_target(second, 0x33a0780, offset, disp, size, target_b), target_b)
            changed = bytearray(second)
            changed[offset + disp] ^= 1
            with self.subTest(offset=offset):
                with self.assertRaises(m.EvidenceError):
                    m.checked_copy_target(changed, 0x33a0780, offset, disp, size, target_b)
        with self.assertRaises(m.EvidenceError):
            m.checked_copy_target(second, 0x33a0780, len(second), 1, 5, 0)


    def test_outer_counterpart_comparison_and_corruption(self):
        original = bytearray(m.read_va(self.data, self.secs, 0x495a170, 0x16e, True))
        twin = bytearray(m.read_va(self.data, self.secs, 0x4959950, 0x16e, True))
        result = m.compare_outer_counterpart(original, twin)
        self.assertEqual(result['raw_different_bytes'], 21)
        self.assertEqual(result['mask_bytes'], 44)
        self.assertEqual(result['masked_sha256'], '0e31cbe78f96717e4c0dda86f82937455332da63201c7d99b626a5ad48a7a0bc')
        for off, disp, size, target_a, target_b in m.OUTER_COPY_OPERANDS:
            self.assertEqual(m.checked_copy_target(twin, 0x4959950, off, disp, size, target_b), target_b)
            altered = bytearray(twin)
            altered[off + disp] ^= 1
            with self.subTest(offset=off):
                with self.assertRaises(m.EvidenceError):
                    m.checked_copy_target(altered, 0x4959950, off, disp, size, target_b)
                with self.assertRaises(m.EvidenceError):
                    m.compare_outer_counterpart(original, altered)
        with self.assertRaises(m.EvidenceError):
            m.compare_outer_counterpart(original, twin[:-1])

    def test_key_compare_rip_load_and_symbol_binding(self):
        site = 0x42f830f
        raw = bytearray(m.read_va(self.data, self.secs, site, 7, True))
        self.assertEqual(m.decode_rip_load(raw, site), 0x576e488)
        raw[0] ^= 1
        with self.assertRaises(m.EvidenceError):
            m.decode_rip_load(raw, site)
        symbols = {r['symbol_name'] for r in self.evidence['relocations'] if r['symbol_name']}
        self.assertEqual(symbols, {'memcmp', 'memcpy', 'memmove'})
        for index in (0, 1 << 31):
            with self.assertRaises(m.EvidenceError):
                m.dynamic_symbol(self.data, self.secs, index)

    def test_named_failure_edges_are_selected_branches(self):
        by_site = {row['site_va']: row for row in self.evidence['branches']}
        self.assertEqual(len(self.evidence['failure_branches']), len(m.FAILURE_BRANCHES))
        for row in self.evidence['failure_branches']:
            branch = by_site[row['site_va']]
            self.assertEqual(row['target_va'], branch['target_va'])
            self.assertEqual(row['raw_hex'], branch['raw_hex'])

    def test_relocations_and_bad_fields(self):
        rows = self.evidence['relocations']
        m.check_relocations(rows)
        for field in ('type', 'symbol_index', 'addend'):
            changed = copy.deepcopy(rows)
            changed[0][field] ^= 1
            with self.subTest(field=field):
                with self.assertRaises(m.EvidenceError):
                    m.check_relocations(changed)
        with self.assertRaises(m.EvidenceError):
            m.check_relocations(rows[:-1])
        with self.assertRaises(m.EvidenceError):
            m.check_relocations(rows + rows[:1])

    def test_selected_relocations_are_backed_by_real_records(self):
        for row in self.evidence['relocations']:
            off = int(row['entry_file_offset'], 16)
            self.assertEqual(self.data[off:off + 24].hex(), row['raw_hex'])

    def test_all_immediate_opcodes_and_values(self):
        for label, site, prefix, length, expected in m.CONSTANT_SITES:
            raw = bytearray(m.read_va(self.data, self.secs, site, len(bytes.fromhex(prefix)) + length, True))
            self.assertEqual(m.decode_immediate(raw, prefix, length, expected), expected)
            for index in (0, len(raw) - 1):
                altered = bytearray(raw)
                altered[index] ^= 1
                with self.subTest(label=label, index=index):
                    with self.assertRaises(m.EvidenceError):
                        m.decode_immediate(altered, prefix, length, expected)

    def test_split_pivot_boundaries_and_conservation(self):
        pivots = [4, 4, 4, 4, 4, 5, 5, 6, 6, 6, 6, 6]
        sides = ['left'] * 6 + ['right'] * 6
        for pos in range(12):
            result = m.split_projection(pos)
            self.assertEqual(result['old_pivot_index'], pivots[pos])
            self.assertEqual(result['insert_side'], sides[pos])
            all_keys = result['left'] + [result['promoted']] + result['right']
            self.assertEqual(all_keys, sorted(list(range(1, 23, 2)) + [2 * pos]))
            self.assertIn(len(result['left']), (5, 6))
            self.assertIn(len(result['right']), (5, 6))

    def test_split_position_rejects_invalid_inputs(self):
        for pos in (-1, 12, 100, 0.5, True, '5'):
            with self.subTest(position=pos):
                with self.assertRaises(ValueError):
                    m.split_projection(pos)

    def test_multilevel_tree_insertions_and_duplicates(self):
        for sequence in (list(range(1021)), list(reversed(range(1021))),
                         [(i * 311) % 1021 for i in range(1021)]):
            root = None
            seen = set()
            for index, key in enumerate(sequence):
                root, added = synthetic_insert(root, key)
                self.assertTrue(added)
                seen.add(key)
                if index < 20 or index % 47 == 0:
                    self.assertEqual(inspect_tree(root)[0], sorted(seen))
            actual, height = inspect_tree(root)
            self.assertEqual(actual, sorted(seen))
            self.assertGreaterEqual(height, 2)
            for key in (0, 10, 510, 1020):
                root, added = synthetic_insert(root, key)
                self.assertFalse(added)
                self.assertEqual(inspect_tree(root)[0], actual)

    def test_synthetic_route_cases_and_low_dword_comparison(self):
        cases = (
            (0, False, 2, False, ('user_value', True, False)),
            (2, False, 0, True, ('hash_absent', False, False)),
            (0x100000002, False, 0, True, ('hash_absent', False, False)),
            (2, True, 0x100000002, True, ('slab_absent', False, False)),
            (2, True, 0, False, ('set_miss', False, True)),
            (2, True, 0, True, ('set_hit', True, True)),
        )
        for a, b, c, d, expected in cases:
            row = m.route_projection(a, b, c, d)
            self.assertEqual((row['exit'], row['change_mark'], row['continues_to_unlink']), expected)
        for bad in (-1, 1 << 64, True, '2'):
            with self.assertRaises(ValueError):
                m.route_projection(bad, True, 0, False)
        with self.assertRaises(ValueError):
            m.route_projection(2, 1, 0, False)

    def test_gate_target_and_counter_floor(self):
        row = next(r for r in self.evidence['branches'] if r['site_va'] == '0x42f82a4')
        self.assertEqual(row['target_va'], '0x42f84b9')
        by_site = {r['site_va']: r for r in self.evidence['branches']}
        self.assertEqual(by_site['0x42f7a4d']['target_va'], '0x42f818f')
        self.assertEqual(by_site['0x42f7dee']['target_va'], '0x42f818f')
        for count, expected in ((0, 0), (1, 0), (2, 1), ((1 << 64) - 1, (1 << 64) - 2)):
            self.assertEqual(count - (1 if count else 0), expected)

    def test_emission_is_stable_and_machine_readable(self):
        with tempfile.TemporaryDirectory() as temp:
            a, b = Path(temp) / 'a', Path(temp) / 'b'
            m.emit(a, self.evidence)
            m.emit(b, self.evidence)
            self.assertEqual(sorted(x.name for x in a.iterdir()), sorted(x.name for x in b.iterdir()))
            for f in a.iterdir():
                self.assertEqual(f.read_bytes(), (b / f.name).read_bytes())
            result = json.loads((a / 'evidence.json').read_text())
            self.assertEqual(result['target_sha256'], m.TARGET_SHA256)
            self.assertEqual(len(result['synthetic_split_cases']), 24)


if __name__ == '__main__':
    unittest.main()
