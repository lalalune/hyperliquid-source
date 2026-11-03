"""Negative controls and synthetic models for the selected static evidence."""
import itertools
import json
import struct
import sys
import tempfile
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import abci_row_repr115 as evidence


class Node:
    def __init__(self, keys, children=()):
        self.keys = list(keys)
        self.children = list(children)
        self.parent = None
        self.parent_index = None
        for i, child in enumerate(self.children):
            child.parent, child.parent_index = self, i


def forward_step(cursor):
    """Synthetic model of the selected cursor; not execution of node code."""
    if cursor['remaining'] == 0:
        return None
    cursor['remaining'] -= 1
    if cursor['tag'] != 1:
        raise ValueError('tag')
    node = cursor['node']
    depth = cursor['depth']
    index = cursor['index']
    if node is None:
        node = cursor['root']
        while depth:
            node = node.children[0]
            depth -= 1
        index = 0
    while index >= len(node.keys):
        parent = node.parent
        if parent is None:
            raise ValueError('missing parent')
        index = node.parent_index
        node = parent
        depth += 1
    result = node.keys[index]
    if depth:
        next_node = node.children[index + 1]
        for _ in range(depth - 1):
            next_node = next_node.children[0]
        cursor['node'], cursor['index'] = next_node, 0
    else:
        cursor['node'], cursor['index'] = node, index + 1
    cursor['depth'] = 0
    return result


def dedup_until_zero(rows, value_offset, value_width):
    """Reference model: emit last in each adjacent run, stop at zero payload."""
    emitted = []
    for row in rows:
        if len(row) != 32:
            raise ValueError('row size')
        if not int.from_bytes(row[value_offset:value_offset + value_width], 'little'):
            break
        if emitted and emitted[-1][:20] == row[:20]:
            emitted[-1] = row
        else:
            emitted.append(row)
    return emitted


def row(key, payload, pointer_layout):
    if len(key) != 20:
        raise ValueError('key size')
    if pointer_layout:
        return key + b'abcd' + struct.pack('<Q', payload)
    return key + struct.pack('<IQ', payload, payload * 3)


def scratch_rows(count):
    if count < 0:
        raise ValueError('negative count')
    return max(min(count, 250000), count - count // 2)


def selected_shrink(capacity, length, old_pointer, new_pointer, sentinel):
    """Synthetic zero-head, zero-request branch with an injected helper result."""
    if not 0 <= length <= capacity:
        raise ValueError('invalid descriptor')
    if capacity == length:
        return capacity, old_pointer, 'unchanged'
    if length == 0:
        return 0, sentinel, 'release boundary'
    if new_pointer == 0:
        raise ValueError('allocation failure boundary')
    return length, new_pointer, 'resize boundary'


class BinaryControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = evidence.TARGET.read_bytes()
        cls.sections = evidence.elf_index.sections(cls.data)
        cls.files = evidence.extract(cls.data)

    def test_identity_accepts_target(self):
        evidence.identity(self.data)
        self.assertEqual(len(evidence.SHA115), 64)

    def test_identity_rejects_wrong_digest(self):
        with self.assertRaisesRegex(ValueError, 'digest'):
            evidence.identity(b'incorrect')
        with self.assertRaisesRegex(ValueError, 'digest'):
            evidence.identity(self.data, '0' * 64)

    def test_bad_digest_does_not_create_output(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'not-created'
            with self.assertRaises(ValueError):
                evidence.generate(b'bad input', output)
            self.assertFalse(output.exists())

    def test_elf_file_mappings_and_boundaries(self):
        section = next(s for s in self.sections if s['name'] == '.text')
        actual, offset = evidence.mapping(self.sections, section['address'], 1, True)
        self.assertEqual(actual['name'], '.text')
        self.assertEqual(offset, section['offset'])
        with self.assertRaises(ValueError):
            evidence.mapping(self.sections, section['address'] - 1, 1, True)
        with self.assertRaises(ValueError):
            evidence.mapping(self.sections, section['address'] + section['size'] - 1, 2, True)
        for va, size in ((-1, 1), (0, 0), (2**64, 1)):
            with self.subTest(va=va, size=size), self.assertRaises(ValueError):
                evidence.mapping(self.sections, va, size)

    def test_nobits_and_ambiguous_mapping_rejected(self):
        base = {'name': 'x', 'type': 1, 'flags': 4, 'address': 100, 'offset': 0, 'size': 8}
        nobits = dict(base, type=8)
        with self.assertRaises(ValueError):
            evidence.mapping([nobits], 100, 1)
        with self.assertRaises(ValueError):
            evidence.mapping([base, dict(base, name='overlap')], 100, 1)
        with self.assertRaises(ValueError):
            evidence.mapping([dict(base, flags=0)], 100, 1, executable=True)
        self.assertEqual(evidence.mapping([base, nobits], 100, 1)[1], 0)

    def test_each_body_digest_and_every_single_byte_corruption_at_boundary(self):
        for label, start, end, digest in evidence.BODIES:
            original = evidence.read_va(self.data, self.sections, start, end - start, True)
            evidence.checked_body(original, digest)
            for i in (0, len(original) // 2, len(original) - 1):
                changed = bytearray(original)
                changed[i] ^= 1
                with self.subTest(label=label, offset=i), self.assertRaises(ValueError):
                    evidence.checked_body(changed, digest)

    def test_changed_context_is_rejected(self):
        section = {'name': '.text', 'type': 1, 'flags': 4, 'address': 0x1000,
                   'offset': 0, 'size': 4}
        spec = (('test', 0x1000, '01020304'),)
        self.assertEqual(len(evidence.check_context(bytes.fromhex('01020304'), [section], spec)), 1)
        with self.assertRaises(ValueError):
            evidence.check_context(bytes.fromhex('01020305'), [section], spec)

    def test_direct_and_indirect_transfer_targets(self):
        for name, va, form, expected in evidence.TRANSFERS:
            raw = evidence.read_va(self.data, self.sections, va, 6, True)
            _, actual = evidence.branch_bytes(raw, va, form, expected)
            self.assertEqual(actual, expected, name)

    def test_branch_corruption_controls(self):
        raw = evidence.read_va(self.data, self.sections, 0x5169698, 6, True)
        changed = bytearray(raw)
        changed[1] ^= 1
        with self.assertRaises(ValueError):
            evidence.branch_bytes(changed, 0x5169698, 'call', 0x4cb4ec0)
        changed = bytearray(raw)
        changed[0] = 0x90
        with self.assertRaises(ValueError):
            evidence.branch_bytes(changed, 0x5169698, 'call', 0x4cb4ec0)
        with self.assertRaises(ValueError):
            evidence.branch_bytes(b'\xe8\x00', 0, 'call')
        self.assertEqual(evidence.branch_bytes(bytes.fromhex('75fe'), 0x100, 'jcc'), (2, 0x100))
        self.assertEqual(evidence.branch_bytes(bytes.fromhex('ebfc'), 0x100, 'jump'), (2, 0xfe))

    def test_operand_corruption_controls(self):
        self.assertEqual(evidence.operand_bytes(bytes.fromhex('4883fa40'), '4883fa', 'B', 64)[0], 64)
        for raw in ('4883fa41', '4883fb40', '4883fa'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                evidence.operand_bytes(bytes.fromhex(raw), '4883fa', 'B', 64)

    def test_selected_relocations_and_location(self):
        rel = evidence.relocations(self.data, self.sections, evidence.SLOTS)
        self.assertEqual(rel[0x64dfb50]['symbol_name'], 'memcmp')
        self.assertEqual(rel[0x64df508]['symbol_name'], 'memcpy')
        self.assertEqual(rel[0x64df568]['symbol_name'], 'memmove')
        location = evidence.location(self.data, self.sections, rel, 0x64767a8, 123, 37)
        self.assertEqual(location['source_suffix'], 'l1/src/abci/state.rs')
        with self.assertRaises(ValueError):
            evidence.location(self.data, self.sections, rel, 0x64767a8, 122, 37)

    def test_relocation_wrong_type_target_and_missing(self):
        for targets in ({0x64df508: (8, 0)}, {0x64df480: (8, 0)}, {0x12345678: (8, None)}):
            with self.subTest(targets=targets), self.assertRaises(ValueError):
                evidence.relocations(self.data, self.sections, targets)

    def test_invalid_location_pointer_is_rejected(self):
        rel = {0x64767a8: {'type': 8, 'addend': hex(2**64)}}
        with self.assertRaises(ValueError):
            evidence.location(self.data, self.sections, rel, 0x64767a8, 123, 37)

    def test_duplicate_section_names_rejected(self):
        text = next(s for s in self.sections if s['name'] == '.text')
        with self.assertRaises(ValueError):
            evidence.section_named([text, text], '.text')
        with self.assertRaises(ValueError):
            evidence.section_named([dict(text, type=8)], '.text')

    def test_lsda_synthetic_valid_and_malformed(self):
        fde = {'start': 0x1000, 'end': 0x1010}
        good = bytes.fromhex('ffff010400010000')
        decoded = evidence.lsda_rows(good, 0, len(good), fde)
        self.assertEqual((decoded[0]['start'], decoded[0]['end']), (0x1000, 0x1001))
        typed = bytes.fromhex('ff9b06010400010000')
        self.assertEqual(len(evidence.lsda_rows(typed, 0, len(typed), fde)), 1)
        for raw in (bytes.fromhex('ff00010400010000'), bytes.fromhex('ffff010500010000'),
                    bytes.fromhex('ffff010400000000'), bytes.fromhex('ffff010400011000'),
                    bytes.fromhex('ffff01080002000001010000'), bytes.fromhex('ffff010180')):
            with self.subTest(raw=raw.hex()), self.assertRaises(ValueError):
                evidence.lsda_rows(raw, 0, len(raw), fde)

    def test_actual_unwind_records_are_bounded(self):
        rows = self.files['unwind.tsv'].decode('ascii').splitlines()
        links = self.files['unwind-links.tsv'].decode('ascii').splitlines()
        self.assertGreater(len(rows), 1)
        self.assertTrue(any('first_shrink_failure\t' in line and '0x58028e9' in line for line in links))
        self.assertTrue(any('second_shrink_failure\t' in line and '0x5804809' in line for line in links))
        self.assertTrue(any('no_lsda' in line for line in links))

    def test_generated_file_set_and_selected_counts(self):
        expected = {'functions.tsv', 'windows.tsv', 'transfers.tsv', 'operands.tsv', 'relocations.tsv', 'key-flow.tsv',
                    'unwind.tsv', 'unwind-links.tsv', 'location.json', 'family-differences.json', 'summary.json'}
        self.assertEqual(set(self.files), expected)
        summary = json.loads(self.files['summary.json'])
        self.assertEqual(summary['new_fdes'], len(evidence.BODIES))
        self.assertEqual(summary['selected_transfers'], len(evidence.TRANSFERS))
        self.assertEqual(summary['selected_operands'], len(evidence.OPERANDS))
        self.assertEqual(summary['sha256'], evidence.SHA115)

    def test_all_family_differences_are_raw(self):
        pairs = json.loads(self.files['family-differences.json'])
        self.assertEqual(len(pairs), 6)
        self.assertTrue(all(not p['raw_equal'] and p['difference_count'] > 0 for p in pairs))
        self.assertTrue(all(not p['normalization_masks'] for p in pairs))
        self.assertTrue(all(len(p['differences']) == p['difference_count'] for p in pairs))

    def test_key_projection_crosses_both_frames(self):
        rows = self.files['key-flow.tsv'].decode('ascii').splitlines()
        self.assertEqual(len(rows), 13)
        self.assertIn('\t0x469\t0x3361\t0x468\t0x3360', rows[1])
        self.assertIn('\t0xc31\t0x501\t0xc30\t0x500', rows[-1])

    def test_copy_projection_negative_boundaries(self):
        self.assertEqual(evidence.project_span(10, 100, 20, 10, 20), 100)
        for position, width in ((9, 1), (10, 21), (29, 2), (30, 1)):
            with self.subTest(position=position, width=width), self.assertRaises(ValueError):
                evidence.project_span(10, 100, 20, position, width)
        values = {label: expected for label, _, _, _, expected in evidence.OPERANDS}
        self.assertEqual(len(evidence.key_flow(values)), 12)
        for label, replacement in (('copy_1_len', 0x258), ('copy_11_src', 0x199),
                                   ('worker_subobject_offset', 0x2a1)):
            changed = dict(values, **{label: replacement})
            with self.subTest(label=label), self.assertRaises(ValueError):
                evidence.key_flow(changed)


class SyntheticSemantics(unittest.TestCase):
    def test_all_key_byte_positions_prevent_duplicate_coalescing(self):
        key = bytes(range(20))
        for pointer_layout in (True, False):
            off, width = (24, 8) if pointer_layout else (20, 4)
            for position in range(20):
                different = bytearray(key)
                different[position] ^= 1
                rows = [row(key, 1, pointer_layout), row(bytes(different), 2, pointer_layout)]
                with self.subTest(pointer_layout=pointer_layout, position=position):
                    self.assertEqual(len(dedup_until_zero(rows, off, width)), 2)

    def test_duplicate_key_keeps_last_complete_row(self):
        for pointer_layout in (True, False):
            off, width = (24, 8) if pointer_layout else (20, 4)
            key = bytes(20)
            rows = [row(key, 1, pointer_layout), row(key, 2, pointer_layout), row(key, 3, pointer_layout)]
            self.assertEqual(dedup_until_zero(rows, off, width), [rows[-1]])

    def test_pointer_rows_ignore_four_nonkey_bytes_but_keep_last_row(self):
        first = bytearray(row(bytes(20), 1, True))
        last = bytearray(row(bytes(20), 2, True))
        first[20:24], last[20:24] = b'left', b'rght'
        self.assertEqual(dedup_until_zero([bytes(first), bytes(last)], 24, 8), [bytes(last)])

    def test_nonadjacent_duplicates_remain(self):
        a, b = bytes(20), bytes([1]) + bytes(19)
        rows = [row(a, 1, True), row(b, 2, True), row(a, 3, True)]
        self.assertEqual(dedup_until_zero(rows, 24, 8), rows)

    def test_zero_payload_is_a_stop_not_a_skip(self):
        for pointer_layout in (True, False):
            off, width = (24, 8) if pointer_layout else (20, 4)
            a, b, c = (bytes([i]) * 20 for i in range(3))
            rows = [row(a, 1, pointer_layout), row(b, 0, pointer_layout), row(c, 2, pointer_layout)]
            self.assertEqual(dedup_until_zero(rows, off, width), rows[:1])
            self.assertEqual(dedup_until_zero(rows[1:], off, width), [])

    def test_exhaustive_adjacent_runs_against_independent_grouping(self):
        keys = [bytes([i]) * 20 for i in range(3)]
        for count in range(7):
            for sequence in itertools.product(range(3), repeat=count):
                rows = [row(keys[key], i + 1, False) for i, key in enumerate(sequence)]
                expected = [list(group)[-1] for _, group in itertools.groupby(rows, lambda item: item[:20])]
                self.assertEqual(dedup_until_zero(rows, 20, 4), expected)

    def test_scratch_boundaries_for_large_route(self):
        for n, expected in ((64, 64), (65, 65), (127, 127), (128, 128), (129, 129),
                            (250000, 250000), (250001, 250000), (500000, 250000),
                            (500001, 250001)):
            with self.subTest(n=n):
                self.assertEqual(scratch_rows(n), expected)
        with self.assertRaises(ValueError):
            scratch_rows(-1)

    def test_forward_cursor_inorder_and_exhaustion(self):
        n1, n3, n5, n7 = (Node([i]) for i in (1, 3, 5, 7))
        root = Node([4], [Node([2], [n1, n3]), Node([6], [n5, n7])])
        cursor = {'tag': 1, 'remaining': 7, 'root': root, 'node': None, 'depth': 2, 'index': 0}
        self.assertEqual([forward_step(cursor) for _ in range(7)], list(range(1, 8)))
        self.assertIsNone(forward_step(cursor))
        self.assertEqual(cursor['remaining'], 0)

    def test_cursor_empty_before_tag_check_and_bad_tag_after_decrement(self):
        cursor = {'tag': 9, 'remaining': 0}
        self.assertIsNone(forward_step(cursor))
        cursor['remaining'] = 1
        with self.assertRaisesRegex(ValueError, 'tag'):
            forward_step(cursor)
        self.assertEqual(cursor['remaining'], 0)

    def test_cursor_inconsistent_count_detects_missing_parent(self):
        root = Node([5])
        cursor = {'tag': 1, 'remaining': 2, 'root': root, 'node': None, 'depth': 0, 'index': 0}
        self.assertEqual(forward_step(cursor), 5)
        with self.assertRaisesRegex(ValueError, 'parent'):
            forward_step(cursor)
        self.assertEqual(cursor['remaining'], 0)

    def test_cursor_descent_eight_step_boundaries(self):
        for depth in (0, 1, 7, 8, 9):
            node = Node([1])
            for i in range(depth):
                node = Node([10 + i], [node, Node([100 + i])])
            cursor = {'tag': 1, 'remaining': 1, 'root': node, 'node': None, 'depth': depth, 'index': 0}
            self.assertEqual(forward_step(cursor), 1)

    def test_small_branch_release_resize_alias_and_sentinels(self):
        # Caller supplies head zero and request zero on the selected branch.
        for sentinel in (8, 4):
            self.assertEqual(selected_shrink(0, 0, sentinel, 77, sentinel),
                             (0, sentinel, 'unchanged'))
            self.assertEqual(selected_shrink(64, 0, 99, 77, sentinel),
                             (0, sentinel, 'release boundary'))
            self.assertEqual(selected_shrink(64, 64, 99, 77, sentinel),
                             (64, 99, 'unchanged'))
            self.assertEqual(selected_shrink(64, 63, 99, 77, sentinel),
                             (63, 77, 'resize boundary'))
            with self.assertRaisesRegex(ValueError, 'failure'):
                selected_shrink(64, 63, 99, 0, sentinel)
            with self.assertRaisesRegex(ValueError, 'descriptor'):
                selected_shrink(63, 64, 99, 77, sentinel)

    def test_flag_byte_gate_for_every_byte(self):
        for flag in range(256):
            captured_key = flag != 1
            third_collection_runs = flag == 0
            if third_collection_runs:
                self.assertTrue(captured_key)
            else:
                self.assertNotEqual(flag, 0)


if __name__ == '__main__':
    unittest.main()
