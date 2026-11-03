"""Static corruption controls and synthetic reverse-cursor checks."""
from dataclasses import dataclass, field
import csv
import bisect
import hashlib
import io
import itertools
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import abci_tree_cursor115 as research
from elf_index import sections
from fde_extents import eh_frame_records

U64_MAX = (1 << 64) - 1


@dataclass
class Node:
    keys: list
    children: list = field(default_factory=list)


def in_order(node):
    """Independent abstract oracle, with no cursor or parent-link logic."""
    if not node.children:
        return list(node.keys)
    result = []
    for index, key in enumerate(node.keys):
        result.extend(in_order(node.children[index]))
        result.append(key)
    result.extend(in_order(node.children[-1]))
    return result


def full_binary(height, counter):
    if height == 0:
        key = counter[0]
        counter[0] += 1
        return Node([key])
    left = full_binary(height - 1, counter)
    key = counter[0]
    counter[0] += 1
    right = full_binary(height - 1, counter)
    return Node([key], [left, right])


class Memory:
    """Synthetic, individually bounded memory pages; never target execution."""
    PAGE = 4096

    def __init__(self):
        self.pages = {}
        self.next_page = 0x10000000

    def alloc(self):
        address = self.next_page
        self.next_page += self.PAGE
        self.pages[address] = bytearray(self.PAGE)
        return address

    def position(self, address, size):
        base = address - address % self.PAGE
        offset = address - base
        if base not in self.pages or size < 0 or offset + size > self.PAGE:
            raise ValueError('synthetic address outside allocated page')
        return self.pages[base], offset

    def put(self, address, size, value):
        page, pos = self.position(address, size)
        page[pos:pos + size] = value.to_bytes(size, 'little')

    def get(self, address, size):
        page, pos = self.position(address, size)
        return int.from_bytes(page[pos:pos + size], 'little')


def load_tree(mem, node, layout, parent=0, parent_index=0):
    """Place a valid abstract tree in a synthetic layout from target operands."""
    if node.children and len(node.children) != len(node.keys) + 1:
        raise ValueError('invalid abstract tree')
    address = mem.alloc()
    mem.put(address, 8, parent)
    mem.put(address + layout['parent_index_offset'], 2, parent_index)
    mem.put(address + layout['node_len_offset'], 2, len(node.keys))
    for index, key in enumerate(node.keys):
        mem.put(address + 8 + index * 8, 8, key)
        value = address + layout['value_base_offset'] + index * layout['value_stride']
        mem.put(value, 8, (key * 17 + 3) & U64_MAX)
        if layout['value_stride'] == 72:
            mem.put(value + 0x28, 8, 0 if key % 3 == 0 else key + 1)
    for index, child in enumerate(node.children):
        child_address = load_tree(mem, child, layout, address, index)
        mem.put(address + layout['child_base_offset'] + index * 8, 8, child_address)
    return address


def reverse_step(mem, cursor, layout):
    """Instruction-derived cursor equations on synthetic data, not an emulator."""
    remaining = cursor['remaining']
    if remaining == 0:
        return None
    cursor['remaining'] = remaining - 1
    if cursor['tag'] & 0xffffffff != layout['tag_value']:
        raise ValueError('synthetic unexpected cursor tag')
    node = cursor['current']
    index = cursor['index']
    depth = cursor['root_or_depth']
    if node == 0:
        node = cursor['root_or_depth']
        for _ in range(index):
            length = mem.get(node + layout['node_len_offset'], 2)
            node = mem.get(node + layout['child_base_offset'] + 8 * length, 8)
        index = mem.get(node + layout['node_len_offset'], 2)
        cursor.update(tag=1, current=node, root_or_depth=0, index=index)
        depth = 0
    if index == 0:
        while True:
            parent = mem.get(node, 8)
            if parent == 0:
                raise ValueError('synthetic missing parent')
            depth += 1
            index = mem.get(node + layout['parent_index_offset'], 2)
            node = parent
            if index != 0:
                break
    selected_node, selected_index = node, index
    next_node, next_index = node, index - 1
    if depth:
        next_node = mem.get(node + layout['sibling_base_offset'] + 8 * index, 8)
        for _ in range(depth - 1):
            length = mem.get(next_node + layout['node_len_offset'], 2)
            next_node = mem.get(next_node + layout['child_base_offset'] + 8 * length, 8)
        next_index = mem.get(next_node + layout['node_len_offset'], 2)
    key_pointer = selected_node + 8 * selected_index
    value_pointer = selected_node + layout['value_base_offset'] + layout['value_stride'] * (selected_index - 1)
    cursor.update(current=next_node, root_or_depth=0, index=next_index)
    return key_pointer, value_pointer


def new_cursor(root, height, count):
    return {'tag': 1, 'current': 0, 'root_or_depth': root,
            'index': height, 'remaining': count}


class ExtractorControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = research.TARGET.read_bytes()
        cls.secs = sections(cls.data)
        cls.outputs = research.analyse(cls.data)
        cls.bodies = []
        cls.layouts = []
        for _, start, end, _ in research.BODIES:
            body, _, _ = research.read_va(cls.data, cls.secs, start, end - start)
            cls.bodies.append(body)
            cls.layouts.append(research.parse_fields(body))

    def test_target_hash_and_selected_metrics(self):
        self.assertEqual(research.checked_hash(self.data, research.SHA115), research.SHA115)
        self.assertEqual(len(self.outputs), 20)
        rows = list(csv.DictReader(io.StringIO(self.outputs['functions.tsv'].decode()), delimiter='\t'))
        self.assertEqual(len(rows), 2)
        self.assertEqual([int(row['size']) for row in rows], [692, 692])
        self.assertEqual(sum(len(bytes.fromhex(row['raw_hex'])) for row in rows), 1384)

    def test_wrong_and_truncated_digest_rejected(self):
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            research.checked_hash(self.data, '0' * 64)
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            research.checked_hash(self.data[:1024], research.SHA115)
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            research.historical(b'not the historical artifact')

    def test_same_size_mutation_even_if_digest_is_recomputed(self):
        bad = bytearray(self.data)
        _, off, _ = research.read_va(bad, self.secs, research.BODIES[0][1] + 0x100, 1)
        bad[off] ^= 1
        with self.assertRaisesRegex(ValueError, 'body mismatch'):
            research.analyse(bad, hashlib.sha256(bad).hexdigest())

    def test_fde_range_corruption_even_if_digest_is_recomputed(self):
        _, fdes = eh_frame_records(self.data, self.secs)
        fde = next(x for x in fdes if x['start'] == research.BODIES[0][1])
        _, off, _ = research.read_va(self.data, self.secs, fde['fde'], 16)
        bad = bytearray(self.data)
        bad[off + 12] ^= 1
        with self.assertRaises(ValueError):
            research.analyse(bad, hashlib.sha256(bad).hexdigest())

    def test_instruction_partition_covers_each_complete_extent(self):
        for role, start, end, _ in research.BODIES:
            rows = [r for r in csv.DictReader(io.StringIO(self.outputs['windows.tsv'].decode()), delimiter='\t') if r['role'] == role]
            self.assertEqual(int(rows[0]['start_va'], 16), start)
            self.assertEqual(int(rows[-1]['end_va_exclusive'], 16), end)
            self.assertTrue(all(int(a['end_va_exclusive'], 16) == int(b['start_va'], 16) for a, b in zip(rows, rows[1:])))
            self.assertEqual(sum(int(r['size']) for r in rows), end - start)

    def test_every_selected_transfer_opcode_and_displacement(self):
        for body, (_, start, _, _) in zip(self.bodies, research.BODIES):
            for label, rel, opcode, target in research.EDGES:
                with self.subTest(start=hex(start), label=label):
                    size = 2 if opcode in ('74', '75') else 5 if opcode in ('e8', 'e9') else 6
                    raw = body[rel:rel + size]
                    expected = target if opcode == 'ff15' else start + target
                    self.assertEqual(research.displacement(start + rel, raw, opcode), expected)
                    wrong_op = bytearray(raw)
                    wrong_op[0] ^= 1
                    with self.assertRaises(ValueError):
                        research.displacement(start + rel, wrong_op, opcode)
                    wrong_disp = bytearray(raw)
                    wrong_disp[-1] ^= 1
                    self.assertNotEqual(research.displacement(start + rel, wrong_disp, opcode), expected)

    def test_layout_contradictions_rejected(self):
        for body in self.bodies:
            for relative in (0x14, 0x64, 0x6c, 0x152, 0x175, 0x269, 0x270):
                with self.subTest(relative=relative):
                    damaged = bytearray(body)
                    damaged[relative] ^= 1
                    with self.assertRaises(ValueError):
                        research.parse_fields(damaged)

    def test_unrolled_descents_use_actual_node_operands(self):
        rows = list(csv.DictReader(io.StringIO(self.outputs['descent.tsv'].decode()), delimiter='\t'))
        self.assertEqual(len(rows), 32)
        for role, layout in zip(('cursor_a', 'cursor_b'), self.layouts):
            selected = [r for r in rows if r['role'] == role]
            for phase in ('initial', 'sibling'):
                steps = [r for r in selected if r['phase'] == phase]
                self.assertEqual([int(r['step']) for r in steps], list(range(8)))
                self.assertTrue(all(int(r['length_offset']) == layout['node_len_offset'] for r in steps))
                self.assertTrue(all(int(r['child_base_offset']) == layout['child_base_offset'] for r in steps))

    def test_context_calls_and_old_ownership_boundary(self):
        rows = list(csv.DictReader(io.StringIO(self.outputs['context.tsv'].decode()), delimiter='\t'))
        table = {row['label']: row for row in rows}
        self.assertEqual(int(table['a_tree_call']['target'], 16), research.BODIES[0][1])
        self.assertEqual(int(table['b_tree_call']['target'], 16), research.BODIES[1][1])
        self.assertEqual(int(table['state_location_ref']['target'], 16), 0x64767a8)

    def test_mapping_rejects_nobits_partial_overlap_and_oob(self):
        data = b'abcdefgh'
        good = {'name': 'x', 'type': 1, 'address': 100, 'offset': 0, 'size': 8}
        self.assertEqual(research.read_va(data, [good], 102, 2)[0], b'cd')
        with self.assertRaises(ValueError):
            research.read_va(data, [dict(good, type=8)], 102, 2)
        with self.assertRaises(ValueError):
            research.read_va(data, [good], 107, 2)
        with self.assertRaises(ValueError):
            research.read_va(data, [good, dict(good, name='overlap', address=103, offset=0, size=2)], 102, 2)
        with self.assertRaises(ValueError):
            research.read_va(data, [good], 100, 0)
        with self.assertRaises(ValueError):
            research.read_va(data, [good], (1 << 64) - 1, 2)

    def test_duplicate_missing_and_wrong_relocation_rejected(self):
        record = struct.pack('<QQq', 100, 8, 200)
        sec = {'name': '.rela.dyn', 'type': 4, 'offset': 0, 'size': 24}
        self.assertEqual(research.selected_relocations(record, [sec], (100,))[100]['addend'], '0xc8')
        with self.assertRaises(ValueError):
            research.selected_relocations(record * 2, [dict(sec, size=48)], (100,))
        with self.assertRaises(ValueError):
            research.selected_relocations(record, [sec], (101,))
        with self.assertRaises(ValueError):
            research.selected_relocations(struct.pack('<QQq', 100, 7, 200), [sec], (100,))
        with self.assertRaises(ValueError):
            research.selected_relocations(record, [dict(sec, type=8)], (100,))

    def test_lsda_links_and_corruption_controls(self):
        data = bytes.fromhex('ffff010b96050db20500a305110000')
        sec = {'name': '.gcc_except_table', 'type': 1, 'address': 0x1000, 'offset': 0, 'size': len(data)}
        fde = {'start': 0x2000, 'end': 0x22b4, 'lsda': 0x1000}
        rows = research.selected_lsda(data, [sec], fde)
        self.assertEqual(rows[0]['landing_va'], hex(0x22b2))
        self.assertEqual(rows[1]['landing_va'], '-')
        damaged = bytearray(data)
        damaged[0] = 0
        with self.assertRaises(ValueError):
            research.selected_lsda(damaged, [sec], fde)
        damaged = bytearray(data)
        damaged[3] = 40
        with self.assertRaises(ValueError):
            research.selected_lsda(damaged, [sec], fde)
        damaged = bytearray(data)
        damaged[7:9] = b'\xff\x7f'
        with self.assertRaises(ValueError):
            research.selected_lsda(damaged, [sec], fde)

    def test_extra_bodies_and_family_masks(self):
        rows = list(csv.DictReader(io.StringIO(self.outputs['extra-functions.tsv'].decode()), delimiter='\t'))
        self.assertEqual(len(rows), 9)
        bodies = {row['role']: bytes.fromhex(row['raw_hex']) for row in rows}
        self.assertEqual(bodies['first_compact'], bodies['second_compact'])
        left, right = bytearray(bodies['first_short_sort']), bytearray(bodies['second_short_sort'])
        self.assertNotEqual(left, right)
        left[0x4a:0x4e] = bytes(4)
        right[0x4a:0x4e] = bytes(4)
        self.assertEqual(left, right)
        self.assertEqual(hashlib.sha256(left).digest(), hashlib.sha256(right).digest())

    def test_each_extra_window_detects_every_changed_byte(self):
        for role, label, va, expected, _ in research.EXTRA_POINTS:
            raw, _, _ = research.read_va(self.data, self.secs, va, len(bytes.fromhex(expected)))
            research.check_exact(raw, expected, label)
            for offset in range(len(raw)):
                with self.subTest(role=role, label=label, offset=offset):
                    changed = bytearray(raw)
                    changed[offset] ^= 1
                    with self.assertRaises(ValueError):
                        research.check_exact(changed, expected, label)

    def test_all_family_branch_operands_and_negative_displacements(self):
        for role, (family, start) in research.FAMILY_EDGES.items():
            record = next(row for row in research.EXTRA_BODIES if row[0] == role)
            body, _, _ = research.read_va(self.data, self.secs, start, record[2] - start)
            for label, relative, opcode, target in research.EDGE_FAMILY_SPECS[family]:
                n = 2 if len(opcode) == 2 and opcode not in ('e8', 'e9') else 5 if opcode in ('e8', 'e9') else 6
                raw = body[relative:relative + n]
                with self.subTest(role=role, label=label):
                    self.assertEqual(research.displacement(start + relative, raw, opcode), start + target)
                    changed = bytearray(raw)
                    changed[-1] ^= 1
                    self.assertNotEqual(research.displacement(start + relative, changed, opcode), start + target)
                    changed = bytearray(raw)
                    changed[0] ^= 1
                    with self.assertRaises(ValueError):
                        research.displacement(start + relative, changed, opcode)

    def test_sort_and_output_size_thresholds(self):
        context = {label: bytes.fromhex(raw) for label, _, raw in research.CONTEXT}
        short = context['third_sort_threshold'][3]
        other = context['third_small_sort_threshold'][3]
        representation = context['third_representation_limit'][3]
        self.assertEqual((short, other, representation), (2, 21, 64))
        def route(count):
            sort = 'none' if count < short else 'short' if count < other else 'other'
            form = 'small' if count <= representation else 'other'
            return sort, form
        self.assertEqual([route(x) for x in (0, 1, 2, 20, 21, 64, 65)],
                         [('none','small'), ('none','small'), ('short','small'),
                          ('short','small'), ('other','small'), ('other','small'), ('other','other')])

    def test_dynamic_comparator_binding_and_corruption(self):
        observed = research.symbol_relocation(self.data, self.secs, 0x64dfb50, 'memcmp')
        self.assertEqual(observed['symbol'], 'memcmp')
        self.assertEqual(observed['type'], 6)
        rel = struct.pack('<QQq', 32, (1 << 32) | 6, 0)
        syms = bytearray(48)
        struct.pack_into('<I', syms, 24, 1)
        names = b'\0memcmp\0'
        data = rel + syms + names
        records = [{'name': '.rela.dyn', 'type': 4, 'offset': 0, 'size': 24},
                   {'name': '.dynsym', 'type': 11, 'offset': 24, 'size': 48},
                   {'name': '.dynstr', 'type': 3, 'offset': 72, 'size': len(names)}]
        self.assertEqual(research.symbol_relocation(data, records, 32, 'memcmp')['symbol'], 'memcmp')
        with self.assertRaises(ValueError):
            research.symbol_relocation(data, records, 32, 'memmove')
        with self.assertRaises(ValueError):
            research.symbol_relocation(data, records + [dict(records[1])], 32, 'memcmp')
        broken = bytearray(data)
        broken[8] = 7
        with self.assertRaises(ValueError):
            research.symbol_relocation(broken, records, 32, 'memcmp')
        broken = bytearray(data)
        struct.pack_into('<I', broken, 48, len(names) + 1)
        with self.assertRaises(ValueError):
            research.symbol_relocation(broken, records, 32, 'memcmp')

    def test_decoded_ring_layout_and_value_projection(self):
        fields = {row['field']: row['value'] for row in research.search_layout(self.data, self.secs)}
        self.assertEqual(fields, {'capacity_offset': 0, 'buffer_offset': 8, 'head_offset': 16,
                                  'length_offset': 24, 'key_bytes': 20, 'row_shift': 5,
                                  'matched_value_offset': 20})
        self.assertEqual(1 << fields['row_shift'], 32)

    def test_extra_calls_map_to_recorded_exception_ranges(self):
        rows = list(csv.DictReader(io.StringIO(self.outputs['extra-unwind-calls.tsv'].decode()), delimiter='\t'))
        self.assertEqual(len(rows), 6)
        by_call = {r['call_va']: r for r in rows}
        self.assertEqual(by_call[hex(0x5ba431f)]['landing_va'], hex(0x5ba4667))
        self.assertEqual(by_call[hex(0x5ba48ec)]['landing_va'], hex(0x5ba4972))
        self.assertEqual(by_call[hex(0x5ba496c)]['landing_va'], '-')
        self.assertTrue(all(int(r['range_start'], 16) <= int(r['call_va'], 16) < int(r['range_end'], 16) for r in rows))

    def test_typed_lsda_and_extra_cleanup_coverage(self):
        data = bytes.fromhex('ff9b04010400010000')
        sec = {'name': '.gcc_except_table', 'type': 1, 'address': 0x1000, 'offset': 0, 'size': len(data)}
        fde = {'start': 0x2000, 'end': 0x2001, 'lsda': 0x1000}
        self.assertEqual(len(research.selected_lsda(data, [sec], fde)), 1)
        damaged = bytearray(data)
        damaged[2] = 0x7f
        with self.assertRaises(ValueError):
            research.selected_lsda(damaged, [sec], fde)
        rows = list(csv.DictReader(io.StringIO(self.outputs['extra-unwind.tsv'].decode()), delimiter='\t'))
        self.assertEqual({r['role'] for r in rows}, {'first_pipeline', 'first_collector', 'second_collector'})
        self.assertTrue(any(int(r['action']) != 0 for r in rows if r['role'] == 'second_collector'))

    def test_generated_locations_hide_the_build_prefix(self):
        content = self.outputs['locations.json']
        self.assertNotIn(bytes([47]) + b'rustc' + bytes([47]), content)
        self.assertNotIn(bytes([47]) + b'home' + bytes([47]), content)
        self.assertIn(b'library/alloc/src/collections/btree/navigate.rs', content)
        self.assertIn(b'l1/src/abci/state.rs', content)


class SyntheticTreeControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        data = research.TARGET.read_bytes()
        secs = sections(data)
        cls.layouts = []
        for _, start, end, _ in research.BODIES:
            body, _, _ = research.read_va(data, secs, start, end - start)
            cls.layouts.append(research.parse_fields(body))

    def verify_tree(self, node, height, layout):
        expected = in_order(node)
        self.assertEqual(expected, sorted(expected))
        mem = Memory()
        root = load_tree(mem, node, layout)
        cursor = new_cursor(root, height, len(expected))
        observed = []
        for _ in expected:
            key_address, value_address = reverse_step(mem, cursor, layout)
            key = mem.get(key_address, 8)
            value = mem.get(value_address, 8)
            self.assertEqual(value, (key * 17 + 3) & U64_MAX)
            observed.append(key)
        self.assertEqual(observed, list(reversed(expected)))
        before = dict(cursor)
        self.assertIsNone(reverse_step(mem, cursor, layout))
        self.assertEqual(cursor, before)
        return mem, root

    def test_single_leaf_and_multikey_internal_nodes(self):
        for layout in self.layouts:
            with self.subTest(stride=layout['value_stride']):
                self.verify_tree(Node([1, 2, 3]), 0, layout)
                tree = Node([30, 60], [Node([10, 20]), Node([40, 50]), Node([70, 80])])
                self.verify_tree(tree, 1, layout)

    def test_deep_descent_and_ancestor_climb_across_eight_boundaries(self):
        for height in (0, 1, 2, 3, 7, 8, 9):
            tree = full_binary(height, [1])
            for layout in self.layouts:
                with self.subTest(height=height, stride=layout['value_stride']):
                    self.verify_tree(tree, height, layout)

    def test_nonempty_bad_tag_decrements_before_failure(self):
        for layout in self.layouts:
            mem = Memory()
            cursor = {'tag': 2, 'current': 0, 'root_or_depth': 0, 'index': 0, 'remaining': 1}
            with self.assertRaisesRegex(ValueError, 'tag'):
                reverse_step(mem, cursor, layout)
            self.assertEqual(cursor['remaining'], 0)

    def test_empty_bad_tag_returns_before_tag_check(self):
        for layout in self.layouts:
            cursor = {'tag': 2, 'current': 0, 'root_or_depth': 0, 'index': 0, 'remaining': 0}
            self.assertIsNone(reverse_step(Memory(), cursor, layout))
            self.assertEqual(cursor['remaining'], 0)

    def test_excess_remaining_missing_parent_is_failure(self):
        for layout in self.layouts:
            mem = Memory()
            root = load_tree(mem, Node([2]), layout)
            cursor = {'tag': 1, 'current': root, 'root_or_depth': 0, 'index': 0, 'remaining': 1}
            with self.assertRaisesRegex(ValueError, 'parent'):
                reverse_step(mem, cursor, layout)
            self.assertEqual(cursor['remaining'], 0)

    def test_tree_model_rejects_inaccessible_root(self):
        for layout in self.layouts:
            cursor = new_cursor(0, 0, 1)
            with self.assertRaisesRegex(ValueError, 'synthetic address'):
                reverse_step(Memory(), cursor, layout)
            self.assertEqual(cursor['remaining'], 0)

    def test_cutoff_and_optional_pointer_are_distinct_gates(self):
        node = Node([30, 60], [Node([10, 20]), Node([40, 50]), Node([70, 80])])
        layout = self.layouts[1]
        for threshold in (0, 20, 29, 30, 31, 59, 60, 61, 80, U64_MAX):
            mem = Memory()
            root = load_tree(mem, node, layout)
            cursor = new_cursor(root, 1, len(in_order(node)))
            got = []
            while True:
                item = reverse_step(mem, cursor, layout)
                if item is None:
                    break
                key = mem.get(item[0], 8)
                if key <= threshold:
                    break
                if mem.get(item[1] + 0x28, 8) == 0:
                    continue
                got.append(key)
            expected = [k for k in reversed(in_order(node)) if k > threshold and k % 3 != 0]
            self.assertEqual(got, expected)

    def test_unordered_rows_make_early_stop_unsound(self):
        # Deliberately violate the B-tree ordering precondition. The real code's
        # first <= cutoff exit then cannot be promoted into a global guarantee.
        sequence = [20, 9, 19]
        collected = []
        for key in sequence:
            if key <= 10:
                break
            collected.append(key)
        self.assertEqual(collected, [20])
        self.assertIn(19, [key for key in sequence if key > 10])


def synthetic_compact(rows):
    # Equation-level reconstruction of the selected compactor; this is not
    # execution of node instructions. The independent oracle below groups runs.
    result = list(rows)
    if any(len(row) != 32 for row in result):
        raise ValueError('synthetic row must contain 32 bytes')
    n = len(result)
    if n < 2:
        return result
    i = 0
    while i + 1 < n and result[i][:20] != result[i + 1][:20]:
        i += 1
    if i + 1 == n:
        return result
    result[i], result[i + 1] = result[i + 1], result[i]
    write = i + 1
    for read in range(i + 2, n):
        if result[write - 1][:20] == result[read][:20]:
            result[write - 1], result[read] = result[read], result[write - 1]
        else:
            result[write] = result[read]
            write += 1
    return result[:write]


def row_for(key, serial):
    return key.to_bytes(20, 'big') + serial.to_bytes(12, 'little')


def small_insertion(rows):
    data = list(rows)
    for i in range(1, len(data)):
        item = data[i]
        j = i
        while j and item[:20] < data[j - 1][:20]:
            data[j] = data[j - 1]
            j -= 1
        data[j] = item
    return data


class SyntheticRowControls(unittest.TestCase):
    def test_all_short_key_runs_keep_the_last_whole_row(self):
        for length in range(8):
            for keys in itertools.product(range(3), repeat=length):
                rows = [row_for(k, serial) for serial, k in enumerate(keys)]
                expected = [list(group)[-1] for _, group in itertools.groupby(rows, key=lambda row: row[:20])]
                with self.subTest(keys=keys):
                    self.assertEqual(synthetic_compact(rows), expected)

    def test_each_key_byte_matters_and_payload_bytes_do_not(self):
        blank = bytes(32)
        for offset in range(32):
            changed = bytearray(blank)
            changed[offset] = 1
            got = synthetic_compact([blank, bytes(changed)])
            if offset < 20:
                self.assertEqual(got, [blank, bytes(changed)])
            else:
                self.assertEqual(got, [bytes(changed)])

    def test_small_sort_and_compaction_keep_latest_equal_key(self):
        for size in range(2, 21):
            rows = [row_for((size - i) % 5, i) for i in range(size)]
            sorted_rows = small_insertion(rows)
            self.assertEqual(sorted_rows, sorted(rows, key=lambda row: row[:20]))
            last_by_key = {}
            for row in rows:
                last_by_key[row[:20]] = row
            expected = [last_by_key[key] for key in sorted(last_by_key)]
            self.assertEqual(synthetic_compact(sorted_rows), expected)

    def test_nonadjacent_duplicates_are_not_removed_without_sort(self):
        rows = [row_for(1, 1), row_for(2, 2), row_for(1, 3)]
        self.assertEqual(synthetic_compact(rows), rows)
        self.assertEqual(len(synthetic_compact(small_insertion(rows))), 2)

    def test_invalid_synthetic_row_is_rejected(self):
        with self.assertRaises(ValueError):
            synthetic_compact([bytes(31)])

    def test_synthetic_row_projection_preserves_all_key_and_value_bytes(self):
        key = bytes(range(20))
        count = 0x10203040
        word = 0x1020304050607080
        row = key + count.to_bytes(4, 'little') + word.to_bytes(8, 'little')
        self.assertEqual(len(row), 32)
        self.assertEqual(row[:20], key)
        self.assertEqual(int.from_bytes(row[20:24], 'little'), count)
        self.assertEqual(int.from_bytes(row[24:32], 'little'), word)
        for i in range(20):
            changed = bytearray(row)
            changed[i] ^= 1
            self.assertNotEqual(row[:20], changed[:20])
        for i in range(20, 32):
            changed = bytearray(row)
            changed[i] ^= 1
            self.assertEqual(row[:20], changed[:20])

    def test_second_collector_null_or_zero_stops_not_skips(self):
        def take_prefix(records):
            out = []
            for entry in records:
                if entry is None or entry[0] == 0:
                    break
                out.append(entry)
            return out
        self.assertEqual(take_prefix([(2, 10), None, (3, 20)]), [(2, 10)])
        self.assertEqual(take_prefix([(2, 10), (0, 0), (3, 20)]), [(2, 10)])
        self.assertEqual(take_prefix([]), [])



def synthetic_segment_search(segment, target):
    if not segment:
        return False, 0
    base, remaining = 0, len(segment)
    while remaining > 1:
        half = remaining // 2
        middle = base + half
        if segment[middle] <= target:
            base = middle
        remaining -= half
    if segment[base] == target:
        return True, base
    return False, base + (segment[base] < target)


def synthetic_ring_search(capacity, head, length, physical, target):
    # Selected split and midpoint equations, only for well-formed synthetic
    # descriptors. The independent oracle is bisect on logical row order.
    if capacity < 0 or length < 0 or length > capacity or len(physical) != capacity:
        raise ValueError('invalid synthetic ring')
    if capacity and not 0 <= head < capacity:
        raise ValueError('invalid synthetic head')
    if not length:
        return False, 0
    tail = capacity - head
    if length > tail:
        pivot = physical[0]
        if pivot == target:
            return True, tail
        if pivot < target:
            hit, position = synthetic_segment_search(physical[:length - tail], target)
            return hit, tail + position
        return synthetic_segment_search(physical[head:], target)
    return synthetic_segment_search(physical[head:head + length], target)


class SyntheticRingSearchControls(unittest.TestCase):
    def test_all_small_wrapped_and_contiguous_unique_key_cases(self):
        cases = 0
        for capacity in range(1, 13):
            for head in range(capacity):
                for length in range(capacity + 1):
                    logical = [i * 2 + 2 for i in range(length)]
                    physical = [None] * capacity
                    for i, value in enumerate(logical):
                        physical[(head + i) % capacity] = value
                    for target in range(2 * length + 4):
                        expected_index = bisect.bisect_left(logical, target)
                        expected_hit = expected_index < length and logical[expected_index] == target
                        hit, index = synthetic_ring_search(capacity, head, length, physical, target)
                        self.assertEqual((hit, index), (expected_hit, expected_index))
                        cases += 1
        self.assertEqual(cases, 9646)

    def test_wrapped_duplicate_hits_only_claim_a_matching_index(self):
        logical = [1, 2, 2, 2, 4]
        capacity, head = 7, 5
        physical = [None] * capacity
        for i, value in enumerate(logical):
            physical[(head + i) % capacity] = value
        hit, index = synthetic_ring_search(capacity, head, len(logical), physical, 2)
        self.assertTrue(hit)
        self.assertEqual(logical[index], 2)

    def test_empty_and_invalid_ring_boundaries(self):
        self.assertEqual(synthetic_ring_search(0, 0, 0, [], 5), (False, 0))
        with self.assertRaises(ValueError):
            synthetic_ring_search(3, 3, 1, [1, None, None], 1)
        with self.assertRaises(ValueError):
            synthetic_ring_search(3, 0, 4, [1, 2, 3], 1)
        with self.assertRaises(ValueError):
            synthetic_ring_search(3, 0, 1, [1], 1)



if __name__ == '__main__':
    unittest.main()
