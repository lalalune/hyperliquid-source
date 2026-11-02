"""Static byte controls and independent synthetic invariants for RE-006."""
import bisect
from pathlib import Path
import struct
import tempfile
import unittest

from tools import book_user_entry94 as entry


class Overlay:
    """Read-only image with selected bytes changed, without copying the ELF."""
    def __init__(self, image, changes):
        self.image = image
        self.changes = changes

    def read(self, va, size, executable=False):
        raw = bytearray(self.image.read(va, size, executable))
        for address, value in self.changes.items():
            if va <= address < va + size:
                raw[address - va] = value
        return bytes(raw)

    def offset(self, *args, **kwargs):
        return self.image.offset(*args, **kwargs)


def flip(image, va):
    return Overlay(image, {va: image.read(va, 1)[0] ^ 1})


class Node:
    def __init__(self, keys=(), values=(), children=()):
        self.keys = list(keys)
        self.values = list(values)
        self.children = list(children)
        self.parent = None
        self.reparent()

    def reparent(self):
        for child in self.children:
            child.parent = self


class SyntheticTree:
    """A model of the read interpretation, never target code or emulation."""
    def __init__(self, constants):
        self.c = constants
        self.root = None
        self.size = 0
        self.split_positions = set()

    def insert(self, key, value):
        if len(key) != self.c['key_size']:
            raise ValueError('invalid key length')
        inserted_value = value
        if self.root is None:
            self.root = Node([key], [value])
            self.size = 1
            return value, True
        node = self.root
        while True:
            position = bisect.bisect_left(node.keys, key)
            if position < len(node.keys) and node.keys[position] == key:
                return node.values[position], False
            if not node.children:
                break
            node = node.children[position]
        pending_right = None
        while True:
            if len(node.keys) < self.c['capacity']:
                node.keys.insert(position, key)
                node.values.insert(position, value)
                if pending_right is not None:
                    node.children.insert(position + 1, pending_right)
                    node.reparent()
                self.size += 1
                return inserted_value, True
            pivot, side, local = entry.split_position(position, self.c)
            self.split_positions.add(position)
            parent = node.parent
            promoted_key = node.keys[pivot]
            promoted_value = node.values[pivot]
            old_children = node.children[:]
            right = Node(node.keys[pivot + 1:], node.values[pivot + 1:],
                         old_children[pivot + 1:] if old_children else ())
            node.keys = node.keys[:pivot]
            node.values = node.values[:pivot]
            node.children = old_children[:pivot + 1] if old_children else []
            node.reparent()
            target = node if side == 'left' else right
            target.keys.insert(local, key)
            target.values.insert(local, value)
            if pending_right is not None:
                target.children.insert(local + 1, pending_right)
                target.reparent()
            if parent is None:
                self.root = Node([promoted_key], [promoted_value], [node, right])
                self.size += 1
                return inserted_value, True
            position = parent.children.index(node)
            node = parent
            key, value, pending_right = promoted_key, promoted_value, right

    def items_and_depths(self):
        def walk(node, lower, upper, depth, root):
            if len(node.keys) > self.c['capacity'] or len(node.keys) != len(node.values):
                raise AssertionError('invalid node width')
            if not root and len(node.keys) < self.c['midpoint']:
                raise AssertionError('underfull non-root')
            if not node.keys or node.keys != sorted(set(node.keys)):
                raise AssertionError('unordered node keys')
            if any((lower is not None and k <= lower) or
                   (upper is not None and k >= upper) for k in node.keys):
                raise AssertionError('key outside parent interval')
            if not node.children:
                return list(zip(node.keys, node.values)), [depth]
            if len(node.children) != len(node.keys) + 1:
                raise AssertionError('wrong child count')
            result, depths = [], []
            edges = [lower] + node.keys + [upper]
            for i, child in enumerate(node.children):
                if child.parent is not node:
                    raise AssertionError('incorrect parent')
                sub, sub_depths = walk(child, edges[i], edges[i + 1], depth + 1, False)
                result.extend(sub)
                depths.extend(sub_depths)
                if i < len(node.keys):
                    result.append((node.keys[i], node.values[i]))
            return result, depths
        return walk(self.root, None, None, 0, True)


class BookUserEntry94Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = entry.TARGET.read_bytes()
        entry.verify_digest(cls.data)
        cls.image = entry.Image(cls.data)
        cls.constants = entry.constants(cls.image)
        cls.fdes = entry.selected_fdes(cls.image)

    def test_exact_input_digest(self):
        self.assertEqual(entry.digest(self.data), entry.TARGET_DIGEST)

    def test_wrong_and_truncated_digest_rejected(self):
        with self.assertRaises(ValueError):
            entry.verify_digest(self.data, '0' * 64)
        with self.assertRaises(ValueError):
            entry.verify_digest(self.data[:4096])

    def test_corrupted_input_rejected(self):
        changed = bytearray(self.data)
        changed[-1] ^= 1
        with self.assertRaises(ValueError):
            entry.verify_digest(changed)

    def test_short_or_non_elf_rejected(self):
        with self.assertRaises(ValueError):
            entry.Image(b'not an ELF')

    def test_fde_ranges_are_independently_parsed(self):
        self.assertEqual([(r['start'], r['end']) for _, r, _, _ in self.fdes],
                         [(0x25a7730, 0x25a78d6), (0x287ae20, 0x287aff0),
                          (0x1a9a820, 0x1a9bc1a), (0x2517560, 0x25175b2),
                          (0x3438fc0, 0x343904a)])
        self.assertEqual(sum(len(raw) for _, _, _, raw in self.fdes), 6220)

    def test_corrupted_fde_start_rejected(self):
        changed = bytearray(self.data)
        record = self.fdes[0][1]['fde']
        off = self.image.offset(record + 8, 1)
        changed[off] ^= 1
        with self.assertRaises(ValueError):
            entry.selected_fdes(entry.Image(changed))

    def test_invalid_nobits_and_nonexecuting_address(self):
        bss = next(s for s in self.image.sections if s['name'] == '.bss')
        self.assertEqual(bss['type'], 8)
        for va in (-1, 0, bss['address'], 1 << 63):
            with self.subTest(va=va), self.assertRaises(ValueError):
                self.image.read(va, 1, executable=True)
        with self.assertRaises(ValueError):
            self.image.read(self.fdes[0][1]['start'], 0, executable=True)
        with self.assertRaises(ValueError):
            self.image.read(bss['address'], 1)

    def test_window_corruption_controls(self):
        self.assertEqual(len(entry.window_rows(self.image)), len(entry.WINDOWS))
        for name, start, end, _ in entry.WINDOWS:
            with self.subTest(window=name), self.assertRaises(ValueError):
                entry.window_rows(flip(self.image, (start + end) // 2))

    def test_constant_instruction_corruption_rejected(self):
        for va in (0x25a77a2, 0x25a7767, 0x25a775e, 0x1a9a84c,
                   0x1a9a868, 0x1a9aa73, 0x287ae9d, 0x1a9b260,
                   0x26edfff, 0x26ec0f7, 0x26ee034, 0x26edf67,
                   0x26ebe02, 0x251756a, 0x251756d, 0x251758e, 0x251759e, 0x25175a6,
                   0x2517594, 0x2517597, 0x3438fdf, 0x3438ff0, 0x3438ff3,
                   0x3438ffd, 0x3439000, 0x3439004, 0x3439007):
            with self.subTest(va=va), self.assertRaises(ValueError):
                entry.constants(flip(self.image, va))

    def test_layout_closes_node_arrays(self):
        c = self.constants
        self.assertEqual((c['key_size'], c['value_stride'], c['capacity']), (20, 80, 11))
        self.assertEqual((c['parent_offset'], c['keys_offset'], c['parent_index_offset']),
                         (0x370, 0x378, 0x454))
        self.assertEqual((c['node_length_offset'], c['edge_offset']), (0x456, 0x458))
        self.assertEqual((c['leaf_bytes'], c['internal_bytes']), (0x458, 0x4b8))
        self.assertEqual(c['internal_bytes'] - c['edge_offset'], (c['capacity'] + 1) * 8)

    def test_context_offsets(self):
        c = self.constants
        self.assertEqual((c['book_user_offset'], c['order_user_offset'], c['user_index_offset']),
                         (0xb8, 0xb8, 0x20))
        self.assertEqual((c['slot_stride'], c['slot_vacant_tag']), (0xf8, 2))
        self.assertEqual(c['order_flag_offset'], 0x90)
        self.assertEqual((c['queue_capacity_offset'], c['queue_pointer_offset'],
                          c['queue_head_offset'], c['queue_length_offset'],
                          c['queue_item_stride']), (0, 8, 16, 24, 8))

    def test_initial_record_writes(self):
        rows = entry.initial_stores(self.image)
        self.assertEqual([(int(r[2], 16), r[3], r[4]) for r in rows],
                         [(0, 8, 0), (8, 8, 8), (16, 16, 0), (32, 8, 0),
                          (48, 16, 0), (72, 8, 0)])
        defined = {i for _, _, off, width, _ in rows for i in range(int(off, 16), int(off, 16) + width)}
        self.assertEqual(set(range(80)) - defined, set(range(40, 48)) | set(range(64, 72)))

    def test_each_initial_write_is_pinned(self):
        for row in entry.initial_stores(self.image):
            with self.subTest(site=row[0]), self.assertRaises(ValueError):
                entry.initial_stores(flip(self.image, int(row[0], 16)))

    def test_all_selected_branch_conditions_and_destinations(self):
        for va, name, _ in entry.BRANCHES:
            raw, fallthrough, target = entry.branch(self.image, va, name)
            self.assertGreater(len(raw), 1)
            self.assertGreater(fallthrough, va)
            self.assertTrue(any(start <= va < end and start <= target < end
                                for _, start, end, _ in entry.FUNCTIONS))

    def test_each_branch_condition_flip_rejected(self):
        for va, name, _ in entry.BRANCHES:
            byte0 = self.image.read(va, 1, True)[0]
            changed_va = va + (byte0 == 0x0f)
            with self.subTest(va=va), self.assertRaises(ValueError):
                entry.branch(flip(self.image, changed_va), va, name)

    def test_each_branch_displacement_is_in_a_pinned_window(self):
        for va, name, _ in entry.BRANCHES:
            raw, _, _ = entry.branch(self.image, va, name)
            displacement = va + (2 if raw[0] == 0x0f else 1)
            with self.subTest(va=va), self.assertRaises(ValueError):
                entry.window_rows(flip(self.image, displacement))

    def test_call_targets_and_displacement_corruption(self):
        for _, site, target in entry.DIRECT_CALLS:
            raw, actual = entry.direct_call(self.image, site, target)
            self.assertEqual(actual, target)
            self.assertEqual(len(raw), 5)
            with self.subTest(site=site), self.assertRaises(ValueError):
                entry.direct_call(flip(self.image, site + 1), site, target)

    def test_rip_references_and_displacement_corruption(self):
        for label, site, prefix, target in entry.REFERENCES:
            _, actual = entry.rip_reference(self.image, site, prefix, target)
            self.assertEqual(actual, target)
            with self.subTest(label=label), self.assertRaises(ValueError):
                entry.rip_reference(flip(self.image, site + len(bytes.fromhex(prefix))),
                                    site, prefix, target)

    def test_selected_relocations_and_symbols(self):
        rows = entry.relocations(self.image, {r[3] for r in entry.REFERENCES})
        self.assertEqual(len(rows), 10)
        self.assertEqual(rows[0x5771620][2], 0x3438fc0)
        self.assertEqual(rows[0x576e488][3], 'memcmp')
        self.assertEqual(rows[0x576e0e0][3], 'memmove')
        self.assertEqual(rows[0x576dfe0][3], 'memcpy')
        with self.assertRaises(ValueError):
            entry.relocations(self.image, {0})

    def test_wrong_relocation_type_is_rejected(self):
        rows = entry.relocations(self.image, {r[3] for r in entry.REFERENCES})
        off = rows[0x576dfe0][4] + 8
        changed = bytearray(self.data)
        info = struct.unpack_from('<Q', changed, off)[0]
        struct.pack_into('<Q', changed, off, (info & ~0xffffffff) | 7)
        with self.assertRaises(ValueError):
            entry.relocations(entry.Image(changed), {r[3] for r in entry.REFERENCES})

    def test_wrong_relocation_symbol_is_rejected(self):
        rows = entry.relocations(self.image, {r[3] for r in entry.REFERENCES})
        off = rows[0x576e488][4] + 8
        changed = bytearray(self.data)
        # Point the memcmp relocation to the independently observed memcpy symbol.
        struct.pack_into('<Q', changed, off, (rows[0x576dfe0][1] << 32) | 6)
        with self.assertRaises(ValueError):
            entry.relocations(entry.Image(changed), {r[3] for r in entry.REFERENCES})

    def test_wrong_relocation_addend_is_rejected(self):
        rows = entry.relocations(self.image, {r[3] for r in entry.REFERENCES})
        off = rows[0x576dfd8][4] + 16
        changed = bytearray(self.data)
        old = struct.unpack_from('<q', changed, off)[0]
        struct.pack_into('<q', changed, off, old + 1)
        with self.assertRaises(ValueError):
            entry.relocations(entry.Image(changed), {r[3] for r in entry.REFERENCES})

    def test_diagnostic_text_and_corruption(self):
        for item in entry.DIAGNOSTICS:
            row = entry.diagnostic(self.image, *item)
            self.assertTrue(row[-1].startswith('assertion failed: '))
            with self.subTest(label=item[0]), self.assertRaises(ValueError):
                entry.diagnostic(flip(self.image, int(row[3], 16)), *item)

    def test_all_twelve_full_leaf_split_positions(self):
        expected = [(4, 'left', i) for i in range(5)] + [
            (5, 'left', 5), (5, 'right', 0),
            (6, 'right', 0), (6, 'right', 1), (6, 'right', 2),
            (6, 'right', 3), (6, 'right', 4)]
        self.assertEqual([entry.split_position(i, self.constants) for i in range(12)], expected)
        for position in range(12):
            row = entry.split_example(position, self.constants)
            self.assertEqual(row[6] + row[7], 11)
            self.assertEqual(sorted((row[6], row[7])), [5, 6])
        for invalid in (-1, 12, 13):
            with self.subTest(position=invalid), self.assertRaises(ValueError):
                entry.split_position(invalid, self.constants)

    def test_duplicate_user_keeps_existing_value(self):
        tree = SyntheticTree(self.constants)
        key = bytes(20)
        self.assertEqual(tree.insert(key, 'first'), ('first', True))
        self.assertEqual(tree.insert(key, 'replacement'), ('first', False))
        self.assertEqual(tree.size, 1)
        self.assertEqual(tree.items_and_depths(), ([(key, 'first')], [0]))

    def test_lexicographic_key_order_is_bytewise(self):
        tree = SyntheticTree(self.constants)
        keys = [bytes([0xff]) + bytes(19), bytes([0x80]) + bytes(19),
                bytes([0x01]) + bytes(19), bytes(19) + b'\xff', bytes(20)]
        for key in keys:
            tree.insert(key, key.hex())
        rows, _ = tree.items_and_depths()
        self.assertEqual([k for k, _ in rows], sorted(keys))
        with self.assertRaises(ValueError):
            tree.insert(bytes(19), 0)

    def test_multi_level_synthetic_sequences_against_sorted_map(self):
        sequences = [list(range(300)), list(reversed(range(300))),
                     [(i * 113) % 307 for i in range(307)]]
        for numbers in sequences:
            with self.subTest(first=numbers[0]):
                tree = SyntheticTree(self.constants)
                expected = {}
                for number in numbers:
                    key = number.to_bytes(20, 'big')
                    value = (number, number ^ 0x55)
                    expected[key] = value
                    self.assertEqual(tree.insert(key, value), (value, True))
                rows, depths = tree.items_and_depths()
                self.assertEqual(rows, sorted(expected.items()))
                self.assertEqual(tree.size, len(expected))
                self.assertEqual(len(set(depths)), 1)
                self.assertGreaterEqual(depths[0], 2)
                for key, value in expected.items():
                    self.assertEqual(tree.insert(key, 'unused'), (value, False))
                self.assertEqual(tree.size, len(expected))

    def test_nonfull_leaf_every_length_and_position(self):
        for length in range(self.constants['capacity']):
            for position in range(length + 1):
                with self.subTest(length=length, position=position):
                    tree = SyntheticTree(self.constants)
                    old = list(range(2, 2 * length + 1, 2))
                    for number in old:
                        tree.insert(number.to_bytes(20, 'big'), number)
                    new = 2 * position + 1
                    tree.insert(new.to_bytes(20, 'big'), new)
                    rows, depths = tree.items_and_depths()
                    self.assertEqual(rows, [(n.to_bytes(20, 'big'), n) for n in sorted(old + [new])])
                    self.assertEqual(depths, [0])
                    self.assertFalse(tree.split_positions)

    def test_root_split_for_all_positions(self):
        c = self.constants
        for position in range(c['capacity'] + 1):
            with self.subTest(position=position):
                tree = SyntheticTree(c)
                for old in range(2, 2 * c['capacity'] + 1, 2):
                    tree.insert(old.to_bytes(20, 'big'), old)
                inserted = position * 2 + 1
                self.assertEqual(tree.insert(inserted.to_bytes(20, 'big'), inserted), (inserted, True))
                promoted = [10] * 5 + [12, 12] + [14] * 5
                self.assertEqual(tree.root.keys, [promoted[position].to_bytes(20, 'big')])
                rows, depths = tree.items_and_depths()
                self.assertEqual([int.from_bytes(key, 'big') for key, _ in rows],
                                 sorted(list(range(2, 23, 2)) + [inserted]))
                self.assertEqual(depths, [1, 1])

    def test_queue_append_index_against_modulo(self):
        for capacity in range(1, self.constants['capacity'] + 1):
            for head in range(capacity):
                for length in range(capacity):
                    self.assertEqual(entry.queue_append_index(capacity, head, length),
                                     (head + length) % capacity)
        for state in ((0, 0, 0), (3, 3, 0), (3, 0, 3), (3, -1, 0), (3, 0, -1),
                      ((1 << 64) - 1, (1 << 64) - 2, 2)):
            with self.subTest(state=state), self.assertRaises(ValueError):
                entry.queue_append_index(*state)

    def test_full_queue_growth_preserves_fifo_order(self):
        actions = set()
        count = 1
        self.assertEqual(entry.queue_growth_example(0, 0, 1)[-1], '1')
        for capacity in range(1, self.constants['capacity'] + 1):
            for head in range(capacity):
                for extra in range(1, capacity + 1):
                    row = entry.queue_growth_example(capacity, head, capacity + extra)
                    self.assertEqual(row[5], head)
                    self.assertEqual(row[4], capacity - head)
                    self.assertEqual(row[2], capacity)
                    self.assertEqual([int(x) for x in row[-1].split(',')],
                                     list(range(1, capacity + 2)))
                    self.assertEqual(row[-2], (row[-3] + capacity) % (capacity + extra))
                    actions.add(row[6])
                    count += 1
        self.assertEqual(count, 507)
        self.assertEqual(actions, {'no-wrap', 'move-high', 'copy-low'})
        for state in ((-1, 0, 1), (0, 1, 1), (1, 1, 2), (3, 0, 3)):
            with self.subTest(state=state), self.assertRaises(ValueError):
                entry.queue_growth_example(*state)

    def test_generate_all_outputs_with_no_external_tools(self):
        expected = {'functions.tsv', 'function-bytes.tsv', 'witnesses.tsv', 'branches.tsv',
                    'calls.tsv', 'indirect-references.tsv', 'relocations.tsv',
                    'failure-diagnostics.tsv', 'initial-value.tsv', 'split-cases.tsv',
                    'queue-growth-cases.tsv', 'evidence.json'}
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / 'evidence'
            result = entry.generate(self.data, out)
            self.assertEqual({p.name for p in out.iterdir()}, expected)
            self.assertEqual(result['counts']['synthetic_split_positions'], 12)
            self.assertEqual(result['counts']['selected_fdes'], 5)
            self.assertEqual(result['counts']['synthetic_queue_growth_cases'], 507)


if __name__ == '__main__':
    unittest.main()
