"""Static witnesses and model controls for the node 94 order index."""
import bisect
from dataclasses import dataclass, field
import hashlib
import struct
import unittest

from tools import book_user_index_delete94 as evidence


# This synthetic model exercises the documented interpretation; it does not
# execute, emulate or record the target binary.
EvidenceError = evidence.EvidenceError


@dataclass(eq=False)
class Node:
    entries: list = field(default_factory=list)
    children: list = field(default_factory=list)
    parent: object = None

    def __post_init__(self):
        for child in self.children:
            child.parent = self


def fixture_entry(key, layout):
    if not isinstance(key, int) or isinstance(key, bool) or not 0 <= key < (1 << 64):
        raise EvidenceError('fixture key outside unsigned 64-bit range')
    size = layout['value_stride']
    if size % 8:
        raise EvidenceError('unexpected fixture value width')
    return key, struct.pack('<Q', key) * (size // 8)


def tree_inorder(node):
    result = []
    for i, entry in enumerate(node.entries):
        if node.children:
            result.extend(tree_inorder(node.children[i]))
        result.append(entry)
    if node.children:
        result.extend(tree_inorder(node.children[-1]))
    return result


def tree_shape(node):
    return {'keys': [entry[0] for entry in node.entries],
            'children': [tree_shape(child) for child in node.children]}


def validate_tree(root, layout):
    if not isinstance(root, Node) or root.parent is not None:
        raise EvidenceError('fixture root or parent is invalid')
    seen_nodes = set()
    leaf_depths = set()
    min_keys = layout['minimum_nonroot_keys']
    max_keys = layout['maximum_keys']
    size = layout['value_stride']

    def walk(node, lower, upper, depth, is_root):
        if not isinstance(node, Node) or id(node) in seen_nodes:
            raise EvidenceError('fixture contains a duplicate or cyclic node')
        seen_nodes.add(id(node))
        count = len(node.entries)
        if count > max_keys or (not is_root and count < min_keys):
            raise EvidenceError('fixture node occupancy outside valid range')
        if node.children and (len(node.children) != count + 1 or (is_root and not count)):
            raise EvidenceError('fixture child count does not match keys')
        last = lower
        for entry in node.entries:
            if not isinstance(entry, tuple) or len(entry) != 2:
                raise EvidenceError('fixture entry is not a key-value pair')
            key, value = entry
            if (not isinstance(key, int) or isinstance(key, bool) or not 0 <= key < (1 << 64)
                    or not isinstance(value, bytes) or len(value) != size):
                raise EvidenceError('fixture key or payload invalid')
            if (last is not None and key <= last) or (upper is not None and key >= upper):
                raise EvidenceError('fixture keys are not strictly ordered')
            last = key
        if not node.children:
            leaf_depths.add(depth)
            return
        limits = [lower] + [entry[0] for entry in node.entries] + [upper]
        for i, child in enumerate(node.children):
            if not isinstance(child, Node) or child.parent is not node:
                raise EvidenceError('fixture child parent link is invalid')
            walk(child, limits[i], limits[i + 1], depth + 1, False)

    walk(root, None, None, 0, True)
    if len(leaf_depths) != 1:
        raise EvidenceError('fixture leaves have different depths')
    return next(iter(leaf_depths))


def find_key(root, key):
    node = root
    while True:
        i = bisect.bisect_left([entry[0] for entry in node.entries], key)
        if i < len(node.entries) and node.entries[i][0] == key:
            return node, i
        if not node.children:
            return None, None
        node = node.children[i]


def repair_after_delete(root, node, layout, events):
    minimum = layout['minimum_nonroot_keys']
    maximum = layout['maximum_keys']
    while node.parent is not None and len(node.entries) < minimum:
        parent = node.parent
        index = next((i for i, child in enumerate(parent.children) if child is node), None)
        if index is None:
            raise EvidenceError('fixture parent does not contain child')
        if index:
            sibling = parent.children[index - 1]
            if len(sibling.entries) + len(node.entries) + 1 <= maximum:
                sibling.entries.extend([parent.entries.pop(index - 1)] + node.entries)
                sibling.children.extend(node.children)
                for child in node.children:
                    child.parent = sibling
                parent.children.pop(index)
                events.append('merge-left')
            else:
                count = minimum - len(node.entries)
                for _ in range(count):
                    node.entries.insert(0, parent.entries[index - 1])
                    parent.entries[index - 1] = sibling.entries.pop()
                    if sibling.children:
                        child = sibling.children.pop()
                        node.children.insert(0, child)
                        child.parent = node
                events.append('borrow-left')
                break
        else:
            if len(parent.children) < 2:
                raise EvidenceError('fixture missing right sibling')
            sibling = parent.children[1]
            if len(node.entries) + len(sibling.entries) + 1 <= maximum:
                node.entries.extend([parent.entries.pop(0)] + sibling.entries)
                node.children.extend(sibling.children)
                for child in sibling.children:
                    child.parent = node
                parent.children.pop(1)
                events.append('merge-right')
            else:
                count = minimum - len(node.entries)
                for _ in range(count):
                    node.entries.append(parent.entries[0])
                    parent.entries[0] = sibling.entries.pop(0)
                    if sibling.children:
                        child = sibling.children.pop(0)
                        node.children.append(child)
                        child.parent = node
                events.append('borrow-right')
                break
        if parent.parent is None and not parent.entries:
            root = parent.children[0]
            root.parent = None
            events.append('collapse-root')
            break
        node = parent
    return root


def delete_model(root, key, layout):
    # Preconditions restrict the model to well-formed B-trees. They are not
    # claims about what arbitrary malformed target memory does.
    validate_tree(root, layout)
    if not isinstance(key, int) or isinstance(key, bool) or not 0 <= key < (1 << 64):
        raise EvidenceError('fixture deletion key outside unsigned 64-bit range')
    node, index = find_key(root, key)
    if node is None:
        return root, None, ['miss']
    removed = node.entries[index]
    events = []
    if node.children:
        leaf = node.children[index]
        while leaf.children:
            leaf = leaf.children[-1]
        predecessor = leaf.entries.pop()
        events.append('predecessor')
        root = repair_after_delete(root, leaf, layout, events)
        replacement_node, replacement_index = find_key(root, key)
        if replacement_node is None:
            raise EvidenceError('fixture lost internal replacement key')
        replacement_node.entries[replacement_index] = predecessor
    else:
        node.entries.pop(index)
        events.append('leaf')
        root = repair_after_delete(root, node, layout, events)
    validate_tree(root, layout)
    return root, removed, events


def leaf(keys, layout):
    return Node([fixture_entry(key, layout) for key in keys])


def two_leaf(left_count, right_count, layout):
    left = leaf(range(1, left_count + 1), layout)
    right = leaf(range(101, 101 + right_count), layout)
    return Node([fixture_entry(100, layout)], [left, right])


def deep_tree(layout, left_count=None, right_count=None):
    minimum = layout['minimum_nonroot_keys']
    left_count = minimum if left_count is None else left_count
    right_count = minimum if right_count is None else right_count
    counter = [0]

    def entry():
        counter[0] += 1
        return fixture_entry(counter[0], layout)

    def internal_level(count):
        children = []
        separators = []
        for index in range(count + 1):
            children.append(Node([entry() for _ in range(minimum)]))
            if index < count:
                separators.append(entry())
        return Node(separators, children)

    left = internal_level(left_count)
    separator = entry()
    right = internal_level(right_count)
    return Node([separator], [left, right])


def fixture_row(label, root, key, layout):
    before = tree_inorder(root)
    height_before = validate_tree(root, layout)
    old_shape = tree_shape(root)
    new_root, removed, events = delete_model(root, key, layout)
    after = tree_inorder(new_root)
    expected = [entry for entry in before if entry[0] != key]
    if after != expected or (removed is None) != (len(expected) == len(before)):
        raise EvidenceError('fixture model did not preserve ordered key-value pairs')
    return {'label': label, 'key': key, 'height_before': height_before,
            'height_after': validate_tree(new_root, layout), 'before_count': len(before),
            'after_count': len(after), 'events': ','.join(events),
            'removed_payload_sha256': '' if removed is None else hashlib.sha256(removed[1]).hexdigest(),
            'before': old_shape, 'after': tree_shape(new_root)}


def fixture_records(layout):
    out = []
    minimum = layout['minimum_nonroot_keys']
    maximum = layout['maximum_keys']
    # The matrix varies both siblings around the exact merge/borrow boundary.
    for left_count in range(minimum, maximum + 1):
        for right_count in range(minimum, maximum + 1):
            for side in ('left', 'right'):
                root = two_leaf(left_count, right_count, layout)
                key = 1 if side == 'left' else 101
                out.append(fixture_row('pair-%s-%d-%d' % (side, left_count, right_count), root, key, layout))
    for key in (1, 3, 6, 7):
        out.append(fixture_row('root-leaf-%d' % key, leaf(range(1, 7), layout), key, layout))
    out.append(fixture_row('last-root-key', leaf([1], layout), 1, layout))
    out.append(fixture_row('internal-predecessor', two_leaf(6, 5, layout), 100, layout))
    out.append(fixture_row('internal-predecessor-root-collapse', two_leaf(5, 5, layout), 100, layout))
    children = [leaf(range(1, 6), layout), leaf(range(101, 106), layout),
                leaf(range(201, 212), layout)]
    root = Node([fixture_entry(100, layout), fixture_entry(200, layout)], children)
    out.append(fixture_row('prefer-left-even-when-right-can-lend', root, 103, layout))
    root = deep_tree(layout)
    out.append(fixture_row('propagate-two-merges', root, 1, layout))
    edge = (1 << 64) - 1
    root = leaf([0, 1, edge - 1, edge], layout)
    out.append(fixture_row('unsigned-key-maximum', root, edge, layout))
    return out



class StaticEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = evidence.BINARY.read_bytes()
        evidence.authenticate(cls.data)
        cls.image = evidence.Image(cls.data)
        cls.layout = evidence.limits_from_image(cls.image)

    def changed(self, va, index=0):
        mutated = bytearray(self.data)
        offset = self.image.offset(va, index + 1, True) + index
        mutated[offset] ^= 1
        return mutated

    def test_digest_corruption_fails(self):
        mutated = self.changed(0x28668c5)
        with self.assertRaisesRegex(evidence.EvidenceError, 'SHA-256 mismatch'):
            evidence.authenticate(mutated)

    def test_fde_body_hashes_and_fixed_witnesses(self):
        records = evidence.function_records(self.data, self.image)
        self.assertEqual(len(records), 6)
        self.assertEqual([r['bytes'] for r in records], [883, 883, 730, 3248, 839, 958])
        self.assertEqual(len(evidence.validate_pins(self.image)), 45)
        mutated = self.changed(0x1b172ca, 3)
        with self.assertRaisesRegex(evidence.EvidenceError, 'instruction witness changed'):
            evidence.validate_pins(evidence.Image(mutated))

    def test_changed_fde_start_is_rejected(self):
        mutated = bytearray(self.data)
        record = self.image.offset(0x11057d0, 12)
        # Change the encoded initial-location displacement, not the code.
        mutated[record + 8] ^= 1
        with self.assertRaises((evidence.EvidenceError, ValueError)):
            evidence.function_records(mutated, evidence.Image(mutated))

    def test_invalid_addresses_and_nobits_rejected(self):
        for va, size in ((-1, 1), (1 << 64, 1), (0, 0), (0, -1)):
            with self.subTest(va=va, size=size):
                with self.assertRaises(evidence.EvidenceError):
                    self.image.read(va, size)
        # TLS .tbss shares virtual coordinates with other sections; select
        # the distinct ordinary .bss when checking NOBITS exclusion.
        bss = next(section for section in self.image.sections if section['name'] == '.bss')
        with self.assertRaises(evidence.EvidenceError):
            self.image.read(bss['address'], 1)
        # Read-only assertion text is file-backed but is not executable code.
        with self.assertRaises(evidence.EvidenceError):
            self.image.read(0x3b3e65, 1, executable=True)

    def test_layout_capacity_and_bad_value_stride(self):
        self.assertEqual((self.layout['key_slots_from_layout'], self.layout['value_slots_from_layout'],
                          self.layout['child_slots_from_layout']), (11, 11, 12))
        mutated = self.changed(0x1b22c18, 3)
        with self.assertRaisesRegex(evidence.EvidenceError, 'layout or limits'):
            evidence.limits_from_image(evidence.Image(mutated))

    def test_direct_edges_and_bad_displacement(self):
        calls = evidence.validate_calls(self.image)
        self.assertEqual(len(calls), 10)
        self.assertEqual(evidence.decode_call(self.image, 0x2866932), 0x1b22a90)
        mutated = self.changed(0x2866932, 1)
        with self.assertRaisesRegex(evidence.EvidenceError, 'call target changed'):
            evidence.validate_calls(evidence.Image(mutated))

    def test_branch_destinations_and_bad_opcode(self):
        branches = {r['label']: r for r in evidence.branch_records(self.image)}
        self.assertEqual(len(branches), 39)
        self.assertEqual(branches['left-edge-uses-right-sibling']['taken_target'], 0x1b176d0)
        self.assertEqual(branches['merge-capacity-error']['taken_target'], 0x1b17dcf)
        self.assertEqual(branches['root-replacement-height-zero']['taken_target'], 0x2866ba6)
        self.assertEqual(branches['removed-value-is-sentinel']['taken_target'], 0x2866b7f)
        self.assertEqual(branches['left-borrow-copy-length-error']['taken_target'], 0x1af75fe)
        self.assertEqual(branches['right-borrow-second-level-zero']['taken_target'], 0x1afd2a2)
        mutated = self.changed(0x1af730f)
        with self.assertRaises(evidence.EvidenceError):
            evidence.branch_records(evidence.Image(mutated))

    def test_sentinel_comparison_widths(self):
        wrapper = self.image.read(0x2866ae3, 4, True)
        spot = self.image.read(0x26de5a9, 8, True)
        perp = self.image.read(0x26df646, 8, True)
        # REX.W selects a 64-bit wrapper operand; both outer encodings use a
        # 32-bit memory operand. Values below are synthetic width controls.
        self.assertEqual(wrapper, bytes.fromhex('4883fd02'))
        self.assertEqual(spot, bytes.fromhex('83bc24d004000002'))
        self.assertEqual(perp, bytes.fromhex('83bc24e004000002'))
        for word, wrapper_equal, caller_equal in (
                (0, False, False), (2, True, True), (0x100000002, False, True)):
            with self.subTest(word=word):
                self.assertEqual(word == wrapper[-1], wrapper_equal)
                self.assertEqual(word & 0xffffffff == spot[-1], caller_equal)

    def test_copy_masks_and_corruption_outside_or_inside_mask(self):
        masks, differences, digest = evidence.compare_copies(self.image)
        self.assertEqual((len(masks), len(differences)), (9, 18))
        self.assertEqual(sum(row['mask_size'] for row in masks), 36)
        self.assertEqual(digest, 'bbbe123041ba59f9f10d2d8027b1e654b16c708c3b79df0bf8cbf27bc5ffc776')
        mutated = self.changed(0x28660a0)
        with self.assertRaisesRegex(evidence.EvidenceError, 'outside declared masks'):
            evidence.compare_copies(evidence.Image(mutated))
        del mutated
        mutated = self.changed(0x28660a0 + masks[0]['mask_offset'])
        with self.assertRaisesRegex(evidence.EvidenceError, 'different targets'):
            evidence.compare_copies(evidence.Image(mutated))

    def test_failure_messages_and_dynamic_relocations(self):
        assertions = {row['name']: row for row in evidence.assertion_records(self.image)}
        self.assertEqual(len(assertions), 10)
        self.assertEqual(assertions['merged-node-capacity']['target'], 0x3b3fa7)
        self.assertEqual(assertions['replacement-height']['text'], 'assertion failed: self.height > 0')
        self.assertIn('Right(idx) => idx <= right_len', assertions['merge-cursor-range']['text'])
        slots = {row['slot']: row for row in evidence.dyn_symbol_slots(self.image)}
        self.assertEqual(slots[0x576dfe0]['symbol'], 'memcpy')
        self.assertEqual(slots[0x576e0e0]['symbol'], 'memmove')
        self.assertEqual((slots[0x576e010]['relocation_type'], slots[0x576e010]['addend']), (8, 0x54c8cb0))
        self.assertEqual(len(slots), 6)
        mutated_relocation = bytearray(self.data)
        mutated_relocation[slots[0x576dfe0]['record_file_offset'] + 8] ^= 1
        with self.assertRaisesRegex(evidence.EvidenceError, 'unexpected dynamic relocation'):
            evidence.dyn_symbol_slots(evidence.Image(mutated_relocation))
        del mutated_relocation
        mutated = self.changed(0x1af75da, 1)
        with self.assertRaisesRegex(evidence.EvidenceError, 'assertion text changed'):
            evidence.assertion_records(evidence.Image(mutated))

    def test_indirect_slots_and_bad_displacement(self):
        relocations = evidence.dyn_symbol_slots(self.image)
        references = {row['name']: row for row in evidence.indirect_references(self.image, relocations)}
        self.assertEqual(len(references), 14)
        self.assertEqual(references['predecessor-copy']['slot'], 0x576dfe0)
        self.assertEqual(references['missing-parent-key-failure']['slot'], 0x576e098)
        mutated = self.changed(0x1b22bd1, 2)
        with self.assertRaisesRegex(evidence.EvidenceError, 'indirect reference target mismatch'):
            evidence.indirect_references(evidence.Image(mutated), relocations)
        with self.assertRaisesRegex(evidence.EvidenceError, 'indirect reference target mismatch'):
            evidence.indirect_references(self.image, [])


class SyntheticTreeControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        data = evidence.BINARY.read_bytes()
        evidence.authenticate(data)
        cls.layout = evidence.limits_from_image(evidence.Image(data))

    def delete(self, tree, key):
        return delete_model(tree, key, self.layout)

    def test_leaf_absence_last_key_and_unsigned_bounds(self):
        tree = leaf([0, 1, (1 << 64) - 1], self.layout)
        before = tree_inorder(tree)
        new_root, removed, events = self.delete(tree, 2)
        self.assertIs(new_root, tree)
        self.assertIsNone(removed)
        self.assertEqual(events, ['miss'])
        self.assertEqual(tree_inorder(tree), before)
        new_root, removed, events = self.delete(tree, (1 << 64) - 1)
        self.assertEqual(removed[0], (1 << 64) - 1)
        self.assertEqual(events, ['leaf'])
        self.assertEqual([item[0] for item in tree_inorder(new_root)], [0, 1])
        new_root, removed, events = self.delete(leaf([0], self.layout), 0)
        self.assertEqual((removed[0], events, tree_shape(new_root)), (0, ['leaf'], {'keys': [], 'children': []}))
        for key in (-1, 1 << 64, True):
            with self.subTest(key=key):
                with self.assertRaises(evidence.EvidenceError):
                    self.delete(leaf([1], self.layout), key)

    def test_exact_right_merge_and_borrow_boundaries(self):
        tree, removed, events = self.delete(two_leaf(5, 6, self.layout), 1)
        self.assertEqual((removed[0], events), (1, ['leaf', 'merge-right', 'collapse-root']))
        self.assertEqual([x[0] for x in tree.entries], [2, 3, 4, 5, 100, 101, 102, 103, 104, 105, 106])
        tree, removed, events = self.delete(two_leaf(5, 7, self.layout), 1)
        self.assertEqual((removed[0], events), (1, ['leaf', 'borrow-right']))
        self.assertEqual(tree_shape(tree), {'keys': [101], 'children': [
            {'keys': [2, 3, 4, 5, 100], 'children': []},
            {'keys': [102, 103, 104, 105, 106, 107], 'children': []}]})

    def test_exact_left_merge_and_borrow_boundaries(self):
        tree, removed, events = self.delete(two_leaf(6, 5, self.layout), 101)
        self.assertEqual((removed[0], events), (101, ['leaf', 'merge-left', 'collapse-root']))
        self.assertEqual([x[0] for x in tree.entries], [1, 2, 3, 4, 5, 6, 100, 102, 103, 104, 105])
        tree, removed, events = self.delete(two_leaf(7, 5, self.layout), 101)
        self.assertEqual((removed[0], events), (101, ['leaf', 'borrow-left']))
        self.assertEqual(tree_shape(tree), {'keys': [7], 'children': [
            {'keys': [1, 2, 3, 4, 5, 6], 'children': []},
            {'keys': [100, 102, 103, 104, 105], 'children': []}]})

    def test_all_98_pair_boundaries(self):
        count = 0
        for left_count in range(5, 12):
            for right_count in range(5, 12):
                for side in ('left', 'right'):
                    with self.subTest(left=left_count, right=right_count, side=side):
                        tree = two_leaf(left_count, right_count, self.layout)
                        before = tree_inorder(tree)
                        key = 1 if side == 'left' else 101
                        after, removed, events = self.delete(tree, key)
                        own = left_count if side == 'left' else right_count
                        other = right_count if side == 'left' else left_count
                        direction = 'right' if side == 'left' else 'left'
                        expected = ['leaf']
                        if own == 5:
                            expected += ([f'merge-{direction}', 'collapse-root'] if other <= 6
                                         else [f'borrow-{direction}'])
                        self.assertEqual(events, expected)
                        self.assertEqual(tree_inorder(after), [pair for pair in before if pair[0] != key])
                        self.assertEqual(removed[0], key)
                        count += 1
        self.assertEqual(count, 98)

    def test_left_sibling_priority_even_with_right_donor(self):
        children = [leaf(range(1, 6), self.layout), leaf(range(101, 106), self.layout),
                    leaf(range(201, 212), self.layout)]
        root = Node([fixture_entry(100, self.layout), fixture_entry(200, self.layout)], children)
        tree, removed, events = self.delete(root, 103)
        self.assertEqual((removed[0], events), (103, ['leaf', 'merge-left']))
        self.assertEqual([x[0] for x in tree.entries], [200])
        self.assertEqual([len(child.entries) for child in tree.children], [10, 11])

    def test_internal_predecessor_pairing_with_and_without_collapse(self):
        for left_count, expected in ((5, ['predecessor', 'merge-right', 'collapse-root']),
                                     (6, ['predecessor'])):
            with self.subTest(left=left_count):
                root = two_leaf(left_count, 5, self.layout)
                root.entries[0] = (100, bytes([0xa5]) * 184)
                root.children[0].entries[-1] = (left_count, bytes([0x5a]) * 184)
                before = tree_inorder(root)
                tree, removed, events = self.delete(root, 100)
                self.assertEqual(events, expected)
                self.assertEqual(removed, (100, bytes([0xa5]) * 184))
                self.assertEqual(tree_inorder(tree), [x for x in before if x[0] != 100])
                self.assertIn((left_count, bytes([0x5a]) * 184), tree_inorder(tree))

    def test_ancestor_cascade_and_parent_links(self):
        root = deep_tree(self.layout)
        before = tree_inorder(root)
        self.assertEqual((len(before), validate_tree(root, self.layout)), (71, 2))
        tree, removed, events = self.delete(root, 1)
        self.assertEqual(events, ['leaf', 'merge-right', 'merge-right', 'collapse-root'])
        self.assertEqual(removed[0], 1)
        self.assertEqual(validate_tree(tree, self.layout), 1)
        self.assertEqual(tree_inorder(tree), before[1:])

    def test_ancestor_borrows_right_and_updates_child_parent(self):
        root = deep_tree(self.layout, 5, 7)
        before = tree_inorder(root)
        tree, removed, events = self.delete(root, 1)
        self.assertEqual(events, ['leaf', 'merge-right', 'borrow-right'])
        self.assertEqual(removed[0], 1)
        self.assertEqual(validate_tree(tree, self.layout), 2)
        self.assertEqual([len(child.entries) for child in tree.children], [5, 6])
        self.assertEqual(tree_inorder(tree), before[1:])

    def test_ancestor_borrows_left_and_updates_child_parent(self):
        root = deep_tree(self.layout, 7, 5)
        key = root.children[1].children[0].entries[0][0]
        before = tree_inorder(root)
        tree, removed, events = self.delete(root, key)
        self.assertEqual(events, ['leaf', 'merge-right', 'borrow-left'])
        self.assertEqual(removed[0], key)
        self.assertEqual(validate_tree(tree, self.layout), 2)
        self.assertEqual([len(child.entries) for child in tree.children], [6, 5])
        self.assertEqual(tree_inorder(tree), [x for x in before if x[0] != key])

    def test_corrupt_fixture_controls(self):
        invalid = []
        root = two_leaf(5, 5, self.layout)
        root.children[0].entries.reverse()
        invalid.append(root)
        root = two_leaf(5, 5, self.layout)
        root.children[0].entries[0] = (1, b'bad payload')
        invalid.append(root)
        root = two_leaf(5, 5, self.layout)
        root.children.pop()
        invalid.append(root)
        root = two_leaf(5, 5, self.layout)
        root.children[0].parent = None
        invalid.append(root)
        root = two_leaf(5, 5, self.layout)
        root.children[0].entries.pop()
        invalid.append(root)
        for index, root in enumerate(invalid):
            with self.subTest(corruption=index):
                before = tree_shape(root)
                with self.assertRaises(evidence.EvidenceError):
                    self.delete(root, 1)
                self.assertEqual(tree_shape(root), before)

    def test_fixture_inventory(self):
        rows = fixture_records(self.layout)
        self.assertEqual(len(rows), 108)
        cascade = next(row for row in rows if row['label'] == 'propagate-two-merges')
        self.assertEqual((cascade['height_before'], cascade['height_after'], cascade['after_count']), (2, 1, 70))
        self.assertEqual(cascade['removed_payload_sha256'], hashlib.sha256((1).to_bytes(8, 'little') * 23).hexdigest())


if __name__ == '__main__':
    unittest.main()
