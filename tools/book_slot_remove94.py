#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Static, digest-bound evidence for one book slot-index deletion path."""
import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from elf_index import sections, unwind_index
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / 'artifacts/node/94/hl-node'
DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

FUNCTIONS = [('entry', 76823056, 76823329, '205beefaac4947edbaf9374427fd39dcea4bad2557f5ca5cb1f01ce7038bf4af'),
 ('cursor', 69926512, 69926997, 'bca0d72dc1c780e22946b719c90786528e5713ea657cfea74830a3b85562971a'),
 ('leaf_and_ancestors', 69851920, 69853460, '1439156e32e065eb7acec031d9a6a4c9807d4a991f0e193b2598949d3be6b81f'),
 ('merge', 69734528, 69735344, 'd13fb5fb2d236b3bef9f0159500024a7e4336e273225b2a84bf2fefd3348cc31'),
 ('borrow_left', 69679728, 69680270, 'd6b7df1292bb954a9383d125b1dc98b8104f38cc79db93d7369805b62bc24fc3'),
 ('borrow_right', 69707568, 69708181, '851cd12f6841a50433282e17c5800eb9b5e5f6eeb91b24887ce553fd4ddb86f6')]

ANCHORS = [('search',
  76823061,
  '488b074885c00f84d20000004889fb488b4f08488b160fb778624189f841c1e00348c7c6ffffffff0f1f004d85c0742b483b54f010410f97c14180d90048ffc64983c0f84180f90174e1410fb6f985ff750ceb170f1f80000000004889fe4883e901727a488b44f068ebab'),
 ('found_and_remove',
  76823168,
  '488944241048894c2418488974242048895c2428c644240f00488d7c2430488d742410488d54240fe8c3c396ff48ff4b10807c240f01'),
 ('root_shrink',
  76823217,
  '807c240f017533488b3b4885ff743b488b43084885c0743f488b4f6848890b48ffc84889430848c70100000000bec800000031d2ff1525a5e200'),
 ('leaf_or_internal', 69926520, '488b06488b7e08488b4e104885ff0f8443010000488b4cc8684889f848ffc80f8481000000'),
 ('predecessor_leaf',
  69926686,
  '0fb7416248ffc848894c241848c7442420000000004889442428488d7c2430488d742418e8c9dbfeff'),
 ('direct_leaf', 69926863, '4889042448c74424080000000048894c24104889e64889dfe824dbfeff'),
 ('delete_and_minimum',
  69851950,
  '4c8b3e488b5610410fb75f62498d7cd708498b44d7084889442458498d34d74883c6104989d648f7d24801da48c1e203ff157c054d014c89fe8d43ff66418947624d8b6c24086683f8040f8758010000'),
 ('left_merge_test', 69852115, '0fb7466201c383fb0c0f8385000000'),
 ('right_merge_test', 69852229, '0fb7426201c383fb0c732f'),
 ('merge_call', 69852253, '4c89f1e81b34feff'),
 ('left_rotate_call', 69852263, '488d7c2478be01000000e8fa5dfdff49ffc6'),
 ('right_rotate_call', 69852287, '488dbc24b00000004889f3be01000000e89ccafdff'),
 ('parent_retry', 69852336, '488b1e4885db741e48897424384c897424400fb743626683f80476354c8b742440488b742438'),
 ('merge_guards',
  69734542,
  '4c8b7618450fb76e624c89e8f6c2017408488b46280fb740624839c10f87b5020000488b4628440fb778624f8d042f49ffc04983f80c0f83b4020000'),
 ('left_rotation_guards',
  69679742,
  '488b6f280fb74d62488d040e4883f80c0f83af0100004889f34989fe4c8b7f18450fb767624d89e54929f50f82ad0100006645896f62'),
 ('right_rotation_guards',
  69707582,
  '4989fe488b6f180fb77d62488d043e4883f80c0f830c0200004889f34d8b6e28450fb77d624929f70f8210020000668945626645897d62'),
 ('predecessor_swap', 69926784, '488b4cf00848897cf0084885d27466'),
 ('root_flag_and_upward_rotation',
  69853336,
  '4885c00f852bfcffff488b442450c60001e91efcffffbe050000004829c6488dbc24e8000000e8ad59fdffe904fcffffbe050000004829c6488dbc2420010000e853c6fdff'),
 ('merge_writes',
  69734663,
  '488b5e104c894424206645894662498d7cdc08498b44dc0848890424498d34dc4883c6104889dd48f7d54801cd48c1e5034889eaff159fcf4e014c896c2408488b04244b8944ee08488b442418488d7008488b442410498d3cc64883c7084c893c24428d14fd00000000ff1569ce4e01'),
 ('merge_parent_length', 69734969, '6641ff4c2462be6800000048837c2450024c8b7c24184c8b6424100f82cc000000'),
 ('merge_release',
  69735206,
  '31db4c89ff31d2ff15ddcc4e01f644243001490f45dc48035c2438488b4424404c8930488b4c24284889480848895810'),
 ('left_rotate_separator', 69679898, '4b8b44ef08498b0e498b5610488b74d108488944d108488974dd00'),
 ('right_rotate_separator', 69707637, '498b44dd00498b0e498b5610488b74d108488944d108488974fd08'),
 ('root_shrink_failures',
  76823291,
  '488d3d0604df00ff1568a9e200488d3d29a7dafb488d158289dd00be21000000ff15e7a5e200'),
 ('slot_parent_index', 69852030, '488b064885c0746b498d4d010fb756604885d274674989f7'),
 ('slot_parent_link', 69680080, '488b74cd6848892e89cf66894e60'),
 ('cancel_slot_key', 70221192, '4c8b72f84c89b424b8000000'),
 ('slot_remove_arguments', 70221272, '4889de4c89f24d89e0'),
 ('cancel_call', 70222463, '4983c520488db424b80000004c89efe87db76400'),
 ('upward_left_choice',
  69852453,
  '4889d90fb7c0488b1b4885db0f84610300004c89f6498d7e01440fb761604d85e448897c24700f847f0000004e8b7ce36049ffcc'),
 ('upward_left_capacity', 69852561, '450fb77762428d1430ffc283fa0c0f8309030000'),
 ('upward_right_choice', 69852624, '0fb753626685d20f841e0300004c8b4370'),
 ('upward_right_capacity', 69852701, '450fb748624a8d340848ffc64883fe0c0f8395020000'),
 ('upward_separator_and_shift',
  69852753,
  '440fb7ea488974246866418977624a8d3ce34883c7084e8b74e3084a8d34e34883c6104c89e548f7d54c01ed48c1e5034889ea488b0555024d01ffd0488b4424204d8974c708488b442430488d7008'),
 ('upward_parent_count', 69853045, '66ff4b62be680000004c8b7424704983fe024c8b6c24484c8b6424300f8279fdffff'),
 ('upward_child_check', 69853079, '488b54242848ffc2488b6c24684889e8482b4424204839c20f852d010000'),
 ('upward_link_update', 69853168, '488d4201498b74d7684c893e668956604889c2'),
 ('upward_root_flag', 69853336, '4885c00f852bfcffff488b442450c60001e91efcffff'),
 ('upward_borrow_left', 69853358, 'be050000004829c6488dbc24e8000000e8ad59fdffe904fcffff'),
 ('upward_borrow_right', 69853384, 'be050000004829c6488dbc2420010000e853c6fdffe9eafbffff')]

BRANCHES = [(76823067, '0f84', 'null root: absent'),
 (76823107, '74', 'node key count exhausted'),
 (76823133, '74', 'advance while key is greater'),
 (76823159, '72', 'height underflow: absent'),
 (76823222, '75', 'no root shrink flag'),
 (76823230, '74', 'shrink with null root: failure'),
 (76823239, '74', 'shrink with zero height: failure'),
 (69926534, '0f84', 'already at leaf'),
 (69926551, '0f84', 'predecessor descent complete'),
 (69852024, '0f87', 'remaining node length above four'),
 (69852036, '74', 'underfull node is root'),
 (69852049, '74', 'no left sibling, select right'),
 (69852124, '0f83', 'left pair too large to merge, rotate'),
 (69852159, '0f84', 'parent has no separator: failure'),
 (69852631, '0f84', 'upward repair parent has no separator: failure'),
 (69853103, '0f85', 'upward copy-size consistency check fails'),
 (69852238, '73', 'right pair too large to merge, rotate'),
 (69852342, '74', 'no parent: stop upward repair'),
 (69852362, '76', 'parent has at most four keys: repair upward'),
 (69734570, '0f87', 'selected index beyond node length: failure'),
 (69734596, '0f83', 'merged key count at least twelve: failure'),
 (69735026, '0f85', 'merge edge-copy length mismatch: failure'),
 (69679758, '0f83', 'left rotation destination reaches twelve: failure'),
 (69679785, '0f82', 'left rotation donor subtraction borrows: failure'),
 (69679862, '0f85', 'left rotation copy-size mismatch: failure'),
 (69679939, '74', 'left rotation nonzero and zero child heights disagree: failure'),
 (69680035, '0f84', 'both left rotation child heights zero: return'),
 (69707601, '0f83', 'right rotation destination reaches twelve: failure'),
 (69707622, '0f82', 'right rotation donor subtraction borrows: failure'),
 (69707755, '0f84', 'right rotation nonzero and zero child heights disagree: failure'),
 (69707977, '0f84', 'both right rotation child heights zero: return'),
 (69852465, '0f84', 'upward node has no parent'),
 (69852491, '0f84', 'upward index zero selects right sibling'),
 (69852575, '0f83', 'upward left pair too large to merge'),
 (69852717, '0f83', 'upward right pair too large to merge'),
 (69853073, '0f82', 'combined node is leaf, release leaf-size allocation'),
 (69853339, '0f85', 'root remains nonempty')]

BRANCH_TARGETS = {76823067: 76823283,
 76823107: 76823152,
 76823133: 76823104,
 76823159: 76823283,
 76823222: 76823275,
 76823230: 76823291,
 76823239: 76823304,
 69926534: 69926863,
 69926551: 69926686,
 69852024: 69852374,
 69852036: 69852145,
 69852049: 69852154,
 69852124: 69852263,
 69852159: 69853435,
 69852631: 69853435,
 69853103: 69853410,
 69852238: 69852287,
 69852342: 69852374,
 69852362: 69852417,
 69734570: 69735269,
 69734596: 69735294,
 69735026: 69735319,
 69679758: 69680195,
 69679785: 69680220,
 69679862: 69680245,
 69679939: 69680041,
 69680035: 69680180,
 69707601: 69708131,
 69707622: 69708156,
 69707755: 69707983,
 69707977: 69708116,
 69852465: 69853336,
 69852491: 69852624,
 69852575: 69853358,
 69852717: 69853384,
 69853073: 69852432,
 69853339: 69852364}

CALLS = ((70222478, 76823056),
 (76823208, 69926512),
 (69926722, 69851920),
 (69926887, 69851920),
 (69852256, 69734528),
 (69852273, 69679728),
 (69852303, 69707568),
 (69853374, 69679728),
 (69853400, 69707568))

# Context only: the already researched cancellation caller tests this result.
ANCHORS = [*ANCHORS, ('caller_set_result', 0x42f829d, '4c8b6c245084c00f840f020000')]
BRANCHES = [*BRANCHES, (0x42f82a4, '0f84', 'set removal returned false: skip tracker work')]
BRANCH_TARGETS[0x42f82a4] = 0x42f84b9


class EvidenceError(ValueError):
    """The input does not satisfy a pinned evidence obligation."""


def authenticate(data):
    if hashlib.sha256(data).hexdigest() != DIGEST:
        raise EvidenceError('node 94 input SHA-256 mismatch')


def file_offset(data, va, size):
    if not isinstance(va, int) or not isinstance(size, int) or va < 0 or size <= 0:
        raise EvidenceError('invalid virtual address or length')
    hits = [s for s in sections(data) if s['type'] != 8 and s['flags'] & 4
            and s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(hits) != 1:
        raise EvidenceError('range has no unique file-backed executable mapping')
    return hits[0]['offset'] + va - hits[0]['address']


def read_va(data, va, size):
    off = file_offset(data, va, size)
    return bytes(data[off:off + size])


def checked_witnesses(data):
    rows = []
    for name, va, expected_hex in ANCHORS:
        expected = bytes.fromhex(expected_hex)
        raw = read_va(data, va, len(expected))
        if raw != expected:
            raise EvidenceError('witness differs: ' + name)
        rows.append({'name': name, 'va': hex(va), 'file_offset': hex(file_offset(data, va, len(raw))),
                     'raw_hex': raw.hex(), 'size': len(raw)})
    return rows


def direct_call(data, site, expected):
    raw = read_va(data, site, 5)
    if raw[0] != 0xe8 or site + 5 + struct.unpack_from('<i', raw, 1)[0] != expected:
        raise EvidenceError('direct call mismatch at ' + hex(site))
    return {'site_va': hex(site), 'target_va': hex(expected), 'raw_hex': raw.hex()}


def branch(data, site, opcode, meaning):
    op = bytes.fromhex(opcode)
    if len(op) not in (1, 2):
        raise EvidenceError('unsupported branch opcode width')
    size = 2 if len(op) == 1 else 6
    raw = read_va(data, site, size)
    if not raw.startswith(op):
        raise EvidenceError('branch opcode mismatch at ' + hex(site))
    relative = struct.unpack('<b' if size == 2 else '<i', raw[len(op):])[0]
    target = site + size + relative
    if target != BRANCH_TARGETS[site]:
        raise EvidenceError('branch destination mismatch at ' + hex(site))
    return {'site_va': hex(site), 'target_va': hex(target), 'raw_hex': raw.hex(), 'when_taken': meaning}


def functions(data):
    secs, idx = unwind_index(data)
    _, fdes = eh_frame_records(data, secs)
    index = {row['start']: row for row in idx}
    by_start = {}
    for fde in fdes:
        by_start.setdefault(fde['start'], []).append(fde)
    rows = []
    for name, start, end, expected in FUNCTIONS:
        match = by_start.get(start, [])
        if (len(match) != 1 or match[0]['end'] != end or match[0]['cie'] != 0xce1518
                or match[0]['lsda'] is not None or start not in index or index[start]['fde'] != match[0]['fde']):
            raise EvidenceError('FDE mismatch: ' + name)
        raw = read_va(data, start, end - start)
        digest = hashlib.sha256(raw).hexdigest()
        if digest != expected:
            raise EvidenceError('function body mismatch: ' + name)
        rows.append({'role': name, 'start_va': hex(start), 'end_va_exclusive': hex(end),
                     'fde_va': hex(match[0]['fde']), 'cie_va': hex(match[0]['cie']),
                     'lsda_va': None, 'file_offset': hex(file_offset(data, start, len(raw))),
                     'size': len(raw), 'sha256': digest, 'raw_hex': raw.hex()})
    return rows


class Node:
    """Synthetic tree used only to project the statically observed operations."""
    def __init__(self, count, children=None):
        if not isinstance(count, int) or count < 0 or count > 11:
            raise ValueError('invalid key count')
        self.keys = [None] * count
        self.children = list(children or [])
        if self.children and len(self.children) != count + 1:
            raise ValueError('invalid child count')


def fill_keys(root):
    counter = 0
    def walk(node):
        nonlocal counter
        for i in range(len(node.keys)):
            if node.children:
                walk(node.children[i])
            node.keys[i] = counter
            counter += 1
        if node.children:
            walk(node.children[-1])
    walk(root)
    return counter


def flat(node):
    out = []
    for i, key in enumerate(node.keys):
        if node.children:
            out.extend(flat(node.children[i]))
        out.append(key)
    if node.children:
        out.extend(flat(node.children[-1]))
    return out


def shape(node):
    return {'keys': list(node.keys), 'children': [shape(child) for child in node.children]}


def height(node):
    if not node.children:
        return 0
    levels = [height(child) for child in node.children]
    if len(set(levels)) != 1:
        raise ValueError('unequal leaf depths')
    return 1 + levels[0]


def check_tree(node, *, is_root=True):
    if len(node.keys) > 11 or (not is_root and len(node.keys) < 5):
        raise ValueError('synthetic node occupancy invalid')
    if node.children and len(node.children) != len(node.keys) + 1:
        raise ValueError('synthetic edge count invalid')
    for child in node.children:
        check_tree(child, is_root=False)
    vals = flat(node)
    if any(type(x) is not int or x < 0 or x >= 1 << 64 for x in vals):
        raise ValueError('synthetic key outside u64')
    if any(a >= b for a, b in zip(vals, vals[1:])):
        raise ValueError('synthetic keys not strictly ordered')
    height(node)
    return vals


def repair_decision(count, sibling, has_left):
    if type(count) is not int or type(sibling) is not int or not 0 <= count <= 4 or not 0 <= sibling <= 11 or type(has_left) is not bool:
        raise ValueError('invalid repair decision inputs')
    direction = 'left' if has_left else 'right'
    total = count + sibling + 1
    return {'direction': direction, 'combined': total,
            'operation': 'merge' if total < 12 else 'borrow',
            'borrow_count': 0 if total < 12 else 5 - count}


def remove_model(root, key):
    """Project one deletion on a valid synthetic tree; no machine code runs."""
    before = check_tree(root)
    if type(key) is not int or not 0 <= key < 1 << 64:
        raise ValueError('key outside u64')
    node, path, found = root, [], False
    while True:
        i = 0
        while i < len(node.keys) and node.keys[i] < key:
            i += 1
        if i < len(node.keys) and node.keys[i] == key:
            found = True
            break
        if not node.children:
            return root, {'found': False, 'events': [], 'before_count': len(before), 'after_count': len(before)}
        path.append((node, i))
        node = node.children[i]
    events = []
    if node.children:
        origin, index = node, i
        path.append((node, i))
        node = node.children[i]
        while node.children:
            j = len(node.children) - 1
            path.append((node, j))
            node = node.children[j]
        origin.keys[index], node.keys[-1] = node.keys[-1], origin.keys[index]
        i = len(node.keys) - 1
        events.append({'kind': 'predecessor'})
    del node.keys[i]
    while path and len(node.keys) <= 4:
        parent, index = path.pop()
        has_left = index > 0
        other = parent.children[index - 1 if has_left else index + 1]
        decision = repair_decision(len(node.keys), len(other.keys), has_left)
        events.append({'kind': decision['operation'], 'side': decision['direction'],
                       'current_count': len(node.keys), 'sibling_count': len(other.keys),
                       'amount': decision['borrow_count'], 'node_height': height(node)})
        if decision['operation'] == 'borrow':
            amount = decision['borrow_count']
            if has_left:
                for _ in range(amount):
                    node.keys.insert(0, parent.keys[index - 1])
                    parent.keys[index - 1] = other.keys.pop()
                    if other.children:
                        node.children.insert(0, other.children.pop())
            else:
                for _ in range(amount):
                    node.keys.append(parent.keys[index])
                    parent.keys[index] = other.keys.pop(0)
                    if other.children:
                        node.children.append(other.children.pop(0))
            break
        if has_left:
            other.keys.append(parent.keys.pop(index - 1))
            other.keys.extend(node.keys)
            other.children.extend(node.children)
            del parent.children[index]
        else:
            node.keys.append(parent.keys.pop(index))
            node.keys.extend(other.keys)
            node.children.extend(other.children)
            del parent.children[index + 1]
        node = parent
    if root.children and not root.keys:
        root = root.children[0]
        events.append({'kind': 'root_contract'})
    after = check_tree(root)
    if after != [v for v in before if v != key]:
        raise AssertionError('synthetic deletion did not conserve keys')
    return root, {'found': found, 'events': events, 'before_count': len(before), 'after_count': len(after)}


def internal(count, leaf_sizes=None):
    sizes = leaf_sizes if leaf_sizes is not None else [5] * (count + 1)
    return Node(count, [Node(size) for size in sizes])


def make_fixture(name):
    if name == 'empty_miss':
        root, pick = Node(0), lambda r: 0
    elif name == 'leaf_delete':
        root, pick = Node(6), lambda r: r.keys[2]
    elif name == 'root_merge':
        root, pick = Node(1, [Node(5), Node(5)]), lambda r: r.children[0].keys[0]
    elif name == 'leaf_merge_right_boundary':
        root, pick = Node(1, [Node(5), Node(6)]), lambda r: r.children[0].keys[0]
    elif name == 'leaf_merge_left_boundary':
        root, pick = Node(1, [Node(6), Node(5)]), lambda r: r.children[1].keys[0]
    elif name == 'leaf_borrow_right':
        root, pick = Node(1, [Node(5), Node(7)]), lambda r: r.children[0].keys[0]
    elif name == 'leaf_borrow_left':
        root, pick = Node(1, [Node(7), Node(5)]), lambda r: r.children[1].keys[0]
    elif name == 'internal_predecessor_merge':
        root, pick = Node(1, [Node(5), Node(5)]), lambda r: r.keys[0]
    elif name == 'internal_predecessor':
        root, pick = Node(1, [Node(6), Node(5)]), lambda r: r.keys[0]
    elif name == 'deep_miss':
        root, pick = Node(1, [internal(5), internal(5)]), lambda r: (1 << 64) - 1
    elif name == 'three_level_contract':
        left = Node(5, [internal(5) for _ in range(6)])
        right = Node(5, [internal(5) for _ in range(6)])
        root, pick = Node(1, [left, right]), lambda r: r.children[0].children[0].children[0].keys[0]
    elif name == 'deep_contract':
        root, pick = Node(1, [internal(5), internal(5)]), lambda r: r.children[0].children[0].keys[0]
    elif name == 'deep_borrow_right':
        root, pick = Node(1, [internal(5), internal(7)]), lambda r: r.children[0].children[0].keys[0]
    elif name == 'deep_borrow_left':
        root, pick = Node(1, [internal(7), internal(5)]), lambda r: r.children[1].children[0].keys[0]
    elif name == 'deep_merge_root_retained':
        root, pick = Node(2, [internal(5), internal(5), internal(5)]), lambda r: r.children[1].children[0].keys[0]
    else:
        raise ValueError('unknown fixture')
    fill_keys(root)
    return root, pick(root)


FIXTURES = ('empty_miss', 'leaf_delete', 'root_merge', 'leaf_merge_right_boundary',
            'leaf_merge_left_boundary', 'leaf_borrow_right', 'leaf_borrow_left',
            'internal_predecessor', 'internal_predecessor_merge', 'deep_miss',
            'deep_contract', 'deep_borrow_right', 'deep_borrow_left',
            'deep_merge_root_retained', 'three_level_contract')


def scenario_rows():
    rows = []
    for name in FIXTURES:
        root, key = make_fixture(name)
        before = shape(root)
        initial_height = height(root)
        root, result = remove_model(root, key)
        rows.append({'name': name, 'key': key, 'height_before': initial_height,
                     'height_after': height(root), 'before': before, 'after': shape(root), 'result': result})
    return rows


def relocation(data, site, prefix, length):
    raw = read_va(data, site, length)
    if not raw.startswith(bytes.fromhex(prefix)):
        raise EvidenceError('RIP-relative instruction mismatch at ' + hex(site))
    target = site + length + struct.unpack_from('<i', raw, length - 4)[0]
    return {'site_va': hex(site), 'slot_va': hex(target), 'raw_hex': raw.hex()}


# Fixed source-location references, restricted to documented error arms.
DIAGNOSTICS = (
    (0x429e0e2, 0x6ee259, 40, 0x571c4b0),
    (0x4281365, 0x6ee3b9, 142, 0x571c5b8),
    (0x428137e, 0x6ee447, 42, 0x571c5d0),
    (0x4281397, 0x6ee259, 40, 0x571c4b0),
    (0x4273c43, 0x6ee305, 51, 0x571c528),
    (0x4273c5c, 0x6ee338, 39, 0x571c540),
    (0x4273c75, 0x6ee259, 40, 0x571c4b0),
    (0x4273ba9, 0x6ee2b6, 40, 0x571c558),
    (0x427a963, 0x6ee35f, 50, 0x571c570),
    (0x427a97c, 0x6ee391, 40, 0x571c588),
    (0x427a8cf, 0x6ee2b6, 40, 0x571c5a0),
    (0x4943b08, 0x6ee238, 33, 0x571c498),
)


def read_data_va(data, va, size):
    if va < 0 or size <= 0:
        raise EvidenceError('invalid data range')
    matches = [s for s in sections(data) if s['type'] != 8 and
               s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise EvidenceError('data range is not uniquely file-backed')
    sec = matches[0]
    off = sec['offset'] + va - sec['address']
    return bytes(data[off:off + size])


def relative_relocations(data, slots):
    result = {}
    for sec in sections(data):
        if sec['type'] != 4:
            continue
        if sec['size'] % 24:
            raise EvidenceError('partial relocation record')
        for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
            slot, info, addend = struct.unpack_from('<QQq', data, off)
            if slot in slots:
                if slot in result or info != 8:
                    raise EvidenceError('unexpected or duplicate location relocation')
                result[slot] = addend
    if set(result) != set(slots):
        raise EvidenceError('missing location relocation')
    return result


MESSAGE_HASHES = {7266872: 'b1b22104583ceb9fa5956115eaa5c8dcccce466e55c25655b0b0500b6affe85d',
 7266905: 'b6f2eaf4643bf15ebd9b009e697edcb88dfb52efe506a69586e276462f795d3f',
 7266998: 'ca6da24e22ccd442e9c0d1c946cd3b635ae3288168137ecfc24b6da9ca78c560',
 7267077: 'd4a3b4905c53e2263ed604ad22cc882269faddbf032ec57fe725340375b9ca4c',
 7267128: '8c46893672d1442e1dc833392553af28a1a930b9381a47c538c9c4c00ea745ba',
 7267167: 'a20313aaa9a4f45c2c9b703298db06ab60fc2e4b9cce36cf0bf325e038261c19',
 7267217: '0153c8f117ad71188a2d64a5e9b85b06c406382c225561ad23e075de3801b453',
 7267257: 'f08caaa376efcff7f1e0be1b8a47179b79a276c4322356639cbed96c88519226',
 7267399: '21901133a9be14b3c2d033423eef89861da6284054bf47dac6087330b3ec1935'}
LOCATION_LINES = {91341976: (618, 9),
 91342000: (1876, 5),
 91342120: (1537, 13),
 91342144: (1538, 13),
 91342168: (1585, 22),
 91342192: (1600, 13),
 91342216: (1601, 13),
 91342240: (1649, 22),
 91342264: (1491, 9),
 91342288: (1414, 9)}
SOURCE_PATH_HASH = 'dcc3d7e62284f492b539255e9be3475501be4557c502aad1498aa1d2bca75d15'


def diagnostic_records(data):
    rels = relative_relocations(data, {row[3] for row in DIAGNOSTICS})
    rows = []
    for site, expected_text, expected_size, expected_location in DIAGNOSTICS:
        raw = read_va(data, site, 25)
        if raw[:3] != b'\x48\x8d\x3d' or raw[7:10] != b'\x48\x8d\x15' or raw[14] != 0xbe or raw[19:21] != b'\xff\x15':
            raise EvidenceError('diagnostic instruction shape changed')
        text_va = site + 7 + struct.unpack_from('<i', raw, 3)[0]
        location_va = site + 14 + struct.unpack_from('<i', raw, 10)[0]
        size = struct.unpack_from('<I', raw, 15)[0]
        call_slot = site + 25 + struct.unpack_from('<i', raw, 21)[0]
        if (text_va, size, location_va, call_slot) != (expected_text, expected_size, expected_location, 0x576e108):
            raise EvidenceError('diagnostic references changed')
        text_bytes = read_data_va(data, text_va, size)
        zero, path_len, line, column = struct.unpack('<QQII', read_data_va(data, location_va, 24))
        if zero != 0 or path_len == 0 or path_len > 1024:
            raise EvidenceError('invalid source location')
        path = read_data_va(data, rels[location_va], path_len)
        suffix = b'/'.join(path.split(b'/')[-4:]).decode('utf-8')
        if (hashlib.sha256(text_bytes).hexdigest() != MESSAGE_HASHES[text_va]
                or (line, column) != LOCATION_LINES[location_va]
                or hashlib.sha256(path).hexdigest() != SOURCE_PATH_HASH
                or suffix != 'src/collections/btree/node.rs'):
            raise EvidenceError('diagnostic data changed')
        rows.append({'site_va': hex(site), 'raw_hex': raw.hex(), 'message_va': hex(text_va),
                     'message_size': size, 'message_sha256': hashlib.sha256(text_bytes).hexdigest(),
                     'location_va': hex(location_va), 'path_va': hex(rels[location_va]),
                     'path_suffix': suffix, 'path_sha256': hashlib.sha256(path).hexdigest(),
                     'line': line, 'column': column, 'call_slot_va': hex(call_slot)})
    return rows


# Selected fixed instruction boundaries. The single register call obtains its
# pointer from a preceding RIP-relative load, which is recorded separately.
INDIRECT_CALLS = (
    (0x4943ae5, 0x576e010), (0x4943b02, 0x576e470), (0x4943b1b, 0x576e108),
    (0x429db5e, 0x576e0e0), (0x429dd15, 0x576e010), (0x429deb9, 0x576dfe0),
    (0x429ded7, 0x576e0e0), (0x429dfca, 0x576dfe0), (0x429e0f5, 0x576e108),
    (0x429e10e, 0x576e098), (0x428113b, 0x576e0e0), (0x4281171, 0x576dfe0),
    (0x4281191, 0x576e0e0), (0x428128b, 0x576dfe0), (0x428132d, 0x576e010),
    (0x4281378, 0x576e108), (0x4281391, 0x576e108), (0x42813aa, 0x576e108),
    (0x4273ae2, 0x576e0e0), (0x4273b14, 0x576dfe0), (0x4273b60, 0x576e0e0),
    (0x4273b7d, 0x576dfe0), (0x4273bbc, 0x576e108), (0x4273c56, 0x576e108),
    (0x4273c6f, 0x576e108), (0x4273c88, 0x576e108), (0x427a7af, 0x576dfe0),
    (0x427a7d3, 0x576e0e0), (0x427a819, 0x576dfe0), (0x427a834, 0x576e0e0),
    (0x427a8e2, 0x576e108), (0x427a976, 0x576e108), (0x427a98f, 0x576e108),
)


def indirect_call(data, site, expected):
    row = relocation(data, site, 'ff15', 6)
    if int(row['slot_va'], 16) != expected:
        raise EvidenceError('indirect call slot mismatch at ' + hex(site))
    return row


EXPECTED_SLOT_RELOCS = {
    0x576dfe0: (6, 6, 'memcpy', 0),
    0x576e010: (8, 0, None, 0x54c8cb0),
    0x576e098: (8, 0, None, 0x157b810),
    0x576e0e0: (6, 9, 'memmove', 0),
    0x576e108: (8, 0, None, 0x157b7f0),
    0x576e470: (8, 0, None, 0x157a9f0),
}


def slot_relocations(data):
    wanted = {target for _, target in INDIRECT_CALLS}
    rows = []
    found = {}
    secs = sections(data)
    dynsym = next(s for s in secs if s['name'] == '.dynsym' and s['type'] != 8)
    dynstr = next(s for s in secs if s['name'] == '.dynstr' and s['type'] != 8)
    strings = data[dynstr['offset']:dynstr['offset'] + dynstr['size']]
    for sec in secs:
        if sec['type'] != 4:
            continue
        if sec['size'] % 24:
            raise EvidenceError('partial relocation record')
        for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
            slot, info, addend = struct.unpack_from('<QQq', data, off)
            if slot not in wanted:
                continue
            if slot in found:
                raise EvidenceError('duplicate call slot relocation')
            typ, index = info & 0xffffffff, info >> 32
            name = None
            if index:
                pos = dynsym['offset'] + index * 24
                if pos + 24 > dynsym['offset'] + dynsym['size']:
                    raise EvidenceError('dynamic symbol outside table')
                name_off = struct.unpack_from('<I', data, pos)[0]
                if name_off >= len(strings):
                    raise EvidenceError('dynamic symbol name outside table')
                end = strings.find(b'\0', name_off)
                if end < 0:
                    raise EvidenceError('unterminated dynamic symbol')
                name = bytes(strings[name_off:end]).decode('ascii')
            if (typ, index, name, addend) != EXPECTED_SLOT_RELOCS[slot]:
                raise EvidenceError('call slot relocation changed')
            found[slot] = {'slot_va': hex(slot), 'relocation_type': typ, 'symbol_index': index,
                           'symbol_name': name, 'addend': hex(addend) if addend >= 0 else '-' + hex(-addend)}
    if set(found) != wanted:
        raise EvidenceError('missing call slot relocation')
    for slot in sorted(found):
        rows.append(found[slot])
    return rows


def collect(data):
    authenticate(data)
    fn = functions(data)
    witnesses = checked_witnesses(data)
    branches = [branch(data, *item) for item in BRANCHES]
    edges = [direct_call(data, *item) for item in CALLS]
    # Each value is extracted from a checked witness at a fixed operand byte.
    u8 = lambda addr: read_va(data, addr, 1)[0]
    u32 = lambda addr: struct.unpack('<I', read_va(data, addr, 4))[0]
    constants = {
        'tree_height_offset': u8(0x4943a27),
        'tree_count_offset': u8(0x4943ab0),
        'node_keys_offset': u8(0x429db3e),
        'parent_edge_index_offset': u8(0x429db8d),
        'node_count_offset': u8(0x4943a2e),
        'node_edges_offset': u8(0x42afe90),
        'underfull_inclusive': u8(0x429db77),
        'capacity_exclusive': u8(0x4273a8d),
        'upward_target_count': u32(0x429e0af),
        'released_internal_root_size': u32(0x4943adf),
    }
    if constants != {'tree_height_offset': 8, 'tree_count_offset': 16, 'node_keys_offset': 8,
                     'parent_edge_index_offset': 96, 'node_count_offset': 98, 'node_edges_offset': 104,
                     'underfull_inclusive': 4, 'capacity_exclusive': 12, 'upward_target_count': 5,
                     'released_internal_root_size': 200}:
        raise EvidenceError('decoded constants mismatch')
    slots = [relocation(data, 0x429db5e, 'ff15', 6),
             relocation(data, 0x429deb9, 'ff15', 6),
             relocation(data, 0x4943ae5, 'ff15', 6)]
    if read_va(data, 0x429de8b, 2) != bytes.fromhex('ffd0'):
        raise EvidenceError('register call encoding changed')
    load = relocation(data, 0x429de84, '488b05', 7)
    if load['slot_va'] != '0x576e0e0':
        raise EvidenceError('register call source changed')
    indirect = [indirect_call(data, *row) for row in INDIRECT_CALLS]
    return {'target_sha256': DIGEST, 'coordinate_system': 'linked ELF virtual addresses; ends exclusive',
            'functions': fn, 'witnesses': witnesses, 'calls': edges, 'branches': branches,
            'selected_rip_relative_slots': slots, 'indirect_calls': indirect,
            'register_call': {'site_va': '0x429de8b', 'raw_hex': 'ffd0', 'source_load': load},
            'call_slot_relocations': slot_relocations(data), 'diagnostics': diagnostic_records(data), 'decoded_constants': constants,
            'limitations': ['FDE ranges are unwind extents and do not prove source function boundaries.',
                            'Branch and call lists are selected instruction sites, not a complete CFG.',
                            'Models are synthetic projections and do not execute the target.',
                            'Other function copies, allocator behavior and unwind effects are unresolved.']}


def write_json(path, obj):
    path.write_text(json.dumps(obj, sort_keys=True, indent=2) + '\n', encoding='utf-8')


def generate(data, out):
    evidence = collect(data)
    cases = scenario_rows()
    out.mkdir(parents=True, exist_ok=True)
    write_json(out / 'evidence.json', evidence)
    write_json(out / 'repair-cases.json', {'kind': 'synthetic model; not target execution', 'cases': cases})
    lines = ['current_count\tsibling_count\thas_left\tcombined\toperation\tborrow_count']
    for current in range(5):
        for sibling in range(12):
            for left in (False, True):
                decision = repair_decision(current, sibling, left)
                lines.append(f"{current}\t{sibling}\t{int(left)}\t{decision['combined']}\t{decision['operation']}\t{decision['borrow_count']}")
    (out / 'decisions.tsv').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    return evidence, cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    generate(BINARY.read_bytes(), args.out)


if __name__ == '__main__':
    main()
