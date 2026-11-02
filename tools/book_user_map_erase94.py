#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
FUNCTIONS = [('cursor', 69951552, 69952490, '413f03cd7da569bf65ed536e8b2f249a1d0001a91b98bf918fe5f9069b64c4f0'),
 ('leaf_remove', 69868528, 69869280, 'f75c5f1c64b8218c34bc814c7210ec39d1034fa236e282d6df28cf9b257c3806'),
 ('merge', 69744144, 69745352, 'e3e6fe7808ab843daf4bf3d9c157a69b052f6606c8e2ec6b6fefd05ef9ea7924'),
 ('borrow_left', 69689472, 69690619, '6eae403695b1396d1eb6a1f1186e568da70b6d9267884280cf227871bac91cb0'),
 ('borrow_right', 69704640, 69705906, 'cf742d082e55f25952212401fa77e82284aabb447faf3ab9fe59bf4ba4140839'),
 ('ancestor_repair', 69034256, 69035740, 'd4a740d4666f6009ec826e9f869de8556dfb08b5a72c6f7933368730c5557c22')]

WITNESSES = [('context_cursor_call', 76831812, 'c644240f00488d7c2450488d742430488d54240fe8e30397ff'),
 ('context_count_decrement', 76831924, '49ff4e10'),
 ('context_root_shrink',
  76831944,
  '807c240f01488b7c241875484889fb498b3e4885ff0f84f6000000498b46084885c00f84f8000000488b8f5804000049890e48ffc84989460848c7817003000000000000beb804000031d2ff15f782e200'),
 ('cursor_choose_leaf', 69951563, '488b06488b7e08488b4e104885ff0f84a6020000488b8cc858040000'),
 ('cursor_predecessor',
  69951806,
  '0fb7815604000048ffc848898c249800000048c78424a00000000000000048898424a80000004889e7488db42498000000e87cbafeff'),
 ('cursor_replace_key',
  69952010,
  '488d34898bbcb088030000897c24100f1084b0780300000f2904248bbc24c000000089bcb0880300000f288424b00000000f1184b07803000048c1e604'),
 ('cursor_direct_leaf',
  69952261,
  '488984248000000048c78424880000000000000048898c2490000000488db424800000004889dfe8bfb8feff'),
 ('leaf_key_layout', 69868563, '410fb78d5604000048894c24104f8d3cb64b8dbcbd78030000'),
 ('leaf_value_stride', 69868662, '49c1e7044b8d3c2f430f10443d00430f104c3d10430f10543d20430f105c3d30'),
 ('leaf_count_and_sibling',
  69868758,
  '488b7c24108d47ff66418985560400004d8b6424086683f804776a498b85700300004885c07467498d4c2401410fb795540400004885d2745e488bb4d05004000048ffca'),
 ('leaf_left_boundary', 69868861, '0fb7865604000001c783ff0c0f839a000000ba01000000488d742430'),
 ('leaf_empty_parent', 69868909, '6683b856040000000f842c010000488b9060040000'),
 ('leaf_right_boundary', 69868981, '0fb7825604000001c783ff0c733e488d74246831d2488b0c24488d7c2418e83818feff'),
 ('leaf_borrow_and_ancestor',
  69869033,
  '488d7c2430be01000000e88842fdff4c8b342449ffc6eb13488d7c2468be01000000e8b07dfdff4c8b3424498bbd700300004885ff7416498d742401e8e642f3ff84c07508488b442408c60001'),
 ('merge_capacity',
  69744161,
  '4c8b7618450fb7be560400004c89f8f6c201740b488b46280fb780560400004839c10f8734040000488b6e280fb785560400004d8d040749ffc04983f80c0f8331040000'),
 ('merge_parent_links', 69744773, '4c89a670030000418d3c176689be54040000'),
 ('merge_release_size', 69744935, 'be5804000048837c245802'),
 ('left_guards',
  69689489,
  '488b5f28440fb7b3560400004a8d04364883f80c0f83050400004c8b6718410fb7ac24560400004989ef4929f70f820504000048897c2438664589bc2456040000488944242866898356040000'),
 ('right_guards',
  69704657,
  '4c8b6f18450fb78d560400004a8d040e4883f80c0f8395040000488b5f28440fb783560400004929f00f829904000066418985560400006644898356040000'),
 ('ancestor_initial', 69034273, '0fb787560400006683f8047614b0014881c4080100005b415c415d415e415f5dc3'),
 ('ancestor_choose_left',
  69034344,
  '4889d90fb7c0488b9b700300004885db0f84cf040000498d7f01440fb7a9540400004d85ed48897c24380f84880000004e8bb4eb5004000049ffcd'),
 ('ancestor_left_boundary',
  69034459,
  '450fb7be56040000428d1438ffc283fa0c0f836b040000498d340748ffc64883fe0c0f838e040000'),
 ('ancestor_choose_right', 69034528, '0fb793560400006685d20f8493040000488bab60040000'),
 ('ancestor_right_boundary', 69034611, '440fb785560400004a8d340048ffc64883fe0c0f83eb030000'),
 ('ancestor_reparent', 69035108, '4a8b94fb5804000048899a70030000664489ba54040000'),
 ('ancestor_release_sizes', 69035274, '66ff8b56040000be58040000'),
 ('ancestor_internal_size', 69035432, 'beb8040000'),
 ('leaf_cleanup_tail', 0x42a1ec2, '4889c3488dbc24b8000000e89e3cf3ff4889dfe836e23b01'),
 ('ancestor_borrow_calls',
  69035613,
  'be050000004829c6488dbc2498000000e80efa0900e9b7faffffbe050000004829c6488dbc24d0000000e834350a00')]

BRANCHES = [('cursor_leaf', 69951577, '0f84a6020000'),
 ('leaf_above_minimum', 69868783, '776a'),
 ('leaf_root', 69868795, '7467'),
 ('leaf_right_sibling', 69868813, '745e'),
 ('leaf_left_borrow', 69868873, '0f839a000000'),
 ('leaf_no_separator', 69868917, '0f842c010000'),
 ('leaf_right_borrow', 69868993, '733e'),
 ('leaf_no_ancestor', 69869086, '7416'),
 ('leaf_ancestor_result', 69869100, '7508'),
 ('merge_index_guard', 69744195, '0f8734040000'),
 ('merge_capacity_guard', 69744223, '0f8331040000'),
 ('left_capacity_guard', 69689509, '0f8305040000'),
 ('left_donor_guard', 69689534, '0f8205040000'),
 ('left_length_guard', 69689668, '0f8598030000'),
 ('right_capacity_guard', 69704677, '0f8395040000'),
 ('right_donor_guard', 69704698, '0f8299040000'),
 ('ancestor_enough', 69034284, '7614'),
 ('ancestor_root', 69034360, '0f84cf040000'),
 ('ancestor_right_sibling', 69034386, '0f8488000000'),
 ('ancestor_left_borrow', 69034476, '0f836b040000'),
 ('ancestor_merge_guard', 69034493, '0f838e040000'),
 ('ancestor_no_separator', 69034538, '0f8493040000'),
 ('ancestor_right_borrow', 69034630, '0f83eb030000'),
 ('context_root_null', 76831965, '0f84f6000000'),
 ('context_height_zero', 76831978, '0f84f8000000')]

CALLS = [('caller_cursor', 76831832, 'e8e30397ff'),
 ('cursor_predecessor_leaf', 69951855, 'e87cbafeff'),
 ('cursor_direct_leaf', 69952300, 'e8bfb8feff'),
 ('leaf_merge', 69869011, 'e83818feff'),
 ('leaf_borrow_left', 69869043, 'e88842fdff'),
 ('leaf_borrow_right', 69869067, 'e8b07dfdff'),
 ('leaf_ancestor', 69869093, 'e8e642f3ff'),
 ('ancestor_borrow_left', 69035629, 'e80efa0900'),
 ('ancestor_borrow_right', 69035655, 'e834350a00'),
 ('leaf_cleanup', 0x42a1ecd, 'e89e3cf3ff'),
 ('leaf_cleanup_exit', 0x42a1ed5, 'e836e23b01')]

INDIRECT = [('leaf_memmove_slot', 69868653, '488b2d6cc44c01'),
 ('merge_memmove', 69744382, 'ff15dca94e01'),
 ('merge_memcpy', 69744467, 'ff1587a84e01'),
 ('merge_release', 69745218, 'ff15c8a54e01'),
 ('leaf_failure', 69869242, 'ff15d8c14c01'),
 ('ancestor_release', 69034325, 'ff15b57e5901'),
 ('ancestor_memmove_slot', 69034757, '488b05d47d5901'),
 ('left_shift', 69689610, 'ff15d07f4f01'),
 ('left_value_shift', 69689644, 'ff15ae7f4f01')]

DIAGNOSTICS = [('leaf_empty_parent', 69869223, '488d3d4dc344fc488d15cba54701be7b000000ff15d8c14c01'),
 ('merge_cursor', 69745277, '488d3d35a946fc488d152d8b4901be8e000000ff1572a64e01'),
 ('merge_capacity', 69745302, '488d3daaa946fc488d152c8b4901be2a000000ff1559a64e01'),
 ('left_capacity', 69690544, '488d3d4e7e47fc488d156a604a01be33000000ff153f7c4f01'),
 ('left_donor', 69690569, '488d3d687e47fc488d1569604a01be27000000ff15267c4f01'),
 ('left_slices', 69690594, '488d3d707d47fc488d15c05f4a01be28000000ff150d7c4f01'),
 ('right_capacity', 69705856, '488d3dd84247fc488d15e2244a01be32000000ff156f404f01'),
 ('right_donor', 69705881, '488d3df14247fc488d15e1244a01be28000000ff1556404f01'),
 ('ancestor_capacity', 69035665, '488d3daf7d51fc488d15315f5401be2a000000ff155e7a5901'),
 ('ancestor_empty_parent', 69035715, '488d3d317b51fc488d15af5d5401be7b000000ff15bc795901')]

import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from elf_index import sections, unwind_index
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / 'artifacts/node/94/hl-node'
DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'


class EvidenceError(ValueError):
    pass


def checked_digest(data):
    if hashlib.sha256(data).hexdigest() != DIGEST:
        raise EvidenceError('node 94 digest mismatch')


def map_offset(secs, address, size, executable=False):
    if address < 0 or size <= 0:
        raise EvidenceError('invalid address or size')
    matches = [s for s in secs if s['type'] != 8 and (not executable or s['flags'] & 4)
               and s['address'] <= address and address + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise EvidenceError('address lacks a unique file-backed section')
    sec = matches[0]
    return sec['offset'] + address - sec['address']


def get_bytes(data, secs, address, size):
    off = map_offset(secs, address, size, True)
    return bytes(data[off:off + size])


def check_bytes(actual, expected):
    if actual != bytes.fromhex(expected):
        raise EvidenceError('selected instruction bytes changed')


def check_body(body, digest):
    if hashlib.sha256(body).hexdigest() != digest:
        raise EvidenceError('selected body changed')


def decode_branch(address, raw):
    if len(raw) == 2 and 0x70 <= raw[0] <= 0x7f:
        delta = struct.unpack_from('<b', raw, 1)[0]
        code = raw[0] & 15
    elif len(raw) == 6 and raw[0] == 15 and 0x80 <= raw[1] <= 0x8f:
        delta = struct.unpack_from('<i', raw, 2)[0]
        code = raw[1] & 15
    else:
        raise EvidenceError('unsupported conditional instruction')
    return code, address + len(raw) + delta


def decode_call(address, raw):
    if len(raw) != 5 or raw[0] != 0xe8:
        raise EvidenceError('unsupported direct call')
    return address + 5 + struct.unpack_from('<i', raw, 1)[0]


def decode_rip(address, raw):
    if raw[:2] == b'\xff\x15' and len(raw) == 6:
        return address + 6 + struct.unpack_from('<i', raw, 2)[0]
    if len(raw) == 7 and raw[:3] in (b'\x48\x8b\x2d', b'\x48\x8b\x05'):
        return address + 7 + struct.unpack_from('<i', raw, 3)[0]
    raise EvidenceError('unsupported indirect instruction')


def relocation_rows(data, secs, wanted):
    syms = next(x for x in secs if x['name'] == '.dynsym' and x['type'] != 8)
    strs = next(x for x in secs if x['name'] == '.dynstr' and x['type'] != 8)
    strings = data[strs['offset']:strs['offset'] + strs['size']]
    found = {}
    for sec in secs:
        if sec['type'] != 4:
            continue
        if sec['size'] % 24:
            raise EvidenceError('partial relocation')
        for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
            addr, info, addend = struct.unpack_from('<QQq', data, off)
            if addr not in wanted:
                continue
            if addr in found:
                raise EvidenceError('duplicate relocation')
            typ, index = info & 0xffffffff, info >> 32
            name = ''
            if index:
                sympos = syms['offset'] + index * 24
                if sympos + 24 > syms['offset'] + syms['size']:
                    raise EvidenceError('dynamic symbol outside table')
                nameoff = struct.unpack_from('<I', data, sympos)[0]
                if nameoff >= len(strings):
                    raise EvidenceError('dynamic symbol name outside table')
                end = strings.find(b'\0', nameoff)
                if end < 0:
                    raise EvidenceError('unterminated dynamic symbol')
                name = strings[nameoff:end].decode('ascii')
            found[addr] = (typ, index, name, addend)
    if set(found) != wanted:
        raise EvidenceError('missing relocation')
    expected = {0x576dfe0: (6, 6, 'memcpy', 0), 0x576e010: (8, 0, '', 0x54c8cb0),
                0x576e098: (8, 0, '', 0x157b810), 0x576e0e0: (6, 9, 'memmove', 0)}
    if any(found[a] != expected.get(a) for a in found):
        raise EvidenceError('relocation changed')
    return [[hex(a), str(found[a][0]), str(found[a][1]), found[a][2], hex(found[a][3])] for a in sorted(found)]


def diagnostic_rows(data, secs):
    prepared = []
    for name, address, expected in DIAGNOSTICS:
        raw = get_bytes(data, secs, address, 25)
        check_bytes(raw, expected)
        if raw[:3] != b'\x48\x8d\x3d' or raw[7:10] != b'\x48\x8d\x15' or raw[14] != 0xbe:
            raise EvidenceError('unsupported diagnostic sequence')
        literal = address + 7 + struct.unpack_from('<i', raw, 3)[0]
        location = address + 14 + struct.unpack_from('<i', raw, 10)[0]
        length = struct.unpack_from('<I', raw, 15)[0]
        litoff = map_offset(secs, literal, length)
        locoff = map_offset(secs, location, 24)
        prepared.append((name, address, raw, literal, length, litoff, location, locoff))
    wanted = {row[6] for row in prepared}
    addends = {}
    for sec in secs:
        if sec['type'] != 4:
            continue
        if sec['size'] % 24:
            raise EvidenceError('partial relocation')
        for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
            address, info, addend = struct.unpack_from('<QQq', data, off)
            if address in wanted:
                if address in addends or info != 8 or addend < 0:
                    raise EvidenceError('unexpected source location relocation')
                addends[address] = addend
    if set(addends) != wanted:
        raise EvidenceError('missing source location relocation')
    result = [['role', 'site_va', 'instruction_hex', 'literal_va', 'literal_length', 'literal_hex',
               'location_va', 'location_record_hex', 'path_va', 'path_length', 'path_sha256', 'path_suffix', 'line', 'column']]
    for name, address, raw, literal, length, litoff, location, locoff in prepared:
        pointer, plen, line, column = struct.unpack_from('<QQII', data, locoff)
        if pointer != 0 or not (0 < plen <= 4096):
            raise EvidenceError('unsupported source location')
        path_va = addends[location]
        pathoff = map_offset(secs, path_va, plen)
        path = bytes(data[pathoff:pathoff+plen])
        marker = path.rfind(b'src/')
        if marker < 0 or path[marker:] != b'src/collections/btree/node.rs':
            raise EvidenceError('unexpected diagnostic source suffix')
        result.append([name, hex(address), raw.hex(), hex(literal), str(length),
                       data[litoff:litoff+length].hex(), hex(location), data[locoff:locoff+24].hex(),
                       hex(path_va), str(plen), hashlib.sha256(path).hexdigest(), path[marker:].decode('ascii'), str(line), str(column)])
    return result


def repair_decision(remaining, sibling, side, minimum, capacity):
    if side not in ('left', 'right') or not (0 <= remaining < minimum and 0 <= sibling < capacity):
        raise EvidenceError('projection outside modeled range')
    return 'merge' if remaining + sibling + 1 < capacity else 'borrow_' + side


def project_header_decrement(value):
    """Project the observed 64-bit decrement; invalid tree reachability is unknown."""
    if not 0 <= value < (1 << 64):
        raise EvidenceError('header counter outside u64')
    return (value - 1) & ((1 << 64) - 1)


def project_leaf(target, sibling, separator, remove_index, side, minimum=5, capacity=12):
    """Project one valid non-root leaf deletion; this is not target execution."""
    if side not in ('left', 'right') or not (minimum <= len(target) < capacity):
        raise EvidenceError('invalid target leaf')
    if not (minimum <= len(sibling) < capacity) or not (0 <= remove_index < len(target)):
        raise EvidenceError('invalid sibling or removal index')
    left, right = (list(sibling), list(target)) if side == 'left' else (list(target), list(sibling))
    combined = left + [separator] + right
    keys = [row[0] for row in combined]
    if keys != sorted(set(keys)):
        raise EvidenceError('keys are not strictly ordered')
    remaining = list(target)
    deleted = remaining.pop(remove_index)
    if len(remaining) >= minimum:
        return {'action': 'none', 'deleted': deleted, 'target': remaining,
                'sibling': list(sibling), 'separator': separator}
    decision = repair_decision(len(remaining), len(sibling), side, minimum, capacity)
    if decision == 'merge':
        merged = list(sibling) + [separator] + remaining if side == 'left' else remaining + [separator] + list(sibling)
        return {'action': decision, 'deleted': deleted, 'merged': merged, 'separator': None}
    donor = list(sibling)
    if side == 'left':
        promoted = donor.pop()
        remaining.insert(0, separator)
    else:
        promoted = donor.pop(0)
        remaining.append(separator)
    return {'action': decision, 'deleted': deleted, 'target': remaining,
            'sibling': donor, 'separator': promoted}


def project_two_level(minimum, capacity):
    """Project one two-level merge and root contraction on a synthetic tree."""
    if (minimum, capacity) != (5, 12):
        raise EvidenceError('unsupported fixture thresholds')
    counter = 0
    def pair():
        nonlocal counter
        value = (counter, 1000 + counter)
        counter += 1
        return value
    def branch():
        keys, children = [], []
        for index in range(minimum + 1):
            children.append([pair() for _ in range(minimum)])
            if index < minimum:
                keys.append(pair())
        return {'keys': keys, 'children': children}
    left = branch()
    root_separator = pair()
    right = branch()
    original = {'root_keys': [root_separator], 'left': left, 'right': right}
    first = project_leaf(left['children'][0], left['children'][1], left['keys'][0], 2, 'right', minimum, capacity)
    if first['action'] != 'merge':
        raise EvidenceError('fixture did not take leaf merge')
    left_after = {'keys': left['keys'][1:], 'children': [first['merged']] + left['children'][2:]}
    action = repair_decision(len(left_after['keys']), len(right['keys']), 'right', minimum, capacity)
    if action != 'merge':
        raise EvidenceError('fixture did not take ancestor merge')
    contracted = {'keys': left_after['keys'] + [root_separator] + right['keys'],
                  'children': left_after['children'] + right['children']}
    return {'before': original, 'deleted': first['deleted'], 'after': contracted,
            'events': ['leaf_merge_right', 'ancestor_merge_right', 'root_contract']}


def table(rows):
    stream = io.StringIO(newline='')
    writer = csv.writer(stream, delimiter='\t', lineterminator='\n')
    writer.writerows(rows)
    return stream.getvalue().encode('utf-8')


def bind_fdes(fdes, index):
    by_start = {}
    for fde in fdes:
        by_start.setdefault(fde['start'], []).append(fde)
    by_entry = {}
    for row in index:
        by_entry.setdefault(row['start'], []).append(row['fde'])
    selected = {}
    for role, start, end, _ in FUNCTIONS:
        matches = by_start.get(start, [])
        if len(matches) != 1 or matches[0]['end'] != end or by_entry.get(start) != [matches[0]['fde']]:
            raise EvidenceError('unwind extent or index binding changed')
        selected[role] = matches[0]
    return selected


def extract(data):
    checked_digest(data)
    secs, index = unwind_index(data)
    _, fdes = eh_frame_records(data, secs)
    selected = bind_fdes(fdes, index)
    function_rows = [['role', 'start_va', 'end_va_exclusive', 'file_offset', 'fde_va', 'cie_va', 'lsda_va', 'size', 'sha256', 'raw_hex']]
    for role, start, end, digest in FUNCTIONS:
        body = get_bytes(data, secs, start, end - start)
        check_body(body, digest)
        f = selected[role]
        function_rows.append([role, hex(start), hex(end), hex(map_offset(secs, start, end-start, True)), hex(f['fde']), hex(f['cie']), '' if f['lsda'] is None else hex(f['lsda']), str(len(body)), digest, body.hex()])
    witness_rows = [['role', 'va', 'file_offset', 'size', 'bytes_hex']]
    for name, address, expected in WITNESSES:
        raw = get_bytes(data, secs, address, len(expected)//2)
        check_bytes(raw, expected)
        witness_rows.append([name, hex(address), hex(map_offset(secs, address, len(raw), True)), str(len(raw)), raw.hex()])
    branch_rows = [['role', 'va', 'bytes_hex', 'condition_code', 'target_va']]
    for name, address, expected in BRANCHES:
        raw = get_bytes(data, secs, address, len(expected)//2)
        check_bytes(raw, expected)
        cc, target = decode_branch(address, raw)
        map_offset(secs, target, 1, True)
        branch_rows.append([name, hex(address), raw.hex(), hex(cc), hex(target)])
    call_rows = [['role', 'va', 'bytes_hex', 'target_va']]
    for name, address, expected in CALLS:
        raw = get_bytes(data, secs, address, 5)
        check_bytes(raw, expected)
        target = decode_call(address, raw)
        map_offset(secs, target, 1, True)
        call_rows.append([name, hex(address), raw.hex(), hex(target)])
    slot_rows = [['role', 'va', 'bytes_hex', 'slot_va']]
    wanted = set()
    for name, address, expected in INDIRECT:
        raw = get_bytes(data, secs, address, len(expected)//2)
        check_bytes(raw, expected)
        slot = decode_rip(address, raw)
        map_offset(secs, slot, 8)
        wanted.add(slot)
        slot_rows.append([name, hex(address), raw.hex(), hex(slot)])
    rels = relocation_rows(data, secs, wanted)
    diag_rows = diagnostic_rows(data, secs)
    cap = get_bytes(data, secs, 0x42a1d46, 3)[2]
    lower = get_bytes(data, secs, 0x42a1ceb, 4)[3]
    if (cap, lower) != (12, 4):
        raise EvidenceError('threshold bytes changed')
    minimum = lower + 1
    constants = [
        ('node_key_base', 0x42a1c24, 8, 4, 4, 0x378),
        ('node_key_next', 0x42a1c4c, 8, 4, 4, 0x38c),
        ('node_count', 0x42a1c13, 8, 4, 4, 0x456),
        ('parent_pointer', 0x42a1cf1, 7, 3, 4, 0x370),
        ('parent_edge', 0x42a1d02, 8, 4, 4, 0x454),
        ('children_base', 0x42b605f, 8, 4, 4, 0x458),
        ('value_stride', 0x42a1cc8, 4, 3, 1, 0x50),
        ('leaf_release_size', 0x41d6511, 5, 1, 4, 0x458),
        ('internal_release_size', 0x41d65a8, 5, 1, 4, 0x4b8),
        ('underfull_maximum', 0x42a1ceb, 4, 3, 1, 4),
        ('exclusive_capacity', 0x42a1d46, 3, 2, 1, 12),
        ('borrow_target_count', 0x41d665d, 5, 1, 4, 5),
    ]
    constants_rows = [['role', 'va', 'instruction_hex', 'operand_offset', 'width', 'value_decimal']]
    for name, address, length, offset, width, expected in constants:
        raw = get_bytes(data, secs, address, length)
        value = int.from_bytes(raw[offset:offset+width], 'little')
        if value != expected:
            raise EvidenceError('instruction operand changed')
        constants_rows.append([name, hex(address), raw.hex(), str(offset), str(width), str(value)])
    cases = [['remaining', 'sibling', 'side', 'projected_action', 'reachable_valid_state_claimed']]
    for remaining in range(minimum):
        for sibling in range(cap):
            for side in ('left', 'right'):
                cases.append([str(remaining), str(sibling), side, repair_decision(remaining, sibling, side, minimum, cap), 'no'])
    structures = [['side', 'sibling_length', 'removed_position', 'input_json', 'projection_json']]
    for side in ('left', 'right'):
        for sibling_count in (minimum, minimum+1, minimum+2, cap-1):
            for pos in (0, 2, 4):
                if side == 'left':
                    sib = [(k, 1000+k) for k in range(sibling_count)]
                    sep = (sibling_count, 1000+sibling_count)
                    target = [(k, 1000+k) for k in range(sibling_count+1, sibling_count+1+minimum)]
                else:
                    target = [(k, 1000+k) for k in range(minimum)]
                    sep = (minimum, 1000+minimum)
                    sib = [(k, 1000+k) for k in range(minimum+1, minimum+1+sibling_count)]
                before = {'target':target, 'sibling':sib, 'separator':sep}
                after = project_leaf(target, sib, sep, pos, side, minimum, cap)
                structures.append([side, str(sibling_count), str(pos), json.dumps(before, separators=(',',':'), sort_keys=True),
                                   json.dumps(after, separators=(',',':'), sort_keys=True)])
    counters = [['before_u64', 'after_u64', 'reachable_valid_state_claimed']]
    for value in (0, 1, 2, (1 << 64) - 1):
        counters.append([str(value), str(project_header_decrement(value)), 'no'])
    summary = {'artifact_sha256': DIGEST, 'coordinate_system': 'linked ELF virtual address',
               'selected_fdes': len(FUNCTIONS), 'selected_body_bytes': sum(end-start for _,start,end,_ in FUNCTIONS),
               'witnesses': len(WITNESSES), 'conditional_branches': len(BRANCHES), 'direct_calls': len(CALLS),
               'indirect_sites': len(INDIRECT), 'relocation_slots': len(rels), 'diagnostics': len(DIAGNOSTICS), 'projection_rows': len(cases)-1, 'structural_projection_rows': len(structures)-1, 'two_level_examples': 1, 'counter_projection_rows': len(counters)-1, 'selected_constants': len(constants),
               'minimum_keys_inferred': minimum, 'merge_exclusive_limit': cap,
               'scope': 'six selected unwind extents and bounded call-site context; projections are synthetic'}
    return {'functions.tsv': table(function_rows), 'witnesses.tsv': table(witness_rows),
            'branches.tsv': table(branch_rows), 'calls.tsv': table(call_rows), 'constants.tsv': table(constants_rows),
            'indirect.tsv': table(slot_rows), 'diagnostics.tsv': table(diag_rows), 'relocations.tsv': table([['slot_va','type','symbol_index','symbol','addend']] + rels),
            'repair-cases.tsv': table(cases), 'header-count-cases.tsv': table(counters), 'structural-cases.tsv': table(structures),
            'two-level-case.json': (json.dumps(project_two_level(minimum, cap), indent=2, sort_keys=True)+'\n').encode(), 'summary.json': (json.dumps(summary, indent=2, sort_keys=True)+'\n').encode()}


def main():
    parser = argparse.ArgumentParser(description='Generate static node 94 user-map deletion evidence')
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    evidence = extract(BINARY.read_bytes())
    args.out.mkdir(parents=True, exist_ok=True)
    for name in sorted(evidence):
        (args.out / name).write_bytes(evidence[name])


if __name__ == '__main__':
    main()
