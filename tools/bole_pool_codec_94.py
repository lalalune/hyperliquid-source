#!/usr/bin/env python3
"""Extract the node #94 BolePool map codec from pinned ELF bytes, without execution."""
import argparse
import csv
import hashlib
import io
from pathlib import Path
import struct

from elf_index import sections
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
FUNCTIONS = [
    ('writer', 0x232ad20, 0x232b3d9, '3908afc53220f34f8a557a06dce8aaee0f4a951d9bbf327bf83a83e98d53a952'),
    ('map_reader', 0x198bad0, 0x19905b7, '96c82ef722a138aacccdc0daa6882ce8eca25e4b2c12fd63c53a3e9d4c3d7932'),
    ('key_classifier', 0x22e3620, 0x22e38a7, '97348aa4642d2c83d9f3cb46e2b8877600dc1984049def84ec2786b3038fe04f'),
    ('field_pmv', 0x23d5a60, 0x23d5af1, 'ca9808f12b66b67871ba8655da0f5eeb0c313559bcc52546c15b50bababc7e38'),
    ('field_r', 0x23d7290, 0x23d72ec, '7de022f2086dec77620617466592cde20f66585dd6fe6b6d21ba2f375efae183'),
    ('field_b', 0x23d8b30, 0x23d8b8c, '0f41ae32611cdd952f35cc03fc414134f7c7e05fe9ad85df41afd0f91eb430d9'),
    ('field_uobc', 0x23d7660, 0x23d76bc, 'f7a6ee4c0c1670f1177b28845618a88c6d801a48c3a415c03bcd3e32cf6c7bd9'),
    ('field_u', 0x23d8bf0, 0x23d8c4c, 'c550e4dabd4dd83d63eea9b8d05d768542ce185b5a0d323328baff6d8e3d0a12'),
    ('bool_field', 0x23d49a0, 0x23d4abd, '85652d2e8d36204df40e5893c419cb918292d3c0627be2c699addf00654dba1b'),
    ('signed_field', 0x23d7b30, 0x23d7bb5, '05532be600099453e9f1833e30117776e100c6616ce2195749630ab58c2a9aa2'),
    ('float_field', 0x23d9250, 0x23d92c8, 'b8e5cdf6874f53785a37d3898f107684a3ccd11a0726fea53f34f6c195c8bc49'),
    ('nested_option_field', 0x23d97c0, 0x23d9816, '2fe272ffa0552d3fb883726efb10bd5a54b71a6d1beca8e8f450fbb201a0e8dd'),
    ('unsigned_field', 0x23d3710, 0x23d3795, '5452edbe9841d9aeb4f9daa64981d67b6aef7b69844805dedcde3c06b68ea80d'),
    ('u_collection_wrapper', 0x25e20f0, 0x25e21b9, '867643f66018a3e27e9a7f7e6d43c3374ed4a242529302d6d7d7a1623de8c2ed'),
    ('u_pair_collector', 0x2567ed0, 0x25681d0, '6541dba97384b8f783d3e393e1886353e45e228b21d2776194b80bf183bf3fe9'),
    ('u_list_writer', 0x1e490a0, 0x1e4932b, '5c53e97ff02a81e85d83c70b3a8b637daeb63eaff249a9de58bc199ff852c570'),
    ('u_pair_writer', 0x1de2330, 0x1de28cc, '8daf76896ae2d95ad11f545274cccc306974dbb9bdbc5a8242571b9bb296c69b'),
    ('u_key_writer_b', 0x1e0d0a0, 0x1e0d205, 'a202a759a0a5e43cfc7b1a4a6733a47b15471f87c5f2da3f3b2822d700289361'),
    ('u_key_writer_a', 0x1e0d6c0, 0x1e0d825, 'bf4abe873a69aa8b81d345b2ccdecb4c7ee611eb3dd0a55d5d77b5b955fd4279'),
    ('u_value_writer_a', 0x28d3ab0, 0x28d3d21, '64ec8e9e48152b9ee6f0532d5194f294b6aafacd8291caa34eb7f29d74919e81'),
    ('u_value_writer_b', 0x28d3d30, 0x28d3efc, 'cbe57c2f0448420a51976cacc4eaba4270e320adb6c8ec8959a8a33ff9c68800'),
    ('field_error_constructor', 0x1704040, 0x17040e8, 'ad5042017db16f416d08dc6c2f7ce60c5454ba2d10545823bd195da7f93859ca'),
]
# Each row is an exact RIP-relative key LEA and its immediate length instruction.
# Helper calls are encoded separately so the names in helpers are tied to writer order.
KEY_SITES = [
    (0x232adaa, 0x232adb1, None), (0x232ae1d, 0x232ae24, None),
    (0x232ae87, 0x232ae8e, None), (0x232aef0, 0x232aef7, None),
    (0x232af3b, 0x232af42, None), (0x232af8a, 0x232af96, None),
    (0x23d5a7e, 0x23d5a88, 0x232afbd), (0x232afd4, 0x232afe0, None),
    (0x23d72a1, 0x23d72a8, 0x232b007), (0x232b020, 0x232b02c, None),
    (0x232b04d, 0x232b059, None), (0x23d8b41, 0x23d8b48, 0x232b07c),
    (0x232b090, 0x232b09c, None), (0x232b0b8, 0x232b0c4, None),
    (0x232b0e0, 0x232b0ec, None), (0x23d7671, 0x23d7678, 0x232b118),
    (0x232b131, 0x232b13d, None), (0x232b161, 0x232b16d, None),
    (0x232b191, 0x232b19d, None), (0x232b1bd, 0x232b1c9, None),
    (0x23d8c01, 0x23d8c08, 0x232b1f1),
]
# Object offset instruction: address, literal opcode prefix, displacement length.
VALUE_SITES = [
    (0x232ad9a, '450fb6b424', 4), (0x232ae0e, '440fb6b0', 4),
    (0x232ae78, '440fb6b0', 4), (0x232aee2, '4d8ba5', 4),
    (0x232af2d, '4d8ba5', 4), (0x232af82, '450fb685', 4),
    (0x232afae, '498b95', 4), (0x232afcd, '4d8b85', 4),
    (0x232aff8, '498d95', 4), (0x232b017, 'f2410f1085', 4),
    (0x232b044, 'f2410f1085', 4), (0x232b079, '4c89ea', 0),
    (0x232b08c, '4d8d45', 1), (0x232b0b4, '4d8d45', 1),
    (0x232b0dc, '4d8d45', 1), (0x232b109, '488d90', 4),
    (0x232b12d, '4c8d40', 1), (0x232b15a, '4c8d80', 4),
    (0x232b18a, '448b80', 4), (0x232b1b6, '4c8b80', 4),
    (0x232b1e2, '4881c2', 4),
]
VALUE_CALLS = [0x232adea, 0x232ae58, 0x232aec2, 0x232af19, 0x232af64,
               0x232af9e, 0x232afbd, 0x232afe8, 0x232b007, 0x232b034,
               0x232b061, 0x232b07c, 0x232b0a4, 0x232b0cc, 0x232b0f4,
               0x232b118, 0x232b145, 0x232b175, 0x232b1a5, 0x232b1d1, 0x232b1f1]
MISSING_GUARDS = [
    (0x198c0b8, 0x198de8b, 'f68424c800000001', 0x198de93, 0x198ded8, 'zero'),
    (0x198dee8, 0x198debb, 'f684242804000001', 0x198dec3, 0x198dee5, 'zero'),
    (0x198df69, 0x198dec5, 'f68424e002000001', 0x198decd, 0x198df66, 'zero'),
    (0x198dff3, 0x198dfdd, '83bc246004000002', 0x198dfe5, 0x198e0f3, 'equal_2'),
    (0x198e266, 0x198e25c, 'f68424f004000001', 0x198e264, 0x198e2de, 'zero'),
    (0x198e2ec, 0x198e2de, 'f684248000000001', 0x198e2e6, 0x198e376, 'zero'),
]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def check_digest(data, expected=SHA256):
    require(hashlib.sha256(data).hexdigest() == expected, 'input SHA-256 mismatch')


class View:
    def __init__(self, data):
        self.data = data
        self.sections = sections(data)

    def offset(self, va, size=1, executable=False):
        require(isinstance(va, int) and isinstance(size, int) and va >= 0 and size > 0,
                'invalid VA or size')
        candidates = [s for s in self.sections if s['type'] != 8
                      and (not executable or s['flags'] & 4)
                      and s['address'] <= va and va + size <= s['address'] + s['size']]
        require(len(candidates) == 1, 'VA has no unique file-backed section')
        s = candidates[0]
        return s['offset'] + va - s['address']

    def get(self, va, size, executable=False):
        offset = self.offset(va, size, executable)
        return self.data[offset:offset + size]

    def expect(self, va, pattern):
        require(self.get(va, len(pattern)) == pattern, f'unexpected instruction at {va:#x}')

    def rel32(self, va, prefix):
        self.expect(va, prefix)
        raw = self.get(va + len(prefix), 4)
        return va + len(prefix) + 4 + struct.unpack('<i', raw)[0]

    def jump(self, va):
        op = self.get(va, 2)
        if op in (b'\x0f\x84', b'\x0f\x85'):
            return op[1], self.rel32(va, op)
        require(op[0] in (0x74, 0x75), f'unexpected conditional branch at {va:#x}')
        return op[0], va + 2 + struct.unpack('<b', op[1:])[0]

    def table(self, va, count):
        return [va + struct.unpack('<i', self.get(va + i * 4, 4))[0] for i in range(count)]


def return_index(view, va):
    code = view.get(va, 9, True)
    if code[:2] == b'\x31\xc9':
        result = 0
    else:
        require(code[0] == 0xb1, 'unexpected classifier return')
        result = code[1]
    require(code[2:] == b'\x88\x48\x01\xc6\x00\x09\xc3', 'unexpected classifier return tail')
    return result


def classifier(view):
    """Decode the finite comparison constants and the two jump tables."""
    view.expect(0x22e3623, bytes.fromhex('48ffca4883fa0c'))
    require(view.rel32(0x22e3630, b'\x48\x8d\x0d') == 0x3d9018, 'length table reference')
    require(view.rel32(0x22e364f, b'\x48\x8d\x15') == 0x3d904c, 'single-byte table reference')
    unknown = return_index(view, 0x22e3817)
    require(unknown == 21, 'unknown tag')
    expected_lengths = [0x22e3640, 0x22e367b, 0x22e36fb, 0x22e37af,
                        0x22e3817, 0x22e3817, 0x22e3804, 0x22e365f,
                        0x22e3817, 0x22e3817, 0x22e3817, 0x22e36a5, 0x22e36ce]
    require(view.table(0x3d9018, 13) == expected_lengths, 'length dispatch table mismatch')
    result = []
    def add(name, site, ret):
        require(name and all(0x20 <= b < 0x7f for b in name), 'invalid key constant')
        idx = return_index(view, ret)
        require(idx < unknown, 'unknown branch masquerades as a key')
        result.append((name.decode('ascii'), idx, site, ret))
    view.expect(0x22e3643, bytes.fromhex('83c19e83f913'))
    for n, target in enumerate(view.table(0x3d904c, 20)):
        if return_index(view, target) != unknown:
            add(bytes([ord('b') + n]), 0x3d904c + 4*n, target)
    for site in (0x22e367b, 0x22e3686, 0x22e3691):
        view.expect(site, b'\x66\x81\x3e')
        name = view.get(site + 3, 2)
        cond, target = view.jump(site + 5)
        if cond == 0x85:  # JNE unknown; fallthrough is successful.
            require(target == 0x22e3817, 'two-byte mismatch branch')
            target = site + 11
        else:
            require(cond == 0x84, 'two-byte equality branch')
        add(name, site, target)
    for site in (0x22e36fb, 0x22e3714, 0x22e372d, 0x22e3746, 0x22e375f, 0x22e3778, 0x22e3791):
        view.expect(site, bytes.fromhex('0fb70e81f1'))
        name = view.get(site + 5, 2)
        view.expect(site + 7, bytes.fromhex('00000fb6560283f2'))
        name += view.get(site + 15, 1)
        view.expect(site + 16, bytes.fromhex('6609ca'))
        cond, target = view.jump(site + 19)
        if cond == 0x75:
            require(target == 0x22e3817, 'three-byte mismatch branch')
            target = site + 21
        else:
            require(cond == 0x84, 'three-byte equality branch')
        add(name, site, target)
    for site in (0x22e37af, 0x22e37b7, 0x22e37c3, 0x22e37cf, 0x22e37db, 0x22e37e7, 0x22e37f3):
        view.expect(site, b'\x81\x3e')
        name = view.get(site + 2, 4)
        cond, target = view.jump(site + 6)
        if cond == 0x75:
            require(target == 0x22e3817, 'four-byte mismatch branch')
            target = site + 8
        else:
            require(cond in (0x74, 0x84), 'four-byte equality branch')
        add(name, site, target)
    view.expect(0x22e365f, b'\x48\xb9')
    add(view.get(0x22e3661, 8), 0x22e365f, 0x22e3672)
    view.expect(0x22e36a5, b'\x48\xb9')
    view.expect(0x22e36b5, b'\x48\x81\xf2')
    add(view.get(0x22e36a7, 8) + view.get(0x22e36b8, 4), 0x22e36a5, 0x22e36c5)
    view.expect(0x22e36ce, b'\x48\xb9')
    view.expect(0x22e36db, b'\x48\xba')
    first, second = view.get(0x22e36d0, 8), view.get(0x22e36dd, 8)
    require(first[5:] == second[:3], 'thirteen-byte overlap mismatch')
    add(first[:5] + second, 0x22e36ce, 0x22e36f2)
    view.expect(0x22e3804, b'\xb9')
    view.expect(0x22e380b, b'\xba')
    first, second = view.get(0x22e3805, 4), view.get(0x22e380c, 4)
    require(first[3:] == second[:1], 'seven-byte overlap mismatch')
    add(first[:3] + second, 0x22e3804, 0x22e3820)
    require(len(result) == 28 and len({x[0] for x in result}) == 28, 'key count or uniqueness')
    require({x[1] for x in result} == set(range(21)), 'classifier field IDs incomplete')
    return sorted(result, key=lambda x: (x[1], x[0]))


def key_instruction(view, site, len_site):
    prefix = view.get(site, 3, True)
    require(prefix in (b'\x48\x8d\x05', b'\x48\x8d\x15', b'\x48\x8d\x35'), 'key LEA form')
    literal = view.rel32(site, prefix)
    op = view.get(len_site, 5, True)
    require(op[0] in (0xb9, 0xba), 'key length instruction')
    size = struct.unpack('<I', op[1:])[0]
    require(1 <= size <= 13, 'key length outside expected range')
    return view.get(literal, size).decode('ascii'), literal


def guard(view, case):
    code = view.get(case, 16, True)
    if code[:3] == b'\x80\x7c\x24':
        comparison, branch = code[:5], case + 5
        location, sentinel = f'rsp+{code[3]:#x}/byte', code[4]
    elif code[:4] == b'\x48\x83\xbc\x24':
        comparison, branch = code[:9], case + 9
        location, sentinel = f'rsp+{struct.unpack("<I", code[4:8])[0]:#x}/qword', code[8]
    elif code[:3] == b'\x83\xbc\x24':
        comparison, branch = code[:8], case + 8
        location, sentinel = f'rsp+{struct.unpack("<I", code[3:7])[0]:#x}/dword', code[7]
    else:
        require(code[:3] == b'\x4d\x85\xe4', 'unrecognized duplicate guard')
        comparison, branch = code[:3], case + 3
        location, sentinel = 'r12/test', 0
    condition, diagnostic = view.jump(branch)
    require(condition in (0x84, 0x85), 'duplicate guard is not near je/jne')
    return comparison, location, sentinel, 'equal' if condition == 0x84 else 'not_equal', diagnostic


def unique_direct_call(view, site, size, target):
    """Find a unique near-call encoding to a known target in a bounded byte window."""
    raw = view.get(site, size, True)
    matches = [site + i for i in range(len(raw) - 4) if raw[i] == 0xe8 and
               site + i + 5 + struct.unpack_from('<i', raw, i + 1)[0] == target]
    require(len(matches) == 1, 'diagnostic constructor call is not unique')
    return matches[0]


def nested_omits_o(view, word0, word8, wordc, word10, reference):
    """Static model of the value-B predicate, conditional on one nonzero helper result."""
    view.expect(0x28d3d5c, bytes.fromhex(
        '4d8b274d85e40f94c1418b6f0839c50f94c0458b6f0c4585ed0f94c220ca20c2'
        '418b5f1085db0f94c020d00fb6c0ba0200000029c2'))
    view.expect(0x28d3dff, bytes.fromhex(
        '85db0f94c14585ed0f94c24d85e4400f94c649bc0000000000000080'
        '39c50f94c04020d64020c64084ce753d'))
    require(0 <= word0 < 1 << 64 and all(0 <= x < 1 << 32
            for x in (word8, wordc, word10, reference)) and reference != 0,
            'predicate inputs outside observed unsigned widths or zero helper result')
    return word0 == 0 and word8 == reference and wordc == 0 and word10 == 0


def tsv(header, rows):
    buf = io.StringIO(newline='')
    writer = csv.writer(buf, delimiter='\t', lineterminator='\n')
    writer.writerow(header)
    writer.writerows(rows)
    return buf.getvalue().encode('utf-8')


def extract(data):
    check_digest(data)
    view = View(data)
    _, fdes = eh_frame_records(data, view.sections)
    by_start = {}
    for fde in fdes:
        by_start.setdefault(fde['start'], []).append(fde)
    funcs = []
    for name, start, end, digest in FUNCTIONS:
        found = by_start.get(start, [])
        require(len(found) == 1 and found[0]['end'] == end, f'FDE extent mismatch for {name}')
        body = view.get(start, end - start, True)
        check_digest(body, digest)
        funcs.append((name, hex(start), hex(end), hex(found[0]['fde']), hex(view.offset(start)), len(body), digest))
    # The reader passes a relocated two-word type description to an error helper.
    type_slot = view.rel32(0x198cb53, b'\x48\x8d\x15')
    require(type_slot == 0x5685cc8, 'type description reference')
    relas = [s for s in view.sections if s['name'] == '.rela.dyn' and s['type'] == 4]
    require(len(relas) == 1 and relas[0]['size'] % 24 == 0, 'unsupported RELA section')
    rela = relas[0]
    wanted_slots = {type_slot, 0x5773120, 0x576e890, 0x57727a0, 0x5770e28}
    matches = {slot: [] for slot in wanted_slots}
    for pos in range(rela['offset'], rela['offset'] + rela['size'], 24):
        target, info, addend = struct.unpack_from('<QQq', data, pos)
        if target in matches:
            matches[target].append((pos, info, addend))
    require(all(len(match) == 1 and match[0][1] == 8 for match in matches.values()),
            'reference is not unique R_X86_64_RELATIVE')
    reloc_offset, _, type_text = matches[type_slot][0]
    type_size = struct.unpack('<Q', view.get(type_slot + 8, 8))[0]
    identity = view.get(type_text, type_size)
    require(identity == b'struct BolePool with 21 elements', 'reader type description mismatch')
    names = classifier(view)
    by_key = {name: idx for name, idx, _, _ in names}
    view.expect(0x232ad37, bytes.fromhex('807a0b007440'))
    view.expect(0x232ad45, bytes.fromhex('ba15000000'))
    view.expect(0x232ad85, bytes.fromhex('ba15000000'))
    view.expect(0x198ee84, b'\xe8')
    require(view.rel32(0x198ee84, b'\xe8') == 0x22e3620, 'reader classifier call')
    require(view.rel32(0x198f087, b'\x48\x8d\x0d') == 0x36fa5c, 'reader jump table reference')
    cases = view.table(0x36fa5c, 22)
    require(all(0x198bad0 <= c < 0x19905b7 for c in cases), 'reader case outside FDE extent')
    rows, by_idx = [], {}
    for ordinal, ((site, len_site, call), (value_site, op_hex, disp_size)) in enumerate(zip(KEY_SITES, VALUE_SITES)):
        name, literal = key_instruction(view, site, len_site)
        require(name in by_key and by_key[name] == ordinal, 'writer order and classifier ID mismatch')
        prefix = bytes.fromhex(op_hex)
        view.expect(value_site, prefix)
        disp = int.from_bytes(view.get(value_site + len(prefix), disp_size), 'little') if disp_size else 0
        if call is not None:
            callee = view.rel32(call, b'\xe8')
            require(any(start == callee and start <= site < end for _, start, end, _ in FUNCTIONS), 'name helper call mismatch')
        else:
            callee = None
        comparison, location, sentinel, when, diagnostic = guard(view, cases[ordinal])
        require(0x198bad0 <= diagnostic < 0x19905b7, 'duplicate diagnostic outside reader')
        # At the taken branch the target points to a compact key followed by the duplicate-field literal.
        target = view.rel32(diagnostic, b'\x48\x8d\x05')
        require(view.get(target, len(name)) == name.encode(), 'duplicate diagnostic names different field')
        tail = view.get(diagnostic, min(100, 0x19905b7 - diagnostic), True)
        require(b'duplicate field' in view.data, 'missing error string')
        # The machine code references the same retained duplicate literal, not an inferred error label.
        duplicate_refs = []
        for i in range(len(tail) - 7):
            if tail[i:i+3] in (b'\x48\x8d\x05', b'\x48\x8d\x0d', b'\x48\x8d\x15', b'\x48\x8d\x35'):
                addr = diagnostic + i + 7 + struct.unpack('<i', tail[i+3:i+7])[0]
                try:
                    if view.get(addr, len(b'\x11duplicate field')) == b'\x11duplicate field':
                        duplicate_refs.append(addr)
                except ValueError:
                    pass
        require(duplicate_refs, f'no duplicate field reference for {name}')
        error_call = unique_direct_call(view, diagnostic, len(tail), 0x1704040)
        by_idx[ordinal] = name
        rows.append((ordinal, name, hex(site), hex(literal), hex(view.offset(literal)),
                     hex(value_site), hex(disp), prefix.hex(), hex(call) if call else '-',
                     hex(callee) if callee else '-', hex(VALUE_CALLS[ordinal]),
                     hex(view.rel32(VALUE_CALLS[ordinal], b'\xe8')), hex(cases[ordinal]), comparison.hex(), location,
                     sentinel, when, hex(diagnostic), hex(duplicate_refs[0]), hex(error_call)))
    require(len(rows) == 21, 'field count')
    view.expect(0x17040c9, bytes.fromhex('c60306'))
    aliases = [(name, idx, by_idx[idx], hex(site), hex(view.offset(site)),
                view.get(site, 4 if site < 0x1000000 else 12).hex(), hex(ret))
               for name, idx, site, ret in names]
    # These windows are the map-finalization instructions. Register reuse matters:
    # the pair-field windows below reuse the values established in the pml window.
    windows = [
        (0x198de2b, 'f68424e80200000141bf0a0000004c0f45bc2440050000'),
        (0x198de42, 'f68424f00200000141bca08601004c0f45a42448050000'),
        (0x198de59, '31c0f68424f802000001488b8c24e0040000480f44c848898c24e0040000f68424a002000001488b8c24d8040000480f44c8'),
        (0x198e154, '488b8424e80400004885c0b9005c2605480f45c848898c2488000000b850c30000488b8c24c8040000480f44c848898c24c8040000'),
        (0x198e189, '488b8424880200004885c041bd60ea0000490f44c54889842488020000bd0a000000488b8424d0040000480f44c548898424d0040000'),
        (0x198e201, '488b8424900200004885c0490f44c54889842490020000b864000000488b8c24b8040000480f44c848898c24b8040000'),
        (0x198e231, '488b8424980200004885c0490f44c54889842498020000488b8424c0040000480f44c548898424c0040000'),
    ]
    for start, expected_hex in windows:
        view.expect(start, bytes.fromhex(expected_hex))
    def imm32(site, prefix):
        view.expect(site, prefix)
        return struct.unpack('<I', view.get(site + len(prefix), 4))[0]
    ten = imm32(0x198e1a6, b'\xbd')
    sixty_thousand = imm32(0x198e194, b'\x41\xbd')
    defaults = [
        ('pmmt', 'scalar', imm32(0x198de33, b'\x41\xbf'), '-', 0x198de2b, 23),
        ('pmmu', 'scalar', imm32(0x198de4a, b'\x41\xbc'), '-', 0x198de42, 23),
        ('pmv', 'scalar', 0, '-', 0x198de59, 30),
        ('pma', 'scalar', 0, '-', 0x198de59, 50),
        ('pmdl', 'two decoded words', imm32(0x198e15f, b'\xb9'), imm32(0x198e170, b'\xb8'), 0x198e154, 53),
        ('pml', 'two decoded words', sixty_thousand, ten, 0x198e189, 54),
        ('ubgl', 'two decoded words', sixty_thousand, imm32(0x198e218, b'\xb8'), 0x198e201, 48),
        ('ubul', 'two decoded words', sixty_thousand, ten, 0x198e231, 43),
    ]
    # Boolean presence uses sentinel 2; successful map finalization masks bit 0.
    # The dp sentinel starts in bpl, while the remaining four are stored directly.
    view.expect(0x198bf66, bytes.fromhex('c644246802c644241c02c644247802c64424700240b502'))
    for name, start, opcode in [('dp', 0x198e63a, '0fb64424102401'),
                                ('du', 0x198e648, '0fb64424702401'),
                                ('o', 0x198e656, '0fb64424782401'),
                                ('e', 0x198e664, '0fb644241c2401'),
                                ('bwo', 0x198e66b, '0fb64c246880e101')]:
        blob = bytes.fromhex(opcode)
        view.expect(start, blob)
        sentinel = guard(view, cases[by_key[name]])[2]
        require(sentinel == 2 and blob[-1] == 1, 'boolean absent sentinel or mask')
        defaults.append((name, 'boolean', sentinel & blob[-1], '-', start, len(blob)))
    view.expect(0x198e133, bytes.fromhex('4883bc2480020000007516ff155c46de03'))
    view.expect(0x198e1bf, bytes.fromhex('83bc24b0000000007538488dbc2400010000ff15512cde03'))
    defaults.extend([('bog', 'helper-dependent', '-', '-', 0x198e133, 17),
                     ('uobc', 'helper-dependent', '-', '-', 0x198e1bf, 24)])
    default_rows = [(name, by_key[name], shape, first, second, hex(start), hex(view.offset(start)),
                     view.get(start, size, True).hex())
                    for name, shape, first, second, start, size in sorted(defaults, key=lambda row: by_key[row[0]])]
    missing = []
    for site, guard_site, guard_hex, branch, expected_target, absent in MISSING_GUARDS:
        view.expect(guard_site, bytes.fromhex(guard_hex))
        cond, target = view.jump(branch)
        require(target == expected_target, 'missing-field branch target')
        literal = view.rel32(site, b'\x48\x8d\x05')
        tail = view.get(site, 100, True)
        view.expect(site + 15, bytes.fromhex('48c78424'))
        size = struct.unpack('<I', view.get(site + 23, 4))[0]
        require(1 <= size <= 13, 'missing diagnostic key length')
        name = view.get(literal, size).decode('ascii')
        require(name in by_key, 'missing diagnostic key')
        error = []
        for i in range(len(tail) - 7):
            if tail[i:i+3] in (b'\x48\x8d\x05', b'\x48\x8d\x0d', b'\x48\x8d\x15', b'\x48\x8d\x35'):
                addr = site + i + 7 + struct.unpack('<i', tail[i+3:i+7])[0]
                try:
                    if view.get(addr, len(b'\x0fmissing field')) == b'\x0fmissing field':
                        error.append(addr)
                except ValueError:
                    pass
        require(error, f'no missing field reference for {name}')
        error_call = unique_direct_call(view, site, len(tail), 0x1704040)
        missing.append((name, by_key[name], hex(guard_site), guard_hex, hex(branch), hex(cond),
                        hex(target), absent, hex(site), hex(literal), hex(error[0]), hex(error_call)))
    unknown_case = cases[21]
    view.expect(unknown_case, bytes.fromhex('488dbc24000100004c89f6ba01000000'))
    view.expect(unknown_case + 16, b'\xe8')
    # Exact instructions selected to preserve the cross-function edge, headers and error path.
    anchors = [(label, hex(va), hex(view.offset(va)), view.get(va, n, True).hex()) for label, va, n in [
        ('writer_header_mode_and_count', 0x232ad37, 24), ('writer_header_other_count', 0x232ad7d, 18),
        ('writer_failure_result', 0x232b20f, 17), ('reader_classifier_call', 0x198ee84, 5),
        ('reader_field_dispatch', 0x198f087, 16), ('unknown_field_case', unknown_case, 39),
        ('u_collection_nonempty_test', 0x25e20ff, 8),
        ('u_pair_allocation_size', 0x2567ed8, 42),
        ('u_collector_pair_addresses', 0x2567f7a, 42),
        ('u_pair_loop_and_failure', 0x1e49280, 42),
        ('u_pair_two_item_header', 0x1de2397, 10),
        ('u_pair_immediate_marker', 0x1de2432, 20),
        ('u_key_b_format_arguments', 0x1e0d18b, 23),
        ('u_key_a_format_arguments', 0x1e0d7ab, 23),
        ('u_value_b_omit_o_predicate', 0x28d3d5c, 53),
        ('u_value_b_omit_o_branch', 0x28d3dff, 44),
        ('u_value_a_omit_o_predicate', 0x28d3adc, 53),
        ('field_error_return_tag', 0x17040c9, 17)]]
    edge_sites = [('nonzero_header', 0x232ad4a, b'\xe8'),
                  ('zero_header', 0x232ad8a, b'\xe8'),
                  ('reader_classifier', 0x198ee84, b'\xe8'),
                  ('unknown_value', unknown_case + 16, b'\xe8'),
                  ('pmv_value', 0x23d5aaf, b'\xe8'),
                  ('pma_value', 0x23d7b73, b'\xe8'),
                  ('float_value', 0x23d9292, b'\xe8'),
                  ('mbs_value', 0x23d3753, b'\xe8'),
                  ('r_nested_tail', 0x23d72cc, b'\xe9'),
                  ('b_nested_tail', 0x23d8b6c, b'\xe9'),
                  ('uobc_nested_tail', 0x23d769c, b'\xe9'),
                  ('u_nested_tail', 0x23d8c2c, b'\xe9'),
                  ('u_collect_pairs', 0x25e215a, b'\xe8'),
                  ('u_write_pairs', 0x25e2168, b'\xe8'),
                  ('u_list_header', 0x1e49107, b'\xe8'),
                  ('u_first_pair', 0x1e4915f, b'\xe8'),
                  ('u_loop_pair', 0x1e4928e, b'\xe8'),
                  ('u_pair_header', 0x1de239c, b'\xe8'),
                  ('u_pair_first_component_b', 0x1de23f5, b'\xe8'),
                  ('u_pair_first_component_a', 0x1de2474, b'\xe8'),
                  ('u_pair_second_component_a', 0x1de25e6, b'\xe8'),
                  ('u_pair_second_component_b', 0x1de26c0, b'\xe8'),
                  ('u_value_b_optional_o', 0x28d3e57, b'\xe8'),
                  ('u_value_b_required_t', 0x28d3e98, b'\xe8'),
                  ('u_value_a_optional_o', 0x28d3bf4, b'\xe8'),
                  ('u_value_a_required_t', 0x28d3c41, b'\xe8')]
    edges = [(label, hex(site), hex(view.offset(site)), view.get(site, 5, True).hex(),
              hex(view.rel32(site, op))) for label, site, op in edge_sites]
    nested_omits_o(view, 0, 1, 0, 0, 1)  # Validate both predicate instruction windows.
    nested_fields = []
    for index, (site, length_site, value_call, offset, presence) in enumerate([
            (0x28d3e32, 0x28d3e39, 0x28d3e57, 0, 'conditional'),
            (0x28d3e6f, 0x28d3e76, 0x28d3e98, 0x18, 'unconditional')]):
        name, literal = key_instruction(view, site, length_site)
        nested_fields.append((index, name, presence, hex(offset), hex(site), hex(literal),
                              hex(view.offset(literal)), hex(value_call), hex(view.rel32(value_call, b'\xe8'))))
    require([x[1] for x in nested_fields] == ['o', 't'], 'nested user-state keys')
    view.expect(0x28d3e89, bytes.fromhex('4983c718'))
    dispatch = []
    for kind, base, count in [('key_length', 0x3d9018, 13), ('single_byte_key', 0x3d904c, 20),
                              ('reader_field', 0x36fa5c, 22)]:
        targets = view.table(base, count)
        for index, target in enumerate(targets):
            slot = base + index * 4
            selector = (str(index + 1) if kind == 'key_length' else
                        chr(ord('b') + index) if kind == 'single_byte_key' else str(index))
            outcome = return_index(view, target) if kind == 'single_byte_key' else '-'
            dispatch.append((kind, selector, hex(base), hex(slot), hex(view.offset(slot)),
                             view.get(slot, 4).hex(), hex(target), outcome))
    indirect = []
    for label, site in [('u_key_b_format', 0x1e0d198), ('u_key_a_format', 0x1e0d7b8),
                        ('u_value_b_predicate_first', 0x28d3d4e), ('u_value_b_predicate_second', 0x28d3df1),
                        ('u_value_a_predicate_first', 0x28d3ace), ('u_value_a_predicate_second', 0x28d3b75),
                        ('missing_bog_default', 0x198e13e), ('missing_uobc_default', 0x198e1d1)]:
        slot = view.rel32(site, b'\xff\x15')
        require(slot in matches, 'unexpected indirect call slot')
        rela_off, _, target = matches[slot][0]
        indirect.append((label, hex(site), view.get(site, 6, True).hex(), hex(slot), hex(view.offset(slot)),
                         hex(rela_off), 'R_X86_64_RELATIVE', hex(target)))
    return {
        'functions.tsv': tsv(['role','start_va','end_exclusive_va','fde_va','file_offset','size','body_sha256'], funcs),
        'fields.tsv': tsv(['ordinal','writer_key','key_lea_va','key_literal_va','key_literal_file_offset','object_access_va','object_offset','access_opcode','name_helper_call_va','name_helper_va','value_call_va','value_callee_va','reader_case_va','guard_bytes','guard_location','sentinel','duplicate_when','duplicate_target_va','duplicate_literal_va','error_constructor_call_va'], rows),
        'accepted-keys.tsv': tsv(['accepted_key','field_index','writer_key','comparison_va','file_offset','comparison_bytes','return_va'], aliases),
        'missing-fields.tsv': tsv(['field','field_index','guard_va','guard_bytes','branch_va','branch_opcode','branch_target_va','missing_condition','diagnostic_va','field_literal_va','missing_literal_va','error_constructor_call_va'], missing),
        'default-branches.tsv': tsv(['field','field_index','representation','first_word','second_word','window_va','file_offset','window_bytes'], default_rows),
        'anchors.tsv': tsv(['observation','va','file_offset','bytes_hex'], anchors),
        'edges.tsv': tsv(['role','site_va','file_offset','instruction_bytes','target_va'], edges),
        'indirect-edges.tsv': tsv(['role','site_va','instruction_bytes','slot_va','slot_file_offset',
                                  'rela_file_offset','relocation_type','target_va'], indirect),
        'dispatch-tables.tsv': tsv(['table','selector','table_va','slot_va','slot_file_offset',
                                    'signed_rel32_bytes','target_va','classifier_index'], dispatch),
        'nested-fields.tsv': tsv(['ordinal','key','presence','object_offset','key_lea_va','literal_va',
                                  'literal_file_offset','value_call_va','value_callee_va'], nested_fields),
        'type-record.tsv': tsv(['reader_lea_va','slot_va','slot_file_offset','rela_file_offset',
                                'relocation_type','literal_va','literal_file_offset','literal_length','literal'],
                               [(hex(0x198cb53), hex(type_slot), hex(view.offset(type_slot)), hex(reloc_offset),
                                 'R_X86_64_RELATIVE', hex(type_text), hex(view.offset(type_text)), type_size,
                                 identity.decode('ascii'))]),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    outputs = extract(TARGET.read_bytes())
    args.out.mkdir(parents=True, exist_ok=True)
    for name, contents in sorted(outputs.items()):
        (args.out / name).write_bytes(contents)
    print(f'wrote {len(outputs)} deterministic evidence files')


if __name__ == '__main__':
    main()
