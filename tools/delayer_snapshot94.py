#!/usr/bin/env python3
"""Extract bounded node-94 ActionDelayer codec evidence from authenticated ELF bytes."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections
from fde_extents import eh_frame_records

SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
BINARY = ROOT / 'artifacts/node/94/hl-node'

# Starts are investigation seeds, not inferred from the next unwind index row.
STARTS = (0x16fde80, 0x1767dd0, 0x22ecd20, 0x22ed250, 0x2311e90, 0x23d8e00,
          0x23d9170, 0x23d9250)


def require(condition, message):
    if not condition:
        raise ValueError(message)


class Image:
    def __init__(self, data):
        require(hashlib.sha256(data).hexdigest() == SHA256, 'wrong target SHA-256')
        self.data = data
        self.sections = sections(data)
        _, fdes = eh_frame_records(data, self.sections)
        self.fdes = {}
        for start in STARTS:
            rows = [f for f in fdes if f['start'] == start]
            require(len(rows) == 1, 'missing or duplicate selected FDE')
            row = rows[0]
            require(row['end'] > start, 'empty FDE')
            s, _ = self.locate(start, row['end'] - start)
            require(s['name'] == '.text' and s['flags'] & 4, 'FDE outside file-backed executable section')
            self.fdes[start] = row

    def locate(self, va, size):
        require(isinstance(va, int) and isinstance(size, int) and va >= 0 and size > 0,
                'invalid virtual range')
        require(va + size <= 1 << 64, 'virtual range overflow')
        rows = [s for s in self.sections if s['type'] != 8 and s['flags'] & 2 and
                s['address'] <= va and va + size <= s['address'] + s['size']]
        require(len(rows) == 1, 'virtual range is not uniquely file-backed')
        s = rows[0]
        off = s['offset'] + va - s['address']
        require(off + size <= len(self.data), 'file range outside image')
        return s, off

    def read(self, va, size):
        _, off = self.locate(va, size)
        return self.data[off:off + size]

    def offset(self, va, size=1):
        return self.locate(va, size)[1]

    def code(self, start):
        row = self.fdes[start]
        return self.read(start, row['end'] - start)


def branch(code, base, va):
    """Decode only selected direct conditional or unconditional branch forms."""
    i = va - base
    require(0 <= i < len(code), 'branch outside selected FDE')
    if code[i:i + 2] in (b'\x0f\x84', b'\x0f\x85'):
        require(i + 6 <= len(code), 'truncated branch')
        return va + 6 + struct.unpack_from('<i', code, i + 2)[0], 6, code[i:i + 2].hex()
    if code[i:i + 1] in (b'\x74', b'\x75', b'\xeb'):
        require(i + 2 <= len(code), 'truncated branch')
        return va + 2 + struct.unpack_from('<b', code, i + 1)[0], 2, code[i:i + 1].hex()
    if code[i:i + 1] in (b'\xe8', b'\xe9'):
        require(i + 5 <= len(code), 'truncated branch')
        return va + 5 + struct.unpack_from('<i', code, i + 1)[0], 5, code[i:i + 1].hex()
    raise ValueError('unsupported branch at selected site')


def rip(image, va, prefix):
    data = image.read(va, 7)
    require(data[:3] == bytes.fromhex(prefix), 'unexpected RIP-relative opcode')
    return va + 7 + struct.unpack_from('<i', data, 3)[0]


def pin(image, va, expected):
    expected = bytes.fromhex(expected)
    require(image.read(va, len(expected)) == expected, 'selected byte anchor changed')


def jump_table(image, va, count, start):
    fde = image.fdes[start]
    rows = []
    for n in range(count):
        addr = va + n * 4
        raw = image.read(addr, 4)
        dst = va + struct.unpack('<i', raw)[0]
        require(fde['start'] <= dst < fde['end'], 'jump table target outside FDE')
        rows.append({'index': n, 'slot_va': hex(addr), 'raw': raw.hex(), 'target_va': hex(dst)})
    return rows


# The shared first-byte selector of the three 12-byte names is handled separately.
# Each listed start is a branch target in the captured length table, except the
# three case arms reached through that selector. These are analyst seeds; their
# instructions, targets, lengths and immediate bytes are verified below.
KEY_PATHS = (
    (0x22ecd41, 11, b''), (0x22ecdb5, 15, b''),
    (0x22ece53, 25, b''), (0x22ecf71, 12, b'v'),
    (0x22ecfe6, 21, b''), (0x22ed0be, 23, b''),
    (0x22ed1aa, 12, b's'), (0x22ed1f4, 12, b'd'),
)


def extract_byte_path(code, start, total, prefix=b''):
    """Recover one compare chain; reject any altered encoding or rejection edge."""
    base, end, reject, accept = 0x22ecd20, 0x22ed241, 0x22ed238, 0x22ed23a
    require(len(code) == end - base, 'matcher FDE size changed')
    pos = start
    values = list(prefix)
    rows = []
    tag = None
    while len(values) < total:
        i = pos - base
        require(0 <= i < len(code), 'compare outside matcher')
        if code[i:i + 1] == b'\xb1':
            require(i + 2 <= len(code) and tag is None, 'bad tag instruction')
            tag = code[i + 1]
            pos += 2
            i += 2
        if code[i:i + 2] == b'\x80\x3e':
            require(i + 3 <= len(code), 'truncated byte compare')
            off, value, size = 0, code[i + 2], 3
        elif code[i:i + 2] == b'\x80\x7e':
            require(i + 4 <= len(code), 'truncated byte compare')
            off, value, size = code[i + 2], code[i + 3], 4
        else:
            raise ValueError('unsupported key compare')
        require(off == len(values), 'nonsequential key offset')
        cmp_va = pos
        pos += size
        target, insn_size, opcode = branch(code, base, pos)
        final_equal = len(values) + 1 == total and opcode in ('74', '0f84')
        require((target == accept if final_equal else target == reject), 'key mismatch edge changed')
        require(opcode in (('74', '0f84') if final_equal else ('75', '0f85')),
                'unexpected key condition')
        rows.append({'offset': off, 'value': value, 'compare_va': hex(cmp_va),
                     'branch_va': hex(pos), 'branch_opcode': opcode, 'branch_target_va': hex(target),
                     'raw': code[cmp_va - base:pos + insn_size - base].hex()})
        values.append(value)
        pos += insn_size
    if tag is None:
        require(code[pos - base:pos - base + 2] == b'\x31\xc9', 'missing zero tag')
        tag = 0
        pos += 2
        require(code[pos - base:pos - base + 7] == bytes.fromhex('884801c60009c3'),
                'zero-tag return changed')
    elif pos != reject:
        target, _, opcode = branch(code, base, pos)
        require(opcode in ('e9', 'eb') and target == accept, 'success edge changed')
    require(0 <= tag < 8, 'invalid recognized tag')
    return {'start_va': hex(start), 'length': total, 'prefix_hex': prefix.hex(),
            'key': bytes(values).decode('ascii'), 'tag': tag, 'comparisons': rows}


def selected_byte_paths(image):
    code = image.code(0x22ecd20)
    pin(image, 0x22ecd20, '4889f84883c2f54883fa0e')
    require(rip(image, 0x22ecd31, '488d0d') == 0x3da1c8, 'matcher table reference changed')
    table = jump_table(image, 0x3da1c8, 15, 0x22ecd20)
    # Exact selector form: load the first byte and route d/s/v separately.
    pin(image, 0x22ecf53, '0fb60e83f964')
    require(branch(code, 0x22ecd20, 0x22ecf59) == (0x22ed1f4, 6, '0f84'), 'd selector')
    pin(image, 0x22ecf5f, '83f973')
    require(branch(code, 0x22ecd20, 0x22ecf62) == (0x22ed1aa, 6, '0f84'), 's selector')
    pin(image, 0x22ecf68, '83f976')
    require(branch(code, 0x22ecd20, 0x22ecf6b) == (0x22ed238, 6, '0f85'), 'v selector')
    paths = [extract_byte_path(code, *p) for p in KEY_PATHS]
    require(sorted(x['tag'] for x in paths) == list(range(8)), 'matcher tags not complete')
    starts = {11: 0x22ecd41, 12: 0x22ecf53, 15: 0x22ecdb5,
              21: 0x22ecfe6, 23: 0x22ed0be, 25: 0x22ece53}
    for length in range(11, 26):
        require(int(table[length - 11]['target_va'], 16) == starts.get(length, 0x22ed238),
                'length table changed')
    pin(image, 0x22ed238, 'b108884801c60009c3')
    return sorted(paths, key=lambda x: x['tag']), table


def decode_key_rules(paths, candidate):
    """Apply extracted equalities to a synthetic key; this is not a node decoder."""
    require(isinstance(candidate, bytes), 'key must be bytes')
    for path in paths:
        if len(candidate) != path['length'] or not candidate.startswith(bytes.fromhex(path['prefix_hex'])):
            continue
        if all(candidate[p['offset']] == p['value'] for p in path['comparisons']):
            return path['tag']
    return 8


def fast_key_paths(image):
    """Extract the optimized matcher's constants and verify its selected branches."""
    base = 0x22ed250
    code = image.code(base)
    pin(image, base, '4889f84883c2f54883fa0e')
    require(image.read(0x22ed25b, 2) == b'\x0f\x87', 'fast length gate')
    # branch() intentionally admits only the selected equal/not-equal branches.
    gate = image.read(0x22ed25b, 6)
    require(0x22ed261 + struct.unpack_from('<i', gate, 2)[0] == 0x22ed3c1,
            'fast length rejection target changed')
    require(rip(image, 0x22ed261, '488d0d') == 0x3da204, 'fast length table reference')
    table = jump_table(image, 0x3da204, 15, base)
    starts = {11: 0x22ed271, 12: 0x22ed301, 15: 0x22ed29e,
              21: 0x22ed366, 23: 0x22ed398, 25: 0x22ed2cb}
    for length in range(11, 26):
        require(int(table[length - 11]['target_va'], 16) == starts.get(length, 0x22ed3c1),
                'fast length table changed')

    out = []
    # Two overlapping little-endian 64-bit comparisons, covering each key.
    for va, length in ((0x22ed271, 11), (0x22ed29e, 15)):
        b = image.read(va, 42)
        require(b[:2] == b'\x48\xb9' and b[10:15] == bytes.fromhex('48330e48ba')
                and b[23:26] == bytes.fromhex('483356') and b[26] == length - 8
                and b[27:30] == bytes.fromhex('4809ca'), 'fast word compare changed')
        left, right = b[2:10], b[15:23]
        require(left[length - 8:] == right[:16 - length], 'word-compare overlap disagrees')
        key = left + right[16 - length:]
        tgt, size, op = branch(code, base, va + 30)
        require(tgt == 0x22ed3c1 and op == '0f85', 'word-compare failure changed')
        p = va + 30 + size
        tail = image.read(p, 2)
        if tail == b'\x31\xc9':
            tag = 0
            pin(image, p, '31c9884801c60009c3')
        else:
            require(tail[0] == 0xb1, 'word-compare tag changed')
            tag = tail[1]
            require(image.read(p + 2, 7) == bytes.fromhex('884801c60009c3'), 'word return changed')
        out.append({'start_va': hex(va), 'length': length, 'tag': tag,
                    'key': key.decode('ascii'), 'chunks_hex': [left.hex(), right.hex()],
                    'chunk_offsets': [0, length - 8], 'failure_va': hex(tgt)})

    # Three 16-byte comparisons overlap. Resolve both RIP-relative constants.
    for va, length, expected_tag in ((0x22ed2cb, 25, 1), (0x22ed366, 21, 3),
                                     (0x22ed398, 23, 2)):
        b = image.read(va, 43)
        require(b[:7] == bytes.fromhex('f30f6f06f30f6f') and b[7] == 0x4e
                and b[8] == length - 16 and b[9:13] == bytes.fromhex('660f740d')
                and b[17:21] == bytes.fromhex('660f7405')
                and b[25:39] == bytes.fromhex('660fdbc1660fd7c881f9ffff0000'),
                'fast SIMD comparison changed')
        right_va = va + 17 + struct.unpack_from('<i', b, 13)[0]
        left_va = va + 25 + struct.unpack_from('<i', b, 21)[0]
        left, right = image.read(left_va, 16), image.read(right_va, 16)
        require(left[length - 16:] == right[:32 - length], 'SIMD overlap disagrees')
        key = left + right[32 - length:]
        target, size, op = branch(code, base, va + 39)
        if expected_tag == 2:
            require(op == '74' and target == 0x22ed3d3, 'SIMD success edge changed')
            tag_va = target
        else:
            require(op in ('0f85', '75') and target == 0x22ed3c1, 'SIMD failure edge changed')
            tag_va = va + 39 + size
        tag_bytes = image.read(tag_va, 2)
        require(tag_bytes == bytes((0xb1, expected_tag)), 'SIMD result tag changed')
        require(image.read(tag_va + 2, 7) == bytes.fromhex('884801c60009c3'), 'SIMD return changed')
        out.append({'start_va': hex(va), 'length': length, 'tag': tag_bytes[1],
                    'key': key.decode('ascii'), 'chunks_hex': [left.hex(), right.hex()],
                    'chunk_offsets': [0, length - 16],
                    'constant_vas': [hex(left_va), hex(right_va)], 'branch_va': hex(va + 39),
                    'branch_target_va': hex(target), 'branch_opcode': op})

    # At length 12, three adjacent scalar comparisons form an ordered chain.
    for va, tag, expected_target, expected_opcode in (
            (0x22ed301, 4, 0x22ed3ca, '0f84'),
            (0x22ed321, 5, 0x22ed3dc, '0f84'),
            (0x22ed341, 6, 0x22ed3c1, '75')):
        b = image.read(va, 28)
        require(b[:2] == b'\x48\xb9' and b[10:19] == bytes.fromhex('48330e8b56084881f2')
                and b[23:26] == bytes.fromhex('4809ca'), 'fast 12-byte comparison changed')
        key = b[2:10] + b[19:23]
        target, size, opcode = branch(code, base, va + 26)
        require(target == expected_target and opcode == expected_opcode, 'fast selector branch changed')
        tag_va = target if tag != 6 else va + 26 + size
        require(image.read(tag_va, 2) == bytes((0xb1, tag)), 'fast selector tag changed')
        require(image.read(tag_va + 2, 7) == bytes.fromhex('884801c60009c3'), 'selector return changed')
        out.append({'start_va': hex(va), 'length': 12, 'tag': tag,
                    'key': key.decode('ascii'), 'chunks_hex': [key[:8].hex(), key[8:].hex()],
                    'chunk_offsets': [0, 8], 'branch_va': hex(va + 26),
                    'branch_target_va': hex(target), 'branch_opcode': opcode})
    require(sorted(x['tag'] for x in out) == list(range(8)), 'fast tags incomplete')
    return sorted(out, key=lambda x: x['tag']), table


def fde_records(image):
    out = []
    for start in STARTS:
        f = image.fdes[start]
        b = image.code(start)
        out.append({'start_va': hex(start), 'end_va_exclusive': hex(f['end']),
                    'fde_va': hex(f['fde']), 'cie_va': hex(f['cie']),
                    'file_offset': hex(image.offset(start, len(b))), 'size': len(b),
                    'sha256': hashlib.sha256(b).hexdigest()})
    return out


def mode_and_guard(image):
    mode_code = image.code(0x23d8e00)
    reader_code = image.code(0x1767dd0)
    require(branch(mode_code, 0x23d8e00, 0x23d8e36) == (0x23d8e87, 2, '75'),
            'mode discriminator branch changed')
    pin(image, 0x23d8e32, '41833f01')
    first = rip(image, 0x23d8e52, '488d35')
    other = rip(image, 0x23d8e91, '488d35')
    pin(image, 0x23d8e59, 'ba08000000')
    pin(image, 0x23d8e98, 'ba07000000')
    require(image.read(first, 8) == b'PerAsset' and image.read(other, 7) == b'Enabled',
            'mode variant literals changed')
    require(branch(mode_code, 0x23d8e00, 0x23d8e43) == (0x25a8f80, 5, 'e8'),
            'mode one-entry header call changed')
    pin(image, 0x23d8e3e, 'ba01000000')
    require(branch(mode_code, 0x23d8e00, 0x23d8e82) == (0x25ecca0, 5, 'e9'),
            'mode payload tail call changed')
    name_va = rip(image, 0x176ac22, '488d15')
    pin(image, 0x176ac31, 'b90b000000')
    require(image.read(name_va, 11) == b'BucketGuard', 'guard type name changed')
    require(branch(reader_code, 0x1767dd0, 0x176ac39) == (0x16accd0, 5, 'e8'),
            'guard reader call changed')
    return {
        'mode': {'tag_test_va': '0x23d8e32', 'branch_va': '0x23d8e36',
                 'tag_one_key_va': hex(first), 'tag_one_key': image.read(first, 8).decode('ascii'),
                 'tag_one_header_count': 1, 'tag_one_payload_call_va': '0x23d8e82',
                 'tag_one_payload_target_va': '0x25ecca0',
                 'other_key_va': hex(other), 'other_key': image.read(other, 7).decode('ascii')},
        'status_guard_type': {'name_reference_va': '0x176ac22', 'name_va': hex(name_va),
                              'length': 11, 'name': image.read(name_va, 11).decode('ascii'),
                              'call_va': '0x176ac39', 'call_target_va': '0x16accd0'},
    }


def sequence_decisions(image):
    """Bind the six early length checks and the two trailing-field paths."""
    code = image.code(0x1767dd0)
    helper = image.code(0x16fde80)
    # Each row reaches the numbered invalid-length construction before a child.
    specs = (
        (0x17687aa, '4585e4', 0x17687ad, 0x1768b2a, 0x1768b43, 0x1768b45, 0x17687cc, 0x1778870),
        (0x176880d, '85ed', 0x176880f, 0x1768a4b, 0x1768a5e, 0x1768a63, 0x176882e, 0x196a060),
        (0x176886c, '85ed', 0x176886e, 0x1768b4f, 0x1768b62, 0x1768b67, 0x1768888, 0x1684530),
        (0x176889a, '85ed', 0x176889c, 0x1768ef3, 0x1768f06, 0x1768f0b, 0x17688bb, 0x1684530),
        (0x17688cd, '85ed', 0x17688cf, 0x1769099, 0x17690ac, 0x17690b1, 0x17688f3, 0x1a44850),
        (0x1768923, '85ed', 0x1768925, 0x1769260, 0x1769273, 0x1769278, 0x176894b, 0x16accd0),
    )
    child_failures = ((0x17687d6, '4883f809', 0x17687da, 0x17689e8),
                      (0x1768838, '4883f809', 0x176883c, 0x1768a88),
                      (0x1768892, '3c09', 0x1768894, 0x1768aec),
                      (0x17688c5, '3c09', 0x17688c7, 0x1768aec),
                      (0x17688fd, '4883f809', 0x1768901, 0x17691c2),
                      (0x1768955, '3c09', 0x1768957, 0x176929d))
    rows = []
    for index, (test, test_raw, site, target, number, error_call, child_call, child) in enumerate(specs):
        pin(image, test, test_raw)
        require(branch(code, 0x1767dd0, site) == (target, 6, '0f84'), 'sequence length branch changed')
        if index == 0:
            pin(image, number, '31f6')
        else:
            raw = image.read(number, 5)
            require(raw[0] == 0xbe and struct.unpack_from('<I', raw, 1)[0] == index,
                    'sequence diagnostic index changed')
        require(branch(code, 0x1767dd0, error_call) == (0x1703e70, 5, 'e8'),
                'sequence diagnostic call changed')
        require(branch(code, 0x1767dd0, child_call) == (child, 5, 'e8'),
                'sequence child call changed')
        compare, compare_raw, failure_site, failure_target = child_failures[index]
        pin(image, compare, compare_raw)
        require(branch(code, 0x1767dd0, failure_site) == (failure_target, 6, '0f85'),
                'sequence child-failure branch changed')
        rows.append({'index': index, 'test_va': hex(test), 'test_bytes': test_raw,
                     'absent_branch_va': hex(site), 'absent_target_va': hex(target),
                     'branch_bytes': image.read(site, 6).hex(), 'diagnostic_index_va': hex(number),
                     'diagnostic_call_va': hex(error_call), 'child_call_va': hex(child_call),
                     'child_target_va': hex(child), 'child_status_test_va': hex(compare),
                     'child_status_test_bytes': compare_raw, 'child_failure_branch_va': hex(failure_site),
                     'child_failure_target_va': hex(failure_target),
                     'child_failure_branch_bytes': image.read(failure_site, 6).hex()})
    pin(image, 0x176896c, '85ed')
    require(branch(code, 0x1767dd0, 0x176896e) == (0x17695d7, 6, '0f84'), 'six-entry mode default changed')
    pin(image, 0x17695d7, '48c74424580000000048c744246800000000bd01000000')
    require(branch(code, 0x1767dd0, 0x1768988) == (0x16850e0, 5, 'e8'), 'mode child changed')
    require(branch(code, 0x1767dd0, 0x17696bd) == (0x16fde80, 5, 'e8'), 'scale presence call changed')
    pin(image, 0x17696cb, '807c242800')
    require(branch(code, 0x1767dd0, 0x17696d0) == (0x1769746, 2, '75'), 'scale default branch changed')
    pin(image, 0x16fde88, '8b460885c0')
    require(branch(helper, 0x16fde80, 0x16fde8d) == (0x16fdec3, 2, '74'), 'empty scale slot changed')
    pin(image, 0x16fdec3, '48c7430800000000c60309')
    require(branch(helper, 0x16fde80, 0x16fde9a) == (0x16841b0, 5, 'e8'), 'scale value child changed')
    pin(image, 0x17698bd, '8b8424e802000085c0')
    require(branch(code, 0x1767dd0, 0x17698c6) == (0x17698fc, 2, '74'), 'extra-elements branch changed')
    return {'required_prefix': rows, 'empty_after_six_branch_va': '0x176896e',
            'empty_after_six_target_va': '0x17695d7', 'mode_child_call_va': '0x1768988',
            'scale_presence_call_va': '0x17696bd', 'scale_presence_child_va': '0x16fde80',
            'scale_empty_branch_va': '0x16fde8d', 'scale_empty_target_va': '0x16fdec3',
            'scale_selection_branch_va': '0x17696d0', 'extra_count_test_va': '0x17698bd',
            'extra_count_zero_branch_va': '0x17698c6'}


def field_records(image, paths):
    # Writer sites in serialization order, and observed child call sites.
    writer = [
        (0x2311f10, '488d35', 0x2311f3a, 0x30, 0),
        (0x2311f51, '488d35', 0x2311f7b, 0x48, 1),
        (0x2311f96, '488d35', 0x2311fbf, 0x60, 2),
        (0x2311fde, '488d35', 0x2312007, 0x68, 3),
        (0x2312022, '488d35', 0x231204c, 0x70, 4),
        (0x2312060, '488d15', 0x2312074, 0x20, 5),
        (0x23d8e18, '488d35', 0x231208f, 0x00, 6),
        (0x23120a8, '488d15', 0x23120bc, 0x88, 7),
    ]
    dup_branch = [0x176a9a0, 0x176ab95, 0x176aa9a, 0x176aaed,
                  0x176aa1b, 0x176ac1c, 0x176ac70, 0x176ab40]
    dup_key = [0x176b707, 0x176b57d, 0x176b7cc, 0x176b642,
               0x176b4b8, 0x176b891, 0x176b32e, 0x176b3f3]
    dup_targets = [0x176b69d, 0x176b513, 0x176b762, 0x176b5d8,
                   0x176b44e, 0x176b827, 0x176b2c4, 0x176b389]
    dup_ops = ['0f85', '0f85', '0f84', '0f84', '0f85', '0f85', '0f85', '0f84']
    cases = [0x176a997, 0x176ab8c, 0x176aa91, 0x176aae4, 0x176aa12,
             0x176ac0b, 0x176ac67, 0x176ab37, 0x176acf9]
    missing_key = [0x176834e, 0x17684db, 0x176857e, 0x1768613,
                   0x1768b71, 0x1768c12, None, None]
    child_targets = [0x25e5480, 0x25e93f0, 0x25ac0d0, 0x25ac0d0,
                     0x25e04c0, 0x23d9170, 0x23d8e00, 0x23d9250]
    code = image.code(0x1767dd0)
    table = jump_table(image, 0x2b92f8, 9, 0x1767dd0)
    require([int(r['target_va'], 16) for r in table] == cases, 'reader dispatch targets changed')
    require(rip(image, 0x176a987, '488d0d') == 0x2b92f8, 'reader dispatch table changed')
    result = []
    for label_va, prefix, call_va, obj_offset, tag in writer:
        path = paths[tag]
        name = path['key']
        name_bytes = name.encode('ascii')
        label = rip(image, label_va, prefix)
        require(image.read(label, len(name_bytes)) == name_bytes, 'writer key differs from matcher')
        length_va = label_va + (12 if tag in (5, 7) else 7)
        length_setup = image.read(length_va, 5)
        require(length_setup[0] == (0xb9 if tag in (5, 7) else 0xba) and
                struct.unpack_from('<I', length_setup, 1)[0] == len(name_bytes),
                'writer key length changed')
        call_target, _, call_op = branch(image.code(0x2311e90), 0x2311e90, call_va)
        require(call_op == 'e8' and call_target == child_targets[tag], 'writer child edge changed')
        dup_target, _, op = branch(code, 0x1767dd0, dup_branch[tag])
        require(dup_target == dup_targets[tag] and op == dup_ops[tag], 'duplicate branch changed')
        require(dup_target <= dup_key[tag] < dup_target + 0x80, 'duplicate target and label diverged')
        dp = rip(image, dup_key[tag], '488d05')
        require(image.read(dp, len(name_bytes)) == name_bytes, 'duplicate label mismatch')
        dbytes = image.read(dup_key[tag], 0x60)
        ip = dbytes.find(b'\x48\x8d\x35')
        require(ip >= 0, 'missing duplicate template reference')
        template = rip(image, dup_key[tag] + ip, '488d35')
        require(image.read(template, 17) == b'\x11duplicate field ', 'wrong duplicate template')
        missing = None
        if missing_key[tag] is not None:
            mva = missing_key[tag]
            mp = rip(image, mva, '488d05')
            require(image.read(mp, len(name_bytes)) == name_bytes, 'missing label mismatch')
            mbytes = image.read(mva, 0x80)
            im = mbytes.find(b'\x48\x8d\x35')
            require(im >= 0, 'missing missing-field template reference')
            mt = rip(image, mva + im, '488d35')
            require(image.read(mt, 15) == b'\x0fmissing field ', 'wrong missing template')
            missing = {'key_ref_va': hex(mva), 'key_va': hex(mp), 'template_ref_va': hex(mva + im),
                       'template_va': hex(mt)}
        result.append({'tag': tag, 'key': name, 'key_length': len(name_bytes),
                       'writer_key_ref_va': hex(label_va), 'writer_key_va': hex(label),
                       'writer_key_length_va': hex(length_va), 'writer_key_length_bytes': length_setup.hex(),
                       'writer_child_call_va': hex(call_va), 'writer_child_target_va': hex(call_target),
                       'object_offset': hex(obj_offset), 'reader_case_va': table[tag]['target_va'],
                       'reader_case_test_bytes': image.read(int(table[tag]['target_va'], 16),
                                        dup_branch[tag] - int(table[tag]['target_va'], 16)).hex(),
                       'duplicate_branch_va': hex(dup_branch[tag]), 'duplicate_branch_opcode': op,
                       'duplicate_target_va': hex(dup_target), 'duplicate_key_ref_va': hex(dup_key[tag]),
                       'duplicate_key_va': hex(dp), 'duplicate_template_ref_va': hex(dup_key[tag] + ip),
                       'duplicate_template_va': hex(template), 'missing': missing})
    return result, table


def evidence(image):
    paths, lengths = selected_byte_paths(image)
    fast_paths, fast_table = fast_key_paths(image)
    require([(p['tag'], p['key']) for p in paths] ==
            [(p['tag'], p['key']) for p in fast_paths], 'matcher implementations disagree')
    fields, reader_table = field_records(image, paths)
    nested = mode_and_guard(image)
    sequence = sequence_decisions(image)
    # Fixed-byte witnesses for state-field offsets, writer mode and result flow.
    anchors = [
        ('writer_named_mode', 0x2311eb0, '807a0b007436'),
        ('writer_field_count_a', 0x2311ebe, 'ba08000000'),
        ('writer_field_count_b', 0x2311ef4, 'ba08000000'),
        ('field0_address', 0x2311f2e, '498d7730'),
        ('field1_address', 0x2311f6f, '498d7748'),
        ('field2_load', 0x2311f8b, '4d8b6760'),
        ('field3_load', 0x2311fd3, '4d8b6768'),
        ('field4_address', 0x2312040, '498d7770'),
        ('field5_address', 0x231205c, '4d8d4720'),
        ('field7_load', 0x231209f, 'f2410f108788000000'),
        ('mode_tag_test', 0x23d8e32, '41833f01754f'),
        ('mode_payload', 0x23d8e6c, '4983c708'),
        ('mode_other_success', 0x23d8eab, '4983cf04'),
        ('reader_map_end', 0x176ad1c, '85ed0f842aefffff'),
        ('reader_scale_present_test', 0x1769cba, 'f68424b0030000017511'),
        ('reader_scale_default_store', 0x1769ccc, '660fd68424a8030000'),
        ('reader_mode_missing', 0x1768c8c, '4983fd02753b41bd0100000031d231c9'),
        ('reader_value_mode_store', 0x1768d3f, '4c89ac2400020000'),
        ('reader_scale_result', 0x1768d8f, 'f20f108424a8030000f20f11842488020000'),
        ('reader_result_source', 0x1769050, '488db42400020000'),
        ('reader_result_size_and_destination', 0x1769935, 'ba900000004889df'),
        ('key_reader_direct_path', 0x176a4be, '488d7c2420e85828b800'),
        ('key_reader_utf8_path', 0x176a7a0, '4c89e64c89fae87525b800'),
        ('key_reader_other_path', 0x176a7db, '488d7c2420e86b2ab800'),
    ]
    anchor_rows = []
    for name, va, raw in anchors:
        pin(image, va, raw)
        anchor_rows.append({'name': name, 'va': hex(va), 'file_offset': hex(image.offset(va)), 'bytes': raw})
    reader_code = image.code(0x1767dd0)
    missing_checks = []
    # Some branches go to the absent-field block; others skip it on presence.
    for tag, test_va, raw, branch_va, expected_target, expected_opcode in (
        (0, 0x1769cd5, 'f68424d002000001', 0x1769ced, 0x176834e, '0f84'),
        (1, 0x1768409, 'f6c101', 0x1768414, 0x17684db, '0f84'),
        (2, 0x1768570, 'f684241001000001', 0x1768578, 0x1768601, '0f85'),
        (3, 0x1768601, 'f68424f802000001', 0x1768611, 0x176868a, '75'),
        (4, 0x1768692, 'f6c201', 0x1768695, 0x1768b71, '0f84'),
        (5, 0x1768c0d, '4885c0', 0x1768c10, 0x1768c8c, '75'),
    ):
        pin(image, test_va, raw)
        target, size, opcode = branch(reader_code, 0x1767dd0, branch_va)
        require((target, opcode) == (expected_target, expected_opcode), 'presence branch changed')
        missing_checks.append({'tag': tag, 'test_va': hex(test_va), 'test_bytes': raw,
                               'branch_va': hex(branch_va), 'branch_opcode': opcode,
                               'branch_bytes': image.read(branch_va, size).hex(),
                               'branch_target_va': hex(target)})
    require(branch(reader_code, 0x1767dd0, 0x176ad1e) == (0x1769c4e, 6, '0f84'),
            'map completion edge changed')
    require(branch(reader_code, 0x1767dd0, 0x176ad09) == (0x19682d0, 5, 'e8'),
            'unknown-key child edge changed')
    pin(image, 0x176ad04, 'ba01000000')
    require(branch(reader_code, 0x1767dd0, 0x1769058) == (0x1769935, 5, 'e9'),
            'reader result edge changed')
    # The header gates and selected writer failures lead to bounded local targets.
    writer_code = image.code(0x2311e90)
    require(branch(writer_code, 0x2311e90, 0x2311ec3) == (0x25a8f80, 5, 'e8'),
            'writer named header call changed')
    require(branch(writer_code, 0x2311e90, 0x2311ef9) == (0x25a9bd0, 5, 'e8'),
            'writer positional header call changed')
    error_branches = []
    for va in (0x2311ed1, 0x2311f07, 0x2311f28, 0x2311f44, 0x2311f69,
               0x2311f85, 0x2311fae, 0x2311fcd, 0x2311ff6, 0x2312015,
               0x231203a, 0x2312056, 0x231207e, 0x2312099, 0x23120c6):
        target, size, opcode = branch(writer_code, 0x2311e90, va)
        require(0x2311e90 <= target < image.fdes[0x2311e90]['end'], 'writer branch outside FDE')
        error_branches.append({'va': hex(va), 'file_offset': hex(image.offset(va)),
                               'opcode': opcode, 'target_va': hex(target),
                               'bytes': image.read(va, size).hex()})
    require([r['opcode'] for r in error_branches] == [
        '74', '75', '0f85', '0f85', '0f85', '0f85', '0f85', '0f85',
        '0f85', '0f85', '0f85', '0f85', '0f85', '0f85', '75'],
        'writer branch conditions changed')
    require([r['target_va'] for r in error_branches] == [
        '0x2311f09', '0x2311ed3',
        '0x23120cd', '0x23120e0', '0x23120cd', '0x23120e0', '0x2312110',
        '0x231210b', '0x2312110', '0x231210b', '0x23120cd', '0x23120e0',
        '0x2312121', '0x2312121', '0x2312121'], 'writer error branch map changed')
    # movq has four prefix/opcode bytes and a signed displacement.
    b = image.read(0x1769cc4, 8)
    require(b[:4] == bytes.fromhex('f30f7e05'), 'scale constant load changed')
    constant_ref = 0x1769cc4 + 8 + struct.unpack_from('<i', b, 4)[0]
    constant = image.read(constant_ref, 8)
    require(constant == bytes.fromhex('000000000000f03f'), 'scale default is not binary64 1')
    return {'target': {'release': 'node-94', 'sha256': SHA256},
            'coordinate_system': 'ELF link-time virtual addresses; file offsets are from start of ELF',
            'fdes': fde_records(image), 'anchors': anchor_rows, 'writer_branches': error_branches,
            'reader_missing_checks': missing_checks,
            'unknown_key_route': {'case_va': reader_table[8]['target_va'],
                                  'argument_setup_va': '0x176ad04', 'call_va': '0x176ad09',
                                  'call_target_va': '0x19682d0'},
            'writer_and_reader_fields': fields, 'reader_dispatch_table': reader_table,
            'matcher_length_table': lengths, 'fast_matcher_length_table': fast_table,
            'byte_matcher_paths': paths, 'fast_matcher_paths': fast_paths,
            'nested': nested, 'sequence': sequence,
            'scale_default': {'load_va': '0x1769cc4', 'constant_va': hex(constant_ref),
                              'file_offset': hex(image.offset(constant_ref)), 'bits_le': constant.hex()},
            'limits': ['FDEs are unwind extents, not proof of source-function boundaries',
                       'Selected patterns only; not a complete instruction decode or reachability proof',
                       'Nested values, arbitrary malformed input, live state and other releases are unresolved']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    image = Image(BINARY.read_bytes())
    records = evidence(image)
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / 'codec.json').write_text(json.dumps(records, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    rows = ['tag\tkey\tobject_offset\twriter_key_ref_va\twriter_child_call_va\twriter_child_target_va\treader_case_va\tduplicate_branch_va\tduplicate_target_va\tmissing_key_ref_va']
    for f in records['writer_and_reader_fields']:
        rows.append('\t'.join(str(f[k]) for k in ('tag', 'key', 'object_offset', 'writer_key_ref_va',
                                                   'writer_child_call_va', 'writer_child_target_va',
                                                   'reader_case_va', 'duplicate_branch_va', 'duplicate_target_va'))
                    + '\t' + (f['missing']['key_ref_va'] if f['missing'] else '-'))
    (args.out / 'fields.tsv').write_text('\n'.join(rows) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
