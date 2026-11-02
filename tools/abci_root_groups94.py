#!/usr/bin/env python3
"""Recover selected grouped app-hash preimage writers from node 94 ELF bytes."""

import argparse
import csv
import hashlib
import io
import json
import mmap
import re
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import elf_index
import fde_extents

TARGET = ROOT / 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

# The body hashes authenticate the whole selected unwind extents even in tests
# which deliberately disable the outer artifact digest check.
SELECTED = {
    0x1e5e450: (0x1e5e764, '2f4b31006c3b59fee957650bc82d0687f1c661c676341ee4235bd7b074283496'),
    0x4446d90: (0x44470a4, '88d8519c471eacd79e9cd28f99228b81bd5ed76bd4957cf402584a8e663db645'),
    0x1e5ed40: (0x1e5f00f, '755118d9699d4eabc2405257ab15d4822df389f101720b02d04ef99fa35bd16d'),
    0x44465a0: (0x444686f, 'fa8fa3325b2e88868c99c7b08e2232376b62ff2bdb2c6e648effb037a2bdb42c'),
    0x1e5d9b0: (0x1e5de4c, '4d6e9974eb647bc394e9636a849b10a0efd57a5a7a618d979abc58f4efd1d3b1'),
    0x4445a70: (0x4445f0c, 'c717dda383855ecf696ffed1561a870071623cb78285ae307bcac93a1e8b18a2'),
    0x1e0fcc0: (0x1e0fec4, '8e51023ca4c8495e2a68cd4e152fe63cd8c4c4058f37900ee140f77c1461979a'),
    0x43f69d0: (0x43f6bd4, '748cd5cc2c9687ba65eedc4405478cb2c3bc4f608e1e3777d91c7f7d5a12687b'),
    0x1e0fed0: (0x1e100ba, '36391cb3f6bdc999be0c69f8d8263534a77cedae96395c38681287f4648a30f4'),
    0x43f94f0: (0x43f96da, '2858238b0dcbae56976ab85a049be67890177eda6a1068edc541504ece991501'),
    0x1e0f310: (0x1e0f44f, 'b508ad97f293d7d2d6b22596e8e6adb8b496c7471dfc7ba4137fc147d3c6a77c'),
    0x43f4700: (0x43f483f, '83459649f6824edf72dfd67c8939f9310f0e3e01189da79e69b10d531625815d'),
    0x1e10760: (0x1e10957, '97b91472ee576c4042ccb868b2f5f8221d4e82041f85ddc137460b4642f46830'),
    0x43f4840: (0x43f4a37, '045bbed937f717c7275d1b8cf8cd056a2580db265737f43f4637cba5bd4130d4'),
}

GROUPS = {
    38: {'length': 15, 'box_pattern': rb'\x48\x8d\x85(....)\x49\x89(?:\x04\x24|\x44\x24(.))',
         'low': (0x1e5e450, 0x2817930), 'shared': (0x4446d90, 0x4ae3120)},
    39: {'length': 16, 'box_pattern': rb'\x49\x8d\x86(....)\x48\x89\x45(.)',
         'low': (0x1e5ed40, 0x28185e0), 'shared': (0x44465a0, 0x4ae6ea0)},
    40: {'length': 8, 'box_pattern': rb'\x49\x8d\x8e(....)\x48\x89(?:\x08|\x48(.))',
         'low': (0x1e5d9b0, 0x2817510), 'shared': (0x4445a70, 0x4ae2ad0)},
}
EXPECTED_CAPTURES = {
    38: (0x8f2, 0x3a98, 0x3aa4, 0x3988, 0x39c0, 0x32a8, 0x37c0, 0x37d0,
         0x39c8, 0xbb0, 0x38c0, 0x38b0, 0x8f0, 0x3948, 0x3960),
    39: (0x3980, 0xb90, 0xba0, 0x3ac8, 0x8b8, 0x38f8, 0x3ac9, 0x31a8,
         0x32e8, 0x3328, 0x3908, 0x7a0, 0x3938, 0x3ab0, 0x3aca, 0x3a48),
    40: (0x3abc, 0x3acb, 0x3280, 0x8f1, 0x3610, 0x8e8, 0x3acc, 0x3a68),
}
CAPTURE_CONTEXTS = {
    'low': (0x2756986, 0x2756b6e, 0),
    'secondary': (0x4d7d2fe, 0x4d7d4e3, 0),
    'primary': (0x4d7f2ae, 0x4d7f493, 0xa80),
}
SHARED_CAPTURE_PATTERNS = {
    38: GROUPS[38]['box_pattern'],
    39: rb'\x48\x8d\x85(....)\x49\x89\x45(.)',
    40: rb'\x48\x8d\x8d(....)\x48\x89(?:\x08|\x48(.))',
}
# Only fixed instruction forms are interpreted; no general x86 decoder is used.
STEP = re.compile(rb'\x49\x8b\x56(.)\x48\x89\xe7\x48\x8d\x74\x24\x18\xe8(....)'
                  rb'\x4c\x39\x24\x24(\x0f\x85....|\x75.)', re.S)


def require(ok, what):
    if not ok:
        raise ValueError(what)


def file_offset(sections, va, size):
    """Resolve only a unique allocated, file-backed interval."""
    require(type(va) is int and type(size) is int and va >= 0 and size > 0,
            'invalid virtual interval')
    choices = [s for s in sections if s['type'] != 8 and s['flags'] & 2
               and s['address'] <= va and va + size <= s['address'] + s['size']]
    require(len(choices) == 1, 'virtual interval is not uniquely file-backed')
    s = choices[0]
    return s['offset'] + va - s['address']


class Image:
    def __init__(self, data, check_digest=True):
        self.data = data
        if check_digest:
            require(hashlib.sha256(data).hexdigest() == SHA256, 'artifact digest mismatch')
        self.sections = elf_index.sections(data)
        _, frames = fde_extents.eh_frame_records(data, self.sections)
        by_start = {}
        for fde in frames:
            if fde['start'] in SELECTED:
                require(fde['start'] not in by_start, 'duplicate selected FDE')
                by_start[fde['start']] = fde
        _, entries = elf_index.unwind_index(data)
        indexed = {}
        for row in entries:
            if row['start'] in SELECTED:
                require(row['start'] not in indexed, 'duplicate selected unwind start')
                indexed[row['start']] = row
        require(set(by_start) == set(SELECTED) == set(indexed), 'missing selected FDE')
        self.frames = by_start
        for start, (end, expected) in SELECTED.items():
            fde = by_start[start]
            require(fde['end'] == end, 'selected FDE extent changed')
            require(indexed[start]['fde'] == fde['fde'], 'FDE disagrees with unwind index')
            require(hashlib.sha256(self.read(start, end - start)).hexdigest() == expected,
                    'selected body digest mismatch')
        sections = [s for s in self.sections if s['name'] == '.rela.dyn' and s['type'] != 8]
        require(len(sections) == 1 and sections[0]['size'] % 24 == 0, 'invalid .rela.dyn')
        s = sections[0]
        self.relocations = {}
        for pos in range(s['offset'], s['offset'] + s['size'], 24):
            slot, info, addend = struct.unpack_from('<QQq', data, pos)
            if slot in self.relocations:
                raise ValueError('duplicate relocation offset')
            self.relocations[slot] = (info & 0xffffffff, info >> 32, addend, pos)

    def read(self, va, size):
        off = file_offset(self.sections, va, size)
        return bytes(self.data[off:off + size])

    def off(self, va, size):
        return file_offset(self.sections, va, size)

    def relative(self, slot):
        entry = self.relocations.get(slot)
        require(entry is not None and entry[:2] == (8, 0), 'expected RELATIVE relocation')
        return entry[2]

    def window(self, va, expected):
        raw = bytes.fromhex(expected)
        require(self.read(va, len(raw)) == raw, 'instruction window mismatch')
        return {'va': hex(va), 'file_offset': hex(self.off(va, len(raw))), 'bytes': raw.hex()}

    def target(self, va, prefix):
        raw = self.read(va, len(prefix) + 4)
        require(raw.startswith(prefix), 'relative instruction changed')
        return va + len(raw) + struct.unpack_from('<i', raw, len(prefix))[0]


def capture_groups(image, source='low'):
    require(source in CAPTURE_CONTEXTS, 'unknown capture source')
    begin, end, shift = CAPTURE_CONTEXTS[source]
    code = image.read(begin, end - begin)
    result = {}
    for row, spec in GROUPS.items():
        captures = {}
        pattern = spec['box_pattern'] if source == 'low' else SHARED_CAPTURE_PATTERNS[row]
        for match in re.finditer(pattern, code, re.S):
            box_offset = match.group(2)[0] if match.group(2) else 0
            require(box_offset not in captures, 'duplicate box capture')
            state_offset = struct.unpack('<i', match.group(1))[0]
            captures[box_offset] = {'index': box_offset // 8, 'box_offset': hex(box_offset),
                                    'state_offset': hex(state_offset),
                                    'capture_va': hex(begin + match.start()),
                                    'capture_bytes': match.group().hex()}
        require(sorted(captures) == list(range(0, spec['length'] * 8, 8)),
                'group capture layout changed')
        values = [captures[i] for i in sorted(captures)]
        for previous, current in zip(values, values[1:]):
            require(int(previous['capture_va'], 16) + len(bytes.fromhex(previous['capture_bytes'])) ==
                    int(current['capture_va'], 16), 'noncontiguous capture sequence')
        require(tuple(int(r['state_offset'], 16) for r in values) ==
                tuple(offset + shift for offset in EXPECTED_CAPTURES[row]),
                'state capture mismatch')
        result[row] = values
    return result


def context_links(image):
    # Fat-pointer stores and closure calls in existing builder/closure bodies
    # are connectivity witnesses, not newly owned caller bodies.
    sources = {
        'low': (0x2756f72, 0x56bda38, 'low'),
        'secondary': (0x4d7d8ea, 0x57446e8, 'shared'),
        'primary': (0x4d7f89a, 0x57446e8, 'shared'),
    }
    store_prefixes = {
        'low': (bytes.fromhex('4c89a3'), bytes.fromhex('4889ab'), bytes.fromhex('488983')),
        'secondary': (bytes.fromhex('4c89a3'), bytes.fromhex('4c89ab'), bytes.fromhex('488983')),
        'primary': (bytes.fromhex('4c89a3'), bytes.fromhex('4c89ab'), bytes.fromhex('488983')),
    }
    rows = []
    for source, (first_store, table_base, lane) in sources.items():
        for group in (38, 39, 40):
            site = first_store + (group - 38) * 21
            prefix = store_prefixes[source][group - 38]
            offset = 0x260 + (group - 38) * 0x10
            raw = image.read(site, 21)
            require(raw[:3] == prefix and struct.unpack_from('<I', raw, 3)[0] == offset,
                    'fat pointer data store changed')
            lea = site + 7
            require(image.read(lea, 3) in (b'\x48\x8d\x0d', b'\x48\x8d\x05'), 'table LEA changed')
            target = image.target(lea, image.read(lea, 3))
            require(target == table_base + group * 0x20, 'group table mismatch')
            image.window(site + 14, '48898b' + struct.pack('<I', offset + 8).hex()
                         if group != 40 else '488983' + struct.pack('<I', offset + 8).hex())
            serializer, body = GROUPS[group][lane]
            table = table_base + group * 0x20
            size = struct.unpack('<Q', image.read(table + 8, 8))[0]
            require(size == GROUPS[group]['length'] * 8, 'vtable box size mismatch')
            thunk = image.relative(table + 0x18)
            t = image.read(thunk, 14)
            require(t[:5] == bytes.fromhex('534889fbe8') and t[9:] == bytes.fromhex('4889d85bc3'),
                    'closure thunk changed')
            require(thunk + 9 + struct.unpack_from('<i', t, 5)[0] == body, 'closure body changed')
            call = body + 0x3c
            require(image.target(call, b'\xe8') == serializer, 'serializer call changed')
            rows.append({'group': group, 'builder': source, 'serializer_lane': lane,
                         'vtable': hex(table), 'box_size': size,
                         'thunk': hex(thunk), 'thunk_bytes': t.hex(), 'prior_closure': hex(body),
                         'call_site': hex(call), 'call_bytes': image.read(call, 5).hex(),
                         'serializer': hex(serializer), 'prior_fat_store': hex(site),
                         'prior_table_lea': hex(lea), 'relocation_file_offset': hex(image.relocations[table + 0x18][3])})
    return rows


def prior_builder_flow(image, captures_by_source):
    """Recognize the selected straight-line register-preserving store runs."""
    stores = {'low': 0x2756f72, 'secondary': 0x4d7d8ea, 'primary': 0x4d7f89a}
    null_targets = {'low': (0x27577d0, 0x27577ed),
                    'secondary': (0x4d7e17f, 0x4d7e194),
                    'primary': (0x4d8012f, 0x4d80144)}
    rows = []
    for source, first_store in stores.items():
        captures = captures_by_source[source]
        first38 = int(captures[38][0]['capture_va'], 16)
        first39 = int(captures[39][0]['capture_va'], 16)
        aliases = [image.window(first38 - 11 if source == 'low' else first38 - 3,
                                '4989c44c89b424d8000000' if source == 'low' else '4989c4'),
                   image.window(first39 - 3, '4889c5' if source == 'low' else '4989c5')]
        gaps = []
        for group, size in ((38, 0x80), (39, 0x40)):
            last = captures[group][-1]
            gap_begin = int(last['capture_va'], 16) + len(bytes.fromhex(last['capture_bytes']))
            gap_end = int(captures[group + 1][0]['capture_va'], 16)
            raw_gap = image.read(gap_begin, gap_end - gap_begin)
            prefix = b'\xbf' + struct.pack('<I', size) + b'\xff\x15'
            require(raw_gap.startswith(prefix) and raw_gap[11:14] == b'\x48\x85\xc0',
                    'prior allocation setup changed')
            branch = decode_branch(image, gap_begin + 14)
            require(branch['condition'] == 'equal' and
                    int(branch['target'], 16) == null_targets[source][group - 38],
                    'prior allocation failure branch changed')
            tail = raw_gap[20:]
            expected_tail = (b'\x49\x89\xee\x48\x89\xc5' if source == 'low'
                             else b'\x49\x89\xc5') if group == 38 else b''
            require(tail == expected_tail, 'prior capture register transfer changed')
            gaps.append({'after_group': group, 'begin': hex(gap_begin), 'end_exclusive': hex(gap_end),
                         'bytes': raw_gap.hex(), 'size_argument': size, 'null_branch': branch})
        final = captures[40][-1]
        begin = int(final['capture_va'], 16) + len(bytes.fromhex(final['capture_bytes']))
        require(begin == CAPTURE_CONTEXTS[source][1], 'capture end changed')
        end = first_store + 49
        raw = image.read(begin, end - begin)
        counts = {'stack_load_to_rcx': 0, 'table_lea_to_rcx': 0, 'memory_store': 0}
        pos = 0
        while pos < len(raw):
            tail = raw[pos:]
            if tail.startswith(b'\x48\x8b\x4c\x24'):
                size, kind = 5, 'stack_load_to_rcx'
            elif tail.startswith(b'\x48\x8b\x8c\x24'):
                size, kind = 8, 'stack_load_to_rcx'
            elif tail.startswith(b'\x48\x8d\x0d'):
                size, kind = 7, 'table_lea_to_rcx'
            elif tail.startswith(b'\x48\x89\x0b'):
                size, kind = 3, 'memory_store'
            elif tail.startswith(b'\x48\x89\x4b'):
                size, kind = 4, 'memory_store'
            elif tail.startswith((b'\x48\x89\x8b', b'\x48\x89\xab', b'\x48\x89\x83',
                                  b'\x4c\x89\xa3', b'\x4c\x89\xab',
                                  b'\x4c\x89\xb3', b'\x4c\x89\xbb')):
                size, kind = 7, 'memory_store'
            else:
                raise ValueError('unrecognized prior builder flow instruction')
            require(pos + size <= len(raw), 'truncated prior builder flow instruction')
            counts[kind] += 1
            pos += size
        rows.append({'builder': source, 'begin': hex(begin), 'end_exclusive': hex(end),
                     'file_offset': hex(image.off(begin, len(raw))), 'bytes': raw.hex(),
                     'instruction_counts': counts, 'capture_aliases': aliases, 'capture_gaps': gaps})
    return rows


def decode_branch(image, va):
    raw = image.read(va, 2)
    if raw[0] in (0x74, 0x75):
        size, disp = 2, struct.unpack('b', raw[1:2])[0]
    elif raw == b'\x0f\x84' or raw == b'\x0f\x85':
        size = 6
        raw = image.read(va, size)
        disp = struct.unpack_from('<i', raw, 2)[0]
    else:
        raise ValueError('unexpected conditional branch')
    return {'va': hex(va), 'bytes': raw.hex(), 'target': hex(va + size + disp),
            'fallthrough': hex(va + size), 'condition': 'equal' if raw[0] == 0x74 or raw[:2] == b'\x0f\x84' else 'not_equal'}


def prior_closure_outcomes(image):
    """Selected exits in previously studied closures, as connection context."""
    rows = []
    message = b'called `Result::unwrap()` on an `Err` value'
    for group in (38, 39, 40):
        for lane in ('low', 'shared'):
            body = GROUPS[group][lane][1]
            initial = image.window(body + 0x14,
                                   '48c74424200000000048c74424280100000048c744243000000000')
            result = image.window(body + 0x41, '4c8bb4240801000048b804000000000000804939c6')
            branch = decode_branch(image, body + 0x56)
            require(branch['condition'] == 'not_equal' and int(branch['target'], 16) == body + 0x152,
                    'prior closure result branch changed')
            success_setup = image.window(
                body + 0x5c,
                '4c8b7424204c8b7c2428488b5424300f57c00f294424100f290424'
                '0f298424e00000000f298424d00000000f298424c00000000f298424b0000000'
                '0f298424a00000000f298424900000000f298424800000000f294424700f29442460'
                '0f294424500f294424400f294424300f2944242048c78424f000000088000000'
                '66c78424f80000000100488d7c24204c89fe')
            require(image.read(body + 0xeb, 2) == b'\xff\x15', 'prior hash-update call changed')
            failure_entry = image.window(body + 0x152,
                                         '488b9c24100100004c8bbc2418010000488b7424204885f6740d')
            require(image.read(body + 0x173, 2) == b'\xff\x15', 'prior optional cleanup call changed')
            failure_setup = image.window(body + 0x179,
                                         '4c89b4240801000048899c24100100004c89bc2418010000')
            lea = body + 0x191
            literal = image.target(lea, b'\x48\x8d\x3d')
            length = image.window(body + 0x1ae, 'be2b000000')
            require(image.read(literal, len(message)) == message, 'closure diagnostic bytes changed')
            rows.append({'group': group, 'lane': lane, 'closure': hex(body),
                         'writer_init': initial, 'result_check': result, 'branch': branch,
                         'success_setup': success_setup, 'hash_update_site': hex(body + 0xeb),
                         'failure_entry': failure_entry, 'failure_setup': failure_setup,
                         'optional_cleanup_site': hex(body + 0x173),
                         'diagnostic_lea': hex(lea), 'diagnostic_va': hex(literal),
                         'diagnostic_file_offset': hex(image.off(literal, len(message))),
                         'diagnostic_length': length, 'diagnostic_bytes': message.hex(),
                         'diagnostic': message.decode('ascii')})
    return rows


def regular_fields(image, group, lane, captures):
    start = GROUPS[group][lane][0]
    end = SELECTED[start][0]
    body = image.read(start, end - start)
    matches = list(STEP.finditer(body))
    require(len(matches) == GROUPS[group]['length'] - 1, 'unexpected regular step count')
    fields = []
    for index, m in enumerate(matches, 1):
        require(m.group(1)[0] == index * 8, 'field order changed')
        site = start + m.start()
        call = site + 12
        branch = decode_branch(image, start + m.end() - len(m.group(3)))
        require(branch['condition'] == 'not_equal', 'field result branch changed')
        fields.append({'group': group, 'lane': lane, 'index': index,
                       'state_offset': captures[index]['state_offset'],
                       'box_offset': hex(index * 8), 'load_va': hex(site),
                       'call_va': hex(call), 'callee': hex(image.target(call, b'\xe8')),
                       'branch_va': branch['va'], 'failure_target': branch['target'],
                       'step_bytes': m.group().hex()})
    require(len({r['failure_target'] for r in fields}) == 1, 'failure join changed')
    return fields


def special40(image, lane, captures):
    base = GROUPS[40][lane][0]
    # The positions are anchored by complete FDE hashes and fixed instruction
    # forms. Position 2 contains extra buffer setup; positions 0 and 3 branch.
    specs = [(0, 0x87, 0xb7, 'conditional_nil_or_child'),
             (1, 0xca, 0xd8, 'child'),
             (2, 0xe8, 0x1b0, 'buffer_then_child'),
             (3, 0x1c0, 0x1e7, 'inline_three_way_label'),
             (4, 0x296, 0x2a2, 'child'),
             (5, 0x2ae, 0x2bc, 'child'),
             (6, 0x2c8, 0x2d6, 'child'),
             (7, 0x2e2, 0x2f0, 'child')]
    rows = []
    for index, load_delta, call_delta, kind in specs:
        site, call = base + load_delta, base + call_delta
        raw = image.read(site, 4)
        if index == 0:
            require(raw[:3] == b'\x49\x8b\x06', 'first pointer load changed')
        else:
            require(raw[:2] == b'\x49\x8b' and raw[3] == index * 8, 'special field load changed')
        rows.append({'group': 40, 'lane': lane, 'index': index,
                     'state_offset': captures[index]['state_offset'], 'box_offset': hex(index * 8),
                     'load_va': hex(site), 'load_bytes': raw.hex(), 'call_va': hex(call),
                     'callee': hex(image.target(call, b'\xe8')), 'kind': kind})
    return rows


def literal_from_lea(image, site, length_offset):
    ptr = image.target(site, b'\x48\x8d\x35')
    nraw = image.read(site + length_offset, 5)
    require(nraw[0] == 0xba, 'literal length instruction changed')
    size = struct.unpack_from('<I', nraw, 1)[0]
    require(0 < size <= 32, 'literal length out of bounds')
    raw = image.read(ptr, size)
    return {'literal_va': hex(ptr), 'bytes': raw.hex(), 'text': raw.decode('ascii'),
            'length': size, 'lea_va': hex(site), 'lea_bytes': image.read(site, 7).hex()}


def enums(image):
    out = []
    for lane in ('low', 'shared'):
        base = GROUPS[38][lane][0]
        table = image.target(base + 0x7d, b'\x48\x8d\x0d')
        for tag in range(4):
            entry_va = table + 4 * tag
            raw = image.read(entry_va, 4)
            arm = table + struct.unpack('<i', raw)[0]
            require(base <= arm < SELECTED[base][0], 'enum arm outside selected FDE')
            row = literal_from_lea(image, arm, 12)
            row.update({'group': 38, 'index': 0, 'lane': lane, 'tag': tag,
                        'table': hex(table), 'table_entry': hex(entry_va),
                        'entry_bytes': raw.hex(), 'arm': hex(arm)})
            out.append(row)
        base = GROUPS[40][lane][0]
        for tag, delta in ((0, 0x262), (1, 0x1d8), ('other', 0x278)):
            row = literal_from_lea(image, base + delta, 7)
            row.update({'group': 40, 'index': 3, 'lane': lane, 'tag': tag,
                        'table': '', 'table_entry': '', 'entry_bytes': '', 'arm': hex(base + delta)})
            out.append(row)
    for group in (38, 40):
        a = [r['text'] for r in out if r['group'] == group and r['lane'] == 'low']
        b = [r['text'] for r in out if r['group'] == group and r['lane'] == 'shared']
        require(a == b, 'selected enum strings differ between lanes')
    require([r['text'] for r in out if r['group'] == 38 and r['lane'] == 'low']
            == ['Local', 'Sandbox', 'Testnet', 'Mainnet'], 'network labels changed')
    require([r['text'] for r in out if r['group'] == 40 and r['lane'] == 'low']
            == ['disabled', 'reduceOnly', 'enabled'], 'mode labels changed')
    return out


def named_field_context(image):
    # Existing keyed serializer: use selected load/key pairs only to identify
    # the captured data. This is context, not ownership of its containing FDE.
    specs = (
        (38, 1, 0x275b1d2, '4d8d86983a0000', 0x275b1d9, 'last_hlp_cancel_time'),
        (38, 2, 0x275b1fa, '4d8d86a43a0000', 0x275b201, 'post_only_until_time'),
        (38, 3, 0x275b222, '4d8b8688390000', 0x275b229, 'post_only_until_height'),
        (38, 4, 0x275b30a, '4d8b86c0390000', 0x275b311, 'prune_agent_idx'),
        (38, 5, 0x275b37f, '4d8d86a8320000', 0x275b386, 'register_token_gas_auction'),
        (38, 7, 0x275b046, '4d8d86d0370000', 0x275b04d, 'funding_update_guard'),
        (38, 8, 0x275b332, 'f2410f1086c8390000', 0x275b33b, 'max_hlp_withdraw_fraction_per_day'),
        (38, 10, 0x275b282, '4d8d86c0380000', 0x275b289, 'book_empty_user_states_pruning_guard'),
        (38, 11, 0x275b1aa, '4d8d86b0380000', 0x275b1b1,
         'cancel_aggressive_orders_at_open_interest_cap_guard'),
        (38, 12, 0x275add6, '458b86f0080000', 0x275addd, 'pdl'),
        (38, 13, 0x275b08a, '4d8d8648390000', 0x275b091, 'allowed_liquidators'),
        (39, 0, 0x275b122, 'f2410f108680390000', 0x275b12b, 'max_order_distance_from_anchor'),
        (39, 1, 0x275b14c, '4d8b86900b00004d8b8e980b0000', 0x275b15a, 'scheduled_freeze_height'),
        (39, 2, 0x275b17b, '4d8b86a00b00004d8b8ea80b0000', 0x275b189, 'simulate_crash_height'),
        (39, 3, 0x275b2e2, '458b86c83a0000', 0x275b2e9, 'spot_disabled'),
        (39, 4, 0x275ae3f, '4d8d86b8080000', 0x275ae46, 'qus'),
        (39, 5, 0x275b44b, '4d8d86f8380000', 0x275b452, 'begin_block_logic_guard'),
        (39, 6, 0x275b4f8, '450fb686c93a0000', 0x275b500, 'evm_enabled'),
        (39, 7, 0x275b4c7, '4d8b86a8310000f2410f1086b0310000', 0x275b4d7,
         'partial_liquidation_cooldown'),
        (39, 8, 0x275b3a7, '4d8d86e8320000', 0x275b3ae, 'perp_deploy_gas_auction'),
        (39, 9, 0x275b3cf, '4d8d8628330000', 0x275b3d6, 'spot_pair_deploy_gas_auction'),
        (39, 12, 0x275b591, '4d8d8638390000', 0x275b598, 'hip3_stale_mark_px_guard'),
        (39, 13, 0x275b5d5, '4d8d86b03a0000', 0x275b5dc, 'lvt'),
        (39, 14, 0x275b5fd, '450fb686ca3a0000', 0x275b605, 'hip3_no_cross'),
        (40, 1, 0x275b696, '450fb686cb3a0000', 0x275b69e, 'dex_abstraction_enabled'),
        (40, 5, 0x275aee7, '4d8b86e8080000', 0x275aeee, 'pmu'),
        (40, 7, 0x275b72f, '4d8b86683a0000', 0x275b736, 'pmn'),
    )
    rows = []
    for group, index, load, load_hex, lea, expected in specs:
        window = image.window(load, load_hex)
        raw_load = bytes.fromhex(load_hex)
        if raw_load[:3] in (b'\x4d\x8d\x86', b'\x4d\x8b\x86', b'\x45\x8b\x86'):
            displacement_pos = 3
        elif raw_load[:4] == b'\x45\x0f\xb6\x86':
            displacement_pos = 4
        elif raw_load[:5] == b'\xf2\x41\x0f\x10\x86':
            displacement_pos = 5
        else:
            raise ValueError('unexpected keyed load form')
        displacement = struct.unpack_from('<i', raw_load, displacement_pos)[0]
        require(displacement == EXPECTED_CAPTURES[group][index], 'keyed load does not match capture')
        ptr = image.target(lea, b'\x48\x8d\x15')
        length_instruction = image.read(lea + 10, 5)
        require(length_instruction[0] == 0xb9, 'key length instruction changed')
        length = struct.unpack_from('<I', length_instruction, 1)[0]
        require(0 < length <= 64, 'key length outside expected range')
        key = image.read(ptr, length)
        require(key == expected.encode('ascii'), 'key bytes changed')
        rows.append({'group': group, 'index': index, 'state_offset': hex(displacement),
                     'load_va': window['va'],
                     'load_bytes': window['bytes'], 'lea_va': hex(lea),
                     'lea_bytes': image.read(lea, 7).hex(), 'key_va': hex(ptr),
                     'key_file_offset': hex(image.off(ptr, length)),
                     'length_instruction': length_instruction.hex(), 'key_bytes': key.hex(),
                     'key': key.decode('ascii')})
    return rows


def small_u64_messagepack(value):
    """Prefix model limited to the integer cases pinned in this packet."""
    require(type(value) is int and 0 <= value < 0x10000, 'value outside prefix model')
    if value < 0x80:
        return bytes([value])
    if value < 0x100:
        return b'\xcc' + value.to_bytes(1, 'big')
    return b'\xcd' + value.to_bytes(2, 'big')


def prior_loader_dataflow(image):
    """Pin data offsets in the previously studied reload; do not claim it."""
    before = image.window(0x3272799, '488d7c2468488db424503b0000bae83a0000')
    clear = image.window(0x327280f, '48c78424f80b000000000000')
    after = image.window(0x3272940, '488d742468bae83a00004c89ff')
    incoming = bytes.fromhex(before['bytes'])
    store = bytes.fromhex(clear['bytes'])
    outgoing = bytes.fromhex(after['bytes'])
    base = incoming[4]
    copy_size = struct.unpack_from('<I', incoming, 14)[0]
    store_stack = struct.unpack_from('<I', store, 4)[0]
    require(outgoing[4] == base and struct.unpack_from('<I', outgoing, 6)[0] == copy_size,
            'prior loader copy setup changed')
    require(store_stack - base == EXPECTED_CAPTURES[39][1], 'prior clear is not at the captured offset')
    require(store_stack >= base and store_stack + 8 <= base + copy_size, 'prior clear outside copy')
    return {'copy_base_stack_offset': hex(base), 'copy_size': hex(copy_size),
            'clear_stack_offset': hex(store_stack), 'clear_offset_in_copy': hex(store_stack - base),
            'before': before, 'clear': clear, 'after': after}


def group39_prefix(float_bits, tag, payload):
    """Conditional static model: writes through the second field only."""
    require(type(float_bits) is int and 0 <= float_bits < 1 << 64, 'invalid f64 bits')
    require(type(tag) is int and 0 <= tag < 1 << 32, 'invalid tag')
    return bytes.fromhex('dc0010cb') + float_bits.to_bytes(8, 'big') + (
        small_u64_messagepack(payload) if tag == 1 else b'\xc0')


def analyse(image):
    captures = capture_groups(image)
    secondary_captures = capture_groups(image, 'secondary')
    primary_captures = capture_groups(image, 'primary')
    links = context_links(image)
    flows = prior_builder_flow(image, {'low': captures, 'secondary': secondary_captures,
                                       'primary': primary_captures})
    closure_outcomes = prior_closure_outcomes(image)
    fields = []
    openers = []
    sentinels = []
    for group in (38, 39):
        for lane in ('low', 'shared'):
            base = GROUPS[group][lane][0]
            marker_offset = 0x3a
            raw = image.read(base + marker_offset, 5)
            require(raw[0] == 0xba and struct.unpack_from('<I', raw, 1)[0] == GROUPS[group]['length'],
                    'group opener length changed')
            first_call = base + (0x7a if group == 38 else 0x85)
            # Enum dispatch has multiple label calls; one is retained in enums().
            if group == 39:
                require(image.target(first_call, b'\xe8') == (0x25aa640 if lane == 'low' else 0x4aeafc0),
                        'first float writer changed')
            fields.append({'group': group, 'lane': lane, 'index': 0,
                           'state_offset': captures[group][0]['state_offset'], 'box_offset': '0x0',
                           'kind': 'inline_enum' if group == 38 else 'f64_writer',
                           'load_va': hex(base + (0x77 if group == 38 else 0x7b)),
                           'call_va': '' if group == 38 else hex(first_call),
                           'callee': '' if group == 38 else hex(image.target(first_call, b'\xe8'))})
            fields.extend(regular_fields(image, group, lane, captures[group]))
    for lane in ('low', 'shared'):
        fields.extend(special40(image, lane, captures[40]))
    # The three builders are prior work; capture sites are connectivity
    # witnesses for these otherwise unowned serializer functions.
    for field in fields:
        group, index = field['group'], field['index']
        if field['lane'] == 'low':
            field['state_offset_basis'] = 'low_builder_capture'
            field['primary_state_offset'] = ''
        else:
            field['state_offset'] = secondary_captures[group][index]['state_offset']
            field['state_offset_basis'] = 'secondary_builder_capture'
            field['primary_state_offset'] = primary_captures[group][index]['state_offset']
    for group in (38, 39, 40):
        for lane in ('low', 'shared'):
            parent = GROUPS[group][lane][0]
            marker = parent + (0x46 if group == 40 else 0x3a)
            immediate = image.read(marker, 5)
            require(immediate[0] == 0xba and
                    struct.unpack_from('<I', immediate, 1)[0] == GROUPS[group]['length'],
                    'array opener length changed')
            call = marker + 5
            target = image.target(call, b'\xe8')
            require(target == (0x25a9bd0 if lane == 'low' else 0x4aea420),
                    'array opener target changed')
            openers.append({'group': group, 'lane': lane, 'length': GROUPS[group]['length'],
                            'length_va': hex(marker), 'length_bytes': immediate.hex(),
                            'call_va': hex(call), 'call_bytes': image.read(call, 5).hex(),
                            'callee': hex(target)})
            sentinel_va = parent + (0x17 if group == 40 else 0x13)
            sentinel_opcode = '49bd' if group == 40 else '49bc'
            sentinel = image.window(sentinel_va, sentinel_opcode + '0400000000000080')
            sentinel.update({'group': group, 'lane': lane,
                             'value': hex(struct.unpack('<Q', bytes.fromhex(sentinel['bytes'])[2:])[0])})
            sentinels.append(sentinel)
    variants = enums(image)
    names = named_field_context(image)
    loader_context = prior_loader_dataflow(image)
    names_by_position = {(row['group'], row['index']): row['key'] for row in names}
    for field in fields:
        field['key_context'] = names_by_position.get((field['group'], field['index']), '')
    # Parent serializer branches and the selected freeze-height option child.
    branches = []
    finishers = []
    for lane in ('low', 'shared'):
        for group, start_delta, first_delta, finish_delta in (
                (38, 0x4c, 0x108, 0x284),
                (39, 0x4c, 0x8e, 0x229),
                (40, 0x59, None, 0x304)):
            parent = GROUPS[group][lane][0]
            branch = decode_branch(image, parent + start_delta)
            require(branch['condition'] == 'not_equal', 'opener failure branch changed')
            branch.update({'lane': lane, 'group': group, 'role': 'opener_error'})
            branches.append(branch)
            if first_delta is not None:
                branch = decode_branch(image, parent + first_delta)
                require(branch['condition'] == 'not_equal', 'first value failure branch changed')
                branch.update({'lane': lane, 'group': group, 'role': 'first_value_error'})
                branches.append(branch)
            call = parent + finish_delta
            finishers.append({'lane': lane, 'group': group, 'call': hex(call),
                              'bytes': image.read(call, 5).hex(),
                              'callee': hex(image.target(call, b'\xe8'))})
        base = GROUPS[40][lane][0]
        for name, delta in (('first_nil', 0x8d), ('first_format_error', 0xc4),
                            ('second_child_error', 0xe2), ('third_child_error', 0x1ba),
                            ('third_buffer_open_error', 0x121),
                            ('third_buffer_item_error', 0x16e),
                            ('nil_capacity_empty', 0x219),
                            ('nil_capacity_still_empty', 0x222),
                            ('nil_allocation_success', 0x3a3),
                            ('nil_allocation_result', 0x3c8),
                            ('mode_zero', 0x1c9), ('mode_not_one', 0x1d2),
                            ('mode_write_error', 0x290), ('fifth_child_error', 0x2ac),
                            ('sixth_child_error', 0x2c6), ('seventh_child_error', 0x2e0),
                            ('eighth_child_error', 0x2fa)):
            b = decode_branch(image, base + delta)
            b.update({'lane': lane, 'group': 40, 'role': name})
            branches.append(b)
    for lane, base in (('low', 0x1e0fcc0), ('shared', 0x43f69d0)):
        image.window(base + 0x2d, '833a01')
        branch = decode_branch(image, base + 0x30)
        branch.update({'lane': lane, 'group': 39, 'role': 'freeze_tag_not_one'})
        branches.append(branch)
        image.window(base + 0x36, '488b5208')
        image.window(base + 0x125, 'c60430c0')
    helpers = []
    for lane, option, boolean, integer, option2 in (
            ('low', 0x1e0fcc0, 0x1e0fed0, 0x1e0f310, 0x1e10760),
            ('shared', 0x43f69d0, 0x43f94f0, 0x43f4700, 0x43f4840)):
        u64_writer = 0x25ac0d0 if lane == 'low' else 0x4aeca50
        assert_windows = ((option + 0x14, '49bc0000000000000080'),
                          (boolean + 0x14, '48bb0000000000000080'),
                          (integer + 0x14, '49bc0000000000000080'),
                          (option2 + 0x14, '49bc0000000000000080'),
                          (option + 0x2d, '833a01'),
                          (option + 0x36, '488b5208'),
                          (option + 0x125, 'c60430c0'),
                          (boolean + 0xd4, '0fb62a'),
                          (boolean + 0xe6, '4080cdc2400fb6fd'),
                          (integer + 0xcf, '488b12'),
                          (option2 + 0x2d, '833a02'),
                          (option2 + 0x56, 'c60430c0'))
        windows = [image.window(va, expected) for va, expected in assert_windows]
        for site in (option + 0x42, integer + 0xd8):
            require(image.target(site, b'\xe8') == u64_writer, 'integer writer target changed')
        calls = []
        for kind, site in (('option_u64', option + 0x42), ('boolean_marker', boolean + 0xee),
                           ('u64', integer + 0xd8), ('option_tag2_other', option2 + 0x122)):
            calls.append({'kind': kind, 'site': hex(site), 'bytes': image.read(site, 5).hex(),
                          'target': hex(image.target(site, b'\xe8'))})
        for kind, site in (('option_u64_result', option + 0x50),
                           ('option_allocation_success', option + 0x1aa),
                           ('boolean_capacity_empty', boolean + 0xe4),
                           ('boolean_allocation_success', boolean + 0x18a),
                           ('u64_result', integer + 0xe5),
                           ('option_tag2_other', option2 + 0x30),
                           ('option_tag2_allocation_success', option2 + 0x19d)):
            branch = decode_branch(image, site)
            branch.update({'lane': lane, 'group': '', 'role': kind})
            branches.append(branch)
        terminals = []
        for kind, va, expected in (
                ('option_child_error_copy', option + 0x56, '488b4c24104889430848894b10'),
                ('option_success', option + 0x12d, '4983c4044c8923'),
                ('option_allocation_error', option + 0x1ac,
                 '48c743080000000048b8030000002600000048894310'),
                ('boolean_success', boolean + 0x108, '4883c30449895d00'),
                ('boolean_allocation_error', boolean + 0x18c,
                 '49c745080000000048b8030000002600000049894510'),
                ('integer_success', integer + 0xe7, '4983c404eb0d'),
                ('integer_child_error_copy', integer + 0xed, '488b4c24084889430848894b10'),
                ('option_tag2_nil_success', option2 + 0x5e, '4983c4044c8923'),
                ('option_tag2_allocation_error', option2 + 0x19f,
                 '48c743080000000048b8030000002600000048894310')):
            terminal = image.window(va, expected)
            terminal['role'] = kind
            terminals.append(terminal)
        helpers.append({'lane': lane, 'option_tag1': hex(option), 'boolean': hex(boolean),
                        'integer': hex(integer), 'option_tag2': hex(option2),
                        'windows': windows, 'calls': calls, 'terminal_windows': terminals})
    error_copies = []
    for lane in ('low', 'shared'):
        for group in (38, 39, 40):
            if group == 40:
                va = GROUPS[group][lane][0] + 0x30b
                expected = '488b442418488943100f104424080f1103'
            else:
                va = GROUPS[group][lane][0] + (0x2b9 if group == 38 else 0x274)
                expected = '488b442410488943100f1004240f1103'
            row = image.window(va, expected)
            row.update({'group': group, 'lane': lane})
            error_copies.append(row)
    # Prior encoder windows are cited only as boundaries for the prefix model.
    context = [image.window(0x25a9bde, '81fa000001000f92c034dd83fa10'),
               image.window(0x25a9bec, '0fb6c0bd900000000f43e8'),
               image.window(0x25a9ce0, '66c1c008498b4e0866890431'),
               image.window(0x4aea42e, '81fa000001000f92c034dd83fa10'),
               image.window(0x4aea43c, '0fb6c0bd900000000f43e8'),
               image.window(0x4aea530, '66c1c008498b4e0866890431'),
               image.window(0x25acc63, '4080e60f4080ce9089f0c3'),
               image.window(0x4aed5e3, '4080e60f4080ce9089f0c3'),
               image.window(0x25aa665, '488b4308c60430cb'),
               image.window(0x25aa702, '66480f7ec0480fc8'),
               image.window(0x4aeafe5, '488b4308c60430cb'),
               image.window(0x4aeb082, '66480f7ec0480fc8'),
               image.window(0x25ac0e0, '4881fa00010000'),
               image.window(0x25ac100, '84d20f8813010000'),
               image.window(0x25ac115, '88143049ff4610'),
               image.window(0x25ac228, 'c60430cc'),
               image.window(0x25ac2ba, '4939f77479498b460888143049ff4610'),
               image.window(0x25ac12f, '4881fa00000100'),
               image.window(0x4aeca60, '4881fa00010000'),
               image.window(0x4aeca80, '84d20f8813010000'),
               image.window(0x4aeca95, '88143049ff4610'),
               image.window(0x4aecba8, 'c60430cc'),
               image.window(0x4aecc3a, '4939f77479498b460888143049ff4610'),
               image.window(0x4aecaaf, '4881fa00000100'),
               image.window(0x25ac5a7, 'c60401cd'),
               image.window(0x25ac639, '66c1c608488b4f0866893401'),
               image.window(0x4aecf27, 'c60401cd'),
               image.window(0x4aecfb9, '66c1c608488b4f0866893401'),
               image.window(0x25acc20, '89f80fb6c88d9140ffffff83fa207301c3'),
               image.window(0x4aed5a0, '89f80fb6c88d9140ffffff83fa207301c3')]
    require(image.target(0x25ac13d, b'\xe8') == 0x25ac580 and
            image.target(0x4aecabd, b'\xe8') == 0x4aecf00,
            '16-bit integer encoder call changed')
    # Inputs are synthetic raw words, never obtained from a running node.
    samples = []
    for bits, tag, value in ((0, 0, 42), (0, 1, 0), (0, 1, 42), (0, 1, 127),
                             (0, 1, 128), (0, 1, 255), (0, 1, 256),
                             (0x3ff0000000000000, 1, 65535), (0, 2, 42)):
        samples.append({'f64_bits': hex(bits), 'freeze_tag': tag, 'freeze_payload': value,
                        'prefix_hex': group39_prefix(bits, tag, value).hex()})
    function_rows = []
    for start in sorted(SELECTED):
        end, digest = SELECTED[start]
        fde = image.frames[start]
        function_rows.append({'start': hex(start), 'end_exclusive': hex(end), 'byte_count': end - start,
                              'file_offset': hex(image.off(start, end - start)), 'fde': hex(fde['fde']),
                              'cie': hex(fde['cie']), 'lsda': hex(fde['lsda']) if fde['lsda'] is not None else None,
                              'body_sha256': digest})
    return {'artifact_sha256': SHA256, 'coordinate_system': 'ELF link-time virtual address; file offset',
            'function_extents': function_rows, 'prior_context_links': links, 'prior_builder_flow': flows,
            'prior_closure_outcomes': closure_outcomes,
            'capture_groups': {source: {str(k): v for k, v in sorted(groups.items())}
                               for source, groups in (('low', captures), ('secondary', secondary_captures),
                                                      ('primary', primary_captures))},
            'fields': fields, 'openers': openers, 'sentinels': sentinels, 'enum_cases': variants,
            'named_field_context': names, 'branches': branches,
            'finishers': finishers, 'selected_helper_decisions': helpers, 'error_copies': error_copies,
            'prior_encoder_windows': context, 'prior_loader_dataflow': loader_context,
            'synthetic_group39_prefixes': samples,
            'limitations': ['Selected FDEs and fixed instruction forms only; no execution or whole-CFG proof.',
                            'Loader-to-hash object identity and runtime scheduling remain unresolved.',
                            'Runtime identity between any builder input and the reloaded object remains unresolved.',
                            'Prior builder, closures, encoder and loader are connectivity boundaries.']}


def tsv(rows, columns):
    stream = io.StringIO(newline='')
    writer = csv.writer(stream, delimiter='\t', lineterminator='\n')
    writer.writerow(columns)
    for row in rows:
        writer.writerow([row.get(k, '') for k in columns])
    return stream.getvalue()


def write_outputs(result, out):
    out.mkdir(parents=True, exist_ok=True)
    helper_returns = []
    for helper in result['selected_helper_decisions']:
        for window in helper['terminal_windows']:
            helper_returns.append({'lane': helper['lane'], **window})
    closure_exits = []
    for row in result['prior_closure_outcomes']:
        closure_exits.append({'group': row['group'], 'lane': row['lane'], 'closure': row['closure'],
                              'writer_init_va': row['writer_init']['va'],
                              'writer_init_bytes': row['writer_init']['bytes'],
                              'result_check_va': row['result_check']['va'],
                              'result_check_bytes': row['result_check']['bytes'],
                              'branch_va': row['branch']['va'], 'branch_bytes': row['branch']['bytes'],
                              'fallthrough': row['branch']['fallthrough'], 'error_target': row['branch']['target'],
                              'success_setup_bytes': row['success_setup']['bytes'],
                              'hash_update_site': row['hash_update_site'],
                              'failure_entry_bytes': row['failure_entry']['bytes'],
                              'failure_setup_va': row['failure_setup']['va'],
                              'failure_setup_bytes': row['failure_setup']['bytes'],
                              'diagnostic_va': row['diagnostic_va'], 'diagnostic_bytes': row['diagnostic_bytes']})
    files = {
        'evidence.json': json.dumps(result, indent=2, sort_keys=True) + '\n',
        'fields.tsv': tsv(result['fields'], ['group', 'lane', 'index', 'box_offset', 'state_offset',
                                              'state_offset_basis', 'primary_state_offset', 'key_context', 'kind',
                                              'load_va', 'load_bytes', 'call_va', 'callee', 'branch_va',
                                              'failure_target', 'step_bytes']),
        'enums.tsv': tsv(result['enum_cases'], ['group', 'lane', 'index', 'tag', 'table', 'table_entry',
                                                'entry_bytes', 'arm', 'lea_va', 'lea_bytes', 'literal_va',
                                                'length', 'bytes', 'text']),
        'key-context.tsv': tsv(result['named_field_context'], ['group', 'index', 'state_offset',
                                                               'load_va', 'load_bytes',
                                                               'lea_va', 'lea_bytes', 'key_va',
                                                               'key_file_offset', 'length_instruction',
                                                               'key_bytes', 'key']),
        'branches.tsv': tsv(result['branches'], ['group', 'lane', 'role', 'va', 'bytes', 'condition',
                                                 'fallthrough', 'target']),
        'helper-returns.tsv': tsv(helper_returns, ['lane', 'role', 'va', 'file_offset', 'bytes']),
        'closure-exits.tsv': tsv(closure_exits, ['group', 'lane', 'closure', 'writer_init_va',
                                                  'writer_init_bytes', 'result_check_va', 'result_check_bytes',
                                                  'branch_va', 'branch_bytes', 'fallthrough', 'error_target',
                                                  'success_setup_bytes', 'hash_update_site',
                                                  'failure_entry_bytes', 'failure_setup_va', 'failure_setup_bytes',
                                                  'diagnostic_va', 'diagnostic_bytes']),
        'prefixes.tsv': tsv(result['synthetic_group39_prefixes'], ['f64_bits', 'freeze_tag',
                                                                  'freeze_payload', 'prefix_hex']),
    }
    for name, text in files.items():
        (out / name).write_text(text, encoding='utf-8', newline='\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    with TARGET.open('rb') as source, mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ) as data:
        result = analyse(Image(data))
    write_outputs(result, args.out)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, struct.error, UnicodeError) as exc:
        raise SystemExit('abci_root_groups94: ' + str(exc))
