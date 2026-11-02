#!/usr/bin/env python3
"""Recover selected outcome-tracker codec decisions from the authenticated ELF."""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import re
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections, unwind_index
from fde_extents import eh_frame_records

SHA = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
BINARY = ROOT / 'artifacts/node/94/hl-node'
# Complete FDE body hashes guard the selected instruction interpretations.
BODY_HASH = {
    0x1e0d400: '4db60fe88005e74b874c7b29f56caed0a88d3d65494b2aee8ada3b150f28972c',
    0x1de62f0: '9d4b68cf1351de522437bdef53bca3c15d5b66807e4eb52b7afcb95b481ae40a',
    0x1e372f0: 'dcb51843783da10f6af9c847be5a08f5ca6f604d3f9f8cfd789b9bb8b6a2d6b0',
    0x1fec530: '281a07f9bedf9fffdb9f64ab3f6096a8b6bd9a342a46cf8faebbf54d4f4aae9e',
    0x1fef560: 'ab514985a66ba76699afb9f4b9599a699e05d4b65720186e7608f1238ff459d1',
    0x202c6c0: 'd79f1763045e75d391f9a687837ff95813cffe65376510d847e2afe3fa33ac87',
    0x202bf40: '26e5ff7bfb97d32c83bae54dbf64443eeedf48baecd936ede545c11ee0af4700',
    0x202c210: '83a6f79270461bbb1e120616058f3e239a35661ebba5ae3e9d43a8f545329b68',
    0x202a5f0: 'ed5f180dd2903870176c4d1a0d0954130051de3c58211782d8b03688dbcb6c06',
    0x202b130: '7d50ef2d1ca2281bdb86b0720841719dd5f9be1b29039d83ffba16afdb7adfd0',
    0x16e2850: '0b5c6f1aaac2091f76d97fe1d0b997fb5d7aeb3bc31d811d3d68a8326d926db3',
    0x17f0a00: '2b5e6382eaee5a5d38512e24b78b9b78ce7aef78ab3785169a000ff3fc37c1fb',
    0x2390b60: 'f1a5a8e15bee1b3de61219c95dd868cd87c4ee2f718b54c81b6cd97a4fff104e',
    0x23d7d00: '9a4737b934e0eedeb66b4c093e644464deaecedac251974d63c1000f321fabf0',
    0x26d06d0: '3419949d4fbf68469470861778f98d4911ebda7bf9fb228cbff4eaf543ca7125',
    0x26d0b30: '251bea3e5d45bd7036d3d5c0ee239fe591bd3eeb56ba2e9824ce245835226b55',
    0x27b1fa0: '5f1de53bf6c844f56723585fd6e365e72da44b136b9a86e9901822671197e8e4',
    0x27b21f0: 'f72c56c07614edecc3c9619f3f80de8f4eec213c9916d87f40e6576e4836c591',
    0x27b23a0: '4b1692ff9c3050106c808f282c3e4d5e67fafe00091321a9fd5b2ca2d4db92c2',
    0x27b2400: '3b3fbb73d202a834ee474da62992e8b1574ee7e6f4de079d8caa0c53de81e020',
    0x27b2f30: '30c9c20907d5910212bf85845332e1bd2b8eb55aad56ea4c55dd48709f566959',
    0x27b3300: '1747202bbea793bce2bbdca3a503a432b69942906674d47e2b52068c626d4f9f',
    0x27b46b0: '12234dd30a2853489557ff121070b082f2a0d7f06fbfdb6f4de213bae98d2a75',
}
# Exact instruction starts: writer key, data load, JSON key, JSON data load.
# Last five keys live in their own named-field wrappers.
FIELD_SITES = [
    (0x26d074b, 0x26d0769, 0x26d0b80, None, None),
    (0x26d07d2, 0x26d07f0, 0x26d0bb4, 0x26d0bad, None),
    (0x26d0817, 0x26d0835, 0x26d0be5, 0x26d0bde, None),
    (0x26d0865, 0x26d0855, 0x26d0c16, 0x26d0c0f, None),
    (0x26d08b0, 0x26d08a1, 0x26d0c47, 0x26d0c40, None),
    (0x26d08ee, 0x26d08e7, 0x26d0c78, 0x26d0c71, None),
    (0x26d0916, 0x26d090f, 0x26d0ca9, 0x26d0ca2, None),
    (0x26d093f, 0x26d0937, 0x26d0cda, 0x26d0cd3, None),
    (0x27b1fb1, 0x26d0960, 0x27afcc4, 0x26d0cf9, 0x27b1fa0),
    (0x27b23b1, 0x26d0979, 0x27b10f4, 0x26d0d0c, 0x27b23a0),
    (0x27b3311, 0x26d0992, 0x27af8b4, 0x26d0d1f, 0x27b3300),
    (0x27b2411, 0x26d09ae, 0x27b0db4, 0x26d0d35, 0x27b2400),
    (0x27b2f41, 0x26d09ca, 0x27af6d4, 0x26d0d4b, 0x27b2f30),
]


def require(ok, message):
    if not ok:
        raise ValueError(message)


class Elf:
    def __init__(self, data, expected_sha=SHA):
        require(hashlib.sha256(data).hexdigest() == expected_sha, 'input digest mismatch')
        self.data = data
        self.secs, table = unwind_index(data)
        _, frames = eh_frame_records(data, self.secs)
        fde_by_record = {f['fde']: f for f in frames}
        indexed = {e['start']: e for e in table}
        self.frames = {}
        for start, expected in BODY_HASH.items():
            entry = indexed.get(start)
            require(entry is not None, 'missing indexed FDE')
            frame = fde_by_record.get(entry['fde'])
            require(frame is not None and frame['start'] == start and frame['end'] > start,
                    'FDE start mismatch')
            raw = self.read(start, frame['end'] - start, executable=True)
            require(hashlib.sha256(raw).hexdigest() == expected, 'selected body mismatch')
            self.frames[start] = frame

    def read(self, va, count, executable=False):
        require(type(va) is int and type(count) is int and va >= 0 and count >= 0,
                'bad address or size')
        choices = [s for s in self.secs if s['type'] != 8 and
                   (not executable or s['flags'] & 4) and
                   s['address'] <= va and va + count <= s['address'] + s['size']]
        require(len(choices) == 1, 'VA is not uniquely file backed')
        s = choices[0]
        off = s['offset'] + va - s['address']
        return self.data[off:off + count]

    def offset(self, va):
        matches = [s for s in self.secs if s['type'] != 8 and
                   s['address'] <= va < s['address'] + s['size']]
        require(len(matches) == 1, 'VA is not uniquely file backed')
        return matches[0]['offset'] + va - matches[0]['address']

    def s32(self, va):
        return struct.unpack('<i', self.read(va, 4))[0]

    def rel32(self, site, opcode):
        op = self.read(site, len(opcode), executable=True)
        require(op == opcode, 'unexpected relative instruction')
        return site + len(opcode) + 4 + self.s32(site + len(opcode))

    def lea(self, site):
        raw = self.read(site, 7, executable=True)
        require(raw[:2] == b'\x48\x8d' and raw[2] in (0x05, 0x0d, 0x15, 0x35), 'not a pinned RIP lea')
        return site + 7 + struct.unpack('<i', raw[3:])[0]


def writer_key(elf, site, json_style=False, wrapper=False):
    target = elf.lea(site)
    if wrapper:
        code = elf.read(site + 7, 5, executable=True)
        require(code[0] == 0xba, 'wrapper key length encoding')
        size = struct.unpack('<I', code[1:])[0]
    elif json_style:
        code = elf.read(site + 7, 10, executable=True)
        require(code[:5] == b'\x48\x8d\x7c\x24\x08' and code[5] == 0xba, 'JSON key length encoding')
        size = struct.unpack('<I', code[6:])[0]
    else:
        code = elf.read(site + 7, 14, executable=True)
        if code[0] == 0xba:
            size = struct.unpack('<I', code[1:5])[0]
        else:
            require(code[:4] == b'\x48\x89\xe7\xb9', 'named scalar key length encoding')
            size = struct.unpack('<I', code[4:8])[0]
    require(0 < size <= 8, 'bad field length')
    return target, elf.read(target, size).decode('ascii')


def load_offset(elf, site, style):
    code = elf.read(site, 9, executable=True)
    prefixes = {
        'mp': (b'\x49\x8b\x96', b'\x4d\x8b\x86', b'\x45\x0f\xb6\xa6',
               b'\x45\x0f\xb6\x86', b'\xf2\x41\x0f\x10\x86'),
        'json': (b'\x48\x8d\x8b',),
    }
    for prefix in prefixes[style]:
        if code.startswith(prefix):
            return struct.unpack('<i', code[len(prefix):len(prefix)+4])[0]
    if style == 'mp' and code.startswith(b'\x41\x83\x3e\x02'):
        return 0
    if style == 'mp' and code.startswith(b'\x49\x8d\x56'):
        return code[3]
    if style == 'mp' and code.startswith((b'\x49\x8d\x96', b'\x49\x81\xc6')):
        return struct.unpack('<i', code[3:7])[0]
    if style == 'json' and code.startswith(b'\x48\x8d\x73'):
        return code[3]
    if style == 'json' and code.startswith((b'\x48\x8d\xb3', b'\x48\x81\xc3')):
        return struct.unpack('<i', code[3:7])[0]
    raise ValueError('unexpected field load')


def run_classifier(elf, key):
    """Interpret the selected x86 byte predicates and jump table, not node execution."""
    require(isinstance(key, bytes) and len(key) <= 0xffffffff, 'invalid key')
    lo, hi = elf.frames[0x16e2850]['start'], elf.frames[0x16e2850]['end']
    pc, eax, ecx, zf, cf, result, status = lo, 0, 0, False, False, None, None
    for _ in range(100):
        require(lo <= pc < hi, 'classifier branch outside FDE')
        p = elf.read(pc, min(16, hi-pc), executable=True)
        def byte(at):
            require(0 <= at < len(key), 'classifier read outside key')
            return key[at]
        def compare(a, b):
            return a == b, a < b
        if p[:2] == b'\x83\xfa':
            zf, cf = compare(len(key) & 0xffffffff, p[2]); pc += 3
        elif p[:2] == b'\x83\xf8':
            zf, cf = compare(eax & 0xffffffff, p[2]); pc += 3
        elif p[:2] == b'\x83\xc0':
            eax = (eax + struct.unpack('b', p[2:3])[0]) & 0xffffffff; pc += 3
        elif p[0] in (0x74, 0x75, 0x77, 0xeb):
            take = {0x74: zf, 0x75: not zf, 0x77: not cf and not zf, 0xeb: True}[p[0]]
            delta = struct.unpack('b', p[1:2])[0]; pc = pc + 2 + (delta if take else 0)
        elif p[:2] in (b'\x0f\x84', b'\x0f\x85'):
            take = zf if p[1] == 0x84 else not zf
            delta = struct.unpack('<i', p[2:6])[0]; pc = pc + 6 + (delta if take else 0)
        elif p[0] == 0xe9:
            pc += 5 + struct.unpack('<i', p[1:5])[0]
        elif p[:3] == b'\x0f\xb6\x06':
            eax = byte(0); pc += 3
        elif p[:3] == b'\x0f\xb6\x46':
            eax = byte(p[3]); pc += 4
        elif p[:3] == b'\x48\x8d\x0d':
            ecx = elf.lea(pc); pc += 7
        elif p[:4] == b'\x48\x63\x04\x81':
            require(0 <= eax <= 17, 'classifier jump index outside table')
            eax = elf.s32(ecx + 4 * eax); pc += 4
        elif p[:3] == b'\x48\x01\xc8':
            eax += ecx; pc += 3
        elif p[:2] == b'\xff\xe0':
            pc = eax
        elif p[:2] == b'\x80\x3e':
            zf, cf = compare(byte(0), p[2]); pc += 3
        elif p[:2] == b'\x80\x7e':
            zf, cf = compare(byte(p[2]), p[3]); pc += 4
        elif p[:2] == b'\x31\xc0':
            eax = 0; zf, cf = True, False; pc += 2
        elif p[0] == 0xb0:
            eax = (eax & ~0xff) | p[1]; pc += 2
        elif p[0] == 0xb8:
            eax = struct.unpack('<I', p[1:5])[0]; pc += 5
        elif p[0] == 0x3c:
            zf, cf = compare(eax & 255, p[1]); pc += 2
        elif p[:3] == b'\x0f\x95\xc1':
            ecx = (ecx & ~0xff) | int(not zf); pc += 3
        elif p[:2] == b'\x00\xc9':
            v = (ecx & 255) * 2; ecx = (ecx & ~255) | (v & 255)
            zf, cf = (v & 255) == 0, v > 255; pc += 2
        elif p[:2] == b'\x80\xc1':
            v = (ecx & 255) + p[2]; ecx = (ecx & ~255) | (v & 255)
            zf, cf = (v & 255) == 0, v > 255; pc += 3
        elif p[:3] == b'\x0f\xb6\xc9':
            ecx &= 255; pc += 3
        elif p[:3] == b'\x0f\x45\xc1':
            if not zf: eax = ecx & 0xffffffff
            pc += 3
        elif p[:3] == b'\x88\x47\x01':
            result = eax & 255; pc += 3
        elif p[:2] == b'\xc6\x07':
            status = p[2]; pc += 3
        elif p[0] == 0xc3:
            require(status is not None and result is not None, 'classifier missing output')
            return status, result
        else:
            raise ValueError('unsupported classifier instruction at %#x' % pc)
    raise ValueError('classifier step limit')


def diagnostic(elf, address):
    target = elf.lea(address)
    tail = elf.read(address+7, 15, executable=True)
    require(tail[:10] == b'\x48\x89\x44\x24\x70\x48\xc7\x44\x24\x78', 'diagnostic shape')
    size = struct.unpack('<I', tail[10:14])[0]
    require(0 < size < 16, 'diagnostic length')
    return elf.read(target, size).decode('ascii'), target


def reader_dispatch(elf):
    table = elf.lea(0x17f3584)
    rows = []
    for selector in range(14):
        cell = table + 4 * selector
        target = table + elf.s32(cell)
        require(elf.frames[0x17f0a00]['start'] <= target < elf.frames[0x17f0a00]['end'],
                'reader table target outside FDE')
        if selector == 13:
            # The last arm calls the unknown-value consumer.
            require(elf.read(target, 10, executable=True) == bytes.fromhex('488dbc24800100004c89'), 'unknown arm changed')
            rows.append({'selector': selector, 'entry_va': hex(cell), 'arm_va': hex(target),
                         'key': None, 'duplicate_target_va': None})
            continue
        code = elf.read(target, 15, executable=True)
        if code[:3] == b'\x48\x83\xbc':
            require(code[3] == 0x24 and code[9:11] in (b'\x0f\x84', b'\x0f\x85'), 'bad reader guard')
            branch = target + 9
        elif code[:2] in (b'\x40\x80', b'\x41\x80'):
            require(code[4:6] == b'\x0f\x85', 'bad byte guard')
            branch = target + 4
        else:
            raise ValueError('unknown reader guard')
        op = elf.read(branch, 2, executable=True)
        dest = elf.rel32(branch, op)
        name, name_va = diagnostic(elf, dest)
        rows.append({'selector': selector, 'entry_va': hex(cell), 'arm_va': hex(target),
                     'guard_hex': elf.read(target, branch+6-target).hex(),
                     'duplicate_target_va': hex(dest), 'key_va': hex(name_va), 'key': name})
    return table, rows


# Calls and their subsequent failure branches in the two selected writers.
MP_DECISIONS = [
    (0, 'key', 0x26d075a, 0x26d0763), (0, 'value', 0x26d07b8, 0x26d07c5),
    (1, 'key', 0x26d07e1, 0x26d07ea), (1, 'value', 0x26d07fd, 0x26d080a),
    (2, 'key', 0x26d0826, 0x26d082f), (2, 'value', 0x26d0842, 0x26d084f),
    (3, 'key', 0x26d087a, 0x26d0889), (3, 'value', 0x26d0892, 0x26d089b),
    (4, 'key', 0x26d08bf, 0x26d08c8), (4, 'value', 0x26d08d8, 0x26d08e1),
    (5, 'key_and_value', 0x26d0900, 0x26d0909),
    (6, 'key_and_value', 0x26d0928, 0x26d0931),
    (7, 'key_and_value', 0x26d0951, 0x26d095a),
    (8, 'wrapper', 0x26d096a, 0x26d0973), (9, 'wrapper', 0x26d0983, 0x26d098c),
    (10, 'wrapper', 0x26d099f, 0x26d09a8), (11, 'wrapper', 0x26d09bb, 0x26d09c4),
    (12, 'wrapper', 0x26d09da, 0x26d09e3),
]
JSON_DECISIONS = [
    (0, 0x26d0b94, 0x26d0b9c), (1, 0x26d0bc5, 0x26d0bcd),
    (2, 0x26d0bf6, 0x26d0bfe), (3, 0x26d0c27, 0x26d0c2f),
    (4, 0x26d0c58, 0x26d0c60), (5, 0x26d0c89, 0x26d0c91),
    (6, 0x26d0cba, 0x26d0cc2), (7, 0x26d0ceb, 0x26d0cf3),
    (8, 0x26d0d02, 0x26d0d0a), (9, 0x26d0d15, 0x26d0d1d),
    (10, 0x26d0d2b, 0x26d0d33), (11, 0x26d0d41, 0x26d0d49),
    (12, 0x26d0d5a, 0x26d0d62),
]


def decision(elf, index, stage, call, branch, writer):
    target = elf.rel32(call, b'\xe8')
    raw = elf.read(branch, 2, executable=True)
    if raw == b'\x0f\x85':
        dest = elf.rel32(branch, raw)
        branch_raw = elf.read(branch, 6, executable=True)
    elif raw[0] == 0x75:
        dest = branch + 2 + struct.unpack('b', raw[1:])[0]
        branch_raw = raw
    else:
        raise ValueError('unexpected failure branch')
    frame = elf.frames[writer]
    require(frame['start'] <= dest < frame['end'], 'failure branch outside writer')
    return {'field_index': index, 'stage': stage, 'call_va': hex(call),
            'call_hex': elf.read(call, 5, executable=True).hex(),
            'between_call_and_branch_hex': elf.read(call + 5, branch - call - 5, executable=True).hex(),
            'callee_va': hex(target), 'branch_va': hex(branch),
            'branch_hex': branch_raw.hex(), 'failure_va': hex(dest)}


def small_sort_model(items, limit):
    """Model the bounded backward insertion loop; this does not execute target code."""
    require(isinstance(items, list) and len(items) < limit, 'outside small sort range')
    require(all(isinstance(row, tuple) and len(row) == 2 and type(row[0]) is int and
                0 <= row[0] < 1 << 64 for row in items), 'invalid sort model rows')
    rows = list(items)
    for i in range(len(rows) - 2, -1, -1):
        saved = rows[i]
        j = i
        while j + 1 < len(rows) and rows[j + 1][0] < saved[0]:
            rows[j] = rows[j + 1]
            j += 1
        rows[j] = saved
    return rows


def type_record(elf):
    slot = elf.lea(0x17f1361)
    rela_sections = [s for s in elf.secs if s['name'] == '.rela.dyn' and s['type'] == 4]
    require(len(rela_sections) == 1, 'missing unique relocation section')
    section = rela_sections[0]
    require(section['size'] % 24 == 0, 'bad relocation section size')
    raw = elf.data[section['offset']:section['offset'] + section['size']]
    matches = []
    for index, (address, info, addend) in enumerate(struct.iter_unpack('<QQq', raw)):
        if address == slot:
            matches.append((index, info, addend))
    require(len(matches) == 1, 'type diagnostic relocation is not unique')
    index, info, addend = matches[0]
    require(info == 8 and addend >= 0, 'type diagnostic relocation is not RELATIVE')
    size = struct.unpack('<Q', elf.read(slot + 8, 8))[0]
    require(0 < size <= 128, 'type diagnostic length')
    literal = elf.read(addend, size).decode('ascii')
    match = re.fullmatch(r'struct ([A-Za-z][A-Za-z0-9_]*) with ([0-9]+) elements', literal)
    require(match is not None, 'type diagnostic string mismatch')
    off = section['offset'] + 24 * index
    return {'reader_lea_va': hex(0x17f1361), 'slot_va': hex(slot),
            'relocation_file_offset': hex(off), 'relocation_hex': bytes(elf.data[off:off+24]).hex(),
            'literal_va': hex(addend), 'literal_hex': elf.read(addend, size).hex(),
            'literal': literal, 'type_name': match.group(1), 'element_count': int(match.group(2))}


def build(data, expected_sha=SHA):
    elf = Elf(data, expected_sha)
    table, dispatch = reader_dispatch(elf)
    type_info = type_record(elf)
    rows = []
    for index, (mp_key, mp_load, json_key, json_load, wrapper) in enumerate(FIELD_SITES):
        mp_va, key = writer_key(elf, mp_key, wrapper=wrapper is not None)
        json_va, json_name = writer_key(elf, json_key, json_style=wrapper is None, wrapper=wrapper is not None)
        require(key == json_name, 'writer field names disagree')
        offset = load_offset(elf, mp_load, 'mp')
        if json_load is not None:
            require(offset == load_offset(elf, json_load, 'json'), 'writer field offsets disagree')
        status, selector = run_classifier(elf, key.encode('ascii'))
        require(status == 9 and selector == index and dispatch[index]['key'] == key,
                'reader and writer field order disagree')
        rows.append({'index': index, 'key': key, 'object_offset': hex(offset),
                     'mp_key_site': hex(mp_key), 'mp_key_va': hex(mp_va), 'mp_load_site': hex(mp_load),
                     'json_key_site': hex(json_key), 'json_key_va': hex(json_va),
                     'json_load_site': hex(json_load) if json_load is not None else None,
                     'wrapper_va': hex(wrapper) if wrapper is not None else None,
                     'reader_arm_va': dispatch[index]['arm_va'],
                     'duplicate_target_va': dispatch[index]['duplicate_target_va']})
    require(len(set(r['key'] for r in rows)) == len(rows), 'duplicate writer field')
    # Decode and check the outer serializer wrapper and the branch to its child.
    parent_call = elf.rel32(0x2390e35, b'\xe8')
    wrapper_child = elf.rel32(0x23d7d3c, b'\xe9')
    wrapper_key_va, wrapper_key = writer_key(elf, 0x23d7d11, wrapper=True)
    require(parent_call == 0x23d7d00 and wrapper_child == 0x26d06d0, 'parent call chain changed')
    require(elf.read(0x26d06fd, 1, True) == b'\xba' and elf.read(0x26d0730, 1, True) == b'\xba', 'header shape')
    map_count = struct.unpack('<I', elf.read(0x26d06fe, 4))[0]
    array_count = struct.unpack('<I', elf.read(0x26d0731, 4))[0]
    require(map_count == array_count == len(rows) == type_info['element_count'], 'header count mismatch')
    mp_decisions = [decision(elf, index, stage, call, branch, 0x26d06d0)
                    for index, stage, call, branch in MP_DECISIONS]
    json_decisions = [decision(elf, index, 'field', call, branch, 0x26d0b30)
                      for index, call, branch in JSON_DECISIONS]
    for row in rows[8:]:
        edge = next(d for d in mp_decisions if d['field_index'] == row['index'])
        require(edge['callee_va'] == row['wrapper_va'], 'named wrapper call mismatch')
    # Follow all five named collection wrappers to their adapter's three calls.
    tails = [0x27b1fdc, 0x27b23dc, 0x27b333c, 0x27b243c, 0x27b2f6c]
    nested = []
    for field_index, tail in enumerate(tails, 8):
        adapter = elf.rel32(tail, b'\xe9')
        require(adapter in elf.frames, 'adapter FDE missing')
        calls = [adapter + off for off in (0x50, 0x65, 0x88)]
        targets = [elf.rel32(site, b'\xe8') for site in calls]
        nested.append({'field_index': field_index, 'key': rows[field_index]['key'],
                       'wrapper_tail_va': hex(tail), 'adapter_va': hex(adapter),
                       'collect_site_va': hex(calls[0]), 'collect_target_va': hex(targets[0]),
                       'sort_site_va': hex(calls[1]), 'sort_target_va': hex(targets[1]),
                       'emit_site_va': hex(calls[2]), 'emit_target_va': hex(targets[2])})
    require([nested[i]['sort_target_va'] for i in (1, 2)] == ['0x1fec530', '0x1fef560'], 'sort binding')
    require(nested[1]['emit_target_va'] == nested[2]['emit_target_va'] == '0x1e372f0', 'emit binding')
    small = elf.read(0x1fec530, 0xd7, executable=True)
    require(small == elf.read(0x1fef560, 0xd7, executable=True), 'small sort copies differ')
    require(small[0x1c:0x1f] == b'\x48\x83\xfe' and small[0x37:0x3a] == b'\x48\xc1\xe1', 'sort setup shape')
    require(small[0x6c:0x73] == bytes.fromhex('4c8b0e4d390873'), 'sort comparison shape')
    limit, stride = small[0x1f], 1 << small[0x3a]
    require(limit == 21 and stride == 16, 'sort thresholds changed')
    sample_in = [(3, 'a'), (0, 'b'), (3, 'c'), (2, 'd')]
    sample_out = small_sort_model(sample_in, limit)
    require(elf.rel32(0x1e37357, b'\xe8') == 0x25a9bd0 and
            elf.rel32(0x1e373af, b'\xe8') == 0x1de62f0 and
            elf.rel32(0x1e374de, b'\xe8') == 0x1de62f0 and
            elf.rel32(0x17f3426, b'\xe8') == 0x16e2850 and
            elf.rel32(0x1de6353, b'\xe8') == 0x25a9bd0 and
            elf.rel32(0x1de63a0, b'\xe8') == 0x1e0d400 and
            elf.rel32(0x1de63b9, b'\xe8') == 0x1e0d400 and
            elf.rel32(0x1e0d4d8, b'\xe8') == 0x25ac0d0, 'nested sequence calls')
    sites = [0x17f3426, 0x17f3b52, 0x1e37357, 0x1e373af, 0x1e374de,
             0x1de6353, 0x1de63a0, 0x1de63b9, 0x1e0d4d8]
    edges = [{'site_va': hex(site), 'target_va': hex(elf.rel32(site, b'\xe8')),
              'bytes_hex': elf.read(site, 5, executable=True).hex()} for site in sites]
    missing = []
    for address in (0x17f0f1f, 0x17f0f8d, 0x17f10f4, 0x17f145d):
        name, name_va = diagnostic(elf, address)
        template = elf.lea(address + 43)
        require(elf.read(template, 15) == b'\x0fmissing field ', 'missing template changed')
        missing.append({'key': name, 'site_va': hex(address), 'key_va': hex(name_va),
                        'template_va': hex(template)})
    # The fifth missing-field diagnostic has a larger stack-address encoding.
    name_va = elf.lea(0x17f15a3)
    template = elf.lea(0x17f15d7)
    require(elf.read(template, 15) == b'\x0fmissing field ', 'missing template changed')
    require(elf.read(0x17f15b2, 12, True) == bytes.fromhex('48c78424b803000003000000'), 'missing key length')
    missing.append({'key': elf.read(name_va, 3).decode('ascii'), 'site_va': hex(0x17f15a3),
                    'key_va': hex(name_va), 'template_va': hex(template)})
    windows = []
    fixed_windows = [
        ('outer-parent-to-wrapper', 0x2390e2a, 29),
        ('outer-key-gate', 0x23d7d0b, 54),
        ('header-choice', 0x26d06f1, 83),
        ('dga-nil-decision', 0x26d0769, 57),
        ('uoa-marker-decision', 0x27b21f0, 117),
        ('reader-field-classifier-call', 0x17f3400, 70),
        ('reader-map-selector', 0x17f3572, 34),
        ('reader-map-completion-branch', 0x17f3d6e, 27),
        ('reader-map-end-defaults', 0x17f2d5b, 157),
        ('fs-reader-arm', 0x17f39db, 83),
        ('ndo-reader-arm', 0x17f3af1, 81),
        ('mut-reader-arm', 0x17f3b6c, 81),
        ('reader-missing-nou-nqu', 0x17f2e4c, 54),
        ('reader-unknown-arm', int(dispatch[13]['arm_va'], 16), 37),
        ('small-sort-loop', 0x1fec530, 0xd7),
        ('sequence-header-and-item', 0x1e3734c, 120),
        ('sequence-loop-and-item', 0x1e374a3, 87),
        ('item-pair-header', 0x1de6343, 41),
        ('item-two-value-calls', 0x1de6396, 47),
        ('item-qword-write', 0x1e0d4cf, 31),
    ]
    for label, address, length in fixed_windows:
        windows.append({'label': label, 'va': hex(address), 'file_offset': hex(elf.offset(address)),
                        'bytes_hex': elf.read(address, length, executable=True).hex()})
    # The map-completion path supplies zero when these three presence bits are clear.
    require(elf.rel32(0x17f3d7a, b'\x0f\x84') == 0x17f2d5b, 'map completion branch')
    require(elf.read(0x17f2d7d, 2, True) == b'\x31\xc0', 'missing zero source')
    fs = elf.read(0x17f2d5b, 22, True)
    require(fs[:3] == b'\xf6\x84\x24' and fs[7:18] ==
            bytes.fromhex('01750c0f57c0f20f118424'), 'floating default shape')
    default_rows = [{'key': dispatch[3]['key'], 'test_va': hex(0x17f2d5b),
                     'presence_stack_offset': hex(struct.unpack('<I', fs[3:7])[0]),
                     'value_stack_offset': hex(struct.unpack('<I', fs[18:22])[0]),
                     'default_bits': '0x0000000000000000'}]
    for index, address in ((5, 0x17f2d7f), (6, 0x17f2d9b)):
        c = elf.read(address, 28, True)
        require(c[:3] == b'\xf6\x84\x24' and c[7:12] == bytes.fromhex('01488b8c24') and
                c[16:24] == bytes.fromhex('480f44c848898c24') and c[12:16] == c[24:28],
                'integer default shape')
        default_rows.append({'key': dispatch[index]['key'], 'test_va': hex(address),
                             'presence_stack_offset': hex(struct.unpack('<I', c[3:7])[0]),
                             'value_stack_offset': hex(struct.unpack('<I', c[12:16])[0]),
                             'default_bits': '0x0000000000000000'})
    for row in default_rows:
        arm = int(dispatch[next(i for i in (3, 5, 6) if dispatch[i]['key'] == row['key'])]['arm_va'], 16)
        raw = elf.read(arm, 9, True)
        require(raw[:4] == bytes.fromhex('4883bc24') and raw[8] == 1 and
                struct.unpack('<I', raw[4:8])[0] == int(row['presence_stack_offset'], 16),
                'default and reader presence state disagree')
    functions = []
    for start in sorted(elf.frames):
        f = elf.frames[start]
        functions.append({'start_va': hex(start), 'end_va_exclusive': hex(f['end']),
                          'fde_va': hex(f['fde']), 'file_offset': hex(elf.offset(start)),
                          'body_sha256': hashlib.sha256(elf.read(start, f['end'] - start)).hexdigest()})
    probes = [b'', b'dga', b'fs', b'l', b'otq', b'ots', b'qts', b'otx', b'out', b'dga\x00', b'FS']
    controls = [{'input_hex': p.hex(), 'status': run_classifier(elf, p)[0],
                 'selector': run_classifier(elf, p)[1]} for p in probes]
    # Bound and record the selected error targets, avoiding claims about called parsers.
    errors = []
    for row in dispatch[:13]:
        addr = int(row['duplicate_target_va'], 16)
        template_site = addr + 43
        template = elf.lea(template_site)
        require(elf.read(template, 17) == b'\x11duplicate field ', 'unexpected duplicate template')
        errors.append({'key': row['key'], 'duplicate_va': hex(addr), 'template_va': hex(template)})
    return {'binary_sha256': hashlib.sha256(data).hexdigest(),
            'scope': 'selected FDEs and fixed sites; unrelocated ELF virtual addresses; ends exclusive',
            'functions': functions, 'fields': rows,
            'outer': {'parent_call_va': hex(0x2390e35), 'wrapper_va': hex(parent_call),
                      'wrapper_key_va': hex(wrapper_key_va), 'wrapper_key': wrapper_key,
                      'tail_site_va': hex(0x23d7d3c), 'writer_va': hex(wrapper_child),
                      'named_count': map_count, 'positional_count': array_count},
            'reader_table_va': hex(table), 'reader_dispatch': dispatch, 'type_record': type_info,
            'duplicate_errors': errors, 'missing_diagnostics': missing, 'map_defaults': default_rows,
            'messagepack_decisions': mp_decisions, 'json_decisions': json_decisions,
            'selected_windows': windows, 'selected_edges': edges, 'nested_adapters': nested,
            'small_sort': {'exclusive_limit': limit, 'record_bytes': stride,
                           'copies_equal_bytes': len(small), 'model_input': sample_in,
                           'model_output': sample_out},
            'classifier_probes': controls}


def render_tsv(rows):
    out = io.StringIO(newline='')
    cols = ['index', 'key', 'object_offset', 'mp_key_site', 'mp_key_va', 'mp_load_site',
            'json_key_site', 'json_key_va', 'json_load_site', 'wrapper_va', 'reader_arm_va', 'duplicate_target_va']
    w = csv.DictWriter(out, fieldnames=cols, delimiter='\t', lineterminator='\n')
    w.writeheader(); w.writerows(rows)
    return out.getvalue()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    report = build(BINARY.read_bytes())
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / 'evidence.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    (args.out / 'fields.tsv').write_text(render_tsv(report['fields']), encoding='utf-8')


if __name__ == '__main__':
    main()
