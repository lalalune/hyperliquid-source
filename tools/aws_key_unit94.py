#!/usr/bin/env python3
"""Digest-locked static analysis of node 94 name-key envelope and unit payload.

The x86 length/operand walker is adapted from the independent MIT
HlChain-reader packet. It admits a small encoding subset, not general x86.
The generated transfer models are hypotheses about local code, not execution.
"""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections
from fde_extents import eh_frame_records, uleb

DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
ARTIFACT = 'artifacts/node/94/hl-node'
FUNCTIONS = {
    0x13aa150: 'key_envelope',
    0x13f4250: 'map_key_and_unit',
    0x13f4300: 'direct_key',
    0x1409860: 'unit_payload',
}
REGS = ('rax','rcx','rdx','rbx','rsp','rbp','rsi','rdi',
        'r8','r9','r10','r11','r12','r13','r14','r15')
CONDITIONS = ('o','no','b','ae','e','ne','be','a','s','ns','p','np','l','ge','le','g')

def require(ok, message):
    if not ok:
        raise ValueError(message)


class Image:
    def __init__(self, data, authenticate=True):
        if authenticate:
            require(hashlib.sha256(data).hexdigest() == DIGEST, 'node94 digest mismatch')
        self.data = data
        self.sections = sections(data)
        self.relocations = {}
        rel = [s for s in self.sections if s['name'] == '.rela.dyn']
        require(len(rel) == 1 and rel[0]['type'] == 4, 'missing or ambiguous RELA')
        s = rel[0]
        require(s['size'] % 24 == 0, 'partial RELA entry')
        for pos in range(s['offset'], s['offset'] + s['size'], 24):
            slot, info, addend = struct.unpack_from('<QQq', data, pos)
            if info & 0xffffffff == 8:
                require(info >> 32 == 0, 'relative relocation has a symbol')
                require(slot not in self.relocations, 'duplicate relative relocation')
                self.relocations[slot] = (addend, pos)
        _, fs = eh_frame_records(data, self.sections)
        self.all_fdes = fs
        self.fdes = {}
        for f in fs:
            if f['start'] in FUNCTIONS:
                require(f['start'] not in self.fdes, 'duplicate selected FDE')
                self.fdes[f['start']] = f
        require(set(self.fdes) == set(FUNCTIONS), 'missing selected FDE')

    def offset(self, va, size=1):
        require(isinstance(va, int) and isinstance(size, int) and size > 0 and va >= 0,
                'invalid byte range')
        matches = [s for s in self.sections if s['type'] != 8 and s['flags'] & 2
                   and s['address'] <= va and va + size <= s['address'] + s['size']]
        require(len(matches) == 1, 'range has no unique file-backed section')
        return matches[0]['offset'] + va - matches[0]['address']

    def read(self, va, size):
        pos = self.offset(va, size)
        return self.data[pos:pos + size]

    def pin(self, va, expected):
        expected = bytes.fromhex(expected)
        require(self.read(va, len(expected)) == expected, f'byte contract mismatch at {va:#x}')

    def relative(self, slot):
        require(slot in self.relocations, 'unresolved relative slot')
        return self.relocations[slot][0]


def instruction(image, va, end):
    """Length/operand decode of a closed, reviewed x86-64 encoding subset."""
    data = image.read(va, min(15, end - va))
    p, rex, prefix = 0, 0, []
    while p < len(data) and (data[p] in (0x66, 0xf2, 0xf3) or 0x40 <= data[p] <= 0x4f):
        b = data[p]
        if 0x40 <= b <= 0x4f:
            require(not rex, 'multiple REX prefixes')
            rex = b
        else:
            require(b not in prefix, 'duplicate operand prefix')
            prefix.append(b)
        p += 1
    require(p < len(data), 'truncated opcode')
    op = data[p]; p += 1
    width = 64 if rex & 8 else (16 if 0x66 in prefix else 32)
    row = {'va': va, 'kind': 'other', 'width': width}
    immediate, modrm = 0, False
    if op == 0x0f:
        require(p < len(data), 'truncated extended opcode')
        op = 0x0f00 | data[p]; p += 1
        if 0x0f80 <= op <= 0x0f8f:
            immediate = 4; row.update(kind='branch', condition=CONDITIONS[op & 15])
        elif op == 0x0f0b:
            row['kind'] = 'trap'
        elif op in (0x0f10,0x0f11,0x0f28,0x0f29,0x0f43,0x0f5a,0x0f6e,
                    0x0fb6,0x0fb7,0x0fbe,0x0fbf):
            modrm = True
        elif 0x0fc8 <= op <= 0x0fcf:
            row['register'] = REGS[(op & 7) + (8 if rex & 1 else 0)]
        else:
            raise ValueError(f'unsupported opcode {op:x} at {va:x}')
    elif 0x70 <= op <= 0x7f:
        immediate = 1; row.update(kind='branch', condition=CONDITIONS[op & 15])
    elif op in (0xe8, 0xe9, 0xeb):
        immediate = 1 if op == 0xeb else 4
        row['kind'] = 'call' if op == 0xe8 else 'jump'
    elif op in (0x24, 0x3c):
        immediate = 1
        row['register'] = 'rax'
        row['width'] = 8
    elif 0x50 <= op <= 0x5f:
        row['kind'] = 'push' if op < 0x58 else 'pop'
        row['register'] = REGS[(op & 7) + (8 if rex & 1 else 0)]
    elif 0xb0 <= op <= 0xbf:
        immediate = 1 if op < 0xb8 else width // 8
        row['register'] = REGS[(op & 7) + (8 if rex & 1 else 0)]
    elif op in (0xc3,0xcc,0x90):
        row['kind'] = {0xc3:'return',0xcc:'trap',0x90:'nop'}[op]
    elif op in (0x01,0x09,0x29,0x31,0x33,0x39,0x3b,0x63,0x80,0x81,
                0x83,0x84,0x85,0x88,0x89,0x8b,0x8d,0xc0,0xc1,0xc6,0xc7,0xd1,0xf6,0xff):
        modrm = True
        if op in (0x80,0x83,0xc0,0xc1,0xc6,0xf6): immediate = 1
        if op in (0x81,0xc7): immediate = 2 if width == 16 else 4
    else:
        raise ValueError(f'unsupported opcode {op:x} at {va:x}')
    if modrm:
        require(p < len(data), 'truncated ModRM')
        m = data[p]; p += 1
        mod, field, rm = m >> 6, (m >> 3) & 7, m & 7
        row.update(modrm=m, reg=REGS[field + (8 if rex & 4 else 0)])
        if mod == 3:
            row['rm'] = REGS[rm + (8 if rex & 1 else 0)]
        else:
            mem = {'base': REGS[rm + (8 if rex & 1 else 0)], 'index': None, 'scale': 1, 'disp': 0}
            displacement = 1 if mod == 1 else (4 if mod == 2 else 0)
            if rm == 4:
                require(p < len(data), 'truncated SIB')
                sib = data[p]; p += 1
                base, index = sib & 7, (sib >> 3) & 7
                mem['base'] = REGS[base + (8 if rex & 1 else 0)]
                mem['scale'] = 1 << (sib >> 6)
                if index != 4 or rex & 2:
                    mem['index'] = REGS[index + (8 if rex & 2 else 0)]
                if mod == 0 and base == 5:
                    mem['base'] = None; displacement = 4
            elif mod == 0 and rm == 5:
                mem['base'] = 'rip'; displacement = 4
            require(p + displacement <= len(data), 'truncated displacement')
            if displacement:
                mem['disp'] = int.from_bytes(data[p:p+displacement], 'little', signed=True)
                p += displacement
            row['memory'] = mem
        if op == 0xff:
            require(field in (0,1,2,4), 'unsupported FF operation')
            if field in (2,4): row['kind'] = 'indirect_call' if field == 2 else 'indirect_jump'
        if op in (0xc6,0xc7,0xf6): require(field == 0, 'unsupported immediate operation')
        if op == 0xd1: require(field == 5, 'unsupported shift')
    require(p + immediate <= len(data), 'truncated immediate')
    if immediate:
        raw = data[p:p+immediate]
        row['immediate'] = int.from_bytes(raw, 'little')
        if row['kind'] in ('branch','jump','call'):
            row['target'] = va + p + immediate + int.from_bytes(raw, 'little', signed=True)
        p += immediate

    if op in (0x80,0x84,0x88,0xc6) or 0xb0<=op<=0xb7: row['width'] = 8
    if row['kind'] in ('push','pop','call','indirect_call','indirect_jump','return'): row['width'] = 64
    if op in (0x0f10,0x0f11,0x0f28,0x0f29): row['width'] = 128
    if op in (0x0f10,0x0f11) and (0xf2 in prefix or 0xf3 in prefix):
        row['width'] = 64 if 0xf2 in prefix else 32
    if op in (0x0f10,0x0f11,0x0f28,0x0f29,0x0f5a,0x0f6e):
        row['reg'] = 'xmm'+str(REGS.index(row['reg']))
        if 'rm' in row and op != 0x0f6e: row['rm'] = 'xmm'+str(REGS.index(row['rm']))
    row['memory_width'] = 8 if op in (0x0fb6,0x0fbe) else (16 if op in (0x0fb7,0x0fbf) else row['width'])
    row.update(opcode=op, size=p, bytes=data[:p].hex(), file_offset=image.offset(va,p))
    if 'memory' in row and row['memory']['base'] == 'rip':
        row['rip_target'] = va + p + row['memory']['disp']
        if row['rip_target'] in image.relocations:
            row['relocated_target'], row['relocation_file_offset'] = image.relocations[row['rip_target']]
    return row


def walk(image, start):
    f = image.fdes[start]; p = start; rows = []
    while p < f['end']:
        row = instruction(image,p,f['end']); rows.append(row); p += row['size']
    require(p == f['end'], 'instruction crosses FDE end')
    starts = {r['va'] for r in rows}
    for r in rows:
        if r['kind'] in ('jump','branch'):
            require(r['target'] in starts, 'branch does not reach an in-function instruction start')
    return rows


# These contracts pin instructions used in the local transfer model. Full FDE
# hashes additionally detect alterations to other paths in the selected bodies.
PINS = {
    0x13aa156: '0fb64e2080f9017529488b4e184885c9746e488b561048ffc90fb60248ffc24889561048894e1884c0786831c9',
    0x13aa188: '0fb6462180f9df0f84c50000000fb6c981f9de000000741c40b50281f9800000000f85cb0000000fb6c083f8017465e9f5000000',
    0x13aa1bc: '488b4610488b4e184883f902732f4801c848894610e999000000c60300488d0518c72b0448894308e9ce0000',
    0x13aa1e9: 'b1e03cdf775c3c90733a240fb180eb52',
    0x13aa1f9: '4883c1fe0fb71066c1c2084883c0024889461048894e180fb7c283f8010f8595000000c646200140b5034889dfe825a00400',
    0x13aa22d: '3ca07306240fb190eb1489c280e21f3cc00fb6c0b9a00000000f43c889d0884e2088462180f9df0f',
    0x13aa25a: '488b4e10488b56184883fa04732c4801d148894e1048c746180000000040b5014889dfe87ea00400400f',
    0x13aa294: '4883c2fc8b014883c1040fc848894e104889561883f8010f846bffffffc60304894304',
    0x13f425e: '4889e7ba01000000e8c522fcff0fb604240fb66c24013c097530400fb6c589c0',
    0x13f427e: '488d0dcb37e2fe486304814801c8ffe04889e74c89f6e8c7550100803c24097540',
    0x13f429f: '40886b01c60309eb47',
    0x13f42df: '0f1004240f104c24100f114b100f1103',
    0x13f4308: '4889e7ba01000000e81b22fcff0fb604240fb64c24013c09742f',
    0x13f4351: '884b018803',
    0x1409860: '488b4e184885c9741f488b561048ffc90fb60248ffc24889561048894e18b10284c0780831d2eb3031c9eb2c',
    0x140988c: 'b2e03cdf77263c907306240fb280eb1c3ca07306240fb290eb123cc07306241fb2a0eb0889c27504c60709c3880f8857',
    0x14098bc: '01884702488d051918260448894708c3',
}
BODY_HASHES = {
    0x13aa150: 'bba7172dc81b39c30111b6d0c06775bfc7a0fdbe3df2d3411dd1ca1b24da34e4',
    0x13f4250: 'dd5f7caafa7b03134b5e50728152576f1f53ab3a71d50d7e6afe59b0dee7ce8b',
    0x13f4300: '90304ee294a1a9e3a89e3fd0210107c463732e9053e66ff36170f090aa3cb72e',
    0x1409860: 'f10e1d92c2f01ceec202e725717f94dc205cd285dfe2f9924822b92170cc360f',
}


def decode_selection(image):
    functions, instructions = [], []
    owners = {}
    for start, label in sorted(FUNCTIONS.items()):
        f = image.fdes[start]
        body = image.read(start, f['end'] - start)
        body_hash = hashlib.sha256(body).hexdigest()
        require(body_hash == BODY_HASHES[start], 'selected FDE bytes or extent changed')
        rows = walk(image, start)
        owners[start] = rows
        instructions.extend(dict(row, owner=start, owner_label=label) for row in rows)
        functions.append(dict(f, label=label, file_offset=image.offset(start, len(body)),
                              byte_count=len(body), instruction_count=len(rows), sha256=body_hash))
    for va, expected in sorted(PINS.items()):
        image.pin(va, expected)
    rows = {r['va']: r for r in instructions}
    def immediate(va):
        require(va in rows and 'immediate' in rows[va], 'missing immediate instruction')
        return rows[va]['immediate']
    params = {
        'cache_empty': immediate(0x13aa15a),
        'map16_marker': immediate(0x13aa198),
        'map32_marker': immediate(0x13aa18c),
        'fixed_map_class': immediate(0x13aa1a3),
        'one_entry': immediate(0x13aa1b2),
        'map16_width': immediate(0x13aa1c4),
        'map32_width': immediate(0x13aa262),
        'count_error_tag': immediate(0x13aa2b1),
        'success_tag': immediate(0x13f4274),
        'unit_type_error_tag': immediate(0x140987e),
        'unit_marker': immediate(0x14098a6),
        'negative_class': immediate(0x13aa1e9),
        'negative_limit': immediate(0x13aa1eb),
        'array_boundary': immediate(0x13aa1ef),
        'string_boundary': immediate(0x13aa22d),
        'literal_mask': immediate(0x13aa239),
        'collection_mask': immediate(0x13aa1f3),
        'unit_success_tag': immediate(0x14098b4),
    }
    require(params == {'cache_empty':1, 'map16_marker':0xde, 'map32_marker':0xdf,
                       'fixed_map_class':0x80, 'one_entry':1, 'map16_width':2,
                       'map32_width':4, 'count_error_tag':4, 'success_tag':9,
                       'unit_type_error_tag':2, 'unit_marker':0xc0,
                       'negative_class':0xe0, 'negative_limit':0xdf,
                       'array_boundary':0x90, 'string_boundary':0xa0,
                       'literal_mask':0x1f, 'collection_mask':0x0f,
                       'unit_success_tag':9}, 'instruction constants changed')
    expected_calls = {
        0x13aa226: 0x13f4250, 0x13aa27d: 0x13f4300,
        0x13aa28d: 0x13b4470, 0x13aa2cf: 0x13b4470,
        0x13f4266: 0x13b6530, 0x13f4310: 0x13b6530,
        0x13f4294: 0x1409860,
    }
    for site, target in expected_calls.items():
        require(rows[site]['kind'] == 'call' and rows[site]['target'] == target,
                'selected call edge changed')
    require(rows[0x13aa2dc].get('rip_target') == 0x576e128 and
            image.relative(0x576e128) == 0x157b63b,
            'cleanup landing relocation changed')
    base = rows[0x13f427e]['rip_target']
    unit_block = base + struct.unpack('<i', image.read(base, 4))[0]
    require(base == 0x217a50 and unit_block == 0x13f428e, 'unit dispatch moved')
    valid_starts = {r['va'] for r in owners[0x13f4250]}
    count = 0
    while count < 256:
        delta = struct.unpack('<i', image.read(base + count * 4, 4))[0]
        target = base + delta
        if target != unit_block:
            break
        require(target in valid_starts, 'unit table reaches a non-instruction')
        count += 1
    require(count == 76, 'same-target table run changed')
    table_raw = image.read(base, count * 4)
    table_record = {'base_va':base, 'file_offset':image.offset(base, len(table_raw)),
                    'entry_width':4, 'same_target_entries':count, 'target_va':unit_block,
                    'sha256':hashlib.sha256(table_raw).hexdigest(),
                    'following_entry_va':base + len(table_raw),
                    'following_target_va':target}
    lsda_header, lsda_records = decode_lsda(image, functions, instructions)
    cfg_edges, cfg_paths = normal_flow(instructions, table_record)
    return {'functions':functions, 'instructions':instructions, 'parameters':params,
            'table':table_record, 'lsda_header':lsda_header, 'lsda_records':lsda_records,
            'cfg_edges':cfg_edges, 'cfg_paths':cfg_paths}


def normal_flow(instructions, table_record):
    """Structural normal-flow paths, with calls returning and conditions open."""
    rows = {r['va']:r for r in instructions}
    require(len(rows) == len(instructions), 'duplicate selected instruction')
    edges = []
    for row in instructions:
        site, kind = row['va'], row['kind']
        following = site + row['size']
        options = []
        if kind == 'branch':
            options = [(row['target'], 'taken'), (following, 'fallthrough')]
        elif kind == 'jump':
            options = [(row['target'], 'jump')]
        elif kind == 'indirect_jump':
            require(site == 0x13f428c, 'unmodeled indirect jump')
            options = [(table_record['target_va'], 'checked_table_run')]
        elif kind not in ('return', 'trap') and following in rows:
            options = [(following, 'assumed_return' if kind in ('call', 'indirect_call')
                        else 'fallthrough')]
        for target, edge_kind in options:
            require(target in rows and rows[target]['owner'] == row['owner'],
                    'normal-flow edge leaves selected FDE')
            edges.append({'owner':row['owner'], 'source':site, 'target':target, 'kind':edge_kind})
    adjacent = {}
    for edge in edges:
        adjacent.setdefault(edge['source'], []).append(edge['target'])
    for source in adjacent:
        adjacent[source] = sorted(set(adjacent[source]))
    queries = (
        ('entry_to_map_call', 0x13aa150, 0x13aa226, True),
        ('entry_to_direct_call', 0x13aa150, 0x13aa27d, True),
        ('entry_to_count_error', 0x13aa150, 0x13aa2b1, True),
        ('entry_to_no_marker', 0x13aa150, 0x13aa1d6, True),
        ('map_call_to_cleanup', 0x13aa226, 0x13aa28d, True),
        ('map_call_to_direct_call', 0x13aa226, 0x13aa27d, False),
        ('direct_call_to_map_call', 0x13aa27d, 0x13aa226, False),
        ('map_wrapper_to_unit_call', 0x13f4250, 0x13f4294, True),
        ('map_wrapper_to_name_error', 0x13f4250, 0x13f42a8, True),
        ('unit_call_to_key_write', 0x13f4294, 0x13f429f, True),
        ('unit_call_to_error_copy', 0x13f4294, 0x13f42df, True),
        ('key_write_to_error_copy', 0x13f429f, 0x13f42df, False),
        ('unit_entry_to_success', 0x1409860, 0x14098b4, True),
        ('unit_entry_to_error', 0x1409860, 0x14098b8, True),
        ('direct_wrapper_to_return', 0x13f4300, 0x13f435e, True),
    )
    paths = []
    for label, start, goal, expected in queries:
        require(start in rows and goal in rows, 'CFG query is outside selection')
        pending, previous = [start], {start:None}
        at = 0
        while at < len(pending) and goal not in previous:
            node = pending[at]
            at += 1
            for target in adjacent.get(node, ()):
                if target not in previous:
                    previous[target] = node
                    pending.append(target)
        reached = goal in previous
        require(reached == expected, 'unexpected structural path: ' + label)
        witness = []
        if reached:
            node = goal
            while node is not None:
                witness.append(node)
                node = previous[node]
            witness.reverse()
        paths.append({'label':label, 'start':start, 'goal':goal,
                      'reachable':reached, 'witness':witness})
    return edges, paths


def decode_lsda(image, functions, instructions):
    """Decode selected ULEB call-site records; action semantics stay open."""
    f = next(f for f in functions if f['start'] == 0x13aa150)
    va = f['lsda']
    require(va is not None, 'selected FDE has no LSDA')
    matches = [s for s in image.sections if s['name'] == '.gcc_except_table' and s['type'] != 8]
    require(len(matches) == 1, 'missing exception table')
    sec = matches[0]
    upper = sec['address'] + sec['size']
    require(sec['address'] <= va < upper, 'LSDA outside exception section')
    next_lsdas = [r['lsda'] for r in image.all_fdes
                  if r['lsda'] is not None and va < r['lsda'] < upper]
    if next_lsdas:
        upper = min(next_lsdas)
    data = image.read(va, upper - va)
    require(len(data) >= 4 and data[0] == 0xff and data[1] in (0xff, 0x9b),
            'unsupported LSDA header')
    pos, type_base = 2, None
    if data[1] != 0xff:
        offset, pos = uleb(data, pos, len(data))
        type_base = pos + offset
        require(type_base <= len(data), 'LSDA type base outside range')
    require(pos < len(data) and data[pos] == 1, 'unsupported LSDA call-site encoding')
    pos += 1
    size, pos = uleb(data, pos, len(data))
    end = pos + size
    require(end <= len(data) and (type_base is None or end <= type_base),
            'LSDA call-site table outside range')
    header = {'lsda_va':va, 'file_offset':image.offset(va, 1), 'upper_bound':upper,
              'bytes':data[:pos].hex(), 'table_size':size, 'type_encoding':data[1],
              'type_base_va':None if type_base is None else va + type_base}
    starts = {r['va'] for r in instructions if r['owner'] == f['start']}
    transfers = [r['va'] for r in instructions if r['owner'] == f['start']
                 and r['kind'] in ('call', 'indirect_call')]
    records, previous_end = [], 0
    while pos < end:
        begin = pos
        values = []
        for _ in range(4):
            value, pos = uleb(data, pos, end)
            values.append(value)
        start, length, landing, action = values
        require(length and start >= previous_end and start + length <= f['byte_count'],
                'invalid LSDA range')
        first, last = f['start'] + start, f['start'] + start + length
        dest = f['start'] + landing if landing else None
        require(first in starts and (last in starts or last == f['end']),
                'LSDA range is not instruction-aligned')
        require(dest is None or dest in starts, 'LSDA landing is not instruction-aligned')
        records.append({'record_va':va + begin, 'bytes':data[begin:pos].hex(),
                        'start':first, 'end':last, 'landing':dest, 'action':action,
                        'transfer_sites':[site for site in transfers if first <= site < last]})
        previous_end = start + length
    require(pos == end, 'partial LSDA record')
    return header, records


def normalize(marker, p):
    """Model a fresh marker's local class/payload split (not a node run)."""
    require(type(marker) is int and 0 <= marker <= 255, 'invalid marker')
    if marker < p['fixed_map_class']:
        return 0, marker
    if marker > p['negative_limit']:
        return p['negative_class'], marker
    if marker < p['array_boundary']:
        return p['fixed_map_class'], marker & p['collection_mask']
    if marker < p['string_boundary']:
        return p['array_boundary'], marker & p['collection_mask']
    if marker < p['unit_marker']:
        return p['string_boundary'], marker & p['literal_mask']
    return marker, marker & p['literal_mask']


def unit_model(marker, p):
    """Local unit payload transfer for either EOF or one available byte."""
    if marker is None:
        return {'result_tag':0, 'consumed':0, 'class':None, 'payload':None}
    cls, payload = normalize(marker, p)
    if marker == p['unit_marker']:
        return {'result_tag':p['unit_success_tag'], 'consumed':1, 'class':None, 'payload':None}
    # In this reader raw c0..df errors store the full marker in both fields,
    # unlike the caller's cached representation.
    if p['unit_marker'] <= marker <= p['negative_limit']:
        cls, payload = marker, marker
    return {'result_tag':p['unit_type_error_tag'], 'consumed':1, 'class':cls, 'payload':payload}


def envelope_model(data, p, *, cached_class=1, cached_payload=0):
    """Stop at the delegated name-reader call, or a local error return.

    Model cursor consumption in this function only, before the external reader
    runs. `data` is synthetic, not a target fixture. Cached values other than
    the reset sentinel represent caller-supplied internal state.
    """
    require(isinstance(data, bytes), 'input must be bytes')
    require(0 <= cached_class <= 255 and 0 <= cached_payload <= 255, 'invalid cache')
    consumed = 0
    cls, payload = cached_class, cached_payload
    if cls == p['cache_empty']:
        if not data:
            return {'route':'no_marker', 'consumed':0, 'cache_class':cls,
                    'cache_payload':None, 'result_tag':0, 'count':None}
        cls, payload = normalize(data[0], p)
        consumed = 1
    width = (p['map16_width'] if cls == p['map16_marker'] else
             p['map32_width'] if cls == p['map32_marker'] else 0)
    if width:
        rest = data[consumed:]
        if len(rest) < width:
            return {'route':'truncated_prefix_delegate', 'consumed':len(data),
                    'cache_class':cls, 'cache_payload':payload, 'result_tag':None,
                    'count':None}
        count = int.from_bytes(rest[:width], 'big')
        consumed += width
    elif cls == p['fixed_map_class']:
        count = payload
    else:
        return {'route':'direct_delegate', 'consumed':consumed, 'cache_class':cls,
                'cache_payload':payload, 'result_tag':None, 'count':None}
    if count != p['one_entry']:
        return {'route':'count_error', 'consumed':consumed, 'cache_class':cls,
                'cache_payload':payload, 'result_tag':p['count_error_tag'], 'count':count}
    return {'route':'map_key_delegate', 'consumed':consumed, 'cache_class':p['cache_empty'],
            'cache_payload':payload, 'result_tag':None, 'count':count}


def map_result_model(name_tag, index, unit_tag, p, count):
    """Conditional local result copy, assuming the delegated reader returns."""
    require(type(name_tag) is int and 0 <= name_tag <= 255, 'invalid name tag')
    if name_tag != p['success_tag']:
        return {'route':'copy_name_error', 'result_tag':name_tag, 'index':None}
    require(type(index) is int and 0 <= index < count, 'index outside checked table run')
    require(type(unit_tag) is int and 0 <= unit_tag <= 255, 'invalid unit tag')
    if unit_tag != p['unit_success_tag']:
        return {'route':'copy_unit_error', 'result_tag':unit_tag, 'index':None}
    return {'route':'write_key', 'result_tag':p['success_tag'], 'index':index}


def tsv(columns, rows):
    stream = io.StringIO(newline='')
    writer = csv.writer(stream, delimiter='\t', lineterminator='\n')
    writer.writerow(columns)
    for row in rows:
        writer.writerow(['-' if row.get(col) is None else
                         (json.dumps(row[col], sort_keys=True, separators=(',', ':'))
                          if isinstance(row[col], (list, dict)) else row[col]) for col in columns])
    return stream.getvalue()


def outputs(image):
    found = decode_selection(image)
    ins = found['instructions']
    params = found['parameters']
    branches = [dict(row, fallthrough=row['va'] + row['size']) for row in ins
                if row['kind'] in ('branch', 'jump')]
    calls = []
    for row in ins:
        if row['kind'] not in ('call', 'indirect_call', 'indirect_jump'):
            continue
        target = row.get('target', row.get('relocated_target'))
        calls.append(dict(row, target_label=FUNCTIONS.get(target),
                          boundary='selected' if target in FUNCTIONS else 'external_or_dynamic'))
    marker_rows = []
    unit_rows = []
    for marker in range(256):
        cls, payload = normalize(marker, params)
        marker_rows.append(dict(marker=marker, normalized_class=cls, normalized_payload=payload,
                                **envelope_model(bytes([marker]), params)))
        unit_rows.append(dict(marker=marker, **unit_model(marker, params)))
    unit_rows.append(dict(marker='eof', **unit_model(None, params)))
    prefix_rows = []
    cases = [('fixed', n, bytes([0x80 + n])) for n in range(16)]
    cases += [('map16', n, b'\xde' + n.to_bytes(2, 'big')) for n in (0, 1, 2, 255, 256, 65535)]
    cases += [('map32', n, b'\xdf' + n.to_bytes(4, 'big')) for n in (0, 1, 2, 65535, 65536, 4294967295)]
    cases += [('short16', None, b'\xde' + bytes(n)) for n in range(2)]
    cases += [('short32', None, b'\xdf' + bytes(n)) for n in range(4)]
    for name, count, raw in cases:
        for mode in ('fresh', 'cached'):
            cls, payload = normalize(raw[0], params)
            result = (envelope_model(raw, params) if mode == 'fresh' else
                      envelope_model(raw[1:], params, cached_class=cls, cached_payload=payload))
            prefix_rows.append(dict(kind=name, declared=count, mode=mode, wire_bytes=raw.hex(),
                                    input_bytes=(raw if mode == 'fresh' else raw[1:]).hex(),
                                    initial_class=(params['cache_empty'] if mode == 'fresh' else cls),
                                    initial_payload=(0 if mode == 'fresh' else payload), **result))
    prefix_rows.append(dict(kind='empty', declared=None, mode='fresh', wire_bytes='',
                            input_bytes='', initial_class=params['cache_empty'], initial_payload=0,
                            **envelope_model(b'', params)))
    wrapper_rows = []
    for index in (0, 31, 32, 33, found['table']['same_target_entries'] - 1):
        for unit_tag in (0, 2, params['unit_success_tag']):
            wrapper_rows.append(dict(name_tag=params['success_tag'], input_index=index,
                                     unit_tag=unit_tag,
                                     **map_result_model(params['success_tag'], index, unit_tag,
                                                        params, found['table']['same_target_entries'])))
    for name_tag in (0, 1, 2, 4, 6, 8):
        wrapper_rows.append(dict(name_tag=name_tag, input_index=None, unit_tag=None,
                                 **map_result_model(name_tag, None, None, params,
                                                    found['table']['same_target_entries'])))
    contracts = [{'va':va, 'file_offset':image.offset(va,len(bytes.fromhex(raw))),
                  'bytes':image.read(va,len(bytes.fromhex(raw))).hex()}
                 for va, raw in sorted(PINS.items())]
    summary = {
        'target_sha256': DIGEST,
        'coordinate_system': 'ELF linked virtual address, plus section-mapped file offset',
        'parameters_from_instructions': params,
        'unit_dispatch_run': found['table'], 'lsda_header':found['lsda_header'],
        'metrics': {'selected_fdes':len(found['functions']),
                    'selected_fde_bytes':sum(r['byte_count'] for r in found['functions']),
                    'decoded_instructions':len(ins), 'direct_branches':len(branches),
                    'transfer_sites':len(calls), 'byte_contracts':len(contracts),
                    'fresh_marker_cases':len(marker_rows), 'unit_cases':len(unit_rows),
                    'prefix_cases':len(prefix_rows), 'wrapper_cases':len(wrapper_rows),
                    'lsda_records':len(found['lsda_records']),
                    'cfg_edges':len(found['cfg_edges']), 'cfg_queries':len(found['cfg_paths'])},
        'limits': ['FDE extents are unwind ranges, not a whole-program function census.',
                   'Cases are a static local transfer model, not execution of the node.',
                   'CFG paths over-approximate branches, assume calls return and omit exceptional edges.',
                   'The prior name-reader and cleanup routines remain external boundaries.',
                   'LSDA action semantics, allocator, external helper bodies, #115, visor, Rust comparison and full-component gates remain open.'],
    }
    return {
        'functions.tsv':tsv(['label','start','end','file_offset','fde','cie','lsda','byte_count','instruction_count','sha256'], found['functions']),
        'instructions.tsv':tsv(['owner','owner_label','va','file_offset','bytes','size','opcode','kind','width','memory_width','memory','immediate','target','rip_target','relocated_target'], ins),
        'branches.tsv':tsv(['owner','va','bytes','kind','condition','target','fallthrough'], branches),
        'transfers.tsv':tsv(['owner','va','bytes','kind','target','rip_target','relocated_target','target_label','boundary'], calls),
        'contracts.tsv':tsv(['va','file_offset','bytes'], contracts),
        'exception-sites.tsv':tsv(['record_va','bytes','start','end','landing','action','transfer_sites'], found['lsda_records']),
        'cfg-edges.tsv':tsv(['owner','source','target','kind'], found['cfg_edges']),
        'cfg-paths.tsv':tsv(['label','start','goal','reachable','witness'], found['cfg_paths']),
        'marker-cases.tsv':tsv(['marker','normalized_class','normalized_payload','route','consumed','cache_class','cache_payload','result_tag','count'], marker_rows),
        'unit-cases.tsv':tsv(['marker','result_tag','consumed','class','payload'], unit_rows),
        'prefix-cases.tsv':tsv(['kind','declared','mode','wire_bytes','input_bytes','initial_class','initial_payload','route','consumed','cache_class','cache_payload','result_tag','count'], prefix_rows),
        'wrapper-cases.tsv':tsv(['name_tag','input_index','unit_tag','route','result_tag','index'], wrapper_rows),
        'summary.json':json.dumps(summary, sort_keys=True, indent=2) + '\n',
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    files = outputs(Image((ROOT / ARTIFACT).read_bytes()))
    args.out.mkdir(parents=True, exist_ok=True)
    for name, content in sorted(files.items()):
        (args.out / name).write_text(content, encoding='utf-8', newline='\n')
    print('Static evidence generated; captured programs were not executed.')


if __name__ == '__main__':
    main()
