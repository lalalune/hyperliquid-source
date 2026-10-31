#!/usr/bin/env python3
"""Static node #94 evm_kvs evidence; Python 3.10+ stdlib only (MIT).

No captured executable is run. Unknown instruction encodings fail closed.
The ELF/FDE helpers are repository MIT tooling; reference Rust is not input.
"""
from __future__ import annotations
import argparse
import bisect
from collections import Counter
import hashlib
import json
import mmap
from pathlib import Path
import re
import struct
import sys

TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))
from elf_index import sections
from fde_extents import fde_extents

ROOT = TOOLS.parent
TARGET = 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
REFERENCE_COMMIT = '999556f6e0a474b8312db96ec3149e1c44e97c23'
BASE_COMMIT = '1f8c67c63ca4794c9689235471c60297f8a5c985'
# Embedded compiler path in the target, never the analyst's local home.
PREFIX = b'/home/ubuntu/hl/code_Mainnet/'
SCOPE = b'node/src/evm_kvs.rs'
LEA_RE = re.compile(rb'[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]')
OUTPUTS = ('inventory.json', 'instructions.json')


class EvidenceError(ValueError):
    """Incomplete or inconsistent evidence is never silently accepted."""


def require(condition, message):
    if not condition:
        raise EvidenceError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def authenticate(data):
    require(sha(data) == SHA256, 'node #94 SHA-256 mismatch')


class Image:
    def __init__(self, data):
        self.data = data
        require(len(data) >= 64, 'truncated ELF')
        require(data[:6] == b'\x7fELF\x02\x01', 'expected ELF64 LE')
        require(struct.unpack_from('<HH', data, 16) == (3, 62), 'expected x86-64 ET_DYN')
        self.sections = sections(data)
        names = [s['name'] for s in self.sections]
        require(len(names) == len(set(names)), 'duplicate section names')
        self.by_name = {s['name']: s for s in self.sections}
        for name in ('.text', '.rodata', '.data.rel.ro', '.rela.dyn', '.eh_frame', '.eh_frame_hdr'):
            require(name in self.by_name, f'missing section {name}')
        require(self.by_name['.text']['flags'] & 4, 'non-executable .text')

    def mapping(self, va, size=1):
        require(size > 0 and va >= 0, 'invalid read range')
        matches = [s for s in self.sections if s['type'] != 8 and s['flags'] & 2
                   and s['address'] <= va and va + size <= s['address'] + s['size']]
        require(len(matches) == 1, f'not one file-backed section for {va:#x}+{size}')
        s = matches[0]
        return s, s['offset'] + va - s['address']

    def read(self, va, size):
        _, off = self.mapping(va, size)
        return self.data[off:off + size]

    def section_bytes(self, name):
        s = self.by_name[name]
        return self.data[s['offset']:s['offset'] + s['size']]

    def evidence(self, va, size):
        s, off = self.mapping(va, size)
        return {'va': hex(va), 'file_offset': hex(off), 'section': s['name'],
                'bytes': self.read(va, size).hex()}


def relative_relocations(image):
    s = image.by_name['.rela.dyn']
    require(s['size'] % 24 == 0, 'truncated RELA section')
    result, seen = {}, set()
    for delta in range(0, s['size'], 24):
        pos = s['offset'] + delta
        slot, info, addend = struct.unpack_from('<QQq', image.data, pos)
        require(slot not in seen, 'duplicate relocation slot')
        seen.add(slot)
        if info & 0xffffffff != 8:  # R_X86_64_RELATIVE
            continue
        require(info == 8 and addend >= 0, 'invalid RELATIVE symbol/addend')
        result[slot] = {'target': addend, 'entry_va': s['address'] + delta,
                        'entry_file_offset': pos,
                        'raw': image.data[pos:pos + 24].hex()}
    return result


def decode_location(image, slot, relocation):
    section, _ = image.mapping(slot, 24)
    require(section['name'] == '.data.rel.ro' and slot % 8 == 0, 'Location storage/alignment')
    pointer, length, line, column = struct.unpack('<QQII', image.read(slot, 24))
    require(pointer == 0, 'unexpected pre-relocation Location pointer')
    require(0 < length < 256 and 0 < line < 1000000 and 0 < column < 1000000,
            'invalid Location length/line/column')
    target = relocation['target']
    path_section, _ = image.mapping(target, length)
    require(path_section['name'] == '.rodata', 'Location path outside .rodata')
    path = image.read(target, length)
    require(path.startswith(PREFIX + SCOPE) and path.endswith(b'.rs') and b'\0' not in path,
            'Location path outside exact scope')
    relative = path[len(PREFIX):].decode('ascii')
    require(path == PREFIX + SCOPE, 'Location path differs from exact scope')
    return {**image.evidence(slot, 24), 'path': relative, 'path_bytes': image.evidence(target, length),
            'path_length': length, 'line': line, 'column': column,
            'relocation': {'entry_va': hex(relocation['entry_va']),
                           'entry_file_offset': hex(relocation['entry_file_offset']),
                           'type': 'R_X86_64_RELATIVE', 'addend': hex(target),
                           'bytes': relocation['raw']}}


def locations(image, relocations):
    ro = image.by_name['.rodata']
    dr = image.by_name['.data.rel.ro']
    result = {}
    prefix = PREFIX + SCOPE
    for slot, relocation in sorted(relocations.items()):
        target = relocation['target']
        if not (dr['address'] <= slot < dr['address'] + dr['size']
                and ro['address'] <= target <= ro['address'] + ro['size'] - len(prefix)):
            continue
        if image.read(target, len(prefix)) == prefix:
            # Every matching path relocation must be accounted for; malformed
            # records stop the census instead of silently reducing its count.
            result[slot] = decode_location(image, slot, relocation)
    return result


class Fdes:
    def __init__(self, image):
        summary, rows, _ = fde_extents(image.data)
        for key in ('unwind_start_differs_from_fde_start', 'duplicate_start', 'zero_length',
                    'starts_inside_earlier_extent', 'extent_crosses_section_end',
                    'fde_records_not_in_unwind_table', 'lsda_outside_gcc_except_table'):
            require(summary[key] == 0, f'ambiguous FDE inventory: {key}')
        self.rows = rows
        self.starts = [f['start'] for f in rows]

    def owner(self, va, size=1):
        require(size > 0, 'invalid FDE query size')
        i = bisect.bisect_right(self.starts, va) - 1
        if i >= 0 and va + size <= self.rows[i]['end']:
            return self.rows[i]
        return None

    @staticmethod
    def record(image, fde):
        def record_bytes(va):
            size = 4 + struct.unpack('<I', image.read(va, 4))[0]
            return image.evidence(va, size)
        hdr = image.by_name['.eh_frame_hdr']['address'] + 12 + 8 * fde['index']
        return {'start': hex(fde['start']), 'end_exclusive': hex(fde['end']),
                'size': fde['end'] - fde['start'], 'section': fde['section'],
                'code_sha256': sha(image.read(fde['start'], fde['end'] - fde['start'])),
                'fde_record': record_bytes(fde['fde']), 'cie_record': record_bytes(fde['cie']),
                'unwind_index': fde['index'], 'unwind_index_entry': image.evidence(hdr, 8)}


def decode_lea(raw, site):
    require(len(raw) == 7 and LEA_RE.fullmatch(raw[:3]) is not None, 'unsupported RIP LEA')
    register = ((raw[2] >> 3) & 7) + (8 if raw[0] & 4 else 0)
    displacement = struct.unpack_from('<i', raw, 3)[0]
    return site + 7 + displacement, register


def scan_leas(image):
    """Candidates only; acceptance additionally requires FDE-start disassembly."""
    result = {}
    for s in image.sections:
        if not s['flags'] & 4 or s['type'] == 8:
            continue
        lower, upper = s['offset'], s['offset'] + s['size']
        for match in LEA_RE.finditer(image.data, lower, upper):
            offset = match.start()
            if offset + 7 <= upper:
                site = s['address'] + offset - lower
                target, _ = decode_lea(image.data[offset:offset + 7], site)
                result.setdefault(target, []).append(site)
    return result


def verified_lea(image, instructions, site, expected_target):
    matches = [x for x in instructions if x['site'] == site]
    require(len(matches) == 1, 'LEA candidate is inside another instruction or absent')
    insn = matches[0]
    target, register = decode_lea(insn['raw'], site)
    require(target == expected_target, 'LEA target/decode mismatch')
    require(insn['raw'] == image.read(site, 7), 'LEA bytes differ from input')
    return insn, register



def decode_instruction(code, offset=0, base=0):
    """Restricted legacy x86-64 length decoder, not a general disassembler.

    Decode sequentially from FDE entry; never resynchronize after an unknown
    opcode. ModRM/SIB/displacements and immediates are consumed, so opcode-like
    bytes inside operands cannot become anchors. Only enumerated forms pass.
    Operand semantics used for claims get a second exact decoder below.
    """
    require(0 <= offset < len(code), 'instruction offset outside input')
    start = offset
    def take(n):
        nonlocal offset
        require(offset + n <= len(code), 'truncated instruction')
        value = code[offset:offset+n]
        offset += n
        require(offset - start <= 15, 'overlong instruction')
        return value
    def byte():
        return take(1)[0]
    prefixes = []
    while offset < len(code) and code[offset] in (0x66, 0xf2, 0xf3, 0xf0, 0x2e, 0x64):
        p = byte()
        require(p not in prefixes or p == 0x66, 'duplicate legacy prefix')
        prefixes.append(p)
    require(not (0xf2 in prefixes and 0xf3 in prefixes), 'conflicting repeat prefixes')
    rex = 0
    if offset < len(code) and 0x40 <= code[offset] <= 0x4f:
        rex = byte()
    op = byte()
    operand = 2 if 0x66 in prefixes and not rex & 8 else 4
    kind, imm, modrm, group = 'other', 0, False, None
    if op in (0xe8, 0xe9, 0xeb) or 0x70 <= op <= 0x7f:
        require(not prefixes and not rex, 'unsupported branch prefixes')
        kind = 'call_rel32' if op == 0xe8 else 'jmp_rel32' if op == 0xe9 else 'branch'
        imm = 4 if op in (0xe8, 0xe9) else 1
    elif 0xb8 <= op <= 0xbf:
        imm = 8 if rex & 8 else operand
        kind = 'mov_imm'
    elif 0xb0 <= op <= 0xb7:
        imm = 1
    elif 0x50 <= op <= 0x5f or op in (0x90, 0x98, 0x99, 0xc3, 0xcc, 0xc9, 0xfc):
        pass
    elif op in (0x68, 0x6a, 0xa8, 0xa9, 0xc2):
        imm = 2 if op == 0xc2 else 1 if op in (0x6a, 0xa8) else operand
    elif op in tuple(x + y for x in range(0, 0x40, 8) for y in range(4)) + (
            0x63, 0x69, 0x6b, 0x80, 0x81, 0x83, 0x84, 0x85, 0x86, 0x87,
            0x88, 0x89, 0x8a, 0x8b, 0x8d, 0x8f, 0xc0, 0xc1, 0xc6, 0xc7,
            0xd0, 0xd1, 0xd2, 0xd3, 0xf6, 0xf7, 0xfe, 0xff):
        modrm = True
        if op in (0x69, 0x81, 0xc7): imm = operand
        if op in (0x6b, 0x80, 0x83, 0xc0, 0xc1, 0xc6): imm = 1
        if op in (0x8f, 0xc6, 0xc7): group = {0}
        if op == 0xfe: group = {0, 1}
        if op == 0xff: group = {0, 1, 2, 4, 6}  # excludes far forms and reserved /7
        if op in (0xf6, 0xf7): group = {0, 2, 3, 4, 5, 6, 7}
        if op == 0x8d: kind = 'lea'
        if op == 0xc7: kind = 'mov_imm'
    elif op < 0x40 and op % 8 in (4, 5):
        imm = 1 if op % 8 == 4 else operand
    elif op == 0x0f:
        op2 = byte()
        if 0x80 <= op2 <= 0x8f:
            require(not prefixes and not rex, 'unsupported conditional branch prefixes')
            imm, kind = 4, 'branch'
        elif op2 == 0x0b:
            kind = 'ud2'
        elif 0xc8 <= op2 <= 0xcf:
            require(not prefixes, 'unsupported BSWAP prefixes')
        elif op2 in (0x10, 0x11, 0x14, 0x15, 0x16, 0x17, 0x1f, 0x28, 0x29,
                     0x2a, 0x2c, 0x2d, 0x2e, 0x2f, 0x50, 0x51, 0x54, 0x55,
                     0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e,
                     0x5f, 0x60, 0x61, 0x62, 0x66, 0x6c, 0x6d, 0x6e, 0x6f,
                     0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x7e, 0x7f,
                     0xa3, 0xab, 0xaf, 0xb0, 0xb1, 0xb3, 0xb6, 0xb7, 0xba,
                     0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0, 0xc1, 0xc2, 0xc6,
                     0xd4, 0xd6, 0xd7, 0xdb, 0xdf, 0xe6, 0xeb, 0xef, 0xf3,
                     0xf4, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe) or 0x40 <= op2 <= 0x4f or 0x90 <= op2 <= 0x9f:
            modrm = True
            if op2 in (0x70, 0x71, 0x72, 0x73, 0xba, 0xc2, 0xc6): imm = 1
            if op2 == 0x1f: group = {0}
            if op2 in (0x71, 0x72): group = {2, 4, 6}
            if op2 == 0x73: group = {2, 3, 6, 7}
            if op2 == 0xba: group = {4, 5, 6, 7}
        else:
            raise EvidenceError(f'unsupported 0f opcode {op2:02x}')
    else:
        raise EvidenceError(f'unsupported opcode {op:02x}')
    if modrm:
        m = byte()
        mod, reg, rm = m >> 6, (m >> 3) & 7, m & 7
        require(group is None or reg in group, 'unsupported ModRM group')
        require(op != 0x8d or mod != 3, 'register-source LEA is invalid')
        if op in (0xf6, 0xf7) and reg == 0: imm = 1 if op == 0xf6 else operand
        if mod != 3:
            if rm == 4:
                sib = byte()
                if mod == 0 and sib & 7 == 5: take(4)
            elif mod == 0 and rm == 5:
                take(4)
            if mod == 1: take(1)
            if mod == 2: take(4)
        if 0xf0 in prefixes:
            require(mod != 3 and (op in (0x01, 0x09, 0x21, 0x29, 0x31, 0x80, 0x81, 0x83, 0xff)
                    or op == 0x0f and op2 in (0xb0, 0xb1, 0xc0, 0xc1)), 'unsupported LOCK form')
    else:
        require(0xf0 not in prefixes, 'LOCK without memory operand')
    if 0xf0 in prefixes and op in (0x80, 0x81, 0x83):
        require(reg != 7, 'LOCK CMP is invalid')
    if 0xf0 in prefixes and op == 0xff:
        require(reg in (0, 1), 'unsupported LOCK FF group')
    if prefixes.count(0x66) > 1 or 0x2e in prefixes:
        require(op == 0x0f and op2 == 0x1f and all(p in (0x66, 0x2e) for p in prefixes),
                'redundant prefixes only supported on NOP')
    if 0x64 in prefixes:
        require(prefixes == [0x64] and modrm and mod != 3 and op in (0x8b, 0x89, 0x80, 0x83, 0x88, 0xc6, 0x0f, 0xff, 0x22),
                'unsupported FS form')
    take(imm)
    return {'site': base + start, 'raw': bytes(code[start:offset]), 'kind': kind}


def decode_fde(image, fde):
    code = image.read(fde['start'], fde['end'] - fde['start'])
    instructions, cursor = [], 0
    while cursor < len(code):
        try:
            insn = decode_instruction(code, cursor, fde['start'])
        except EvidenceError as exc:
            raise EvidenceError(f"FDE {fde['start']:#x} site {fde['start']+cursor:#x}: {exc}") from exc
        instructions.append(insn)
        cursor += len(insn['raw'])
    require(cursor == len(code), 'FDE decode did not end exactly')
    validate_branch_boundaries(instructions, fde['start'], fde['end'])
    return instructions

# Finite search probes, not recovered names or source text. Present text is
# checked against the ELF. Absent probes remain negative results.
DIAGNOSTICS = (
    'write_evm_kvs_batch', 'write evm kv batch', 'EvmKvsMsg', 'tcp_bytes',
    'evm kvs large kv', 'rocksdb from tcp stream large',
    'receiving evm kvs for checkpoint that already exists',
    'failed to receive evm kvs', 'rocksdb from tcp stream too large, exiting',
    'received rocksdb from tcp stream', 'evm kvs height mismatch',
    'RocksDb too large', 'evm_kvs_checkpoint', 'rocksdb bug',
)
CONSTANTS = (-1, 8)


def instruction_evidence(image, insn):
    require(insn['raw'] == image.read(insn['site'], len(insn['raw'])), 'instruction evidence differs from input')
    return {**image.evidence(insn['site'], len(insn['raw'])), 'kind': insn['kind']}


def decode_rel32_transfer(raw, site):
    require(len(raw) == 5 and raw[0] in (0xe8, 0xe9), 'not E8/E9 rel32')
    return site + 5 + struct.unpack_from('<i', raw, 1)[0]


def decode_mov_immediate(raw):
    """B8+r imm32 (optional REX without W), or REX.W C7 /0 sign-extended imm32."""
    i, rex = 0, 0
    if raw and 0x40 <= raw[0] <= 0x4f:
        rex, i = raw[0], 1
    require(i < len(raw), 'truncated immediate MOV')
    if 0xb8 <= raw[i] <= 0xbf:
        require(not rex & 8 and len(raw) == i + 5, 'not register imm32 MOV')
        return {'register': raw[i] - 0xb8 + (8 if rex & 1 else 0),
                'value': struct.unpack_from('<I', raw, i+1)[0], 'width': 32}
    require(rex & 8 and raw[i] == 0xc7 and len(raw) >= i + 6, 'not qword immediate MOV')
    require(raw[i+1] >> 3 & 7 == 0, 'not C7 /0')
    if raw[i+1] >> 6 == 3:
        require(len(raw) == i + 6, 'overlong immediate MOV')
        return {'register': (raw[i+1] & 7) + (8 if rex & 1 else 0),
                'value': struct.unpack_from('<i', raw, i+2)[0], 'width': 64}
    memory, end = decode_base_memory(raw, i+1, rex)
    require(end + 4 == len(raw), 'qword MOV trailing/truncated bytes')
    return {'memory': memory, 'value': struct.unpack_from('<i', raw, end)[0], 'width': 64}


def decode_base_memory(raw, i, rex):
    """Only base+signed displacement, with optional no-index SIB. No RIP/index."""
    require(i < len(raw), 'missing ModRM')
    mod, rm = raw[i] >> 6, raw[i] & 7
    require(mod in (0, 1, 2), 'not memory operand')
    i += 1
    if rm == 4:
        require(i < len(raw), 'missing SIB')
        sib = raw[i]; i += 1
        require(sib >> 3 & 7 == 4 and not rex & 2 and sib >> 6 == 0, 'indexed/scaled memory not accepted')
        rm = sib & 7
    require(not (mod == 0 and rm == 5), 'RIP/no-base memory not accepted')
    width = {0: 0, 1: 1, 2: 4}[mod]
    require(i + width <= len(raw), 'truncated displacement')
    disp = int.from_bytes(raw[i:i+width], 'little', signed=True) if width else 0
    return {'base_register': rm + (8 if rex & 1 else 0), 'displacement': disp}, i + width


def decode_pointer_store(raw):
    require(len(raw) >= 3 and 0x48 <= raw[0] <= 0x4f and raw[1] == 0x89,
            'not qword register store')
    memory, end = decode_base_memory(raw, 2, raw[0])
    require(end == len(raw), 'store trailing bytes')
    return memory, (raw[2] >> 3 & 7) + (8 if raw[0] & 4 else 0)


def pointer_length_pair(image, insns, index, literal):
    first = insns[index]
    for previous, current in zip(insns[index:index+5], insns[index+1:index+6]):
        require(current['site'] == previous['site']+len(previous['raw']), 'noncontiguous literal setup')
    target, reg = decode_lea(first['raw'], first['site'])
    require(image.read(target, len(literal)) == literal, 'literal mismatch')
    require(index + 2 < len(insns), 'truncated pointer/length sequence')
    following = insns[index+1]
    # Adjacent fields: store pointer register, then store qword length at +8.
    if len(following['raw']) >= 2 and following['raw'][1] == 0x89:
        memory, source = decode_pointer_store(following['raw'])
        length = decode_mov_immediate(insns[index+2]['raw'])
        require(source == reg, 'stored register differs from LEA')
        require(length.get('memory') == {**memory, 'displacement': memory['displacement'] + 8},
                'length is not adjacent to pointer')
        require(length['value'] == len(literal), 'stored length differs from probe')
        return {'kind': 'adjacent_pointer_length_fields', 'length': len(literal),
                'pointer_field': memory, 'setup': [instruction_evidence(image, x) for x in insns[index:index+3]]}
    # Two observed register pairs. Only intervening non-clobbering LEAs pass.
    length_reg = {2: 1, 7: 6}.get(reg)
    require(length_reg is not None, 'unsupported pointer/length register pair')
    j = index+1
    while j < len(insns) and insns[j]['kind'] == 'lea':
        raw = insns[j]['raw']
        if len(raw) == 7 and LEA_RE.fullmatch(raw[:3]):
            _, dest = decode_lea(raw, insns[j]['site'])
        else:
            require(raw[:2] == b'\x48\x8d', 'unsupported intervening LEA')
            _, end = decode_base_memory(raw, 2, raw[0])
            require(end == len(raw), 'intervening LEA length')
            dest = raw[2] >> 3 & 7
        require(dest not in (reg, length_reg), 'intervening LEA clobbers pair')
        j += 1
        require(j-index <= 4, 'overlong register pair setup')
    require(j+1 < len(insns), 'truncated register pair')
    length = decode_mov_immediate(insns[j]['raw'])
    require(length.get('register') == length_reg and length['value'] == len(literal),
            'register length differs from probe')
    call = insns[j+1]
    require(call['kind'] == 'call_rel32' or len(call['raw']) == 6 and call['raw'][:2] == b'\xff\x15',
            'pair is not followed by a supported call')
    return {'kind': 'register_pointer_length_pair', 'length': len(literal),
            'pointer_register': reg, 'length_register': length_reg,
            'setup': [instruction_evidence(image, x) for x in insns[index:j+2]]}


def counted_fragment(image, anchor, occurrence, probe):
    """Prove a bounded byte pattern, not a formatter grammar or rendered log.

    From the LEA target traverse at most four (u8 length, ASCII bytes, C0)
    chunks, retaining each byte. Accept only a probe wholly within one chunk.
    Stop at the probe's chunk; do not interpret placeholders or later bytes.
    """
    cursor, chunks = anchor, []
    if image.read(cursor, 1) == b'\xc0':
        cursor += 1  # Explicit initial marker; no grammar/argument semantics.
    for _ in range(4):
        n = image.read(cursor, 1)[0]
        require(0 < n < 128, 'zero terminator or counted chunk length outside bounded grammar')
        text = image.read(cursor+1, n) if n else b''
        require(all(32 <= b < 127 or b in (9, 10, 13) for b in text), 'non-ASCII counted chunk')
        require(image.read(cursor+1+n, 1) == b'\xc0', 'counted chunk lacks C0 marker')
        chunks.append({'length': n, 'text': text.decode('ascii'), 'record': image.evidence(cursor, n+2)})
        if cursor+1 <= occurrence and occurrence+len(probe) <= cursor+1+n:
            require(text[occurrence-cursor-1:occurrence-cursor-1+len(probe)] == probe, 'probe differs within chunk')
            return {'kind': 'counted_ascii_chunks', 'chunks': chunks,
                    'probe_offset_in_last_chunk': occurrence-cursor-1,
                    'length': n, 'pattern': image.evidence(anchor, cursor+n+2-anchor)}
        cursor += n+2
    raise EvidenceError('probe outside bounded counted chunks')


def occurrences(image, needle):
    # Whole-file exact bytes, then section mapping; absence is not inferred from
    # absence of code xrefs. The entire binary is already authenticated.
    pos, result = -1, []
    while (pos := image.data.find(needle, pos+1)) >= 0:
        matches = [s for s in image.sections if s['type'] != 8
                   and s['offset'] <= pos and pos+len(needle) <= s['offset']+s['size']]
        require(len(matches) == 1, 'literal has ambiguous/no section mapping')
        s = matches[0]
        result.append({'va': hex(s['address']+pos-s['offset']), 'file_offset': hex(pos),
                       'section': s['name'], 'bytes': needle.hex()})
    return result


def diagnostic_inventory(image, decoded):
    leas = []
    for start, insns in sorted(decoded.items()):
        for i, x in enumerate(insns):
            if len(x['raw']) == 7 and LEA_RE.fullmatch(x['raw'][:3]):
                a, _ = decode_lea(x['raw'], x['site'])
                leas.append((a, start, i))
    result = []
    for text in DIAGNOSTICS:
        probe = text.encode('ascii')
        hits, anchors, rejected = occurrences(image, probe), [], []
        for hit in hits:
            if hit['section'] != '.rodata': continue
            occurrence = int(hit['va'], 16)
            for anchor, start, i in leas:
                if not 0 <= occurrence-anchor <= 128: continue
                insns = decoded[start]
                row = {'owner': hex(start), 'occurrence': hex(occurrence), 'anchor': hex(anchor),
                       'lea': instruction_evidence(image, insns[i])}
                try:
                    proof = (pointer_length_pair(image, insns, i, probe) if occurrence == anchor
                             else counted_fragment(image, anchor, occurrence, probe))
                except EvidenceError as exc:
                    rejected.append({**row, 'reason': str(exc),
                                     'following_instructions': [instruction_evidence(image, x) for x in insns[i+1:i+6]]})
                else:
                    anchors.append({**row, **proof})
        result.append({'probe': text, 'status': 'bound' if anchors else 'present-but-unbound' if hits else 'absent',
                       'occurrences': hits, 'anchors': anchors, 'rejected_candidates': rejected})
    return result


def constant_inventory(image, decoded, diagnostics):
    # The only accepted co-location is an immediate qword at field +16 directly
    # after an authenticated label pointer/+8 length pair. This binds a number
    # to a record construction, never a capacity/unit/timeout interpretation.
    triples = []
    for diagnostic in diagnostics:
        for anchor in diagnostic['anchors']:
            if anchor['kind'] != 'adjacent_pointer_length_fields': continue
            insns = decoded[int(anchor['owner'], 16)]
            site = int(anchor['lea']['va'], 16)
            i = next(i for i, x in enumerate(insns) if x['site'] == site)
            if i+3 >= len(insns): continue
            try:
                immediate = decode_mov_immediate(insns[i+3]['raw'])
            except EvidenceError:
                continue
            if immediate.get('memory') != {**anchor['pointer_field'], 'displacement': anchor['pointer_field']['displacement']+16}:
                continue
            triples.append({'value': immediate['value'], 'label': diagnostic['probe'], 'owner': anchor['owner'],
                            'lea_site': anchor['lea']['va'], 'field': immediate['memory'],
                            'instruction': instruction_evidence(image, insns[i+3])})
    result = []
    for value in CONSTANTS:
        matches = [t for t in triples if t['value'] == value]
        labels = [t['label'] for t in matches]
        unique = bool(matches) and len(labels) == len(set(labels))
        # Include all decoded immediate MOV occurrences as ambiguity controls;
        # this is not a census of arithmetic immediates or constant propagation.
        immediates = []
        for start, insns in sorted(decoded.items()):
            for insn in insns:
                if insn['kind'] != 'mov_imm': continue
                try:
                    immediate = decode_mov_immediate(insn['raw'])
                except EvidenceError:
                    continue
                if immediate['value'] == value:
                    immediates.append({'owner': hex(start), 'decoded': immediate,
                                       'instruction': instruction_evidence(image, insn)})
        result.append({'value': value, 'status': 'bound' if unique else 'unresolved',
                       'binding': 'unique adjacent field construction per scoped label; numeric bytes only' if unique else None,
                       'co_locations': matches, 'immediate_mov_occurrences': immediates,
                       'semantic_name_and_units': 'unresolved'})
    return result


def scoped_edges(image, decoded):
    result = []
    for start, insns in sorted(decoded.items()):
        for insn in insns:
            if insn['kind'] not in ('call_rel32', 'jmp_rel32'): continue
            target = decode_rel32_transfer(insn['raw'], insn['site'])
            if target in decoded:
                result.append({'caller': hex(start), 'callee': hex(target),
                               'instruction': instruction_evidence(image, insn),
                               'signed_displacement': struct.unpack_from('<i', insn['raw'], 1)[0],
                               'next_instruction': hex(insn['site']+5)})
    return result



def validate_branch_boundaries(insns, start, end):
    boundaries = {x['site'] for x in insns}
    for insn in insns:
        raw, site = insn['raw'], insn['site']
        if insn['kind'] in ('call_rel32', 'jmp_rel32'):
            target = decode_rel32_transfer(raw, site)
        elif insn['kind'] == 'branch':
            displacement = int.from_bytes(raw[2:] if raw[0] == 0x0f else raw[1:], 'little', signed=True)
            target = site+len(raw)+displacement
        else:
            continue
        if start <= target < end:
            require(target in boundaries, 'internal branch lands inside an instruction')


def metric_table(metrics):
    """Shared derived report block; verifier/tests reject stale documentation."""
    return ('<!-- BEGIN GENERATED METRICS -->\n'
            '| Metric | Count |\n| --- | ---: |\n' +
            ''.join(f'| {key} | {value} |\n' for key, value in sorted(metrics.items())) +
            '<!-- END GENERATED METRICS -->')


def build(data):
    authenticate(data)
    image = Image(data)
    relocations = relative_relocations(image)
    locs = locations(image, relocations)
    require(locs, 'no exact-path Locations')
    fdes = Fdes(image)
    leas = scan_leas(image)
    scoped, pending = {}, []
    for slot in locs:
        require(leas.get(slot), 'Location lacks a RIP LEA')
        for site in leas[slot]:
            owner = fdes.owner(site, 7)
            require(owner is not None, 'Location LEA lacks an FDE extent')
            scoped[owner['start']] = owner
            pending.append((site, slot, owner['start']))
    decoded = {start: decode_fde(image, fde) for start, fde in sorted(scoped.items())}
    accepted = []
    for site, slot, start in sorted(pending):
        insn, reg = verified_lea(image, decoded[start], site, slot)
        accepted.append({'location': hex(slot), 'owner': hex(start), 'destination_register_index': reg,
                         'instruction': instruction_evidence(image, insn)})
    require({int(x['owner'], 16) for x in accepted} == set(scoped), 'unanchored FDE')
    for slot, loc in locs.items():
        loc['lea_sites'] = [x['instruction']['va'] for x in accepted if x['location'] == hex(slot)]
        loc['owning_fdes'] = sorted({x['owner'] for x in accepted if x['location'] == hex(slot)})
    diagnostics = diagnostic_inventory(image, decoded)
    constants = constant_inventory(image, decoded, diagnostics)
    edges = scoped_edges(image, decoded)
    transfer_counts = Counter(x['kind'] for rows in decoded.values() for x in rows
                              if x['kind'] in ('call_rel32', 'jmp_rel32'))
    metrics = {'locations': len(locs), 'location_leas': len(accepted), 'scoped_fdes': len(scoped),
               'unique_line_column': len({(x['line'], x['column']) for x in locs.values()}),
               'scoped_fde_bytes': sum(f['end']-f['start'] for f in scoped.values()),
               'decoded_instructions': sum(len(x) for x in decoded.values()),
               'diagnostics_probed': len(diagnostics),
               'diagnostics_bound': sum(x['status'] == 'bound' for x in diagnostics),
               'diagnostics_unresolved': sum(x['status'] == 'present-but-unbound' for x in diagnostics),
               'diagnostics_absent': sum(x['status'] == 'absent' for x in diagnostics),
               'pointer_length_anchors': sum(a['kind'] != 'counted_ascii_chunks' for d in diagnostics for a in d['anchors']),
               'counted_fragment_anchors': sum(a['kind'] == 'counted_ascii_chunks' for d in diagnostics for a in d['anchors']),
               'constants_bound': sum(x['status'] == 'bound' for x in constants),
               'constants_unresolved': sum(x['status'] == 'unresolved' for x in constants),
               'scoped_rel32_calls': sum(e['instruction']['kind'] == 'call_rel32' for e in edges),
               'scoped_rel32_jumps': sum(e['instruction']['kind'] == 'jmp_rel32' for e in edges),
               'out_of_scope_rel32_transfers': sum(transfer_counts.values()) - len(edges)}
    evidence = {'schema_version': 1, 'work_item': 'evm-kvs-inventory-94', 'task': 'RE-009 / RE-001 bounded inventory',
                'component': 'storage', 'target': {'path': TARGET, 'sha256': SHA256, 'release': 94},
                'scope_rule': SCOPE.decode('ascii'), 'metrics': metrics,
                'coordinates': 'ELF link-time VA; explicit file offsets; FDE end exclusive; no ASLR/rebase',
                'source_commit': BASE_COMMIT, 'reference_commit_leads_only': REFERENCE_COMMIT,
                'producer_sources_sha256': {f'tools/{name}': sha((TOOLS/name).read_bytes()) for name in
                                           ('evm_kvs_inventory.py', 'elf_index.py', 'fde_extents.py')},
                'method': {'decoder': 'evm_kvs_inventory restricted legacy x86-64 byte decoder v1',
                           'dependency': 'Python 3.10+ stdlib; no external disassembler',
                           'all_fde_records_checked': len(fdes.rows),
                           'boundary_check': 'complete linear decoding from actual FDE start and internal direct-branch alignment; not CFG reachability',
                           'location_layout': 'RELA pointer + u64 path length + u32 line + u32 column',
                           'normalization_masks': [], 'captured_binary_executed': False, 'network_used': False},
                'locations': list(locs.values()), 'location_leas': accepted,
                'fdes': [Fdes.record(image, f) for _, f in sorted(scoped.items())],
                'diagnostics': diagnostics, 'constants': constants, 'call_edges': edges,
                'related_evidence': 'research/work-items/RE-009-storage-state-roots/state-roots.json',
                'remaining_gaps': {
                    'call_targets': 'Direct transfers outside the scoped FDE starts are counted but not attributed.',
                    'helpers': 'No helper closure, argument roles or error propagation established.',
                    'indirect_calls': 'FF15 appears in literal setups; no slot/callee or vtable resolution claimed.',
                    'relocations': 'Location RELATIVE relocations only; no whole-program relocation comparison.',
                    'data_and_vtables': 'Only recorded Location/literal/adjacent-field bytes; other data unresolved.',
                    'whole_elf': 'No build or comparison; normalization masks empty.'},
                'non_claims': [
                    'No runtime behavior, network activity, protocol semantics or source reconstruction.',
                    'No recovered Rust, build, binary equivalence, coverage denominator or progress gate.',
                    'No exclusive component ownership, source function names, CFG reachability or full call graph.',
                    'No claims for evm_rpc, evm_store, l1 EVM, nv_stream, consensus, abci, or generic foundation helpers.',
                    'No re-derivation of RE-009 hashing or changed conclusions about its helpers.',
                    'FDE extents are unwind ranges; code without FDEs, inlining and split bodies remain gaps.',
                    'No semantics for counted-template control bytes or runtime rendering.',
                    'No constant units, capacities, limits or timeouts established by numeric co-location.',
                    'No helper closure, indirect-call/vtable/data closure, relocation equivalence or whole-ELF comparison.',
                    'No parity claim for node #115 or visor.'
                ]}
    instructions = {'target_sha256': SHA256, 'decoder': evidence['method']['decoder'],
                    'columns': ['offset_from_fde_start', 'raw_hex', 'decoded_kind'],
                    'fdes': [{'start': hex(start), 'end_exclusive': hex(scoped[start]['end']),
                              'instructions': [[hex(x['site']-start), x['raw'].hex(), x['kind']] for x in insns]}
                             for start, insns in sorted(decoded.items())]}
    return {'inventory.json': evidence, 'instructions.json': instructions}


def render(value):
    text = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True)
    if isinstance(value, dict) and 'columns' in value:
        # One compact raw instruction row per line keeps the transcript reviewable.
        text = re.sub(r'\[\n\s+("0x[0-9a-f]+"),\n\s+("[0-9a-f]+"),\n\s+("[a-z0-9_]+")\n\s+\]',
                      r'[\1, \2, \3]', text)
    return (text+'\n').encode('ascii')


def generate(binary, out):
    with Path(binary).open('rb') as handle, mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as data:
        result = build(data)
    Path(out).mkdir(parents=True, exist_ok=True)
    for name in OUTPUTS:
        Path(out, name).write_bytes(render(result[name]))
    return result['inventory.json']['metrics']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT/TARGET)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    try:
        metrics = generate(args.binary, args.out)
    except (ValueError, OSError) as exc:
        parser.exit(1, f'FAIL: {exc}\n')
    print(json.dumps(metrics, sort_keys=True))


if __name__ == '__main__':
    main()
