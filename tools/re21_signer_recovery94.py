#!/usr/bin/env python3
"""Extract a static #94 transaction-signer recovery path, without target execution.

The restricted x86 length decoder below is adapted from this repository's
MIT-licensed tools/evm_kvs_inventory.py. It establishes byte boundaries for
this fixed corpus; it does not execute instructions or infer reachability.
"""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import struct
import sys

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
from elf_index import sections
from fde_extents import fde_extents, uleb

ROOT = HERE.parent
TARGET = Path('artifacts/node/94/hl-node')
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

# Names are analytical descriptions, not symbols from the stripped ELF.
FUNCTIONS = {
    0x4e57c90: 'signer recovery and address-result adapter',
    0x4eb8530: 'recovery-context allocation and constructor handoff',
    0x4eb8650: 'recovery-context initialization callback',
    0x5632c40: 'normalized field to 32 output bytes',
    0x5637320: 'public-key storage to field representation',
    0x563a5e0: 'recovered point to public-key storage',
    0x563efa0: 'self-test digest finalization boundary',
    0x56402a0: 'context self-test and digest comparison',
    0x56403a0: 'context layout-size and flag checks',
    0x56403f0: 'existing-context layout-size check',
    0x5640430: 'preallocated context construction',
    0x56404b0: 'preallocated context destruction',
    0x5640530: 'public-key serialization',
    0x5640710: 'compact recoverable-signature parser',
    0x5640860: 'recoverable-signature and digest to public-key adapter',
}


class EvidenceError(ValueError):
    pass


def require(ok, message):
    if not ok:
        raise EvidenceError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def authenticate(data):
    require(sha(data) == SHA256, 'node #94 digest mismatch')


class Image:
    def __init__(self, data, check_hash=True):
        if check_hash:
            authenticate(data)
        self.data = data
        self.sections = sections(data)

    def section(self, name):
        rows = [s for s in self.sections if s['name'] == name]
        require(len(rows) == 1 and rows[0]['type'] != 8, 'missing or ambiguous file section')
        return rows[0]

    def offset(self, va, count, executable=False):
        require(isinstance(va, int) and isinstance(count, int) and va >= 0 and count > 0,
                'invalid virtual address or byte count')
        matches = [s for s in self.sections if s['type'] != 8 and s['flags'] & 2
                   and (not executable or s['flags'] & 4)
                   and s['address'] <= va and va + count <= s['address'] + s['size']]
        require(len(matches) == 1, 'virtual range is not uniquely file-backed')
        s = matches[0]
        off = s['offset'] + va - s['address']
        require(0 <= off and off + count <= len(self.data), 'file range out of bounds')
        return off

    def read(self, va, count, executable=False):
        o = self.offset(va, count, executable)
        return bytes(self.data[o:o + count])


def decode_instruction(code, offset=0, base=0):
    """Restricted legacy x86-64 length decoder, not a general disassembler.

    Decode sequentially from FDE entry; never resynchronize after an unknown
    opcode. ModRM/SIB/displacements and immediates are consumed, so opcode-like
    bytes inside operands cannot become anchors. Only enumerated forms pass.
    Operand semantics used for claims get a second exact decoder below.
    """
    require(0 <= offset < len(code), 'instruction offset outside input')
    if code[offset:offset + 4] == bytes.fromhex('f30f1efa'):
        return {'site': base + offset, 'raw': bytes(code[offset:offset+4]), 'kind': 'other'}
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
        elif op2 in (0x10, 0x11, 0x12, 0x14, 0x15, 0x16, 0x17, 0x1f, 0x28, 0x29,
                     0x2a, 0x2c, 0x2d, 0x2e, 0x2f, 0x50, 0x51, 0x54, 0x55,
                     0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e,
                     0x5f, 0x60, 0x61, 0x62, 0x66, 0x67, 0x68, 0x6c, 0x6d, 0x6e, 0x6f,
                     0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x7e, 0x7f,
                     0xa3, 0xa4, 0xa5, 0xab, 0xac, 0xad, 0xaf, 0xb0, 0xb1, 0xb3, 0xb6, 0xb7, 0xba,
                     0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0, 0xc1, 0xc2, 0xc6,
                     0xd4, 0xd6, 0xd7, 0xdb, 0xdf, 0xe6, 0xeb, 0xef, 0xf3,
                     0xf4, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe) or 0x40 <= op2 <= 0x4f or 0x90 <= op2 <= 0x9f:
            modrm = True
            if op2 in (0x70, 0x71, 0x72, 0x73, 0xa4, 0xac, 0xba, 0xc2, 0xc6): imm = 1
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
        require(prefixes == [0x64] and modrm and mod != 3 and op in (0x8b, 0x89, 0x80, 0x83, 0x88, 0xc6, 0x0f, 0xff, 0x22, 0x2b),
                'unsupported FS form')
    take(imm)
    return {'site': base + start, 'raw': bytes(code[start:offset]), 'kind': kind}




# Selected instruction predicates independently reviewed in the authenticated image.
PINS = {
    0x4e57c9f: '0fb64e40',
    0x4e57ca3: '83f904',
    0x4e57ca6: '0f833d030000',
    0x4e57cd4: '4c8b3585819100',
    0x4e57cdb: '498b3e',
    0x4e57ce6: 'ff157c819100',
    0x4e57cec: '83f801',
    0x4e57cef: '0f85fd020000',
    0x4e57d98: '8b05daea9200',
    0x4e57da0: '0f8566020000',
    0x4e57da6: '488b3dbb069300',
    0x4e57db0: '0f8494020000',
    0x4e57df2: 'ff15387f9100',
    0x4e57df8: '83f801',
    0x4e57dfb: '0f85f1010000',
    0x4e57ea0: '48c78424c001000041000000',
    0x4e57ec4: '41b802000000',
    0x4e57eca: 'ff15a07f9100',
    0x4e57f06: '488d742401',
    0x4e57f76: '48c784249002000088000000',
    0x4e57f94: 'ba40000000',
    0x4e57f9c: 'ff1536629100',
    0x4e57fc0: 'ba20000000',
    0x4e57fc8: 'ff1512629100',
    0x4e57fce: '8b8424bc020000',
    0x4e57fd5: '894311',
    0x4e57fd8: '0f108424ac020000',
    0x4e57fe0: '0f114301',
    0x4e57fe4: 'c60300',
    0x4e57fe9: 'c7430406000000',
    0x4e57ff2: 'c7430403000000',
    0x4e57ff9: 'c60301',
    0x4e58018: '488d3d59e89200',
    0x4e5801f: '488d0d1a8e8f00',
    0x4e58034: 'ff157e689100',
    0x4e5803a: '488b3d27049300',
    0x4e58041: '4885ff',
    0x4e58044: '0f856cfdffff',
    0x4eb8535: 'bf01030000',
    0x4eb853a: 'ff1538eb8b00',
    0x4eb8543: '48b8f0ffffffffffff7f',
    0x4eb8550: '7742',
    0x4eb8555: '4883fb0f',
    0x4eb8559: '7608',
    0x4eb855b: 'ff15775a8b00',
    0x4eb8568: 'ff15225d8b00',
    0x4eb856e: '4885c0',
    0x4eb8571: '7413',
    0x4eb8576: 'be01030000',
    0x4eb8580: 'ff25faea8b00',
    0x4eb858e: 'ff158c5a8b00',
    0x4eb8659: '488b07',
    0x4eb865c: '0fb608',
    0x4eb865f: 'c60000',
    0x4eb8662: '80f901',
    0x4eb8665: '7562',
    0x4eb8667: 'ff1503ea8b00',
    0x4eb8670: '4c8b35f1fd8c00',
    0x4eb8677: '4d85f6',
    0x4eb867a: '743c',
    0x4eb867f: 'ff15dbe98b00',
    0x4eb868b: 'ff15d7e98b00',
    0x4eb8691: '48b8f1ffffffffffff7f',
    0x4eb869e: '7336',
    0x4eb86b2: 'ff1558598b00',
    0x4eb86b8: '48891da9fd8c00',
    0x4eb86c9: '488d3d98878900',
    0x4eb86fb: '0f0b',
    0x4eb86fd: '48891d64fd8c00',
    0x56402ac: '660f6f056c89bcfa',
    0x56402dc: '660f6f05fc72bcfa',
    0x56402ec: '660f6f05dc37bcfa',
    0x56402f9: '660f6f057f3ebcfa',
    0x5640306: '660f6f05927dbcfa',
    0x5640313: '660f6f05753ebcfa',
    0x56402cf: '48c74424603f000000',
    0x5640320: 'e87becffff',
    0x5640327: '488d1552651cfb',
    0x5640334: '4883f820',
    0x564033a: '0fb60c02',
    0x564033e: '380c03',
    0x5640341: '74ed',
    0x5640367: 'e9e48487ff',
    0x56403a8: '4080ff01',
    0x56403ae: '81e700040000',
    0x56403b4: 'b8d0000000',
    0x564043f: 'e85cfeffff',
    0x5640446: 'e855ffffff',
    0x5640453: '7451',
    0x5640472: '488983a8000000',
    0x564048b: '488983b8000000',
    0x5640492: 'e889faffff',
    0x5640497: 'c70301000000',
    0x56404a0: '89abc8000000',
    0x56404c0: '8b07',
    0x56404ca: 'c70700000000',
    0x56404d0: 'c787a000000000000000',
    0x56404da: '48c7879800000000000000',
    0x5640530: 'f30f1efa',
    0x5640555: '4885d2',
    0x5640558: '0f84f2000000',
    0x5640564: '488b12',
    0x564056a: '4181e700010000',
    0x5640571: '4183ff01',
    0x564057f: '4839ea',
    0x5640582: '0f82e8000000',
    0x5640588: '48c70300000000',
    0x5640592: '4885f6',
    0x56405a5: 'e896fb0100',
    0x56405af: '4885c9',
    0x56405b8: '4180fd02',
    0x56405bc: '0f850e010000',
    0x56405d0: 'e84b6dffff',
    0x56405d5: '85c0',
    0x56405d7: '7527',
    0x5640600: '8b442460',
    0x5640606: '75d1',
    0x5640625: 'e81626ffff',
    0x564062a: '4585ff',
    0x564062d: '0f84bd000000',
    0x5640633: '8b442438',
    0x564063d: '41880424',
    0x5640641: '48892b',
    0x5640644: 'b801000000',
    0x56406f0: '41c6042404',
    0x56406f5: '498d7c2421',
    0x56406fd: 'e83e25ffff',
    0x5640710: 'f30f1efa',
    0x564073e: '4885f6',
    0x5640741: '0f84c1000000',
    0x5640747: '4885ed',
    0x564074a: '0f84d0000000',
    0x5640750: '4189cc',
    0x5640753: '83f903',
    0x5640756: '0f87e4000000',
    0x564076f: 'e8bc5fffff',
    0x5640785: 'e8a65fffff',
    0x564078a: '440b6c240c',
    0x564078f: '7557',
    0x564079d: '44886340',
    0x56407a1: 'b801000000',
    0x56407e8: '660fefc0',
    0x56407ec: 'c6434000',
    0x56407f0: '31c0',
    0x5640860: 'f30f1efa',
    0x5640891: '4885f6',
    0x5640894: '0f8406010000',
    0x564089a: '4885d2',
    0x564089d: '0f841d010000',
    0x56408a3: '4885db',
    0x56408a6: '0f8434010000',
    0x56408ac: 'f30f6f0a',
    0x56408cf: '440fb67a40',
    0x56408dc: '31d2',
    0x56408f1: 'e83a5effff',
    0x5640905: 'e8b6e3ffff',
    0x564090a: '85c0',
    0x564090c: '7472',
    0x5640916: 'e8c59cffff',
    0x5640927: 'b801000000',
    0x5640935: '0f112b',
    0x5640949: '0f116b30',
    0x5640980: '660fefc0',
    0x5640984: '31c0',
}


def select_fde_records(records):
    by_start = {}
    for rec in records:
        if rec['start'] in FUNCTIONS:
            require(rec['start'] not in by_start, 'duplicate selected FDE start')
            require('index' in rec and rec['end'] > rec['start'], 'missing indexed positive FDE')
            by_start[rec['start']] = rec
    require(set(by_start) == set(FUNCTIONS), 'missing selected FDE')
    return by_start


def selected_fdes(data):
    _, records, _ = fde_extents(data)
    return select_fde_records(records)


def decode_body(image, fde):
    start, end = fde['start'], fde['end']
    code = image.read(start, end - start, executable=True)
    rows = []
    cursor = 0
    while cursor < len(code):
        try:
            ins = decode_instruction(code, cursor, start)
        except (EvidenceError, IndexError) as error:
            raise EvidenceError(f'unsupported instruction at {start + cursor:#x}: {error}') from error
        require(ins['raw'], 'empty instruction')
        rows.append(ins)
        cursor += len(ins['raw'])
    require(cursor == len(code), 'instruction crosses FDE end')
    starts = {row['site'] for row in rows}
    for ins in rows:
        target = relative_target(ins)
        if target is not None and start <= target < end:
            require(target in starts, f'local control transfer into instruction at {ins["site"]:#x}')
    return rows


def relative_target(ins):
    raw, va = ins['raw'], ins['site']
    if ins['kind'] in ('call_rel32', 'jmp_rel32'):
        return va + len(raw) + struct.unpack_from('<i', raw, 1)[0]
    if ins['kind'] == 'branch':
        if raw[0] == 0x0f:
            return va + len(raw) + struct.unpack_from('<i', raw, 2)[0]
        return va + len(raw) + struct.unpack_from('<b', raw, 1)[0]
    return None


def build_instruction_maps(image, fdes):
    rows = {start: decode_body(image, fdes[start]) for start in sorted(fdes)}
    by_site = {i['site']: i for body in rows.values() for i in body}
    require(len(by_site) == sum(map(len, rows.values())), 'duplicate instruction site')
    return rows, by_site


def instruction(by_site, site, shape=None):
    require(site in by_site, f'expected instruction boundary at {site:#x}')
    ins = by_site[site]
    if shape is not None:
        require(ins['raw'].hex() == shape, f'changed instruction at {site:#x}')
    return ins


def tsv(headers, rows):
    out = io.StringIO(newline='')
    w = csv.writer(out, delimiter='\t', lineterminator='\n')
    w.writerow(headers)
    w.writerows(rows)
    return out.getvalue().encode('utf-8')


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + '\n').encode('ascii')

def validate_pins(by_site):
    for va, expected in sorted(PINS.items()):
        instruction(by_site, va, expected)


def pcrel(ins, prefix):
    raw = ins['raw']
    require(raw.startswith(bytes.fromhex(prefix)) and len(raw) == len(bytes.fromhex(prefix)) + 4,
            'unexpected PC-relative instruction')
    return ins['site'] + len(raw) + struct.unpack_from('<i', raw, len(raw) - 4)[0]


def dynamic_symbol(image, index):
    sym = image.section('.dynsym')
    strings = image.section('.dynstr')
    require(index > 0 and index * 24 + 24 <= sym['size'], 'symbol index outside .dynsym')
    off = sym['offset'] + index * 24
    name_offset = struct.unpack_from('<I', image.data, off)[0]
    require(name_offset < strings['size'], 'symbol name outside .dynstr')
    first, last = strings['offset'] + name_offset, strings['offset'] + strings['size']
    end = image.data.find(b'\0', first, last)
    require(end >= 0, 'unterminated dynamic symbol')
    return bytes(image.data[first:end]).decode('ascii')


# Relocation addends bind selected instruction slots or the once descriptor.
RELATIVE_SLOTS = {
    0x5750e60: 0x4eb8650,
    0x576dfd8: 0x54c06b0,
    0x576e010: 0x54c8cb0,
    0x576e020: 0x1345e2a,
    0x576e1d8: 0x4f59a10,
    0x576e1e0: 0x4f59e40,
    0x576e290: 0x54c2670,
    0x576e470: 0x157a9f0,
    0x576e8b8: 0x4ee3b20,
    0x576fd30: 0x5640860,
    0x576fe60: 0x57882e0,
    0x576fe68: 0x5640710,
    0x576fe70: 0x5640530,
    0x5777060: 0x56403f0,
    0x5777068: 0x56404b0,
    0x5777070: 0x4eb8530,
    0x5777078: 0x56403a0,
    0x5777080: 0x5640430,
    0x57882e0: 0x576dca0,
}


def relocations(image):
    wanted = set(RELATIVE_SLOTS) | {0x576dfe0}
    found = {}
    for secname in ('.rela.dyn', '.rela.plt'):
        sec = image.section(secname)
        require(sec['size'] % 24 == 0, 'invalid RELA section size')
        for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
            dest, info, addend = struct.unpack_from('<QQq', image.data, off)
            if dest not in wanted:
                continue
            require(dest not in found, 'duplicate selected relocation')
            typ, symbol = info & 0xffffffff, info >> 32
            if dest in RELATIVE_SLOTS:
                require(info == 8 and addend == RELATIVE_SLOTS[dest], 'changed RELATIVE relocation')
                name = ''
            else:
                require(typ == 6 and addend == 0, 'changed dynamic relocation')
                name = dynamic_symbol(image, symbol)
                require(name == 'memcpy', 'changed dynamic symbol')
            found[dest] = {'slot': hex(dest), 'section': secname, 'entry_file_offset': hex(off),
                           'r_info': hex(info), 'type': typ, 'symbol_index': symbol,
                           'symbol': name, 'addend': hex(addend),
                           'entry_bytes': bytes(image.data[off:off + 24]).hex()}
    require(set(found) == wanted, 'missing selected relocation')
    return found


def verify_relocation_edges(by_site, found):
    edges = {
        0x4e57cd4: ('4c8b35', 0x576fe60),
        0x4e57ce6: ('ff15', 0x576fe68),
        0x4e57df2: ('ff15', 0x576fd30),
        0x4e57eca: ('ff15', 0x576fe70),
        0x4e57f9c: ('ff15', 0x576e1d8),
        0x4e57fc8: ('ff15', 0x576e1e0),
        0x4e58034: ('ff15', 0x576e8b8),
        0x4eb853a: ('ff15', 0x5777078),
        0x4eb855b: ('ff15', 0x576dfd8),
        0x4eb8568: ('ff15', 0x576e290),
        0x4eb8580: ('ff25', 0x5777080),
        0x4eb858e: ('ff15', 0x576e020),
        0x4eb8667: ('ff15', 0x5777070),
        0x4eb867f: ('ff15', 0x5777060),
        0x4eb868b: ('ff15', 0x5777068),
        0x4eb86b2: ('ff15', 0x576e010),
        0x4e57fb2: ('ff15', 0x576dfe0),
    }
    rows = []
    for site, (prefix, slot) in sorted(edges.items()):
        ins = instruction(by_site, site)
        require(pcrel(ins, prefix) == slot, 'changed call or data slot displacement')
        r = found[slot]
        rows.append([hex(site), ins['raw'].hex(), hex(slot), r['type'], r['addend'], r['symbol']])
    return rows


def function_records(image, fdes, all_rows):
    functions, bodies, unwind = [], {}, []
    header = image.section('.eh_frame_hdr')
    for start in sorted(fdes):
        f = fdes[start]
        end = f['end']
        code = image.read(start, end - start, executable=True)
        file_offset = image.offset(start, len(code), executable=True)
        functions.append([hex(start), hex(end), len(code), hex(file_offset), hex(f['fde']),
                          hex(f['cie']), '' if f['lsda'] is None else hex(f['lsda']),
                          f['index'], sha(code), len(all_rows[start]), FUNCTIONS[start]])
        bodies[hex(start)] = {'start': hex(start), 'end_exclusive': hex(end),
                              'file_offset': hex(file_offset), 'bytes_hex': code.hex(),
                              'sha256': sha(code)}
        fde_len = struct.unpack('<I', image.read(f['fde'], 4))[0] + 4
        cie_len = struct.unpack('<I', image.read(f['cie'], 4))[0] + 4
        table_va = header['address'] + 12 + f['index'] * 8
        unwind.append({'start': hex(start), 'fde_va': hex(f['fde']),
                       'fde_bytes': image.read(f['fde'], fde_len).hex(),
                       'cie_va': hex(f['cie']), 'cie_bytes': image.read(f['cie'], cie_len).hex(),
                       'hdr_entry_va': hex(table_va), 'hdr_entry_bytes': image.read(table_va, 8).hex(),
                       'lsda_va': None if f['lsda'] is None else hex(f['lsda'])})
    return functions, bodies, unwind


def transfer_kind(ins):
    raw = ins['raw']
    if ins['kind'] == 'call_rel32':
        return 'direct_call'
    if ins['kind'] == 'jmp_rel32' or raw[0] == 0xeb:
        return 'direct_jump'
    if ins['kind'] == 'branch':
        return 'conditional'
    if raw == b'\xc3':
        return 'return'
    if raw == b'\x0f\x0b':
        return 'ud2'
    # FF /2 and /4 include register-indirect, memory-indirect and RIP slots.
    p = 0
    while p < len(raw) and (raw[p] in (0x66, 0xf2, 0xf3, 0xf0, 0x2e, 0x64)
                            or 0x40 <= raw[p] <= 0x4f):
        p += 1
    if p + 1 < len(raw) and raw[p] == 0xff:
        op = (raw[p + 1] >> 3) & 7
        if op in (2, 4):
            return 'indirect_call' if op == 2 else 'indirect_jump'
    return None


def transfers(all_rows, fdes):
    rows = []
    for start in sorted(all_rows):
        for ins in all_rows[start]:
            kind = transfer_kind(ins)
            if kind is None:
                continue
            target = relative_target(ins)
            raw = ins['raw']
            slot = None
            if raw[:2] in (b'\xff\x15', b'\xff\x25') and len(raw) == 6:
                slot = ins['site'] + 6 + struct.unpack_from('<i', raw, 2)[0]
            scope = ''
            if target is not None:
                scope = 'same_FDE' if start <= target < fdes[start]['end'] else 'external'
            rows.append([hex(start), hex(ins['site']), raw.hex(), kind,
                         '' if target is None else hex(target),
                         '' if slot is None else hex(slot), scope])
    return rows


def rip_literal(image, by_site, site, prefix, length):
    ins = instruction(by_site, site)
    addr = pcrel(ins, prefix)
    return addr, image.read(addr, length)


def selftest(image, by_site):
    instruction(by_site, 0x56402cf, '48c74424603f000000')
    length = struct.unpack_from('<I', by_site[0x56402cf]['raw'], 5)[0]
    pieces = []
    # These are destination offsets observed in the selected self-test body.
    for site, dst in ((0x56402ec, 0), (0x56402f9, 16),
                      (0x5640306, 32), (0x5640313, 47)):
        addr, block = rip_literal(image, by_site, site, '660f6f05', 16)
        pieces.append((site, dst, addr, block))
    iv_va0, iv0 = rip_literal(image, by_site, 0x56402ac, '660f6f05', 16)
    iv_va1, iv1 = rip_literal(image, by_site, 0x56402dc, '660f6f05', 16)
    initial_words = list(struct.unpack('<8I', iv0 + iv1))
    result = bytearray(length)
    written = set()
    for site, dst, addr, block in pieces:
        require(dst + len(block) <= length, 'self-test chunk out of bounds')
        for i, byte in enumerate(block):
            at = dst + i
            require(at not in written or result[at] == byte, 'self-test overlap differs')
            result[at] = byte
            written.add(at)
    require(len(written) == length, 'self-test chunks do not cover message')
    expected_va, expected = rip_literal(image, by_site, 0x5640327, '488d15', 32)
    digest = hashlib.sha256(result).digest()
    require(digest == expected, 'self-test digest differs from target bytes')
    return {'initial_state_vas': [hex(iv_va0), hex(iv_va1)],
            'initial_state_u32_le': [hex(x) for x in initial_words],
            'message_length': length, 'message_ascii': result.decode('ascii'),
            'message_hex': result.hex(),
            'chunks': [{'load_site': hex(site), 'destination_offset': dst,
                        'source_va': hex(addr), 'bytes': block.hex()}
                       for site, dst, addr, block in pieces],
            'expected_digest_va': hex(expected_va), 'expected_digest': expected.hex(),
            'independent_hashlib_sha256': digest.hex(), 'matches': digest == expected}



def serializer_parameters(by_site):
    flag_mask = struct.unpack_from('<I', instruction(by_site, 0x564056a, '4181e700010000')['raw'], 3)[0]
    instruction(by_site, 0x5640571, '4183ff01')
    instruction(by_site, 0x5640575, '4819ed')
    extra = instruction(by_site, 0x5640578, '83e520')['raw'][-1]
    base = instruction(by_site, 0x564057b, '4883c521')['raw'][-1]
    accepted_low_flag = instruction(by_site, 0x56405b8, '4180fd02')['raw'][-1]
    uncompressed_prefix = instruction(by_site, 0x56406f0, '41c6042404')['raw'][-1]
    instruction(by_site, 0x5640637, '83e001')
    compressed_prefix = instruction(by_site, 0x564063a, '83c002')['raw'][-1]
    return {'compression_mask': flag_mask, 'base_size': base, 'uncompressed_extra': extra,
            'accepted_low_flag': accepted_low_flag, 'uncompressed_prefix': uncompressed_prefix,
            'compressed_prefix_base': compressed_prefix}


def serializer_projection(params, *, capacity, flags, length_pointer=True, output_pointer=True,
                          key_pointer=True, conversion_ok=True, finite=True, y_low_bit=0):
    """Project only selected serializer decisions, assuming callbacks return."""
    require(isinstance(capacity, int) and 0 <= capacity < (1 << 64), 'invalid capacity')
    require(isinstance(flags, int) and 0 <= flags < (1 << 32), 'invalid flags')
    require(y_low_bit in (0, 1), 'invalid parity')
    base, extra, mask = params['base_size'], params['uncompressed_extra'], params['compression_mask']
    required = base if flags & mask else base + extra
    result = {'required': required, 'length_word': 'unchanged', 'cleared_bytes': 0,
              'reason': '', 'returns': 0, 'prefix': None}
    if not length_pointer:
        result['reason'] = 'null_length_callback'
        return result
    if capacity < required:
        result['reason'] = 'capacity_callback'
        return result
    result['length_word'] = 'zero'
    if not output_pointer:
        result['reason'] = 'null_output_callback'
        return result
    result['cleared_bytes'] = capacity
    if not key_pointer:
        result['reason'] = 'null_key_callback'
        return result
    if flags & 0xff != params['accepted_low_flag']:
        result['reason'] = 'invalid_flag_callback'
        return result
    if not conversion_ok:
        result['reason'] = 'point_conversion_failed'
        return result
    if not finite:
        result['reason'] = 'exceptional_point'
        return result
    result.update({'length_word': 'required', 'reason': 'success', 'returns': 1,
                   'prefix': (params['compressed_prefix_base'] + y_low_bit if flags & mask
                              else params['uncompressed_prefix'])})
    return result


def serializer_cases(by_site):
    params = serializer_parameters(by_site)
    base, extra, flag = params['base_size'], params['uncompressed_extra'], params['accepted_low_flag']
    sizes = (0, base - 1, base, base + extra - 1, base + extra, base + extra + 1)
    scenarios = (
        ('normal', {}), ('null_length', {'length_pointer': False}),
        ('null_output', {'output_pointer': False}), ('null_key', {'key_pointer': False}),
        ('conversion_failed', {'conversion_ok': False}), ('exceptional_point', {'finite': False}),
    )
    cases = []
    for flags in (flag, flag | params['compression_mask'], 0):
        for cap in sizes:
            for name, options in scenarios:
                cases.append({'case': name, 'capacity': cap, 'flags': flags,
                              'projection': serializer_projection(params, capacity=cap, flags=flags, **options)})
    return {'parameters': params, 'cases': cases,
            'scope': 'Synthetic selected-branch projection; callback and point operations are external.'}


def recovery_projection(recid, first_status, second_status, recovery_result):
    """Project the selected wrapper and parser branches with opaque helper results."""
    require(isinstance(recid, int) and 0 <= recid <= 255, 'recovery byte out of range')
    for word in (first_status, second_status):
        require(isinstance(word, int) and 0 <= word < (1 << 32), 'status word out of range')
    require(recovery_result in (0, 1), 'unsupported recovery result')
    if recid >= 4:
        return 'outer_error_6'
    if first_status or second_status:
        return 'outer_error_3'
    if recovery_result != 1:
        return 'outer_error_3'
    return 'serialize_public_key'

def limb_bytes(limbs, width=52):
    require(len(limbs) == 5 and width == 52, 'expected five field limbs')
    limits = [1 << width] * 4 + [1 << (256 - width * 4)]
    require(all(isinstance(x, int) and 0 <= x < lim for x, lim in zip(limbs, limits)),
            'field limb outside normalized domain')
    out = bytearray()
    for byte_index in range(32):
        bit = (31 - byte_index) * 8
        li, shift = divmod(bit, width)
        value = limbs[li] >> shift
        if shift + 8 > width and li + 1 < len(limbs):
            value |= limbs[li + 1] << (width - shift)
        out.append(value & 0xff)
    return bytes(out)


def field_store_rows(all_rows):
    group_by_site = {i['site']: i for body in all_rows.values() for i in body}
    width = instruction(group_by_site, 0x563736d, '48c1ef34')['raw'][-1]
    low_mask = struct.unpack_from('<Q', instruction(group_by_site, 0x563734d, '48b9ffffffffffff0f00')['raw'], 2)[0]
    high_mask = struct.unpack_from('<Q', instruction(group_by_site, 0x563a626, '48b8ffffffffffff0000')['raw'], 2)[0]
    require(low_mask == (1 << width) - 1 and high_mask == (1 << (256 - 4 * width)) - 1,
            'field limb widths changed')
    rows, group = [], []
    for ins in all_rows[0x5632c40]:
        group.append(ins)
        raw = ins['raw']
        if raw == b'\x88\x0f':
            dest = 0
        elif len(raw) == 3 and raw[:2] in (b'\x88\x4f', b'\x88\x6f', b'\x88\x47'):
            dest = raw[2]
        else:
            continue
        sequence = [x['raw'] for x in group[:-1] if x['raw'] != bytes.fromhex('4889f0')]
        boundary = 'within'
        if dest == 12:
            require([x.hex() for x in sequence] == ['0fb74e16', '0fb67618', '83e10f', 'c1e604', '09f1'],
                    'first cross-limb field byte changed')
            source_byte = sequence[0][-1]
            limb, shift, boundary = divmod(source_byte, 8)[0], (source_byte % 8) * 8, 'crosses'
        elif dest == 25:
            require([x.hex() for x in sequence] == ['488b08', '0fb67008', '48c1e930', '83e10f', 'c1e604', '09f1'],
                    'second cross-limb field byte changed')
            limb, shift, boundary = 0, sequence[2][-1], 'crosses'
        else:
            require(1 <= len(sequence) <= 2, 'unsupported field-store source shape')
            load = sequence[0]
            if len(load) == 4 and load[:3] in (b'\x48\x8b\x4e', b'\x48\x8b\x48'):
                byte_offset = load[3]
            elif len(load) == 3 and load[:2] in (b'\x8b\x4e', b'\x8b\x48'):
                byte_offset = load[2]
            elif load in (b'\x48\x8b\x08', b'\x48\x8b\x00'):
                byte_offset = 0
            else:
                raise EvidenceError('unsupported field load shape')
            limb, in_limb = divmod(byte_offset, 8)
            shift = in_limb * 8
            if len(sequence) == 2:
                require(sequence[1][:3] == b'\x48\xc1\xe9' and len(sequence[1]) == 4,
                        'unsupported field shift')
                shift += sequence[1][3]
            if raw[:2] == b'\x88\x6f':
                shift += 8
        expected_bit = (31 - dest) * 8
        require((limb, shift) == divmod(expected_bit, width), 'field operand lanes disagree')
        rows.append([hex(ins['site']), raw.hex(), dest, limb, shift, boundary,
                     '|'.join(x['raw'].hex() for x in group)])
        group = []
    require([r[2] for r in rows] == list(range(32)), 'field output stores changed')
    return rows





def parser_call_order(all_rows, by_site):
    events = (
        (0x564076c, '4c89f2', 'pass the first status-word pointer'),
        (0x564076f, 'e8bc5fffff', 'call the first external converter'),
        (0x5640774, '488d7520', 'advance the second input pointer'),
        (0x564077d, '4c89f2', 'pass the same status-word pointer'),
        (0x5640780, '448b6c240c', 'save the first status word'),
        (0x5640785, 'e8a65fffff', 'call the second external converter'),
        (0x564078a, '440b6c240c', 'combine the saved and current status words'),
        (0x564078f, '7557', 'branch when the combined status is nonzero'),
    )
    rows = []
    for site, raw, description in events:
        ins = instruction(by_site, site, raw)
        target = relative_target(ins)
        rows.append([hex(site), ins['raw'].hex(), '' if target is None else hex(target), description])
    between = [i for i in all_rows[0x5640710] if 0x564076f < i['site'] < 0x5640785]
    require(all(transfer_kind(i) is None for i in between), 'unexpected transfer before second converter call')
    return rows

def compact_copy_lanes(by_site):
    # The helper-written temporary values are distinct from the original input.
    # This table describes only their later success-path copies.
    stages = ((0x5640791, '660f6f4c2410', 0x56407b2, '0f110b'),
              (0x5640797, '660f6f542420', 0x56407b5, '0f115310'),
              (0x56407a6, '660f6f5c2430', 0x56407b9, '0f115b20'),
              (0x56407ac, '660f6f642440', 0x56407bd, '0f116330'))
    rows = []
    for load_va, load_shape, store_va, store_shape in stages:
        load = instruction(by_site, load_va, load_shape)['raw']
        store = instruction(by_site, store_va, store_shape)['raw']
        source = load[-1] - 0x10
        dest = 0 if len(store) == 3 else store[-1]
        for i in range(16):
            rows.append([source + i, dest + i, hex(load_va), hex(store_va)])
    require([r[0] for r in rows] == list(range(64)), 'temporary source lanes changed')
    require([r[1] for r in rows] == list(range(64)), 'signature result lanes changed')
    return rows

def address_lane_rows(by_site):
    base_ins = instruction(by_site, 0x4e57fb8, '488db424a0020000')['raw']
    base = struct.unpack_from('<I', base_ins, 4)[0]
    result = []
    for load_site, store_site, width in ((0x4e57fd8, 0x4e57fe0, 16),
                                         (0x4e57fce, 0x4e57fd5, 4)):
        load = instruction(by_site, load_site)['raw']
        store = instruction(by_site, store_site)['raw']
        source = struct.unpack_from('<I', load, len(load) - 4)[0]
        dest = store[-1]
        for i in range(width):
            result.append([hex(load_site), hex(store_site), source + i - base, dest + i])
    require([x[2] for x in result] == list(range(12, 32)), 'digest slice changed')
    require([x[3] for x in result] == list(range(1, 21)), 'address result layout changed')
    return result
BRANCHES = {
    0x4e57ca6: 'recovery byte is at least the wrapper limit',
    0x4e57cef: 'compact parser did not return one',
    0x4e57da0: 'once state is nonzero',
    0x4e57db0: 'recovery context pointer is zero',
    0x4e57dfb: 'public-key recovery did not return one',
    0x4e58044: 'context pointer is nonzero after the once call',
    0x4eb8550: 'requested context size exceeds signed allocation limit',
    0x4eb8559: 'requested context size is at most the small-allocation cutoff',
    0x4eb8571: 'allocator returned null',
    0x4eb8665: 'callback byte was not one',
    0x4eb867a: 'old context pointer is null',
    0x4eb869e: 'old layout size reaches the overflow cutoff',
    0x563744b: 'converted public-key X limbs are all zero',
    0x5640338: 'the self-test comparison reached its byte count',
    0x5640341: 'current self-test digest byte equals expected byte',
    0x56403ac: 'context flags low byte is not one',
    0x56403b9: 'context flag contains the forbidden high bit',
    0x56403f8: 'the existing context state word is zero',
    0x5640453: 'context-size helper returned zero',
    0x56404b7: 'context pointer is nonzero',
    0x56404c4: 'context state word is zero',
    0x5640558: 'serialization output-length pointer is null',
    0x5640582: 'serialization buffer length is below the selected form size',
    0x5640595: 'serialization output pointer is null',
    0x56405b2: 'serialization public-key pointer is null',
    0x56405bc: 'serialization flag low byte is not two',
    0x56405d7: 'public-key storage conversion returned nonzero',
    0x5640606: 'converted point reports the exceptional state word nonzero',
    0x564062d: 'serialization flag selects the uncompressed form',
    0x5640741: 'signature output pointer is null',
    0x564074a: 'compact input pointer is null',
    0x5640756: 'recovery identifier exceeds the parser maximum',
    0x564078f: 'either converter status word is nonzero',
    0x5640894: 'message digest pointer is null',
    0x564089d: 'recoverable-signature pointer is null',
    0x56408a6: 'public-key output pointer is null',
    0x564090c: 'external recovery core returned zero',
}


def decision_rows(by_site):
    out = []
    for site, meaning in sorted(BRANCHES.items()):
        ins = instruction(by_site, site)
        target = relative_target(ins)
        require(ins['kind'] == 'branch' and target is not None, 'decision is not conditional')
        out.append([hex(site), ins['raw'].hex(), hex(target), hex(site + len(ins['raw'])), meaning])
    return out



def model_cases(by_site):
    id_limit = instruction(by_site, 0x4e57ca3, '83f904')['raw'][-1]
    instruction(by_site, 0x564078a, '440b6c240c')
    instruction(by_site, 0x564078f, '7557')
    rows = []
    for recid in (0, id_limit - 1, id_limit):
        for first in (0, 1, 0x80000000):
            for second in (0, 1, 0x80000000):
                for recovery in (0, 1):
                    rows.append({'recovery_id': recid, 'first_helper_status': first,
                                 'second_helper_status': second, 'recovery_result': recovery,
                                 'decision': recovery_projection(recid, first, second, recovery)})
    return {'cases': rows,
            'scope': 'Synthetic branch projections; status-word and recovery-helper internals are external.'}

def static_layout(image, by_site, relas):
    once_target = pcrel(instruction(by_site, 0x4e5801f), '488d0d')
    once_state = pcrel(instruction(by_site, 0x4e58018), '488d3d')
    runtime_ptr = pcrel(instruction(by_site, 0x4e57da6), '488b3d')
    installed_ptr = pcrel(instruction(by_site, 0x4eb86b8), '48891d')
    require(once_target + 0x20 in relas and int(relas[once_target + 0x20]['addend'], 16) == 0x4eb8650,
            'once descriptor method no longer binds callback')
    require(runtime_ptr == installed_ptr, 'context load and store do not address the same global')
    groups = [s for s in image.sections if s['flags'] & 2 and s['address'] <= runtime_ptr
              and runtime_ptr + 8 <= s['address'] + s['size']]
    require(len(groups) == 1 and groups[0]['type'] == 8, 'context global is not unique NOBITS')
    state_data = image.read(once_state, 4)
    return {'once_state_va': hex(once_state), 'once_state_file_bytes': state_data.hex(),
            'once_descriptor_va': hex(once_target), 'descriptor_method_offset': 0x20,
            'descriptor_relocation_slot': hex(once_target + 0x20),
            'descriptor_method_addend': relas[once_target + 0x20]['addend'],
            'context_pointer_va': hex(runtime_ptr), 'context_section': groups[0]['name'],
            'context_section_type': groups[0]['type'], 'context_pointer_file_backed': False,
            'construction_flags': struct.unpack_from('<I', by_site[0x4eb8535]['raw'], 1)[0],
            'reported_context_size': struct.unpack_from('<I', by_site[0x56403b4]['raw'], 1)[0],
            'serialized_length': struct.unpack_from('<I', by_site[0x4e57ea0]['raw'], 8)[0],
            'serialized_flag': struct.unpack_from('<I', by_site[0x4e57ec4]['raw'], 2)[0],
            'sponge_rate': struct.unpack_from('<I', by_site[0x4e57f76]['raw'], 8)[0],
            'sponge_input_length': struct.unpack_from('<I', by_site[0x4e57f94]['raw'], 1)[0],
            'sponge_output_length': struct.unpack_from('<I', by_site[0x4e57fc0]['raw'], 1)[0],
            'recovery_id_limit_exclusive': by_site[0x4e57ca3]['raw'][-1],
            'wrapper_error_id': struct.unpack_from('<I', by_site[0x4e57fe9]['raw'], 3)[0],
            'wrapper_error_parse_or_recover': struct.unpack_from('<I', by_site[0x4e57ff2]['raw'], 3)[0]}



def exception_table(image, fde, boundaries):
    if fde['lsda'] is None:
        return [], None
    sec = image.section('.gcc_except_table')
    off = image.offset(fde['lsda'], 1)
    endsec = sec['offset'] + sec['size']
    require(sec['offset'] <= off < endsec, 'LSDA outside exception table')
    data, pos = image.data, off
    require(pos + 3 <= endsec and bytes(data[pos:pos + 3]) == b'\xff\xff\x01',
            'unsupported LSDA encoding')
    pos += 3
    size, pos = uleb(data, pos, endsec)
    limit = pos + size
    require(limit <= endsec, 'LSDA call-site table exceeds section')
    records, previous_end = [], 0
    while pos < limit:
        first = pos
        begin, pos = uleb(data, pos, limit)
        length, pos = uleb(data, pos, limit)
        landing, pos = uleb(data, pos, limit)
        action, pos = uleb(data, pos, limit)
        require(begin >= previous_end and fde['start'] + begin + length <= fde['end'],
                'invalid LSDA call-site range')
        landing_va = fde['start'] + landing if landing else None
        require(not landing or landing_va in boundaries, 'LSDA landing is not an instruction boundary')
        previous_end = begin + length
        records.append([hex(fde['start']), hex(fde['lsda']), hex(first),
                        hex(fde['start'] + begin), length, hex(fde['start'] + begin + length),
                        '' if landing_va is None else hex(landing_va), action,
                        bytes(data[first:pos]).hex()])
    return records, {'owner': hex(fde['start']), 'lsda_va': hex(fde['lsda']),
                     'file_offset': hex(off), 'table_bytes': bytes(data[off:limit]).hex(),
                     'limitations': 'Exception action chains and external unwind behavior are not decoded.'}


def assertion_strings(image, by_site):
    rows = []
    section = image.section('.rodata')
    for site in (0x5640677, 0x56406d7, 0x564080f, 0x5640827, 0x5640847,
                 0x56409a7, 0x56409c7):
        ins = instruction(by_site, site)
        va = pcrel(ins, '488d3d')
        offset = image.offset(va, 1)
        require(section['offset'] <= offset < section['offset'] + section['size'],
                'assertion string outside rodata')
        end = image.data.find(b'\0', offset, section['offset'] + section['size'])
        require(end >= 0 and end - offset <= 128, 'invalid assertion string')
        value = bytes(image.data[offset:end]).decode('ascii')
        require('/' not in value, 'assertion unexpectedly contains a path')
        rows.append({'lea_site': hex(site), 'lea_bytes': ins['raw'].hex(),
                     'string_va': hex(va), 'value': value})
    return rows

def collect(data):
    image = Image(data)
    fdes = selected_fdes(data)
    all_rows, by_site = build_instruction_maps(image, fdes)
    validate_pins(by_site)
    relas = relocations(image)
    rip_edges = verify_relocation_edges(by_site, relas)
    functions, bodies, unwind = function_records(image, fdes, all_rows)
    decisions = decision_rows(by_site)
    flow = transfers(all_rows, fdes)
    field = field_store_rows(all_rows)
    address = address_lane_rows(by_site)
    compact_lanes = compact_copy_lanes(by_site)
    parser_order = parser_call_order(all_rows, by_site)
    layout = static_layout(image, by_site, relas)
    selftest_record = selftest(image, by_site)
    exceptions, exception_headers = [], []
    for start in sorted(fdes):
        items, header = exception_table(image, fdes[start], {i['site'] for i in all_rows[start]})
        exceptions.extend(items)
        if header is not None:
            exception_headers.append(header)
    assertions = assertion_strings(image, by_site)
    cases = model_cases(by_site)
    serializer_model = serializer_cases(by_site)
    ins_rows = [[hex(start), hex(ins['site']), ins['raw'].hex(), ins['kind']]
                for start in sorted(all_rows) for ins in all_rows[start]]
    pin_rows = [[hex(site), by_site[site]['raw'].hex()] for site in sorted(PINS)]
    summary = {'artifact_sha256': SHA256, 'component': 'evm',
               'selected_fdes': len(fdes),
               'selected_code_bytes': sum(f['end'] - f['start'] for f in fdes.values()),
               'linear_instructions': len(ins_rows), 'control_transfers': len(flow),
               'conditional_transfers': sum(row[3] == 'conditional' for row in flow),
               'annotated_decisions': len(decisions), 'instruction_pins': len(pin_rows),
               'selected_relocations': len(relas), 'selected_rip_edges': len(rip_edges),
               'field_byte_stores': len(field), 'result_byte_lanes': len(address),
               'compact_temporary_byte_lanes': len(compact_lanes), 'parser_order_events': len(parser_order),
               'synthetic_parser_cases': len(cases['cases']), 'synthetic_serializer_cases': len(serializer_model['cases']),
               'exception_callsite_entries': len(exceptions),
               'exception_landing_entries': sum(bool(row[6]) for row in exceptions),
               'assertion_strings': len(assertions),
               'execution': False,
               'limitations': 'Selected FDEs and linear decoding are not a full call graph or a reconstruction comparison.'}
    return {
        'functions.tsv': tsv(['start_va', 'end_va_exclusive', 'bytes', 'file_offset', 'fde_va',
                              'cie_va', 'lsda_va', 'index', 'sha256', 'instructions', 'role_inferred'], functions),
        'bodies.json': json_bytes(bodies),
        'unwind.json': json_bytes(unwind),
        'instructions.tsv': tsv(['fde_start_va', 'site_va', 'bytes', 'shape'], ins_rows),
        'control-flow.tsv': tsv(['fde_start_va', 'site_va', 'bytes', 'kind', 'target_va', 'slot_va', 'scope'], flow),
        'decisions.tsv': tsv(['site_va', 'bytes', 'taken_va', 'fallthrough_va', 'condition'], decisions),
        'instruction-pins.tsv': tsv(['site_va', 'bytes'], pin_rows),
        'relocations.json': json_bytes([relas[k] for k in sorted(relas)]),
        'rip-edges.tsv': tsv(['site_va', 'bytes', 'slot_va', 'relocation_type', 'addend', 'dynamic_symbol'], rip_edges),
        'self-test.json': json_bytes(selftest_record),
        'context-layout.json': json_bytes(layout),
        'field-byte-lanes.tsv': tsv(['store_va', 'bytes', 'output_offset', 'limb', 'bit_offset', 'limb_boundary', 'source_instructions'], field),
        'result-byte-lanes.tsv': tsv(['load_va', 'store_va', 'digest_byte', 'result_offset'], address),
        'compact-copy-lanes.tsv': tsv(['temporary_offset', 'output_offset', 'load_va', 'store_va'], compact_lanes),
        'parser-call-order.tsv': tsv(['site_va', 'bytes', 'relative_target_va', 'observation'], parser_order),
        'synthetic-cases.json': json_bytes(cases),
        'serializer-cases.json': json_bytes(serializer_model),
        'assertion-strings.json': json_bytes(assertions),
        'exception-headers.json': json_bytes(exception_headers),
        'exception-sites.tsv': tsv(['fde_start_va', 'lsda_va', 'record_file_offset', 'start_va', 'length',
                                    'end_va', 'landing_va', 'action', 'bytes'], exceptions),
        'summary.json': json_bytes(summary),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    data = (ROOT / TARGET).read_bytes()
    outputs = collect(data)
    args.out.mkdir(parents=True, exist_ok=True)
    for filename, content in sorted(outputs.items()):
        (args.out / filename).write_bytes(content)
    print(f'Generated {len(outputs)} evidence files for node #94.')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (EvidenceError, ValueError, OSError, struct.error) as exc:
        print(f're21 signer extraction: {exc}', file=sys.stderr)
        raise SystemExit(1)
