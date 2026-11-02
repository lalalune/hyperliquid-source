#!/usr/bin/env python3
"""Extract digest-bound nested configuration map evidence from node 94 ELF bytes."""
import argparse
import csv
import hashlib
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections
from fde_extents import eh_frame_records, uleb

DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
SIZE = 91774280
TARGET = ROOT / 'artifacts/node/94/hl-node'

def verify_identity(data):
    if len(data) != SIZE or hashlib.sha256(data).hexdigest() != DIGEST:
        raise ValueError('node 94 size or SHA-256 mismatch')

class View:
    def __init__(self, data, secs=None):
        self.data = data
        self.sections = sections(data) if secs is None else secs

    def offset(self, va, size):
        if type(va) is not int or type(size) is not int or va < 0 or size <= 0 or va + size > 1 << 64:
            raise ValueError('invalid virtual range')
        hits = [s for s in self.sections if s['type'] != 8 and s['flags'] & 2 and s['size']
                and s['address'] <= va and va + size <= s['address'] + s['size']]
        if len(hits) != 1:
            raise ValueError('virtual range lacks a unique allocated, file-backed section')
        offset = hits[0]['offset'] + va - hits[0]['address']
        if offset < 0 or offset + size > len(self.data):
            raise ValueError('file-backed range is truncated')
        return offset

    def read(self, va, size):
        p = self.offset(va, size)
        return self.data[p:p + size]


def require_bytes(actual, expected, label):
    if actual != expected:
        raise ValueError('byte contract changed: ' + label)


# Restricted x86 byte-pattern reader adapted from the MIT replica-route collector.
def _need(body, pos, count):
    if pos < 0 or count < 0 or pos + count > len(body):
        raise ValueError('truncated instruction')


def decode_one(body, off, base):
    """Decode one length and control-transfer form; no full mnemonic claim."""
    start = off
    prefix66 = False
    rex = 0
    while True:
        _need(body, off, 1)
        p = body[off]
        if p in (0x66, 0xf0, 0xf2, 0xf3, 0x2e, 0x36, 0x3e, 0x26, 0x64, 0x65):
            prefix66 |= p == 0x66
            off += 1
        elif 0x40 <= p <= 0x4f:
            rex = p
            off += 1
        else:
            break
        if off - start > 8:
            raise ValueError('too many prefixes')
    op = body[off]
    off += 1
    kind = 'instruction'
    target = None
    rel_width = 0
    modrm_needed = False
    imm = 0
    op2 = None
    if op == 0x0f:
        _need(body, off, 1)
        op2 = body[off]
        off += 1
        if 0x80 <= op2 <= 0x8f:
            kind, rel_width = 'conditional', 4
        elif op2 == 0x0b:
            kind = 'trap'
        elif 0xc8 <= op2 <= 0xcf:
            pass
        elif (op2 in (0x10, 0x11, 0x13, 0x14, 0x15, 0x1f, 0x28, 0x29, 0x2a, 0x2e, 0x2f, 0x57, 0x58, 0x5c, 0x5e,
                      0x60, 0x62, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x72, 0x73, 0x74, 0x7e, 0x7f, 0xa3, 0xaf, 0xb6, 0xb7,
                      0xb0, 0xb1, 0xbc, 0xc1, 0xbe, 0xbf, 0xd6, 0xd7, 0xdb, 0xdf, 0xe6, 0xeb, 0xef)
              or 0x40 <= op2 <= 0x4f or 0x90 <= op2 <= 0x9f):
            modrm_needed = True
        else:
            raise ValueError(f'unsupported 0f opcode {op2:02x} at {base + start:#x}')
    elif op in (0xe8, 0xe9):
        kind, rel_width = ('call' if op == 0xe8 else 'jump'), 4
    elif op == 0xeb or 0x70 <= op <= 0x7f:
        kind, rel_width = ('jump' if op == 0xeb else 'conditional'), 1
    elif op in (0xc3, 0xcb):
        kind = 'return'
    elif op == 0xc2:
        kind, imm = 'return', 2
    elif op in (0xcc, 0xf4):
        kind = 'trap'
    elif 0x50 <= op <= 0x5f or op in (0x90, 0x98, 0x99, 0xc9):
        pass
    elif 0xb8 <= op <= 0xbf:
        imm = 8 if rex & 8 else (2 if prefix66 else 4)
    elif 0xb0 <= op <= 0xb7 or op in (0x6a, 0xa8, 0x04, 0x0c, 0x24, 0x2c, 0x34, 0x3c):
        imm = 1
    elif op in (0x68, 0xa9, 0x05, 0x0d, 0x25, 0x2d, 0x35, 0x3d):
        imm = 2 if prefix66 else 4
    elif op in (0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0a, 0x0b,
                0x20, 0x21, 0x22, 0x23, 0x28, 0x29, 0x2a, 0x2b,
                0x30, 0x31, 0x32, 0x33, 0x38, 0x39, 0x3a, 0x3b,
                0x63, 0x69, 0x6b, 0x80, 0x81, 0x83, 0x84, 0x85,
                0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8d, 0x8f,
                0xc0, 0xc1, 0xc6, 0xc7, 0xd0, 0xd1, 0xd2, 0xd3,
                0xf6, 0xf7, 0xfe, 0xff):
        modrm_needed = True
    else:
        raise ValueError(f'unsupported opcode {op:02x} at {base + start:#x}')

    rip_disp_pos = None
    modrm = None
    if modrm_needed:
        _need(body, off, 1)
        modrm = body[off]
        off += 1
        mod, reg, rm = modrm >> 6, (modrm >> 3) & 7, modrm & 7
        sib_base = None
        if mod != 3 and rm == 4:
            _need(body, off, 1)
            sib_base = body[off] & 7
            off += 1
        if mod == 0 and rm == 5:
            rip_disp_pos = off
            off += 4
        elif mod == 0 and sib_base == 5:
            off += 4
        elif mod == 1:
            off += 1
        elif mod == 2:
            off += 4
        if op == 0x0f and op2 in (0x70, 0x72, 0x73):
            imm = 1
        elif op in (0x80, 0x83, 0x6b, 0xc0, 0xc1, 0xc6):
            imm = 1
        elif op in (0x81, 0x69, 0xc7):
            imm = 2 if prefix66 else 4
        elif op == 0xf6 and reg in (0, 1):
            imm = 1
        elif op == 0xf7 and reg in (0, 1):
            imm = 2 if prefix66 else 4
        if op == 0xff and reg in (2, 4):
            kind = 'indirect_call' if reg == 2 else 'indirect_jump'
    if rel_width:
        _need(body, off, rel_width)
        delta = int.from_bytes(body[off:off + rel_width], 'little', signed=True)
        off += rel_width
        target = base + off + delta
    else:
        _need(body, off, imm)
        off += imm
        if rip_disp_pos is not None:
            _need(body, rip_disp_pos, 4)
            target = base + off + struct.unpack_from('<i', body, rip_disp_pos)[0]
    if off - start > 15:
        raise ValueError('instruction exceeds x86 maximum')
    _need(body, start, off - start)
    return {'va': base + start, 'end': base + off, 'kind': kind,
            'target': target, 'bytes': bytes(body[start:off]),
            'opcode': (op, op2), 'modrm': modrm,
            'rip_relative': rip_disp_pos is not None}


def decode_body(body, base):
    result = []
    offset = 0
    while offset < len(body):
        row = decode_one(body, offset, base)
        result.append(row)
        offset = row['end'] - base
    if offset != len(body):
        raise ValueError('function decoding exceeded extent')
    starts = {r['va'] for r in result}
    end = base + len(body)
    for row in result:
        if row['kind'] in ('jump', 'conditional') and base <= row['target'] < end:
            if row['target'] not in starts:
                raise ValueError(f'branch into an instruction at {row["va"]:#x}')
        if row['kind'] == 'conditional' and row['end'] < end and row['end'] not in starts:
            raise ValueError('fallthrough is not an instruction boundary')
    return result




def reachable(decoded, source, destination, forbidden=()):
    """Over-approximate normal flow: all conditions feasible and calls return."""
    by_va = {ins['va']: ins for ins in decoded}
    if source not in by_va or destination not in by_va:
        raise ValueError('CFG query is not at an instruction boundary')
    forbidden = set(forbidden)
    if any(va not in by_va for va in forbidden):
        raise ValueError('CFG forbidden VA is not an instruction boundary')
    pending, seen = [source], set()
    while pending:
        va = pending.pop()
        if va in forbidden or va in seen or va not in by_va:
            continue
        if va == destination:
            return True
        seen.add(va)
        ins = by_va[va]
        kind = ins['kind']
        if kind in ('return', 'trap', 'indirect_jump'):
            continue
        if kind == 'jump':
            pending.append(ins['target'])
        elif kind == 'conditional':
            pending.extend((ins['target'], ins['end']))
        else:
            pending.append(ins['end'])
    return False

# The ten selected FDEs are new to this packet. End addresses are exclusive.
FUNCTIONS = (
    ("binary_outer", 0x13bcaa0, 0x13bd489, "fbcc8a8203a335ab00098770f2248b6d570aeac99e13f13cb4d505356ff85f97"),
    ("json_inner", 0x14bc870, 0x14bcdaf, "278904e2d44f3fb124ddfc7908df447fbb7871795c78456f9b30fb52a8da87ea"),
    ("object_key", 0x14b6220, 0x14b6407, "3844b1b8ee57bab083ddd966f1a7a66ec5e631e13dc17e625d18b0a7ed6d7d86"),
    ("array_collect", 0x14c0500, 0x14c069f, "658447c2b387b155ce135c549f1641eadf1a206098b60a38e95d3d6b508bfe06"),
    ("array_step", 0x14b64d0, 0x14b664f, "994c4cbe8e0a56bc604aff01338a21172d9ee2f3adaa6d7ab5352113fd7e5913"),
    ("inner_insert", 0x14cb400, 0x14cb748, "b18b515a3d3fda4a5f5140e5cab6562c7dca65148f16dfe037790e472607eeac"),
    ("outer_insert", 0x14ca9e0, 0x14cad21, "13464f162feca06995e468bca7f11b2969c633b031f4ae2ec6a570895af674df"),
    ("inner_drop", 0x14da1e0, 0x14da323, "fba295d72c0eebe452dbcd83efa142c4aff3c0a541f0b8de12d14271a28e8984"),
    ("inner_drop_iterator", 0x14cced0, 0x14cd27d, "9684fc2bbc6823d4fda72e2a8e6f0bc4276ebe0b45e60cf5f2312e053488b72f"),
    ("array_unwind_drop", 0x14c95b0, 0x14c962c, "ea049661d7578018c488ef7a4b3c9ec6e49b04396e0c8763388fc1039ac9aaa7"),
)

# These closed witnesses are instructions in selected FDEs.
WITNESSES = (
    (0x13bcab4, "440fb64620"),
    (0x13bcac1, "c6462001"),
    (0x13bcac5, "488d05f06ce5fe"),
    (0x13bcad3, "41ffe1"),
    (0x13bcaf3, "83ff11"),
    (0x13bcafc, "488d153d70e5fe"),
    (0x13bce2e, "0f8376030000"),
    (0x13bce34, "80e10f"),
    (0x13bce3f, "0fb74622"),
    (0x13bce4c, "66ffc8"),
    (0x13bce53, "0f84fa040000"),
    (0x13bceb9, "e8120e0000"),
    (0x13bcec2, "80fb09"),
    (0x13bcefa, "e841e7ffff"),
    (0x13bcf7f, "e85cda1000"),
    (0x13bcf89, "0f8414ffffff"),
    (0x13bcf94, "e847d21100"),
    (0x13bd02d, "e81ed71100"),
    (0x13bd0f8, "48899c2490000000"),
    (0x13bd2de, "410fb74622"),
    (0x14bc89e, "48bb0026000001000000"),
    (0x14bc8ed, "83fe7b"),
    (0x14bc8fa, "0f85cd030000"),
    (0x14bc900, "410fb64848"),
    (0x14bc913, "0f84cd030000"),
    (0x14bc969, "e8b298ffff"),
    (0x14bc976, "48b80100000000000080"),
    (0x14bc983, "0f840c020000"),
    (0x14bc98f, "0f80d7010000"),
    (0x14bc9cd, "4883ff3a"),
    (0x14bca00, "4883ff3a"),
    (0x14bca1f, "e8cc090000"),
    (0x14bca2c, "0f846d010000"),
    (0x14bcac3, "e838e90000"),
    (0x14bcad0, "0f8483feffff"),
    (0x14bcaf0, "4983c618"),
    (0x14bcbcc, "e80fd60100"),
    (0x14bcbdd, "fec0"),
    (0x14bcbe5, "e80636feff"),
    (0x14bcc0d, "0f85e1000000"),
    (0x14bcc24, "49894608"),
    (0x14bcc28, "49890e"),
    (0x14bccaf, "48c744242006000000"),
    (0x14bcce6, "48c744242018000000"),
    (0x14bccfc, "e8dfd40100"),
    (0x14bcd9c, "e83fd40100"),
    (0x14b6265, "4983fa2c"),
    (0x14b627d, "48c7042403000000"),
    (0x14b628d, "80780800"),
    (0x14b62cd, "48c7042405000000"),
    (0x14b62e6, "4183fa7d"),
    (0x14b630f, "4180fa22"),
    (0x14b6335, "ff1565892b04"),
    (0x14b63af, "410fb6c2"),
    (0x14b63d2, "48c7042408000000"),
    (0x14b65b9, "4183fa5d"),
    (0x14b65d1, "80780800"),
    (0x14b65dd, "4183f85d"),
    (0x14b65f0, "e8fb7a0000"),
    (0x14b6628, "48c7042407000000"),
    (0x14b6635, "48c7042415000000"),
    (0x14c0575, "e8565fffff"),
    (0x14c0585, "0f80b1000000"),
    (0x14c0598, "7420"),
    (0x14c05b2, "ff1580e42a04"),
    (0x14c05ba, "488b442428"),
    (0x14c0600, "4983c618"),
    (0x14c063c, "488b442410"),
    (0x14cb44d, "0fb7891a020000"),
    (0x14cb48e, "ff15f42f2a04"),
    (0x14cb4bb, "742e"),
    (0x14cb4eb, "488b442418"),
    (0x14cb52c, "4b8d0464"),
    (0x14cb544, "0f1107"),
    (0x14cb62f, "bf20020000"),
    (0x14cb679, "4883f90b"),
    (0x14cb6ba, "48ff4710"),
    (0x14cb6c8, "488906"),
    (0x14da248, "e8832cffff"),
    (0x14da2a0, "4883c008"),
    (0x14da2ad, "4f8d24ec"),
    (0x14da2d0, "4883c518"),
    (0x14da302, "48c1e003"),
    (0x14cace8, "e8f3f40000"),
    (0x14b626b, "4d0fa3d1"),
    (0x14b626f, "7316"),
    (0x14b6287, "4983fa2c"),
    (0x14b628b, "7559"),
    (0x14b6291, "7578"),
    (0x14b62f6, "48ffc8"),
    (0x14b6301, "80780800"),
    (0x14b6305, "0f84c7000000"),
    (0x14b630b, "c6400800"),
    (0x14b6313, "0f8596000000"),
    (0x14b63b3, "83f87d"),
    (0x14b63b6, "750d"),
    (0x14b63b8, "48c7042415000000"),
    (0x14b63c5, "48c7042411000000"),
    (0x14b6560, "4983fa2c"),
    (0x14b6564, "7553"),
    (0x14b6566, "80780800"),
    (0x14b656a, "756b"),
    (0x14b65bd, "7512"),
    (0x14b65bf, "48b80100000000000080"),
    (0x14b65c9, "48ffc8"),
    (0x14b65d5, "7451"),
    (0x14b65d7, "c6400800"),
    (0x14b65e1, "7452"),
    (0x14caa6e, "ff15143a2a04"),
    (0x14caa9e, "743b"),
    (0x14caadb, "488b442418"),
    (0x14cab16, "4b8d0464"),
    (0x14cab2f, "0f114708"),
    (0x14cab37, "410f1184c510010000"),
    (0x14cab4c, "b801000000"),
    (0x14cac15, "4989c4"),
    (0x14cac91, "48ff4610"),
    (0x13bce1f, "41b0e0"),
    (0x13bce22, "80f9df"),
    (0x13bce2b, "80f990"),
    (0x13bcc28, "488b4610"),
    (0x13bcc30, "4883ff02"),
    (0x13bcc3e, "0fb708"),
    (0x13bcc41, "66c1c108"),
    (0x13bcc45, "4883c002"),
    (0x13bcbcd, "488b4610"),
    (0x13bcbd5, "4883ff04"),
    (0x13bcbe3, "8b08"),
    (0x13bcbe9, "0fc9"),
    (0x13bce73, "488b442448"),
    (0x13bce78, "85c0"),
    (0x13bce7a, "0f841e010000"),
    (0x13bcf9e, "4531ff"),
    (0x13bcfa1, "4531f6"),
    (0x13bcfa4, "31ed"),
    (0x13bcfa6, "e94d010000"),
    (0x13bd13f, "488b842498000000"),
    (0x13bd166, "c644242809"),
    (0x13bd170, "0fb74622"),
    (0x13bd180, "66894622"),
    (0x13bcd11, "4801f8"),
    (0x13bcd18, "48c7461800000000"),
    (0x14cb481, "4d89fe"),
    (0x14cb484, "4929d6"),
    (0x14cb487, "490f42d7"),
    (0x14cb494, "4898"),
    (0x14cb496, "85c0"),
    (0x14cb498, "4c0f45f0"),
    (0x14cb49c, "4d85f6"),
    (0x14cb49f, "0f98c0"),
    (0x14cb4a2, "0f9fc1"),
    (0x14cb4a5, "28c1"),
    (0x14caa61, "4c89fb"),
    (0x14caa64, "4829d3"),
    (0x14caa67, "490f42d7"),
    (0x14caa74, "4c89ef"),
    (0x14caa77, "4898"),
    (0x14caa79, "85c0"),
    (0x14caa7b, "480f45d8"),
    (0x14caa7f, "4885db"),
    (0x14caa82, "0f98c0"),
    (0x14caa85, "0f9fc1"),
    (0x14caa88, "28c1"),
    (0x13bd2b8, "80f9c0"),
    (0x13bd2bb, "733c"),
)

# Existing callers are context only, not selected functions.
BOUNDARIES = (
    (0x14a3a81, "e82a890100"),
    (0x14bc53c, "e82f030000"),
    (0x14bc5cf, "e80ce40000"),
    (0x14bc5e5, "e8f6db0100"),
    (0x14bd4ab, "e850300000"),
    (0x13ad0fc, "e89ff90000"),
    (0x13aca29, "8d42ea"),
    (0x13aca2c, "80fa16"),
    (0x13aca2f, "0fb6c0"),
    (0x13aca32, "b918000000"),
    (0x13aca37, "0f43c8"),
    (0x13aca3d, "488d0d5c30e6fe"),
    (0x13aca44, "48630481"),
    (0x13aca48, "4801c8"),
    (0x13aca5a, "ffe0"),
    (0x13c779d, "c640081d"),
    (0x13ac9d6, "0fb6542478"),
    (0x13aca20, "80fa2e"),
    (0x13aca23, "0f848b0e0000"),
    (0x13aca3a, "0fb6c1"),
    (0x13aca4b, "48b90100000000000080"),
    (0x13aca55, "488b6c2468"),
    (0x13ad0d1, "488b4c2458"),
    (0x13ad0d6, "4885c9"),
    (0x13ad0d9, "0f85e83a0000"),
    (0x13ad0e3, "48c744245800000000"),
    (0x13ad0f4, "4889ee"),
    (0x13ad0f7, "ba01000000"),
    (0x13ad101, "0fb68424f0020000"),
    (0x13ad109, "3c09"),
    (0x13ad10b, "0f8543350000"),
    (0x13bba4f, "e87c220000"),
    (0x13bba91, "e89a9bffff"),
    (0x13bbb10, "e8ebf81000"),
    (0x13bbb27, "4839c3"),
    (0x13bbb2a, "0f840cffffff"),
    (0x13bbb50, "4983c518"),
    (0x13bbc21, "e8bae51100"),
)


def section_one(view, name, kind):
    found = [s for s in view.sections if s['name'] == name and s['type'] == kind]
    if len(found) != 1:
        raise ValueError('required section is missing or ambiguous: ' + name)
    return found[0]


def relocation_rows(view, slots):
    """Parse only relocation records for the selected indirect slots."""
    dynsym = section_one(view, '.dynsym', 11)
    dynstr = section_one(view, '.dynstr', 3)
    strings = view.data[dynstr['offset']:dynstr['offset'] + dynstr['size']]
    if dynsym['size'] % 24:
        raise ValueError('bad dynamic-symbol entry size')
    found = {}
    for sec in (s for s in view.sections if s['type'] == 4):
        if sec['size'] % 24:
            raise ValueError('bad RELA entry size')
        for pos in range(sec['offset'], sec['offset'] + sec['size'], 24):
            slot, info, addend = struct.unpack_from('<QQq', view.data, pos)
            if slot not in slots:
                continue
            if slot in found:
                raise ValueError('duplicate selected relocation')
            kind, symbol = info & 0xffffffff, info >> 32
            name = ''
            if symbol:
                if symbol * 24 + 24 > dynsym['size']:
                    raise ValueError('dynamic symbol out of range')
                name_off = struct.unpack_from('<I', view.data, dynsym['offset'] + symbol * 24)[0]
                end = strings.find(b'\0', name_off)
                if name_off >= len(strings) or end < 0:
                    raise ValueError('bad dynamic symbol name')
                name = strings[name_off:end].decode('ascii')
            found[slot] = (sec['name'], pos, kind, symbol, name, addend,
                           view.data[pos:pos + 24].hex())
    return found


def jump_table(view, base, count, starts):
    if not 0 < count <= 256:
        raise ValueError('jump-table count outside selected bound')
    rows = []
    for index in range(count):
        address = base + index * 4
        raw = view.read(address, 4)
        target = base + struct.unpack('<i', raw)[0]
        if target not in starts:
            raise ValueError('jump-table target is not an instruction start')
        rows.append((index, address, view.offset(address, 4), raw.hex(), target))
    return rows


def exception_sites(view, fdes, functions, instruction_starts, calls):
    """Return selected ULEB call-site records; leave action/type meaning open."""
    section = section_one(view, '.gcc_except_table', 1)
    rows, headers = [], []
    known = sorted({f['lsda'] for f in fdes if f['lsda'] is not None})
    for fun in functions:
        address = fun['lsda']
        if address is None:
            continue
        upper = section['address'] + section['size']
        if not section['address'] <= address < upper:
            raise ValueError('LSDA outside exception table')
        following = [p for p in known if address < p < upper]
        if following:
            upper = following[0]
        raw = view.read(address, upper - address)
        if len(raw) < 4 or raw[0] != 0xff or raw[1] not in (0xff, 0x9b):
            raise ValueError('unsupported LSDA header')
        type_encoding = raw[1]
        pos = 2
        type_base = None
        if type_encoding != 0xff:
            displacement, pos = uleb(raw, pos, len(raw))
            type_base = pos + displacement
            if type_base > len(raw):
                raise ValueError('LSDA type base outside bound')
        if pos >= len(raw) or raw[pos] != 1:
            raise ValueError('unsupported call-site encoding')
        pos += 1
        length, pos = uleb(raw, pos, len(raw))
        table_end = pos + length
        if table_end > len(raw) or (type_base is not None and table_end > type_base):
            raise ValueError('LSDA table outside bound')
        headers.append([fun['role'], hx(address), hx(view.offset(address, 1)), hx(upper),
                        raw[:pos].hex(), length, hex(type_encoding),
                        '' if type_base is None else hx(address + type_base)])
        previous = 0
        while pos < table_end:
            entry = pos
            vals = []
            for _ in range(4):
                value, pos = uleb(raw, pos, table_end)
                vals.append(value)
            start, size, landing, action = vals
            if not size or start < previous or start + size > fun['end'] - fun['start']:
                raise ValueError('invalid LSDA call-site range')
            first, last = fun['start'] + start, fun['start'] + start + size
            target = fun['start'] + landing if landing else None
            if first not in instruction_starts or (last not in instruction_starts and last != fun['end']):
                raise ValueError('LSDA range is not instruction aligned')
            if target is not None and not (fun['start'] <= target < fun['end'] and target in instruction_starts):
                raise ValueError('LSDA landing is not an instruction in the selected range')
            inside = [hx(r['va']) for r in calls if first <= r['va'] < last]
            rows.append([fun['role'], hx(address), hx(address + entry), raw[entry:pos].hex(),
                         hx(first), hx(last), hx(target), action, ','.join(inside)])
            previous = start + size
        if pos != table_end:
            raise ValueError('truncated LSDA record')
    return headers, rows


def hx(value):
    return '' if value is None else hex(value)



def delimiter_probe(kind, first, data, mask):
    """Finite parser-step model, stopping before the external string decoder."""
    if kind not in ('object', 'array') or type(first) is not bool or not isinstance(data, bytes):
        raise ValueError('invalid probe input')
    def space(c):
        return c <= 32 and bool(mask & (1 << c))
    pos = 0
    while pos < len(data) and space(data[pos]):
        pos += 1
    if pos == len(data):
        return ('error', 3 if kind == 'object' else 2, pos)
    byte = data[pos]
    closing = 0x7d if kind == 'object' else 0x5d
    if byte == closing:
        return ('end', None, pos)
    if byte == 0x2c and not first:
        pos += 1
        while pos < len(data) and space(data[pos]):
            pos += 1
        if pos == len(data):
            return ('error', 5, pos)
        byte = data[pos]
        if byte == closing:
            return ('error', 21, pos)
    elif not first:
        return ('error', 8 if kind == 'object' else 7, pos)
    if kind == 'object':
        if byte != 0x22:
            return ('error', 17, pos)
        return ('quoted_key_boundary', None, pos + 1)
    return ('string_value_boundary', None, pos)


PROBES = (
    ('object_empty', 'object', True, b''),
    ('object_only_space', 'object', True, b' \t\r\n'),
    ('object_first_end', 'object', True, b'}'),
    ('object_later_end', 'object', False, b' }'),
    ('object_first_key', 'object', True, b'\"p\"'),
    ('object_next_key', 'object', False, b', \t\"p\"'),
    ('object_first_comma', 'object', True, b',\"p\"'),
    ('object_missing_comma', 'object', False, b'\"p\"'),
    ('object_comma_eof', 'object', False, b',  '),
    ('object_trailing_comma', 'object', False, b', }'),
    ('object_unquoted', 'object', True, b'p'),
    ('object_nul', 'object', True, b'\x00'),
    ('object_vertical_tab', 'object', True, b'\x0b'),
    ('array_empty', 'array', True, b''),
    ('array_first_end', 'array', True, b']'),
    ('array_later_end', 'array', False, b' ]'),
    ('array_first_value', 'array', True, b'\"v\"'),
    ('array_next_value', 'array', False, b', \n\"v\"'),
    ('array_first_comma', 'array', True, b',\"v\"'),
    ('array_missing_comma', 'array', False, b'\"v\"'),
    ('array_comma_eof', 'array', False, b',  '),
    ('array_trailing_comma', 'array', False, b', ]'),
    ('array_nul_boundary', 'array', True, b'\x00'),
)



def map_prefix_probe(data):
    """Finite fresh-marker prefix model; no key/value payload is processed."""
    if not isinstance(data, bytes):
        raise ValueError('prefix must be bytes')
    if not data:
        return ('need_marker', None, 0)
    tag = data[0]
    if 0x80 <= tag <= 0x8f:
        return ('map_count', tag & 0x0f, 1)
    width = 2 if tag == 0xde else 4 if tag == 0xdf else 0
    if not width:
        return ('external_boundary', None, 1)
    if len(data) < 1 + width:
        return ('truncated_length', None, len(data))
    return ('map_count', int.from_bytes(data[1:1 + width], 'big'), 1 + width)


PREFIX_PROBES = (
    ('no_marker', b''),
    ('before_fixed_map', bytes.fromhex('7f')),
    ('fixed_empty', bytes.fromhex('80')),
    ('fixed_one', bytes.fromhex('81')),
    ('fixed_max', bytes.fromhex('8f')),
    ('after_fixed_map', bytes.fromhex('90')),
    ('before_map16', bytes.fromhex('dd')),
    ('map16_tag_only', bytes.fromhex('de')),
    ('map16_one_length_byte', bytes.fromhex('de01')),
    ('map16_zero', bytes.fromhex('de0000')),
    ('map16_one', bytes.fromhex('de0001')),
    ('map16_big_endian', bytes.fromhex('de0102')),
    ('map16_max', bytes.fromhex('deffff')),
    ('map16_following_bytes_untouched', bytes.fromhex('de0001aa')),
    ('map32_tag_only', bytes.fromhex('df')),
    ('map32_one_length_byte', bytes.fromhex('df01')),
    ('map32_two_length_bytes', bytes.fromhex('df0102')),
    ('map32_three_length_bytes', bytes.fromhex('df010203')),
    ('map32_zero', bytes.fromhex('df00000000')),
    ('map32_big_endian', bytes.fromhex('df01020304')),
    ('map32_max', bytes.fromhex('dfffffffff')),
    ('after_map32', bytes.fromhex('e0')),
)



def key_order_probe(left, right):
    """Finite model of the two observed memcmp-plus-length decisions."""
    if not isinstance(left, bytes) or not isinstance(right, bytes):
        raise ValueError('decoded keys must be bytes')
    common = min(len(left), len(right))
    for index in range(common):
        if left[index] != right[index]:
            return ('less' if left[index] < right[index] else 'greater', common, index)
    order = 'less' if len(left) < len(right) else 'greater' if len(left) > len(right) else 'equal'
    return (order, common, None)


KEY_PROBES = (
    ('empty_equal', b'', b''),
    ('empty_vs_one', b'', b'a'),
    ('one_vs_empty', b'a', b''),
    ('identical', b'alpha', b'alpha'),
    ('same_prefix_shorter', b'alpha', b'alphabet'),
    ('same_prefix_longer', b'alphabet', b'alpha'),
    ('first_byte_lower', b'Alpha', b'alpha'),
    ('first_byte_higher', b'alpha', b'Alpha'),
    ('last_byte_lower', b'alpha', b'alphb'),
    ('last_byte_higher', b'alphb', b'alpha'),
    ('embedded_nul_equal', bytes.fromhex('610062'), bytes.fromhex('610062')),
    ('after_nul_lower', bytes.fromhex('610062'), bytes.fromhex('610063')),
    ('after_nul_higher', bytes.fromhex('610063'), bytes.fromhex('610062')),
    ('unsigned_high_byte', bytes.fromhex('ff'), bytes.fromhex('7f')),
    ('unsigned_low_byte', bytes.fromhex('7f'), bytes.fromhex('ff')),
)


def inspect(data, authenticate=True):
    if authenticate:
        verify_identity(data)
    view = View(data)
    _, fdes = eh_frame_records(data, view.sections)
    fde_starts = {}
    for fde in fdes:
        fde_starts.setdefault(fde['start'], []).append(fde)
    functions, grouped, all_ins = [], {}, []
    for role, start, end, digest in FUNCTIONS:
        matches = [f for f in fde_starts.get(start, ()) if f['end'] == end]
        if len(matches) != 1:
            raise ValueError('selected FDE missing or ambiguous: ' + role)
        body = view.read(start, end - start)
        if hashlib.sha256(body).hexdigest() != digest:
            raise ValueError('selected FDE bytes changed: ' + role)
        decoded = decode_body(body, start)
        f = matches[0]
        functions.append({'role': role, 'start': start, 'end': end,
                          'fde': f['fde'], 'cie': f['cie'], 'lsda': f['lsda'],
                          'offset': view.offset(start, len(body)), 'size': len(body),
                          'instructions': len(decoded), 'sha256': digest})
        grouped[role] = decoded
        all_ins.extend((role, row) for row in decoded)
    by = {row['va']: row for _, row in all_ins}
    if len(by) != len(all_ins):
        raise ValueError('selected FDEs overlap')
    for address, raw in WITNESSES:
        if address not in by or by[address]['bytes'].hex() != raw:
            raise ValueError('selected instruction changed: ' + hx(address))
    boundary = []
    for address, raw in BOUNDARIES:
        data_bytes = view.read(address, len(bytes.fromhex(raw)))
        if data_bytes.hex() != raw:
            raise ValueError('previous-work boundary changed: ' + hx(address))
        row = decode_one(data_bytes, 0, address)
        if row['end'] != address + len(data_bytes):
            raise ValueError('boundary encoding does not consume its window')
        boundary.append(row)
    mask = struct.unpack('<Q', view.read(0x14bc89e + 2, 8))[0]
    if mask != 0x100002600:
        raise ValueError('JSON whitespace mask changed')
    probes = [(label, kind, first, payload.hex(), *delimiter_probe(kind, first, payload, mask))
              for label, kind, first, payload in PROBES]
    prefixes = [(label, data.hex(), *map_prefix_probe(data)) for label, data in PREFIX_PROBES]
    key_probes = [(label, a.hex(), b.hex(), *key_order_probe(a, b)) for label, a, b in KEY_PROBES]
    field = view.read(0x21bb6c, 33)
    if field != b'eth_chain_to_rpc_provider_to_keys':
        raise ValueError('field spelling changed')
    prior = {r['va']: r for r in boundary}
    field_tag = prior[0x13c779d]['bytes'][-1]
    tag_bias = prior[0x13aca2c]['bytes'][-1]
    table_base = prior[0x13aca3d]['target']
    if (field_tag, tag_bias, table_base) != (0x1d, 0x16, 0x20faa0):
        raise ValueError('field dispatch selector changed')
    center = field_tag - tag_bias
    dispatch = []
    for index in (center - 1, center, center + 1):
        address = table_base + index * 4
        raw = view.read(address, 4)
        target = table_base + struct.unpack('<i', raw)[0]
        dispatch.append((index, address, raw.hex(), target))
    if [r[3] for r in dispatch] != [0x13ad46c, 0x13ad0d1, 0x13ad5da]:
        raise ValueError('field dispatch boundary changed')
    cached, extended, raw_markers = (by[va]['target'] for va in (0x13bcac5, 0x13bcafc, 0x13bd304))
    if (cached, extended, raw_markers) != (0x2137bc, 0x213b40, 0x213b88):
        raise ValueError('binary dispatch table base changed')
    if not cached < extended < raw_markers or (extended - cached) % 4 or (raw_markers - extended) % 4:
        raise ValueError('bad adjacent table spans')
    raw_min = by[0x13bd2b8]['bytes'][-1]
    raw_max = by[0x13bce22]['bytes'][-1]
    if (raw_min, raw_max) != (0xc0, 0xdf):
        raise ValueError('raw marker bounds changed')
    starts = {r['va'] for r in grouped['binary_outer']}
    tables = []
    for name, base, count in [('cached_class', cached, (extended - cached) // 4),
                               ('extended_marker', extended, (raw_markers - extended) // 4),
                               ('raw_c0_df', raw_markers, raw_max - raw_min + 1)]:
        tables.extend((name, *row) for row in jump_table(view, base, count, starts))
    targets = {(name, index): target for name, index, _, _, _, target in tables}
    for key, expected in {('cached_class', 0x80): 0x13bce37,
                          ('cached_class', 0xde): 0x13bcc28,
                          ('cached_class', 0xdf): 0x13bcbcd,
                          ('raw_c0_df', 0x1e): 0x13bcc30,
                          ('raw_c0_df', 0x1f): 0x13bcbd5}.items():
        if targets.get(key) != expected:
            raise ValueError('binary map-prefix route changed')
    calls = [row for _, row in all_ins if row['kind'] in ('call', 'indirect_call', 'indirect_jump')]
    slots = {r['target'] for r in calls if r['kind'] in ('indirect_call', 'indirect_jump')
             and r['rip_relative'] and r['target'] is not None}
    relocs = relocation_rows(view, slots)
    if set(relocs) != slots:
        raise ValueError('selected indirect slot lacks a relocation')
    for _, _, kind, symbol, _, _, _ in relocs.values():
        if (kind, bool(symbol)) not in ((8, False), (6, True)):
            raise ValueError('unsupported selected relocation type')
    # The equal-key route uses an imported byte-comparison function.
    if any(by[site]['target'] != 0x576e488 for site in (0x14cb48e, 0x14caa6e)):
        raise ValueError('selected comparators do not call the same slot')
    if 0x576e488 not in relocs or relocs[0x576e488][4] != 'memcmp':
        raise ValueError('selected byte-comparison symbol changed')
    headers, exceptions = exception_sites(view, fdes, functions, set(by), calls)
    questions = [
        ('json_entry_to_key', 'json_inner', 0x14bc870, 0x14bc969, True),
        ('json_entry_to_wrong_open', 'json_inner', 0x14bc870, 0x14bcccd, True),
        ('json_depth_exhaustion', 'json_inner', 0x14bc913, 0x14bcce6, True),
        ('json_value_to_insert', 'json_inner', 0x14bca1f, 0x14bcac3, True),
        ('json_value_error_to_drop', 'json_inner', 0x14bca2c, 0x14bcbcc, True),
        ('json_insert_to_next_key', 'json_inner', 0x14bcac3, 0x14bc969, True),
        ('json_terminator_failure_to_drop', 'json_inner', 0x14bcc0d, 0x14bccfc, True),
        ('binary_map_to_key', 'binary_outer', 0x13bce3f, 0x13bceb9, True),
        ('binary_key_to_value', 'binary_outer', 0x13bceb9, 0x13bcefa, True),
        ('binary_value_to_insert', 'binary_outer', 0x13bcefa, 0x13bcf7f, True),
        ('binary_replaced_map_to_drop', 'binary_outer', 0x13bcf7f, 0x13bcf94, True),
        ('binary_value_failure_to_drop', 'binary_outer', 0x13bcefa, 0x13bd02d, True),
        ('inner_replace_skips_count_increment', 'inner_insert', 0x14cb52c, 0x14cb6ba, False),
        ('inner_new_item_increments_count', 'inner_insert', 0x14cb62c, 0x14cb6ba, True),
        ('outer_replace_skips_count_increment', 'outer_insert', 0x14cab16, 0x14cac91, False),
        ('outer_new_item_increments_count', 'outer_insert', 0x14cac15, 0x14cac91, True),
        ('array_step_to_success_return', 'array_collect', 0x14c0575, 0x14c063c, True),
        ('array_step_error_to_cleanup', 'array_collect', 0x14c0575, 0x14c05ba, True),
    ]
    cfg = []
    for label, role, start, end, expected in questions:
        got = reachable(grouped[role], start, end)
        if got != expected:
            raise ValueError('closed CFG proposition changed: ' + label)
        cfg.append([label, role, hx(start), hx(end), str(got).lower()])
    return {'view': view, 'functions': functions, 'grouped': grouped, 'instructions': all_ins,
            'witnesses': WITNESSES, 'boundary': boundary, 'dispatch': dispatch,
            'field': field, 'field_tag': field_tag, 'tag_bias': tag_bias, 'tables': tables, 'calls': calls, 'relocations': relocs,
            'lsda_headers': headers, 'exceptions': exceptions, 'cfg': cfg, 'probes': probes, 'mask': mask, 'prefixes': prefixes, 'key_probes': key_probes}


def tsv(path, header, rows):
    with path.open('w', encoding='utf-8', newline='') as handle:
        writer = csv.writer(handle, delimiter='\t', lineterminator='\n')
        writer.writerow(header)
        writer.writerows(rows)


def generate(data, output):
    result = inspect(data)
    view = result['view']
    output.mkdir(parents=True, exist_ok=True)
    tsv(output / 'functions.tsv', ['role', 'start_va', 'end_va_exclusive', 'file_offset', 'size',
        'fde_va', 'cie_va', 'lsda_va', 'instructions', 'sha256'],
        ((r['role'], hx(r['start']), hx(r['end']), hx(r['offset']), r['size'], hx(r['fde']),
          hx(r['cie']), hx(r['lsda']), r['instructions'], r['sha256']) for r in result['functions']))
    tsv(output / 'instructions.tsv', ['role', 'va', 'file_offset', 'bytes', 'kind', 'target_va', 'rip_relative'],
        ((role, hx(r['va']), hx(view.offset(r['va'], len(r['bytes']))), r['bytes'].hex(), r['kind'],
          hx(r['target']), str(r['rip_relative']).lower()) for role, r in result['instructions']))
    tsv(output / 'branches.tsv', ['role', 'va', 'bytes', 'kind', 'taken_va', 'fallthrough_va'],
        ((role, hx(r['va']), r['bytes'].hex(), r['kind'], hx(r['target']),
          hx(r['end']) if r['kind'] == 'conditional' else '') for role, r in result['instructions']
         if r['kind'] in ('conditional', 'jump')))
    tsv(output / 'calls.tsv', ['role', 'va', 'bytes', 'kind', 'target_or_slot_va'],
        ((role, hx(r['va']), r['bytes'].hex(), r['kind'], hx(r['target']))
         for role, r in result['instructions'] if r in result['calls']))
    tsv(output / 'witnesses.tsv', ['va', 'file_offset', 'bytes', 'kind', 'target_va'],
        ((hx(a), hx(view.offset(a, len(bytes.fromhex(raw)))), raw,
          next(r['kind'] for _, r in result['instructions'] if r['va'] == a),
          hx(next(r['target'] for _, r in result['instructions'] if r['va'] == a)))
         for a, raw in result['witnesses']))
    tsv(output / 'prior-boundaries.tsv', ['va', 'file_offset', 'bytes', 'kind', 'target_va'],
        ((hx(r['va']), hx(view.offset(r['va'], len(r['bytes']))), r['bytes'].hex(), r['kind'], hx(r['target']))
         for r in result['boundary']))
    tsv(output / 'binary-jump-tables.tsv', ['table', 'index', 'entry_va', 'file_offset', 'bytes', 'target_va'],
        ((name, index, hx(va), hx(off), raw, hx(target))
         for name, index, va, off, raw, target in result['tables']))
    tsv(output / 'field-dispatch-boundary.tsv', ['index', 'tag', 'entry_va', 'file_offset', 'bytes', 'target_va'],
        ((index, hx(index + result['tag_bias']), hx(va), hx(view.offset(va, 4)), raw, hx(target))
         for index, va, raw, target in result['dispatch']))
    tsv(output / 'relocations.tsv', ['slot_va', 'section', 'record_file_offset', 'type', 'symbol_index',
        'symbol', 'addend', 'record_bytes'],
        ((hx(slot), name, hx(off), kind, symbol, sym_name, hx(addend), raw)
         for slot, (name, off, kind, symbol, sym_name, addend, raw) in sorted(result['relocations'].items())))
    tsv(output / 'lsda-headers.tsv', ['role', 'lsda_va', 'file_offset', 'next_known_upper_bound_va',
        'header_bytes', 'call_site_bytes', 'type_encoding', 'type_base_va'], result['lsda_headers'])
    tsv(output / 'exceptions.tsv', ['role', 'lsda_va', 'record_va', 'record_bytes', 'start_va',
        'end_va_exclusive', 'landing_va', 'action_index', 'transfers'], result['exceptions'])
    tsv(output / 'cfg-propositions.tsv', ['claim', 'role', 'from_va', 'to_va', 'reachable'], result['cfg'])
    tsv(output / 'delimiter-probes.tsv', ['label', 'kind', 'first', 'input_hex', 'result', 'error_code', 'cursor'],
        ((label, kind, str(first).lower(), payload, outcome, '' if error is None else error, pos)
         for label, kind, first, payload, outcome, error, pos in result['probes']))
    tsv(output / 'binary-prefix-probes.tsv', ['label', 'input_hex', 'result', 'count', 'cursor'],
        ((label, payload, outcome, '' if count is None else count, pos)
         for label, payload, outcome, count, pos in result['prefixes']))
    tsv(output / 'key-order-probes.tsv', ['label', 'left_hex', 'right_hex', 'order', 'common_length', 'first_difference'],
        ((label, left, right, order, common, '' if difference is None else difference)
         for label, left, right, order, common, difference in result['key_probes']))
    kinds = {}
    for _, r in result['instructions']:
        kinds[r['kind']] = kinds.get(r['kind'], 0) + 1
    summary = {'artifact_sha256': DIGEST, 'artifact_size': SIZE, 'field_literal_va': hx(0x21bb6c),
               'field_literal_file_offset': hx(view.offset(0x21bb6c, len(result['field']))),
               'field_literal': result['field'].decode('ascii'), 'field_tag': hx(result['field_tag']),
               'field_dispatch_bias': hx(result['tag_bias']),
               'selected_fdes': len(result['functions']),
               'selected_fde_bytes': sum(f['size'] for f in result['functions']),
               'selected_instructions': len(result['instructions']),
               'instruction_kinds': dict(sorted(kinds.items())),
               'selected_witnesses': len(result['witnesses']),
               'prior_boundary_windows': len(result['boundary']),
               'binary_jump_table_entries': len(result['tables']),
               'field_dispatch_controls': len(result['dispatch']),
               'indirect_slots_with_relocations': len(result['relocations']),
               'lsda_headers': len(result['lsda_headers']), 'lsda_call_site_records': len(result['exceptions']),
               'cfg_propositions': len(result['cfg']), 'delimiter_probes': len(result['probes']), 'binary_prefix_probes': len(result['prefixes']), 'key_order_probes': len(result['key_probes']),
               'whitespace_mask': hx(result['mask']),
               'limitations': ['FDE extents are not complete function discovery.',
                 'Instruction lengths and control transfers are restricted-pattern readings, not a full x86 semantics model.',
                 'CFG reachability overapproximates branches and assumes calls return; indirect jumps terminate the search.',
                 'Exception actions and indirect targets are not executed or interpreted.',
                 'Delimiter, binary-prefix and key-order probes are finite static models, not node execution.',
                 'Only the named field and selected ranges are covered.']}
    (output / 'evidence.json').write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args(argv)
    result = generate(TARGET.read_bytes(), args.out)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, OSError, struct.error) as error:
        print('config_nested_map94: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
