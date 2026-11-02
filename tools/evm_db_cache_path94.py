#!/usr/bin/env python3
"""Recover node94 private database cache read paths and state inputs.

Static byte inspection only. Semantic labels are hypotheses; the original
operands, FDE records, RELA entries and exception call-site rows are retained.
"""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import struct
from elf_index import sections
from fde_extents import eh_frame_records, uleb, sleb

ROOT = Path(__file__).resolve().parents[1]
SHA = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
FUNCTIONS = {
    0x1e6af40: 'code read through cache and backend',
    0x1e6b2c0: 'storage read through account and slot caches',
    0x1eadfc0: 'cached account drop',
    0x1eaffe0: 'optional code drop',
    0x1f651f0: 'account read through cache and backend',
    0x27c3dd0: 'account cache occupied or vacant entry',
    0x27c4c80: 'code cache occupied or vacant entry',
    0x27c5000: 'slot cache occupied or vacant entry',
    0x27c9ad0: 'slot insert or replace',
    0x324a070: 'default empty analyzed code',
    0x32d6a90: 'default code static bytes drop',
    0x32d6aa0: 'default code static bytes clone',
    0x4e5a630: 'account cache reserve and rehash',
    0x4e74a50: 'slot cache reserve and rehash',
    0x4e75150: 'code cache reserve and rehash',
    0x4e7e670: 'present account to cached account',
    0x4e7e800: 'optional account to cached account',
    0x4e800d0: 'code drop',
    0x4e80200: 'cached account to optional account',
    0x4ea2820: 'default account bit-slice tail builder',
    0x4ea3470: 'shared bit storage final release',
    0x4ea5380: 'default account static bytes drop',
    0x4ea5390: 'default account static bytes clone',
    0x4ea53c0: 'default account with empty code',
}



def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(blob):
    return hashlib.sha256(blob).hexdigest()


class Image:
    def __init__(self, data):
        require(digest(data) == SHA, 'target digest mismatch')
        self.data = data
        self.secs = sections(data)
        self.cies, fdes = eh_frame_records(data, self.secs)
        self.fdes = {}
        for f in fdes:
            self.fdes.setdefault(f['start'], []).append(f)
        s = self.section('.rela.dyn')
        require(s['size'] % 24 == 0, 'partial RELA record')
        self.relas = {}
        for off in range(s['offset'], s['offset'] + s['size'], 24):
            va, info, addend = struct.unpack_from('<QQq', data, off)
            require(va not in self.relas, 'duplicate RELA slot')
            self.relas[va] = (info, addend, off)

    def section(self, name):
        rows = [s for s in self.secs if s['name'] == name and s['type'] != 8]
        require(len(rows) == 1, 'missing or ambiguous section')
        return rows[0]

    def offset(self, va, size):
        require(type(va) is int and type(size) is int and va >= 0 and size > 0,
                'invalid requested range')
        matches = [s for s in self.secs if s['type'] != 8 and s['flags'] & 2
                   and s['address'] <= va and va + size <= s['address'] + s['size']]
        require(len(matches) == 1, 'range not uniquely file backed')
        s = matches[0]
        off = s['offset'] + va - s['address']
        require(off + size <= len(self.data), 'truncated file range')
        return off

    def read(self, va, size):
        off = self.offset(va, size)
        return self.data[off:off + size]

    def fde(self, va):
        rows = self.fdes.get(va, [])
        require(len(rows) == 1, 'missing or duplicate FDE')
        f = rows[0]
        text = self.section('.text')
        require(text['address'] <= va < f['end'] <= text['address'] + text['size'],
                'invalid executable FDE interval')
        return f

    def relative(self, slot):
        require(slot in self.relas, 'missing relocation')
        info, addend, _ = self.relas[slot]
        require(info == 8, 'not a symbol-free RELATIVE relocation')
        return addend

    def dynamic_symbol(self, slot):
        """Resolve an ELF64 x86-64 GLOB_DAT symbol without loading the ELF."""
        require(slot in self.relas, 'missing relocation')
        info, addend, rel_off = self.relas[slot]
        index, kind = info >> 32, info & 0xffffffff
        require(kind == 6 and index != 0 and addend == 0, 'not a GLOB_DAT symbol relocation')
        syms, strings = self.section('.dynsym'), self.section('.dynstr')
        require(syms['type'] == 11 and strings['type'] == 3 and syms['size'] % 24 == 0,
                'unexpected dynamic symbol or string table')
        # sections() has already validated the ELF section table; read just the
        # symbol section's link field, which the shared reader does not expose.
        shoff = struct.unpack_from('<Q', self.data, 40)[0]
        shentsize = struct.unpack_from('<H', self.data, 58)[0]
        link = struct.unpack_from('<I', self.data,
                                  shoff + self.secs.index(syms) * shentsize + 40)[0]
        require(link == self.secs.index(strings), 'dynamic symbol string-table link mismatch')
        require(index < syms['size'] // 24, 'dynamic symbol index outside table')
        sym_off = syms['offset'] + index * 24
        name_off, st_info, other, shndx, value, size = struct.unpack_from('<IBBHQQ', self.data, sym_off)
        require(name_off < strings['size'], 'dynamic symbol name outside table')
        begin = strings['offset'] + name_off
        end = self.data.find(b'\0', begin, strings['offset'] + strings['size'])
        require(end >= begin, 'unterminated dynamic symbol name')
        name = self.data[begin:end].decode('ascii')
        require(name, 'empty dynamic symbol name')
        return dict(slot=hex(slot), relocation_file_offset=hex(rel_off),
                    symbol_index=index, symbol_file_offset=hex(sym_off), name=name,
                    st_info=st_info, st_other=other, st_shndx=shndx,
                    st_value=hex(value), st_size=size,
                    symbol_raw=self.data[sym_off:sym_off + 24].hex())

    def expect(self, va, hexbytes):
        raw = bytes.fromhex(hexbytes)
        require(self.read(va, len(raw)) == raw, 'byte predicate mismatch')
        return raw


# Restricted x86-64 length/operand decoder. No text disassembler output enters
# the evidence. It rejects unsupported encodings instead of guessing lengths.
# This decodes operands, not effects; it never executes or emulates a function.
def instruction(code, pos):
    start = pos
    prefixes = []
    def take(n):
        nonlocal pos
        require(n > 0 and pos + n <= len(code), 'truncated instruction')
        v = code[pos:pos+n]
        pos += n
        require(pos - start <= 15, 'oversized instruction')
        return v
    while pos < len(code) and (code[pos] in (0x66, 0x2e, 0x64, 0x65, 0xf0, 0xf2, 0xf3)
                              or 0x40 <= code[pos] <= 0x4f):
        prefixes.append(take(1)[0])
    rex = next((p for p in reversed(prefixes) if 0x40 <= p <= 0x4f), 0)
    word = 2 if 0x66 in prefixes else 4
    op = take(1)[0]
    opcode = [op]
    kind = 'ordinary'
    immediate = 0
    relative = False
    modrm_needed = False
    if op in (0xe8, 0xe9, 0xeb) or 0x70 <= op <= 0x7f:
        immediate = 4 if op in (0xe8, 0xe9) else 1
        relative = True
        kind = 'call' if op == 0xe8 else 'jump' if op in (0xe9,0xeb) else 'conditional'
    elif op in (0xc3,0xcc):
        kind = 'return' if op == 0xc3 else 'trap'
    elif 0x50 <= op <= 0x5f or op in (0x90,0x98,0x99):
        pass
    elif 0xb0 <= op <= 0xb7 or op in (0x04,0x0c,0x24,0x2c,0x34,0x3c,0xa8,0x6a):
        immediate = 1
    elif 0xb8 <= op <= 0xbf:
        immediate = 8 if rex & 8 else word
    elif op in (0x05,0x0d,0x25,0x2d,0x35,0x3d,0xa9,0x68):
        immediate = word
    elif op == 0x0f:
        op2 = take(1)[0]
        opcode.append(op2)
        if 0x80 <= op2 <= 0x8f:
            relative, immediate, kind = True, 4, 'conditional'
        elif op2 == 0x0b:
            kind = 'trap'
        elif 0xc8 <= op2 <= 0xcf:
            pass
        elif (0x40 <= op2 <= 0x4f or 0x90 <= op2 <= 0x9f or op2 in
              (0x10,0x11,0x1f,0x28,0x29,0x54,0x55,0x56,0x57,0x60,0x61,0x62,0x64,
               0x6c,0x6d,0x6e,0x6f,0x74,0x75,0x76,0x7e,0x7f,0xaf,0xb0,0xb1,
               0xb6,0xb7,0xbc,0xbd,0xbe,0xbf,0xc1,0xd4,0xd6,0xd7,0xdb,0xdf,0xeb,0xef,0xfb)):
            modrm_needed = True
        elif op2 in (0x70,0x71,0x72,0x73,0xba,0xc2,0xc4,0xc5,0xc6):
            modrm_needed, immediate = True, 1
        else:
            raise ValueError('unsupported two-byte opcode')
    elif op in (0x80,0x83,0xc0,0xc1,0xc6,0x6b):
        modrm_needed, immediate = True, 1
    elif op in (0x81,0xc7,0x69):
        modrm_needed, immediate = True, word
    elif op in (0xf6,0xf7,0xfe,0xff,0x63,0x84,0x85,0x86,0x87,0x88,0x89,0x8a,0x8b,0x8d,
                0xd0,0xd1,0xd2,0xd3) or (op < 0x40 and op % 8 < 4):
        modrm_needed = True
    else:
        raise ValueError('unsupported opcode')
    row = {'kind': kind, 'opcode': bytes(opcode).hex(), 'rex': rex}
    rip_disp = None
    if modrm_needed:
        mr = take(1)[0]
        mod, reg, rm = mr >> 6, (mr >> 3) & 7, mr & 7
        row['modrm'] = mr
        if op == 0xff and reg in (2,4):
            row['kind'] = 'indirect-call' if reg == 2 else 'indirect-jump'
        if op in (0xf6,0xf7) and reg == 0:
            immediate = 1 if op == 0xf6 else word
        displacement = 0
        if mod != 3 and rm == 4:
            sib = take(1)[0]
            row['sib'] = sib
            if mod == 0 and sib & 7 == 5:
                displacement = 4
        elif mod == 0 and rm == 5:
            displacement = 4
            rip_disp = pos
        if mod in (1,2):
            displacement = 1 if mod == 1 else 4
        if displacement:
            row['displacement'] = int.from_bytes(take(displacement), 'little', signed=True)
    if immediate:
        raw = take(immediate)
        row['immediate'] = int.from_bytes(raw, 'little')
        if relative:
            row['target_offset'] = pos + int.from_bytes(raw, 'little', signed=True)
    if rip_disp is not None:
        row['rip_offset'] = pos + struct.unpack_from('<i', code, rip_disp)[0]
    if row['kind'] == 'conditional':
        row['condition'] = opcode[-1] & 15
    row['size'] = pos - start
    row['bytes'] = code[start:pos].hex()
    return row


def decode(code, base):
    rows = []
    pos = 0
    while pos < len(code):
        try:
            row = instruction(code, pos)
        except ValueError as e:
            raise ValueError(f'instruction at {base+pos:#x}: {e}') from e
        row['va'] = base + pos
        for source, dest in [('target_offset','target'),('rip_offset','rip')]:
            if source in row:
                row[dest] = base + row.pop(source)
        rows.append(row)
        pos += row['size']
    boundaries = {r['va'] for r in rows}
    for r in rows:
        if 'target' in r and base <= r['target'] < base + len(code):
            require(r['target'] in boundaries, 'branch into instruction')
    return rows


def tsv(rows, keys):
    buf = io.StringIO()
    writer = csv.DictWriter(buf, keys, delimiter='\t', lineterminator='\n', extrasaction='ignore')
    writer.writeheader()
    writer.writerows(rows)
    return buf.getvalue()


def js(obj):
    return json.dumps(obj, sort_keys=True, indent=2) + '\n'




def call_sites(image, function, boundaries):
    f = image.fde(function)
    if not f['lsda']:
        return [], None
    sec = image.section('.gcc_except_table')
    end = sec['offset'] + sec['size']
    require(sec['address'] <= f['lsda'] < sec['address']+sec['size'], 'LSDA outside exception section')
    pos = image.offset(f['lsda'],1)
    require(pos+3 <= end, 'truncated LSDA header')
    initial = pos
    data = image.data
    require(data[pos] == 0xff, 'unsupported LSDA LPStart')
    pos += 1
    type_encoding = data[pos]
    pos += 1
    type_base = None
    if type_encoding != 0xff:
        require(type_encoding == 0x9b, 'unsupported LSDA type encoding')
        delta,pos = uleb(data,pos,end)
        type_base = pos + delta
        require(type_base <= end, 'LSDA type base out of section')
    require(data[pos] == 1, 'unsupported call-site encoding')
    pos += 1
    length,pos = uleb(data,pos,end)
    limit = pos + length
    require(limit <= end and (type_base is None or limit <= type_base), 'call-site table out of range')
    rows = []
    previous = function
    while pos < limit:
        record = pos
        begin,pos = uleb(data,pos,limit)
        size,pos = uleb(data,pos,limit)
        landing,pos = uleb(data,pos,limit)
        action,pos = uleb(data,pos,limit)
        begin += function
        finish = begin + size
        require(previous <= begin <= finish <= f['end'], 'invalid exception interval')
        require(begin in boundaries and (finish in boundaries or finish == f['end']),
                'exception interval not at instruction boundary')
        require(not landing or (function <= function+landing < f['end']
                                 and function+landing in boundaries), 'invalid landing pad')
        rows.append(dict(function=hex(function), lsda=hex(f['lsda']),
                         site=hex(begin), end=hex(finish),
                         landing=hex(function+landing) if landing else '', action=action,
                         raw=data[record:pos].hex()))
        previous = finish
    return rows, dict(function=hex(function), lsda=hex(f['lsda']),
                      header_and_call_sites=data[initial:limit].hex(),
                      action_table_file_offset=hex(limit),
                      type_table_file_offset=hex(type_base) if type_base is not None else None,
                      limitation='Action chains and type records are not interpreted.')


# Evidence windows are selected by human reading; their bytes and operands are
# independently recovered by this generator, never parsed from disassembly.
WINDOWS = [
 ('account-entry',0x1f65201,0x1f65249),
 ('account-backend-result',0x1f6526b,0x1f6530f),
 ('account-missing-default',0x1f6530f,0x1f65430),
 ('account-present-construction',0x1f654c0,0x1f65570),
 ('account-publish',0x1f655fd,0x1f65732),
 ('account-cleanup',0x1f65783,0x1f657ef),
 ('code-entry-backend-and-default',0x1e6af51,0x1e6aff6),
 ('code-hit-dispatch',0x1e6aff6,0x1e6b00f),
 ('code-publish-and-dispatch',0x1e6b042,0x1e6b10f),
 ('code-clone-variants',0x1e6b10f,0x1e6b20d),
 ('code-output',0x1e6b20d,0x1e6b278),
 ('storage-entry-account-miss',0x1e6b2d1,0x1e6b379),
 ('storage-backend-double-account-check',0x1e6b42c,0x1e6b4d9),
 ('storage-existing-account-slot-hit-or-flag',0x1e6b4d9,0x1e6b557),
 ('storage-missing-account-default',0x1e6b557,0x1e6b595),
 ('storage-new-account-insert-slot',0x1e6b595,0x1e6b5dd),
 ('storage-account-publish',0x1e6b5dd,0x1e6b6c2),
 ('storage-slot-hit',0x1e6b6c2,0x1e6b6d1),
 ('storage-existing-account-backing-read',0x1e6b6d1,0x1e6b788),
 ('storage-slot-publish',0x1e6b788,0x1e6b832),
 ('storage-cleanup',0x1e6b8a0,0x1e6b8cd),
 ('account-entry-hash',0x27c3ddb,0x27c3e2a),
 ('code-entry-hash',0x27c4c8b,0x27c4cda),
 ('slot-entry-hash',0x27c500b,0x27c505a),
 ('account-growth-hash',0x4e5a85c,0x4e5a8aa),
 ('account-inplace-hash',0x4e5aa10,0x4e5aa60),
 ('code-growth-hash',0x4e7536f,0x4e753b1),
 ('code-inplace-hash',0x4e75550,0x4e75593),
 ('slot-growth-hash',0x4e74c7e,0x4e74cbc),
 ('slot-inplace-hash',0x4e74e50,0x4e74e93),
 ('slot-replacement',0x27c9c14,0x27c9c45),
 ('slot-hash-domain',0x27c9ae4,0x27c9b2a),
 ('slot-new-row',0x27c9c45,0x27c9ce1),
 ('optional-account-gate',0x4e7e80e,0x4e7e825),
 ('absent-account-state',0x4e7e8ac,0x4e7e8d8),
 ('present-account-state',0x4e7e742,0x4e7e784),
 ('account-result-absent-gate',0x4e8020f,0x4e80218),
 ('account-result-code-none-gate',0x4e8024c,0x4e80269),
 ('account-result-absent',0x4e8028f,0x4e8029b),
 ('default-account-fields',0x4ea5535,0x4ea559c),
 ('default-code-fields',0x324a1c1,0x324a216),
 ('default-bit-tail',0x4ea2821,0x4ea2864),
 ('account-entry-reserve',0x27c3f28,0x27c3f56),
 ('code-entry-reserve',0x27c4ddc,0x27c4e0a),
 ('slot-entry-reserve',0x27c5163,0x27c5191),
 ('account-reserve-decision',0x4e5a63e,0x4e5a792),
 ('account-reserve-null',0x4e5ae0c,0x4e5ae19),
 ('account-reserve-failure',0x4e5ae76,0x4e5ae9d),
 ('account-rehash-controls',0x4e5a971,0x4e5a994),
 ('account-growth-publication',0x4e5ae1c,0x4e5ae67),
 ('slot-reserve-decision',0x4e74a5e,0x4e74bc1),
 ('slot-reserve-null',0x4e750af,0x4e750bd),
 ('slot-reserve-failure',0x4e75113,0x4e7513a),
 ('slot-rehash-controls',0x4e74da9,0x4e74dd4),
 ('slot-growth-publication',0x4e750c0,0x4e75107),
 ('code-reserve-decision',0x4e7515e,0x4e752b5),
 ('code-reserve-null',0x4e7580b,0x4e75818),
 ('code-reserve-failure',0x4e7586e,0x4e75895),
 ('code-rehash-controls',0x4e754ac,0x4e754d4),
 ('code-growth-publication',0x4e7581b,0x4e75862),
]

# Explicit table windows are justified by the enum arms at their use sites;
# this is not a scan-until-invalid guess about the enum domain.
TABLES = [
 (0x1e6af40,0x1e6b00d,0x3bd324,4,'cached code hit clone'),
 (0x1e6af40,0x1e6b10d,0x3bd314,4,'new code clone'),
 (0x4e80200,0x4e80267,0x7c3b40,4,'optional account code clone'),
 (0x1eaffe0,0x1eb0003,0x3bf228,4,'optional code destruction'),
 (0x4e800d0,0x4e800e5,0x7c3b30,4,'code destruction'),
]

# Each operand is decoded from the indicated authenticated instruction. The
# values are never taken from labels or disassembler output.
OPERANDS = [
 (0x27c3e1a,'account hash domain','immediate'),
 (0x27c4cca,'code hash domain','immediate'),
 (0x27c504a,'slot hash domain','immediate'),
 (0x27c9b20,'slot insertion hash domain','immediate'),
 (0x27c3e85,'account bucket stride','immediate'),
 (0x1e6b08d,'code bucket stride factor','sib'),
 (0x1e6b091,'code bucket stride shift','immediate'),
 (0x1e6b7d2,'slot bucket stride shift','immediate'),
 (0x4e8020f,'account state flag offset','displacement'),
 (0x4e8028f,'absent account output tag','immediate'),
 (0x4e8024f,'absent optional code tag','immediate'),
 (0x4e7e750,'present account state byte','immediate'),
 (0x4e7e8ac,'absent account state byte','immediate'),
 (0x1e6afd5,'absent backend code tag','immediate'),
 (0x1e6afe8,'default cached code tag','immediate'),
 (0x1e6afa9,'backend code field','immediate'),
 (0x1e6b46e,'backend slot field','immediate'),
 (0x1e6b543,'existing account storage flag mask','immediate'),
 (0x1e6b5d2,'cached account bytes','immediate'),
 (0x1f65534,'account info bytes','immediate'),
 (0x324a1b1,'default shared bit allocation bytes','immediate'),
 (0x324a1d4,'default shared bit span','immediate'),
 (0x324a202,'default logical code length','immediate'),
 (0x4e5a723,'account allocation bucket stride','immediate'),
 (0x4e75248,'code allocation bucket stride','immediate'),
 (0x4e74b62,'slot allocation bucket shift','immediate'),
 (0x4e5a6da,'growth scale limit before increment','immediate'),
 (0x4e74b43,'slot shift limit before increment','immediate'),
 (0x27c3f3d,'account reserve mode','immediate'),
 (0x27c4df1,'code reserve mode','immediate'),
 (0x27c5178,'slot reserve mode','immediate'),
]

# Only selected call sites are listed here.  Their displacements and relocation
# addends are decoded from the file and checked against these reviewed targets.
# Earlier packets own the three backing getters; only the call edges are new.
EDGES = [
 (0x1f65233,0x27c3dd0,'account cache entry'),
 (0x1f652a3,0x37d0fb0,'account backing read'),
 (0x1f65317,0x4ea53c0,'default account data'),
 (0x1f6572c,0x4e80200,'account result conversion'),
 (0x1e6af77,0x27c4c80,'code cache entry'),
 (0x1e6afd0,0x37d13c0,'code backing read'),
 (0x1e6afe3,0x324a070,'default code data'),
 (0x1e6b304,0x27c3dd0,'slot account entry'),
 (0x1e6b366,0x37d0fb0,'slot first account read'),
 (0x1e6b45d,0x37d0fb0,'slot second account read'),
 (0x1e6b4ac,0x37d11d0,'slot backing read after new account'),
 (0x1e6b508,0x27c5000,'slot cache entry'),
 (0x1e6b573,0x4e7e800,'new missing account data'),
 (0x1e6b5a2,0x4e7e800,'new present account data'),
 (0x1e6b5c0,0x27c9ad0,'slot insertion into new account'),
 (0x1e6b70a,0x37d0fb0,'slot account recheck'),
 (0x1e6b755,0x37d11d0,'slot backing read after cache miss'),
 (0x27c3f45,0x4e5a630,'account cache reserve'),
 (0x27c4df9,0x4e75150,'code cache reserve'),
 (0x27c5180,0x4e74a50,'slot cache reserve'),
]

# Test/compare instruction, following conditional and the checked destination.
# Descriptions name only the taken path; FDE/bytes remain the primary evidence.
BRANCHES = [
 (0x1f65240,'4d85e4',0x1f65416,'account entry word zero'),
 (0x1f652b0,'4883f801',0x1f65423,'account backing tag differs from one'),
 (0x1f65307,'84c0',0x1f65430,'account backing low byte nonzero'),
 (0x1f65428,'84c0',0x1f6530f,'account backing low byte zero'),
 (0x1e6af80,'4d85ff',0x1e6aff6,'code entry word zero'),
 (0x1e6afd5,'833c2404',0x1e6b00f,'code backing tag differs from four'),
 (0x1e6b30e,'4d85ed',0x1e6b4d9,'slot account entry word zero'),
 (0x1e6b36b,'83bc242001000001',0x1e6b557,'first account tag differs from one'),
 (0x1e6b462,'48837c245000',0x1e6b588,'second account result word zero'),
 (0x1e6b4b1,'80bc242001000000',0x1e6b588,'new-account slot result byte zero'),
 (0x1e6b512,'4d85ed',0x1e6b6c2,'slot entry word zero'),
 (0x1e6b543,'a801',0x1e6b6d1,'cached account state low bit set'),
 (0x1e6b70f,'48837c245000',0x1e6b77b,'cached-account backing result word zero'),
 (0x1e6b75a,'80bc242001000000',0x1e6b77b,'cached-account slot result byte zero'),
 (0x1e6b137,'f048ff00',0x1e6b2af,'post-increment signed less or equal'),
 (0x1e6b1d9,'f048ff01',0x1e6b2af,'post-increment signed less or equal'),
 (0x27c9b2a,'48837e1000',0x27c9cf3,'slot table growth word zero'),
 (0x27c9bb7,'81fdffff0000',0x27c9c14,'slot key comparison mask all ones'),
 (0x27c9bf4,'4585db',0x27c9c45,'slot group has empty control'),
 (0x324a093,'4885c0',0x324a237,'code default first allocation null'),
 (0x324a1bc,'4885c0',0x324a225,'code default second allocation null'),
 (0x4ea53e3,'4885c0',0x4ea55c0,'account default first allocation null'),
 (0x4ea550d,'4885c0',0x4ea55ae,'account default second allocation null'),
 (0x4e8020f,'80beb000000000',0x4e8028f,'account state byte zero'),
 (0x4e8024f,'4983fe04',0x4e803c5,'optional code tag equals four'),
 (0x4e5a648,'4801fe',0x4e5a758,'account count plus request carries'),
 (0x4e5a72b,'48f7e1',0x4e5a758,'account bucket bytes multiply overflows'),
 (0x4e5a789,'4885c0',0x4e5ae0c,'account cache allocation null'),
 (0x4e5a758,'4584c9',0x4e5ae76,'account reserve failure mode nonzero'),
 (0x4e5ae0c,'803c2400',0x4e5ae8f,'account reserve allocation failure mode nonzero'),
 (0x4e74a68,'4801fe',0x4e74b81,'slot count plus request carries'),
 (0x4e74bb8,'4885c0',0x4e750af,'slot cache allocation null'),
 (0x4e74b81,'4584c9',0x4e75113,'slot reserve failure mode nonzero'),
 (0x4e750af,'807c241c00',0x4e7512c,'slot reserve allocation failure mode nonzero'),
 (0x4e75168,'4801fe',0x4e7527d,'code count plus request carries'),
 (0x4e75250,'48f7e1',0x4e7527d,'code bucket bytes multiply overflows'),
 (0x4e752ac,'4885c0',0x4e7580b,'code cache allocation null'),
 (0x4e7527d,'4584c9',0x4e7586e,'code reserve failure mode nonzero'),
 (0x4e7580b,'803c2400',0x4e75887,'code reserve allocation failure mode nonzero'),
]

# Load sites are ordered by key offset, not execution order.  For reserve
# paths, file bytes address backward from controls, so the bucket stride is
# subtracted before comparing their offsets with the direct lookup path.
HASH_PATHS = [
 ('account','lookup',0x27c3dd0,[0x27c3dec,0x27c3e00,0x27c3def,0x27c3de5],0x27c3e1a),
 ('account','in-place',0x4e5a630,[0x4e5aa3f,0x4e5aa34,0x4e5aa1f,0x4e5aa14],0x4e5aa56),
 ('account','growth',0x4e5a630,[0x4e5a887,0x4e5a87c,0x4e5a867,0x4e5a85c],0x4e5a8a0),
 ('code','lookup',0x27c4c80,[0x27c4c9c,0x27c4c9f,0x27c4cb0,0x27c4c95],0x27c4cca),
 ('code','in-place',0x4e75150,[0x4e75575,0x4e7555b,0x4e7556d,0x4e75553],0x4e75589),
 ('code','growth',0x4e75150,[0x4e75391,0x4e75377,0x4e75389,0x4e7536f],0x4e753a7),
 ('slot','lookup',0x27c5000,[0x27c501c,0x27c501f,0x27c5030,0x27c5015],0x27c504a),
 ('slot','in-place',0x4e74a50,[0x4e74e75,0x4e74e5b,0x4e74e6d,0x4e74e53],0x4e74e89),
 ('slot','growth',0x4e74a50,[0x4e74c9d,0x4e74c85,0x4e74c96,0x4e74c7e],0x4e74cb2),
]


def classify(target):
    if target in FUNCTIONS:
        return 'selected-entry'
    if target in (0x37d0fb0,0x37d13c0,0x37d11d0,0x38142d0):
        return 'prior-owned-boundary'
    return 'external-boundary'


def collect(image):
    functions, code, control, refs, relocs, unwind, exceptions, lsda = [], {}, [], [], {}, [], [], []
    instructions = {}
    for start, role in sorted(FUNCTIONS.items()):
        f = image.fde(start)
        raw = image.read(start,f['end']-start)
        rows = decode(raw,start)
        instructions[start] = rows
        functions.append(dict(start=hex(start),end=hex(f['end']),bytes=len(raw),
            file_offset=hex(image.offset(start,len(raw))),fde=hex(f['fde']),cie=hex(f['cie']),
            lsda=hex(f['lsda']) if f['lsda'] else '',sha256=digest(raw),instructions=len(rows),role=role))
        code[hex(start)] = rows
        for key in ('fde','cie'):
            va=f[key]; n=struct.unpack('<I',image.read(va,4))[0]+4
            unwind.append(dict(function=hex(start),kind=key,va=hex(va),raw=image.read(va,n).hex()))
        ex, ls = call_sites(image,start,{r['va'] for r in rows})
        exceptions.extend(ex)
        if ls: lsda.append(ls)
        for r in rows:
            target=r.get('target')
            resolved=False
            if 'rip' in r:
                ptr=r['rip']
                rec=image.relas.get(ptr)
                refs.append(dict(function=hex(start),site=hex(r['va']),address=hex(ptr),bytes=r['bytes'],
                    relative_addend=hex(rec[1]) if rec and rec[0]==8 else ''))
                if rec:
                    info,addend,off=rec
                    relocs[ptr]=dict(slot=hex(ptr),info=hex(info),addend=hex(addend),
                                     file_offset=hex(off),raw=image.data[off:off+24].hex())
                    if info==8 and r['kind'].startswith('indirect-'):
                        target=addend; resolved=True
            if r['kind'] != 'ordinary':
                scope='dynamic' if target is None and r['kind'].startswith('indirect-') else ''
                if target is not None:
                    scope='local' if start<=target<f['end'] else classify(target)
                control.append(dict(function=hex(start),site=hex(r['va']),kind=r['kind'],bytes=r['bytes'],
                    condition=r.get('condition',''),target=hex(target) if target is not None else '',
                    fallthrough=hex(r['va']+r['size']) if r['kind']=='conditional' or 'call' in r['kind'] else '',
                    target_scope=scope,via_relative_relocation=int(resolved)))
    by_va={r['va']:r for rows in instructions.values() for r in rows}
    owners={r['va']:start for start,rows in instructions.items() for r in rows}
    edges=[]
    for site,expected,role in EDGES:
        r=by_va[site]
        require(r['kind'] in ('call','indirect-call'),'selected edge is not a call')
        via = r.get('rip') if r['kind']=='indirect-call' else None
        target = image.relative(via) if via is not None else r.get('target')
        require(target == expected,'selected call target changed')
        edges.append(dict(function=hex(owners[site]),site=hex(site),bytes=r['bytes'],
                          kind=r['kind'],slot=hex(via) if via is not None else '',
                          target=hex(target),scope=classify(target),role=role))
    branches=[]
    for site,hexbytes,target,meaning in BRANCHES:
        r=by_va[site]
        require(r['bytes']==hexbytes,'selected predicate bytes changed')
        branch=by_va.get(site+r['size'])
        require(branch is not None and branch['kind']=='conditional'
                and branch.get('target')==target,'selected predicate branch changed')
        branches.append(dict(function=hex(owners[site]),predicate=hex(site),bytes=r['bytes'],
                             branch=hex(branch['va']),branch_bytes=branch['bytes'],
                             condition=branch['condition'],taken=hex(branch['target']),
                             fallthrough=hex(branch['va']+branch['size']),taken_if=meaning))
    hash_paths=[]
    baseline={}
    for kind,stage,fn,sites,domain_site in HASH_PATHS:
        strides={'account':by_va[0x4e5a723]['immediate'],
                 'code':by_va[0x4e75248]['immediate'],
                 'slot':1<<by_va[0x4e74b62]['immediate']}
        base=0 if stage=='lookup' else -strides[kind]
        loads=[by_va[va] for va in sites]
        require(all(owners[va]==fn for va in sites+[domain_site]), 'hash path outside selected function')
        require(all(r['opcode']=='8b' and r['rex'] & 8 for r in loads), 'hash key load is not 64-bit MOV')
        displacements=[r.get('displacement',0) for r in loads]
        offsets=[d-base for d in displacements]
        domain=by_va[domain_site]
        require(domain['opcode']=='83' and domain.get('modrm')==0xf0, 'hash domain is not XOR immediate')
        shape=(offsets,domain['immediate'])
        if kind not in baseline:
            baseline[kind]=shape
        else:
            require(shape == baseline[kind], 'lookup and rehash key shapes disagree')
        hash_paths.append(dict(kind=kind,stage=stage,function=hex(fn),key_width=max(offsets)+8,
            bucket_base_displacement=base,load_sites=','.join(hex(va) for va in sites),
            load_bytes=','.join(r['bytes'] for r in loads),
            raw_displacements=','.join(map(str,displacements)),key_offsets=','.join(map(str,offsets)),
            domain_site=hex(domain_site),domain_bytes=domain['bytes'],domain_immediate=domain['immediate']))
    windows=[]
    for label,start,end in WINDOWS:
        require(start in by_va,'window start is not an instruction')
        selected=[r for rows in instructions.values() for r in rows if start<=r['va']<end]
        require(selected and selected[-1]['va']+selected[-1]['size']==end,'window end is not a boundary')
        raw=image.read(start,end-start)
        windows.append(dict(name=label,start=hex(start),end=hex(end),raw=raw.hex(),sha256=digest(raw)))
    operands=[]
    for va,label,field in OPERANDS:
        r=by_va[va]
        require(field in r,'missing operand')
        operands.append(dict(name=label,site=hex(va),field=field,value=r[field],bytes=r['bytes']))
    tables=[]
    for fn,site,base,count,role in TABLES:
        require(by_va[site]['kind']=='indirect-jump','table dispatch is not indirect jump')
        bounds={r['va'] for r in instructions[fn]}
        for tag in range(count):
            raw=image.read(base+4*tag,4); displacement=struct.unpack('<i',raw)[0]; target=base+displacement
            require(target in bounds,'table target outside selected instruction boundaries')
            tables.append(dict(function=hex(fn),site=hex(site),table=hex(base),tag=tag,
                               raw=raw.hex(),displacement=displacement,target=hex(target),role=role))
    constants=[]
    for va,size,label in [(0x20ca80,32,'default account code hash'),(0x574ce10,32,'empty slot map header'),
                           (0x202e90,16,'empty control group'),(0x207980,16,'rehash control mask'),
                           (0x1e629b,1,'default code backing byte'),(0x203480,16,'slot map counter adjustment')]:
        constants.append(dict(va=hex(va),size=size,name=label,raw=image.read(va,size).hex()))
        for slot in range(va,va+size,8):
            if slot in image.relas:
                info,addend,off=image.relas[slot]
                relocs[slot]=dict(slot=hex(slot),info=hex(info),addend=hex(addend),file_offset=hex(off),raw=image.data[off:off+24].hex())
    for va,size in [(0x574fb98,40),(0x56df080,40)]:
        constants.append(dict(va=hex(va),size=size,name='default bytes method table; no Rust trait layout assumed',raw=image.read(va,size).hex()))
        for slot in range(va,va+size,8):
            info,addend,off=image.relas[slot]
            require(info==8,'method table relocation not RELATIVE')
            relocs[slot]=dict(slot=hex(slot),info=hex(info),addend=hex(addend),file_offset=hex(off),raw=image.data[off:off+24].hex())
    # This row is arithmetic on operands from the recorded instructions, not
    # a claim that the allocation path was executed.  In particular, a signed
    # imm8 is sign extended by x86 before the final bound is compared.
    sources = [0x4e5a692,0x4e5a695,0x4e5a69d,0x4e5a6da,0x4e5a6ec,
               0x4e5a6f0,0x4e5a723,0x4e5a733,0x4e5a74a,
               0x4e74afd,0x4e74b0f,0x4e74b13,0x4e74b43,0x4e74b55,0x4e74b62,0x4e74b73,
               0x4e751ff,0x4e75211,0x4e75215,0x4e75248,0x4e75258,0x4e7526f]
    source_rows=[dict(site=hex(va),bytes=by_va[va]['bytes'],immediate=by_va[va]['immediate'])
                 for va in sources]
    imm=lambda va: by_va[va]['immediate']
    magic=imm(0x4e5a6f0)
    require(magic == imm(0x4e74b13) == imm(0x4e75215), 'growth constants disagree')
    require(imm(0x4e5a6da) == imm(0x4e74afd) == imm(0x4e751ff)
            and imm(0x4e5a6ec) == imm(0x4e74b0f) == imm(0x4e75211),
            'growth scaling operands disagree')
    divisor=((1<<64)+magic-1)//magic
    limit_base=imm(0x4e5a733)
    delta=imm(0x4e5a74a)
    delta=delta-256 if delta>=128 else delta
    limit=(limit_base+delta) & ((1<<64)-1)
    require(limit_base == imm(0x4e74b55) == imm(0x4e75258)
            and imm(0x4e5a74a) == imm(0x4e74b73) == imm(0x4e7526f),
            'allocation bounds disagree')
    reserve_invariants=dict(source_operands=source_rows,
        small_buckets=[imm(0x4e5a69d),imm(0x4e5a695),imm(0x4e5a695)+imm(0x4e5a692)],
        numerator_factor=1 << imm(0x4e5a6ec),reciprocal_magic=hex(magic),
        candidate_reciprocal_divisor=divisor,
        max_growth_request=hex(imm(0x4e5a6da)+1),
        max_allocation_bytes=hex(limit),slot_preincrement_shift_limit=hex(imm(0x4e74b43)),
        strides=dict(account=imm(0x4e5a723),code=imm(0x4e75248),slot=1<<imm(0x4e74b62)),
        limitation='Derived from selected immediate operands; no allocator execution or source type identity.')
    symbol_slots=[slot for slot,rec in sorted(image.relas.items())
                  if slot in relocs and (rec[0] & 0xffffffff)==6]
    symbols=[image.dynamic_symbol(slot) for slot in symbol_slots]
    require({r['slot']:r['name'] for r in symbols} == {
        '0x576dfe0':'memcpy','0x576e0e0':'memmove','0x576e1f8':'memset'},
        'unexpected dynamic symbol bindings')
    summary=dict(target_sha256=SHA,functions=len(functions),bytes=sum(r['bytes'] for r in functions),
        instructions=len(by_va),control_records=len(control),relocations=len(relocs),
        exception_intervals=len(exceptions),semantic_windows=len(windows),table_entries=len(tables),
        selected_call_edges=len(edges),selected_predicate_branches=len(branches),hash_paths=len(hash_paths),
        dynamic_symbols=len(symbols),
        external_control_targets=sorted({r['target'] for r in control if r['target_scope']=='external-boundary'}),
        dynamic_control_sites=[r['site'] for r in control if r['target_scope']=='dynamic'],
        limitation='Selected FDE and byte ledgers, not whole-component coverage or captured execution.')
    return {
        'functions.tsv':tsv(functions,['start','end','bytes','file_offset','fde','cie','lsda','sha256','instructions','role']),
        'call-edges.tsv':tsv(edges,['function','site','bytes','kind','slot','target','scope','role']),
        'hash-paths.tsv':tsv(hash_paths,['kind','stage','function','key_width','bucket_base_displacement','load_sites','load_bytes','raw_displacements','key_offsets','domain_site','domain_bytes','domain_immediate']),
        'predicate-branches.tsv':tsv(branches,['function','predicate','bytes','branch','branch_bytes','condition','taken','fallthrough','taken_if']),
        'dynamic-symbols.tsv':tsv(symbols,['slot','relocation_file_offset','symbol_index','symbol_file_offset','name','st_info','st_other','st_shndx','st_value','st_size','symbol_raw']),
        'instructions.json':json.dumps(code,sort_keys=True,separators=(',',':'))+'\n',
        'control-flow.tsv':tsv(control,['function','site','kind','bytes','condition','target','fallthrough','target_scope','via_relative_relocation']),
        'rip-references.tsv':tsv(refs,['function','site','address','bytes','relative_addend']),
        'relocations.tsv':tsv([relocs[k] for k in sorted(relocs)],['slot','info','addend','file_offset','raw']),
        'unwind-records.json':js(unwind),'exception-call-sites.tsv':tsv(exceptions,['function','lsda','site','end','landing','action','raw']),
        'lsda-records.json':js(lsda),'semantic-windows.json':js(windows),
        'reserve-invariants.json':js(reserve_invariants),
        'operands.tsv':tsv(operands,['name','site','field','value','bytes']),
        'branch-tables.tsv':tsv(tables,['function','site','table','tag','raw','displacement','target','role']),
        'constants.json':js(constants),'summary.json':js(summary),
    }

MASK = (1 << 64) - 1

def growth_buckets(requested):
    """Synthetic projection of the checked growth arm, not target execution."""
    require(type(requested) is int and 0 <= requested <= MASK, 'invalid requested capacity')
    if requested < 4:
        return 4
    if requested < 8:
        return 8
    if requested < 15:
        return 16
    require(requested <= (1 << 61) - 1, 'capacity scaling overflows')
    return 1 << ((requested * 8 // 7 - 1).bit_length())


def allocation_layout(buckets, stride):
    """Checked table allocation arithmetic for the three observed strides."""
    require(type(buckets) is int and buckets >= 4 and buckets & (buckets-1) == 0,
            'invalid bucket count')
    require(type(stride) is int and stride in (64,96,208), 'unknown bucket stride')
    size = buckets * stride + buckets + 16
    require(size <= (1 << 63) - 16, 'allocation layout overflows')
    return size


def folded_product(a, b):
    require(type(a) is int and type(b) is int and 0 <= a <= MASK and 0 <= b <= MASK,
            'expected two u64 words')
    v = a * b
    return (v & MASK) ^ (v >> 64)


def cache_hash(key, kind, process0, process1, seed):
    """Instruction-derived integer algebra; explicit synthetic process words."""
    require(kind in ('account','code','slot'), 'unknown cache kind')
    require(isinstance(key,bytes) and len(key)==(20 if kind=='account' else 32), 'wrong key width')
    require(all(type(x) is int and 0<=x<=MASK for x in (process0,process1,seed)), 'invalid hash word')
    a,b,c,d=(0,4,8,12) if kind=='account' else (0,16,8,24)
    word=lambda off:int.from_bytes(key[off:off+8],'little')
    mixed=folded_product(word(c)^process1,word(d)^process0)
    mixed^=folded_product(word(a)^seed,word(b)^process0)
    domain={'account':20,'code':32,'slot':4}[kind]
    return folded_product(mixed^domain,process0)


def probe(key, hash_word, controls, keys):
    """Model valid >=16-bucket tables. Bounds rejection is a model guard."""
    require(isinstance(key,bytes) and len(key) in (20,32),'invalid key')
    require(type(hash_word) is int and 0<=hash_word<=MASK,'invalid hash')
    n=len(controls)
    require(n>=16 and n&(n-1)==0 and len(keys)==n,'invalid model table')
    require(all(type(c) is int and (0<=c<128 or c in (128,255)) for c in controls),'invalid controls')
    require(all(k is None or isinstance(k,bytes) and len(k)==len(key) for k in keys),'invalid bucket key')
    require(all(c>=128 or k is not None for c,k in zip(controls,keys)),
            'occupied control lacks a complete key')
    fingerprint=hash_word>>57
    position=hash_word&(n-1); stride=0
    groups=[]
    for _ in range(n//16+1):
        groups.append(position)
        group=[(position+i)&(n-1) for i in range(16)]
        for ix in group:
            if controls[ix]==fingerprint and keys[ix]==key:
                return dict(hit=ix,groups=groups)
        if any(controls[ix]==255 for ix in group):
            return dict(hit=None,groups=groups)
        stride+=16; position=(position+stride)&(n-1)
    raise ValueError('model table has no terminating empty control')


def vacant_publish(controls, index, hash_word, growth_left, items):
    """Publication arithmetic, including tombstone versus empty accounting."""
    n=len(controls)
    require(n>=16 and n&(n-1)==0 and type(index) is int and 0<=index<n,'invalid publication index')
    require(controls[index] in (128,255),'publishing into occupied control')
    require(all(type(x) is int for x in (hash_word,growth_left,items))
            and 0<=hash_word<=MASK and 0<=items<n and 0<=growth_left<=n,
            'invalid publication words')
    decrement=controls[index]&1
    require(growth_left>=decrement,'invalid growth budget')
    mirror=((index-16)&(n-1))+16
    return dict(control=hash_word>>57,index=index,mirror=mirror,
                growth_left=growth_left-decrement,items=items+1)


def account_policy(hit, state, backend_present):
    require(type(hit) is bool and type(backend_present) is bool and type(state) is int and 0<=state<256,'invalid account case')
    final_state=state if hit else (3 if backend_present else 0)
    return dict(backend_account_calls=int(not hit),insert_account=not hit,state=final_state,
                result='account-info' if final_state else 'tag-5-absent',
                note='vacant entry may reserve before backend access')


def code_policy(hit, backend_tag):
    require(type(hit) is bool and type(backend_tag) is int and 0<=backend_tag<=4,'invalid code case')
    return dict(backend_code_calls=int(not hit),insert_code=not hit,
                default_empty=not hit and backend_tag==4,
                clone_tag=1 if not hit and backend_tag==4 else backend_tag if not hit else 'cached',
                note='cached values must be tags 0..3; input backend tag is ignored on hit')


def storage_policy(account_hit, slot_hit, state, first_account, second_account, slot_present):
    require(all(type(v) is bool for v in (account_hit,slot_hit,first_account,second_account,slot_present))
            and type(state) is int and 0<=state<256,'invalid storage case')
    require(account_hit or not slot_hit, 'slot hit requires an account cache hit')
    result=dict(account_backend_calls=0,slot_backend_calls=0,insert_account=False,
                insert_slot=False,source='zero',state=state if account_hit else None,
                slot_entry_probe=account_hit)
    if account_hit:
        if slot_hit:
            result['source']='cached-slot'
            return result
        if not state&1:
            return result
        result['account_backend_calls']=1
        result['slot_backend_calls']=int(second_account)
        result['source']='backend-slot' if second_account and slot_present else 'zero'
        result['insert_slot']=True
        return result
    result['insert_account']=True
    result['account_backend_calls']=1
    result['state']=3 if first_account else 0
    if not first_account:
        return result
    result['account_backend_calls']=2
    result['slot_backend_calls']=int(second_account)
    result['source']='backend-slot' if second_account and slot_present else 'zero'
    result['insert_slot']=True
    return result


def outputs(image):
    check_semantics(image)
    result=collect(image)
    return result


# Authenticated semantic predicates; corruption must fail even if Image is
# supplied directly by a test after construction.
PINS = {
    0x1e6af83: '7471',
    0x1e6afa9: 'be28090000',
    0x1e6afd5: '833c2404',
    0x1e6afd9: '7534',
    0x1e6afe8: '48c78424a000000001000000',
    0x1e6b08d: '488d0c76',
    0x1e6b091: '48c1e105',
    0x1e6b133: '498b46c8',
    0x1e6b137: 'f048ff00',
    0x1e6b13b: '0f8e6e010000',
    0x1e6b1d9: 'f048ff01',
    0x1e6b1dd: '0f8ecc000000',
    0x1e6b2af: '0f0b',
    0x1e6b311: '0f84c2010000',
    0x1e6b373: '0f85de010000',
    0x1e6b468: '0f841a010000',
    0x1e6b46e: '4981c430120000',
    0x1e6b4b9: '0f84c9000000',
    0x1e6b515: '0f84a7010000',
    0x1e6b543: 'a801',
    0x1e6b545: '0f8586010000',
    0x1e6b5d2: 'bab8000000',
    0x1e6b715: '7464',
    0x1e6b762: '7417',
    0x1e6b7d2: '48c1e206',
    0x1f65243: '0f84cd010000',
    0x1f652b0: '4883f801',
    0x1f652b4: '0f8569010000',
    0x1f65423: 'b905000000',
    0x1f65428: '84c0',
    0x1f6542a: '0f84dffeffff',
    0x1f65534: 'ba88000000',
    0x1f65542: 'c684249801000003',
    0x1f65722: '4881c648ffffff',
    0x27c3ddb: '488b15fea5fa024c8b124c8b430c4d31d0488b0b488b43084833420849f7e04989c04989d1488b53044c31d248334e204889c848f7e24931d14d31c14c31c84883f01449f7e24889c14889f84831ca',
    0x27c3e1a: '4883f014',
    0x27c3e85: '4d69f6d0000000',
    0x27c3f07: '741f',
    0x27c4c8b: '488b154e97fa024c8b124c8b43184d31d0488b0b488b43084833420849f7e04989c04989d1488b53104c31d248334e204889c848f7e24931d14d31c14c31c84883f02049f7e24889c14889f84831ca',
    0x27c4cca: '4883f020',
    0x27c4db7: '7423',
    0x27c500b: '488b15ce93fa024c8b124c8b43184d31d0488b0b488b43084833420849f7e04989c04989d1488b53104c31d248334e204889c848f7e24931d14d31c14c31c84883f00449f7e24889c14889f84831ca',
    0x27c504a: '4883f004',
    0x27c5180: 'ff1532e6fa02',
    0x27c9ae4: '488b15f548fa024c8b0a498b7e18498b4608483342084c31cf48f7e74889c74989d0498b06498b5610483346204c31ca48f7e24931d04931f84c31c04883f00449f7e14831c2',
    0x27c9b20: '4883f004',
    0x324a1b1: 'bf28000000',
    0x324a1d4: '48c7401808000000',
    0x324a202: '48c7421800000000',
    0x4e5a64b: '0f8207010000',
    0x4e5a67e: '7628',
    0x4e5a6da: '48b8feffffffffffff1f',
    0x4e74afd: '48b8feffffffffffff1f',
    0x4e751ff: '48b8feffffffffffff1f',
    0x4e5a6ec: '48c1e10348ba93244992244992244889c848f7e24829d148d1e94801d148c1e90248ffc9',
    0x4e74b0f: '48c1e10348ba93244992244992244889c848f7e24829d148d1e94801d148c1e90248ffc9',
    0x4e75211: '48c1e10348ba93244992244992244889c848f7e24829d148d1e94801d148c1e90248ffc9',
    0x4e5a980: '660fefc966410f640c34660febc866410f7f0c34',
    0x4e74dc0: '660fefc966410f640c34660febc866410f7f0c34',
    0x4e754c0: '660fefc966410f640c34660febc866410f7f0c34',
    0x4e5a971: '660f6f0507d03afb',
    0x4e74da9: '660f6f05cf2b39fb',
    0x4e754ac: '660f6f05cc2439fb',
    0x4e5ae24: '48892b488b04244889430848894b10',
    0x4e750c8: '4c892b4c89630848894310',
    0x4e75822: '48892b4c89630848894310',
    0x4e5a85c: '4b8b8c163cffffff4c31c94b8b841638ffffff4833420848f7e14889c14889d64b8b941634ffffff4c31ca4b8b841630ffffff483344241048f7e24831d64831ce4831f04883f01449f7e14831c2',
    0x4e5aa10: '4c8b4d004b8b8c043cffffff4c31c94b8b840438ffffff4833450848f7e14889c14889d74b8b940434ffffff4c31ca4b8b840430ffffff4c31f848f7e24831d74831cf4831f84883f01449f7e14831c2',
    0x4e74c7e: '488b4fd84c31f9488b47c84833420848f7e14889c14889d6488b57d04c31fa488b47c0483344241048f7e24831d64831ce4831f04883f00449f7e74831c2',
    0x4e74e50: '4d8b294b8b4c3cd84c31e94b8b443cc84933410848f7e14889c14889d64b8b543cd04c31ea4b8b443cc04831f848f7e24831d64831ce4831f04883f00449f7e54831c2',
    0x4e7536f: '4a8b4c37b84c31c14a8b4437a84833420848f7e14889c14889d64a8b5437b04c31c24a8b4437a0483344240848f7e24831d64831ce4831f04883f02049f7e04831c2',
    0x4e75550: '4d8b294b8b4c3cb84c31e94b8b443ca84933410848f7e14889c14889d64b8b543cb04c31ea4b8b443ca04831f848f7e24831d64831ce4831f04883f02049f7e54831c2',
    0x4e5a6f0: '48ba9324499224499224',
    0x4e74b13: '48ba9324499224499224',
    0x4e75215: '48ba9324499224499224',
    0x4e5a723: 'b9d0000000',
    0x4e74b43: '48b8feffffffffffff03',
    0x4e74b62: '49c1e706',
    0x4e75248: 'b960000000',
    0x27c3f3d: 'b901000000',
    0x27c4df1: 'b901000000',
    0x27c5178: 'b901000000',
    0x4e7e750: 'c683b000000003',
    0x4e7e8ac: 'c683b000000000',
    0x4e8020f: '80beb000000000',
    0x4e80216: '7477',
    0x4e8024f: '4983fe04',
    0x4e80253: '0f846c010000',
    0x4e8028f: '48c70705000000',
}
TABLE_TARGETS = {3920676: [31895823, 31895994, 31895859, 31895895], 3920660: [31895823, 31895994, 31895859, 31895895], 8141632: [82313833, 82314027, 82313883, 82313911], 3928616: [32178181, 32178210, 32178265, 32178181], 8141616: [82313447, 82313476, 82313531, 82313447]}

def check_semantics(image):
    for va,raw in PINS.items():
        image.expect(va,raw)
    require(image.read(0x202e90,16) == b'\xff'*16, 'changed empty control group')
    require(image.read(0x207980,16) == b'\x80'*16, 'changed rehash control mask')
    require(image.relative(0x574ce10) == 0x202e90, 'changed empty map pointer')
    for base,targets in TABLE_TARGETS.items():
        got=[base+struct.unpack("<i",image.read(base+4*i,4))[0] for i in range(len(targets))]
        require(got==targets,"changed semantic branch table")

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,required=True)
    args=parser.parse_args()
    image=Image((ROOT/'artifacts/node/94/hl-node').read_bytes())
    result=outputs(image)
    args.out.mkdir(parents=True,exist_ok=True)
    for name,contents in sorted(result.items()):
        (args.out/name).write_bytes(contents.encode('ascii'))


if __name__=='__main__':
    main()
