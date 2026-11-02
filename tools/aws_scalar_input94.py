#!/usr/bin/env python3
"""Recover the selected node #94 scalar-input and type-rejection paths.

Only ELF bytes are read. This limited x86-64 walker follows reviewed encodings;
it is not a general disassembler or an emulator. Runtime calls stay boundaries.
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
from fde_extents import eh_frame_records

DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
ARTIFACT = ROOT / 'artifacts/node/94/hl-node'
FUNCTIONS = {
    0x13c1720: 'scalar_dispatch',
    0x1407ff0: 'reject_boolean',
    0x14081b0: 'reject_nil',
    0x1408460: 'reject_signed_8',
    0x1408760: 'reject_float_32',
    0x1408850: 'reject_float_64',
    0x14089b0: 'reject_signed_16',
    0x1408bb0: 'reject_signed_32',
    0x1408ca0: 'reject_signed_64',
    0x14abd30: 'expected_type_dispatch',
    0x4eb8950: 'float_dot_character_sink',
    0x4eb8970: 'float_dot_string_sink',
    0x4eb8af0: 'float_dot_nested_sink',
    0x4eb8e30: 'unexpected_value_formatter',
    0x4eb9100: 'float_value_formatter',
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
        sec = rel[0]
        require(sec['size'] % 24 == 0, 'partial RELA entry')
        for pos in range(sec['offset'], sec['offset'] + sec['size'], 24):
            slot, info, addend = struct.unpack_from('<QQq', data, pos)
            if info & 0xffffffff == 8:
                require(info >> 32 == 0, 'RELATIVE relocation has a symbol')
                require(slot not in self.relocations, 'duplicate relative relocation')
                self.relocations[slot] = (addend, pos)
        _, fs = eh_frame_records(data, self.sections)
        self.fdes = {}
        self.context_fdes = []
        for f in fs:
            if f['start'] in FUNCTIONS:
                require(f['start'] not in self.fdes, 'duplicate selected FDE')
                self.fdes[f['start']] = f
            if all(f['start'] <= site < f['end'] for site in
                   (0x13b6566, 0x13b664f, 0x13b689f)):
                self.context_fdes.append(f)
        require(set(self.fdes) == set(FUNCTIONS), 'missing selected FDE')
        require(len(self.context_fdes) == 1, 'context calls do not share one FDE')

    def offset(self, va, size=1):
        require(isinstance(va, int) and isinstance(size, int) and size > 0 and va >= 0,
                'invalid byte range')
        found = [s for s in self.sections if s['type'] != 8 and s['flags'] & 2
                 and s['address'] <= va and va + size <= s['address'] + s['size']]
        require(len(found) == 1, 'range has no unique file-backed section')
        return found[0]['offset'] + va - found[0]['address']

    def read(self, va, size):
        off = self.offset(va, size)
        return self.data[off:off + size]

    def pin(self, va, expected):
        expected = bytes.fromhex(expected)
        require(self.read(va, len(expected)) == expected, f'byte contract mismatch at {va:#x}')

    def relative(self, slot):
        require(slot in self.relocations, 'unresolved relative slot')
        return self.relocations[slot][0]


def instruction(image, va, end):
    """Length/operand decode of a closed, reviewed x86-64 encoding subset."""
    data = image.read(va, min(15, end - va))
    # Three exact compiler-emitted padding encodings in the selected sink.
    for nop in ('6666662e0f1f840000000000', '0f1f840000000000', '0f1f4000'):
        raw = bytes.fromhex(nop)
        if data.startswith(raw):
            return {'va': va, 'kind': 'nop', 'width': 0, 'opcode': 0x0f1f,
                    'size': len(raw), 'bytes': raw.hex(), 'file_offset': image.offset(va, len(raw))}
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
        elif 0x0f90 <= op <= 0x0f9f:
            modrm = True
            row.update(kind='setcc', condition=CONDITIONS[op & 15])
        elif op == 0x0f0b:
            row['kind'] = 'trap'
        elif op in (0x0f10,0x0f11,0x0f28,0x0f29,0x0f5a,0x0f6e,
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
    elif 0x50 <= op <= 0x5f:
        row['kind'] = 'push' if op < 0x58 else 'pop'
        row['register'] = REGS[(op & 7) + (8 if rex & 1 else 0)]
    elif 0xb0 <= op <= 0xbf:
        immediate = 1 if op < 0xb8 else width // 8
        row['register'] = REGS[(op & 7) + (8 if rex & 1 else 0)]
    elif op in (0xc3,0xcc,0x90):
        row['kind'] = {0xc3:'return',0xcc:'trap',0x90:'nop'}[op]
    elif op in (0x01,0x08,0x09,0x21,0x23,0x29,0x31,0x33,0x39,0x3b,0x63,0x80,0x81,
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

    if op in (0x08,0x80,0x84,0x88,0xc6) or 0xb0<=op<=0xb7 or 0x0f90<=op<=0x0f9f:
        row['width'] = 8
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


def table(image, base, count, starts):
    raw = image.read(base, 4 * count)
    out = []
    for i in range(count):
        delta = struct.unpack_from('<i',raw,4*i)[0]
        target = base + delta
        require(target in starts, f'table target is not an instruction start at {base+4*i:#x}')
        out.append({'slot':base+4*i,'index':i,'delta':delta,'target':target})
    return out


# These are reviewed unwind extents and raw-body digests, not estimates based
# on the next unwind start.  Full input identity is checked before these gates.
EXPECTED_BODIES = {
    0x13c1720: (0x13c19ad, '52b3669f46d4194b6dae6f8fc95dd934bf977823e9915db788b9e56ff18754e9'),
    0x1407ff0: (0x140805e, '26bf343a01ef0b851216c8c9617367053b4b9cd3ac1f7a317934424376fa7e72'),
    0x14081b0: (0x1408219, '07289d95d02b00f78199f44be50b3c5b3fbe57f439758606d40196cb9cb3c29a'),
    0x1408460: (0x14084d2, 'e6a5d5a78ba39cbf1a729b856decf7f58f7e2888e342af8f60ead57e5900053b'),
    0x1408760: (0x14087d3, '0ed566d114103564854249563107ab9f0679dc638b2991494bfdd1baee9b687f'),
    0x1408850: (0x14088bf, '8b98433933eac4f10cbd4a756ee10bcca78f6e38a807a0cf7ca0bc54a1ebef05'),
    0x14089b0: (0x1408a22, '5895956729f53a2906cdb1a99c5544582ed49eb530707a23ebb25c2c6eeeb8c1'),
    0x1408bb0: (0x1408c21, '21c907444c78062a45ade414ef58bd0b70bdbe59ffd1ed9323fe4812feb71988'),
    0x1408ca0: (0x1408d0e, '72792c019049693f23a87c17bdf44d1675b29a29441455eb920b5d80c3c56975'),
    0x14abd30: (0x14abd40, '73a266c7c8ee86fa2addcc6aa746ed789ec1220b78c9de8360c56c6bd74aabbe'),
    0x4eb8950: (0x4eb8969, '21f32a18386889b6563cbcd781e9cc932d5fb5921ec5da043cb23e94a4f8f995'),
    0x4eb8970: (0x4eb8a6a, 'a9c2b6998db3b9c4538e05d849b670ae0f79358e9766f359f41de61ef7ecdd8b'),
    0x4eb8af0: (0x4eb8b03, '5411a156ca3671898965a58df8356f71ea9b77ae5a8960dd3772f40c027c73c8'),
    0x4eb8e30: (0x4eb90f1, '980e975e64b8a4dee27ddf2db2004f5e22d0f19f7288c1e7a8cf1bad75552282'),
    0x4eb9100: (0x4eb91bc, '603ee6e4ef4c5912dac5c398368b19c8c488f919f8a357cff8c554f8dbedb579'),
}

# target basic blocks are independently checked even when they are valid
# instruction starts: a retargeted slot must not silently change a route.
ARMS = {
    0xc0: (0x13c196a, 'nil'),
    0xc2: (0x13c1954, 'false'),
    0xc3: (0x13c1958, 'true'),
    0xca: (0x13c1741, 'float32'),
    0xcb: (0x13c17b5, 'float64'),
    0xcc: (0x13c1866, 'unsigned8'),
    0xcd: (0x13c1848, 'unsigned16'),
    0xce: (0x13c17ef, 'unsigned32'),
    0xcf: (0x13c1793, 'unsigned64'),
    0xd0: (0x13c1817, 'signed8'),
    0xd1: (0x13c18c9, 'signed16'),
    0xd2: (0x13c1898, 'signed32'),
    0xd3: (0x13c18fd, 'signed64'),
    0xe0: (0x13c1977, 'signed_payload'),
}
DEFER = 0x13c1785
NUMERIC_BOUNDARY = 0x13f6dc0
ERROR_BOUNDARY = 0x13b5360
SELECTOR = 0x215a1c

# (guard address, encoded width, short-input branch, complete-input call).
# One-byte loads use a zero-length test rather than a compare-immediate.
READS = {
    0xca: (0x13c1749, 4, 0x13c174d, 0x13c176e),
    0xcb: (0x13c17bd, 8, 0x13c17c1, 0x13c17e5),
    0xcc: (0x13c186a, 1, 0x13c186d, 0x13c188e),
    0xcd: (0x13c1850, 2, 0x13c1854, 0x13c194a),
    0xce: (0x13c17f7, 4, 0x13c17fb, 0x13c188e),
    0xcf: (0x13c179b, 8, 0x13c179f, 0x13c188e),
    0xd0: (0x13c181b, 1, 0x13c181e, 0x13c183e),
    0xd1: (0x13c18d1, 2, 0x13c18d5, 0x13c18f3),
    0xd2: (0x13c18a0, 4, 0x13c18a4, 0x13c18bf),
    0xd3: (0x13c1905, 8, 0x13c1909, 0x13c19a3),
}
CALLS = {
    0x13c176e: 0x1408760, 0x13c17e5: 0x1408850,
    0x13c183e: 0x1408460, 0x13c188e: NUMERIC_BOUNDARY,
    0x13c18bf: 0x1408bb0, 0x13c18f3: 0x14089b0,
    0x13c194a: NUMERIC_BOUNDARY, 0x13c1960: 0x1407ff0,
    0x13c196d: 0x14081b0, 0x13c197d: 0x1408460,
    0x13c19a3: 0x1408ca0,
}

# The named byte sequences are the operations on which the model depends.
# Their VAs, bytes, and all decoded transfers are emitted as evidence.
PINS = {
    0x13c1721: ('normalized selector', '440fb6c2418d8040ffffff83f8207747'),
    0x13c1778: ('zero selector and defer', '4585c075080fb6f1e9c2010000c60702885701884f02'),
    0x13c1757: ('float32 big endian', '8b104883c0040fca4889461048894e18'),
    0x13c17cb: ('float64 big endian', '488b10480fca4883c0084889461048894e18'),
    0x13c17a9: ('unsigned64 big endian', '488b014883c108480fc8'),
    0x13c1805: ('unsigned32 big endian', '8b014883c1040fc848894e1048895618'),
    0x13c1828: ('signed8 cursor', '48ffc90fb60248ffc24889561048894e18'),
    0x13c1877: ('unsigned8 cursor', '48ffc90fb60248ffc24889561048894e18'),
    0x13c18aa: ('signed32 big endian', '8b014883c1040fc848894e1048895618'),
    0x13c18db: ('signed16 big endian', '0fb7014883c10266c1c00848894e1048895618'),
    0x13c1931: ('unsigned16 big endian', '0fb71066c1c2084883c0024889461048894e18'),
    0x13c198b: ('signed64 big endian', '488b014883c108480fc848894e1048895618'),
    0x13c185a: ('short input end pointer A', '4801c848894610e9ac000000'),
    0x13c190b: ('short input end pointer B', '4801d148894e10'),
    0x13c1912: ('short input result', '48c7461800000000c60701488d05d44f2a0448894708'),
    0x13c1954: ('boolean selectors', '31c0eb02b0010fb6f0'),
    0x13c1977: ('signed payload', '0fb6f14889fb'),
    0x1407ff8: ('store boolean payload', '4088742439c644243800'),
    0x1408468: ('sign extend byte', '480fbec64889442440c644243802'),
    0x1408768: ('widen float32', 'f30f5ac0f20f11442440c644243803'),
    0x1408858: ('store float64', 'f20f11442440c644243803'),
    0x14089b8: ('sign extend word', '480fbfc64889442440c644243802'),
    0x1408bb8: ('sign extend dword', '4863c64889442440c644243802'),
    0x1408ca8: ('store signed qword', '4889742440c644243802'),
    0x14abd30: ('expected type dynamic dispatch', '488b07488b4f08488b49184889c7ffe1'),
    0x4eb8950: ('character dot flag', '83fe2e0f94c0084708'),
    0x4eb8959: ('character writer tail transfer', '488b07488b38488b4008488b4020ffe0'),
    0x4eb8973: ('string short length', '4883fa0f772e4885d2'),
    0x4eb8990: ('short byte compare', '803c062e'),
    0x4eb89a7: ('alignment prefix', '488d46074883e0f84829f0'),
    0x4eb89ed: ('first word filter', '4929de4d09de'),
    0x4eb89fe: ('second word filter', '4c29db4c09db'),
    0x4eb89e0: ('complete word filter', '4c8b1c064c89db4c31cb4d89d64929de4d09de4c8b5c06084d31cb4c89d34c29db4c09db4d21c64921de4d39c6753a'),
    0x4eb8a20: ('alignment byte compare', '803c0e2e'),
    0x4eb8a40: ('tail byte compare', '803c062e'),
    0x4eb8a4e: ('dot flag merge', '31c0eb02b001084708'),
    0x4eb8a57: ('string writer tail transfer', '488b07488b38488b4008488b40185b415effe0'),
    0x4eb8e34: ('unexpected kind dispatch', '0fb607488d0d760591fb486304814801c8ffe0'),
    0x4eb8e47: ('boolean payload to formatter', '0fb6470188442418'),
    0x4eb8f4f: ('integer payload to formatter', '488b47084889442418'),
    0x4eb8f8b: ('float payload to formatter', 'f20f104708f20f11442418'),
    0x4eb8fca: ('unit value sink', '488b3e488b4608488b4018488d358f0491fbba0a000000'),
    0x4eb9105: ('float finite magnitude', '48b8ffffffffffffff7f48230748b9000000000000f07f4839c87c2d'),
    0x4eb9187: ('primary format failure', '84c07408b001'),
    0x4eb9193: ('dot flag and suffix decision', '807c241800751a'),
    0x4eb91a8: ('suffix and return decisions', 'ba02000000ff501884c075d731c0'),
}

GUARD_EDGES = {
    0xca: ('b', 0x13c185a), 0xcb: ('b', 0x13c185a),
    0xcc: ('e', 0x13c191a), 0xcd: ('ae', 0x13c192d),
    0xce: ('b', 0x13c190b), 0xcf: ('b', 0x13c190b),
    0xd0: ('e', 0x13c191a), 0xd1: ('b', 0x13c190b),
    0xd2: ('b', 0x13c190b), 0xd3: ('ae', 0x13c1987),
}
VISITOR_TAGS = {
    0x1407ff0: 0, 0x14081b0: 7, 0x1408460: 2, 0x1408760: 3,
    0x1408850: 3, 0x14089b0: 2, 0x1408bb0: 2, 0x1408ca0: 2,
}
EXPECTED_RELOCS = {
    0x576e7a0: 0x13c1720,  # contextual caller's scalar function slot
    0x5668e90: 0x1401120,  # expected-type formatting callback
    0x576e758: 0x4eb8e30,  # unexpected-type formatter
    0x56668f8: 0x216949,  # short-input error slice
    0x5750f90: 0x4eb8970,  # string writer
    0x5750f98: 0x4eb8950,  # character writer
    0x5750fa0: 0x4eb8af0,  # nested-format writer
    0x576e008: 0x1571d90,  # shared format controller, boundary
    0x576e9d0: 0x1570740,  # signed integer formatting, boundary
    0x576ea18: 0x1571d50,  # ordinary float formatting, boundary
    0x576f218: 0x156fff0,  # boolean formatting, boundary
    0x5777088: 0x4eb9100,  # float value callback
}
CONTEXT_CALLS = {
    0x13b6566: (6, 'indirect_call', 0x576e7a0),
    0x13b664f: (5, 'call', 0x13f4360),
    0x13b689f: (5, 'call', 0x13f6410),
}


def analyze(image, body_gates=True):
    """Read the selected FDEs, reviewed branch contracts, data and call edges."""
    functions, instructions, groups = [], [], {}
    for start, label in sorted(FUNCTIONS.items()):
        fde = image.fdes[start]
        expected_end, expected_hash = EXPECTED_BODIES[start]
        require(fde['end'] == expected_end, 'selected FDE end changed')
        raw = image.read(start, fde['end'] - start)
        digest = hashlib.sha256(raw).hexdigest()
        if body_gates:
            require(digest == expected_hash, 'selected function bytes changed')
        rows = walk(image, start)
        groups[start] = rows
        instructions.extend(dict(row, owner=start) for row in rows)
        functions.append({**fde, 'label': label, 'file_offset': image.offset(start, len(raw)),
                          'byte_count': len(raw), 'body_sha256': digest,
                          'instruction_count': len(rows)})

    by_va = {row['va']: row for row in instructions}
    require(len(by_va) == len(instructions), 'overlapping selected instruction addresses')
    for va, (label, raw) in sorted(PINS.items()):
        image.pin(va, raw)
        require(va in by_va, f'contract {label} is not on a decoded instruction')
    require(by_va[0x13c172f]['condition'] == 'a' and
            by_va[0x13c172f]['target'] == 0x13c1778, 'selector guard changed')
    require(by_va[0x13c1731].get('rip_target') == SELECTOR, 'selector base changed')

    slots = table(image, SELECTOR, 33, {r['va'] for r in groups[0x13c1720]})
    for row in slots:
        code = row['index'] + 0xc0
        expected, label = ARMS.get(code, (DEFER, 'deferred'))
        require(row['target'] == expected, f'scalar selector {code:#x} redirected')
        row.update(code=code, role=label, file_offset=image.offset(row['slot'], 4))

    widths = {}
    for code, (guard, expected_width, branch, call) in sorted(READS.items()):
        r = by_va[guard]
        if expected_width == 1:
            require(r['opcode'] == 0x85, 'single-byte zero-length guard changed')
        else:
            require(r['opcode'] == 0x83 and (r['modrm'] >> 3) & 7 == 7 and
                    r['immediate'] == expected_width, 'fixed-width guard changed')
        br = by_va[branch]
        condition, target = GUARD_EDGES[code]
        require(br['kind'] == 'branch' and br['condition'] == condition and
                br['target'] == target, 'length-guard branch changed')
        require(by_va[call]['kind'] == 'call' and by_va[call]['target'] == CALLS[call],
                'complete-input call changed')
        widths[code] = {'width': expected_width, 'guard': guard, 'branch': branch,
                        'condition': condition, 'branch_target': target, 'call': call,
                        'call_target': by_va[call]['target']}
    for va, target in CALLS.items():
        row = by_va[va]
        require(row['kind'] == 'call' and row['target'] == target, 'scalar call changed')

    visitors = []
    for start, expected_tag in sorted(VISITOR_TAGS.items()):
        rows = groups[start]
        tags = [r for r in rows if r['opcode'] == 0xc6 and
                r.get('memory') == {'base': 'rsp', 'index': None, 'scale': 1, 'disp': 0x38}]
        require(len(tags) == 1 and tags[0]['immediate'] == expected_tag,
                'unexpected-type descriptor tag changed')
        refs = {r['rip_target'] for r in rows if 'rip_target' in r}
        require({0x5668e78, 0x576e758, 0x14abd30, 0x20193e} <= refs,
                'visitor descriptor or template reference changed')
        calls = [r for r in rows if r['kind'] == 'call']
        require(len(calls) == 1 and calls[0]['target'] == ERROR_BOUNDARY,
                'visitor error constructor changed')
        visitors.append({'start': start, 'role': FUNCTIONS[start], 'tag_site': tags[0]['va'],
                         'unexpected_kind': tags[0]['immediate'], 'call_site': calls[0]['va'],
                         'constructor': calls[0]['target'], 'expected_vtable': 0x5668e78,
                         'unexpected_formatter_slot': 0x576e758, 'template': 0x20193e})

    relocations = []
    for slot, target in sorted(EXPECTED_RELOCS.items()):
        require(image.relative(slot) == target, 'RELATIVE addend changed')
        addend, file_offset = image.relocations[slot]
        relocations.append({'slot': slot, 'rela_file_offset': file_offset,
                            'type': 8, 'addend': addend})
    error_length = struct.unpack('<Q', image.read(0x5666900, 8))[0]
    error_bytes = image.read(image.relative(0x56668f8), error_length)
    require(error_bytes == b'failed to fill whole buffer', 'short-input error slice changed')
    template_bytes = image.read(0x20193e, 30)
    require(template_bytes == b'\x0einvalid type: \xc0\x0b, expected \xc0\x00',
            'invalid-type template changed')
    require(image.read(0x264f73, 18) == b'variant identifier',
            'expected-type text changed')

    # Only the four kind tags emitted by the selected visitors are studied.
    # The surrounding jump table has no local bounds check; its full domain is
    # not inferred from adjacent bytes.
    format_base = 0x7c93b4
    format_starts = {row['va'] for row in groups[0x4eb8e30]}
    require(by_va[0x4eb8e37].get('rip_target') == format_base,
            'unexpected-value table base changed')
    format_expected = {0: 0x4eb8e47, 2: 0x4eb8f4f, 3: 0x4eb8f8b, 7: 0x4eb8fca}
    formats = []
    for tag, expected in sorted(format_expected.items()):
        slot = format_base + 4 * tag
        displacement = struct.unpack('<i', image.read(slot, 4))[0]
        target = format_base + displacement
        require(target in format_starts and target == expected, 'unexpected-kind arm changed')
        formats.append({'tag': tag, 'slot': slot, 'file_offset': image.offset(slot, 4),
                        'displacement': displacement, 'target': target})
    template_specs = (
        ('boolean', 0x4eb8e6c, 0x1e5964, b'\x09boolean `\xc0\x01`\x00'),
        ('integer', 0x4eb900d, 0x1fd933, b'\x09integer `\xc0\x01`\x00'),
        ('floating', 0x4eb8fb3, 0x1ddd32, b'\x10floating point `\xc0\x01`\x00'),
        ('unit', 0x4eb8fd5, 0x7c946b, b'unit value'),
        ('float_suffix', 0x4eb91a1, 0x7c94c8, b'.0'),
    )
    templates = []
    for label, site, va, expected in template_specs:
        require(by_va[site].get('rip_target') == va, f'{label} pointer changed')
        raw = image.read(va, len(expected))
        require(raw == expected, f'{label} template or slice changed')
        templates.append({'role': label, 'site': site, 'va': va, 'file_offset': image.offset(va, len(raw)),
                          'length': len(raw), 'bytes': raw.hex()})
    require(by_va[0x4eb8fdc].get('immediate') == 10 and
            by_va[0x4eb91a8].get('immediate') == 2, 'length-delimited sink size changed')
    for site, slot in ((0x4eb8e59, 0x576f218), (0x4eb8f62, 0x576e9d0),
                       (0x4eb8fa0, 0x5777088)):
        require(by_va[site].get('rip_target') == slot, 'value-format callback slot changed')
    require(by_va[0x4eb8f69]['kind'] == 'jump' and by_va[0x4eb8f69]['target'] == 0x4eb9001,
            'signed-integer template join changed')
    require(by_va[0x4eb911f]['condition'] == 'l' and by_va[0x4eb911f]['target'] == 0x4eb914e,
            'finite-value branch changed')
    require(by_va[0x4eb916b].get('rip_target') == 0x5750f78 and
            by_va[0x4eb8af6].get('rip_target') == 0x5750f78 and
            by_va[0x4eb8afd]['kind'] == 'indirect_jump' and
            by_va[0x4eb8afd].get('rip_target') == 0x576e008,
            'dot-writer vtable or nested transfer changed')
    word_constants = {'high': by_va[0x4eb89ba]['immediate'],
                      'pattern': by_va[0x4eb89c4]['immediate'],
                      'subtract': by_va[0x4eb89ce]['immediate']}
    require(word_constants == {'high': 0x8080808080808080, 'pattern': 0x2e2e2e2e2e2e2e2e,
                               'subtract': 0x0101010101010100}, 'dot scan constants changed')
    period = by_va[0x4eb8950]['immediate']
    short_max = by_va[0x4eb8973]['immediate']
    require(period == 0x2e and short_max == 15 and all(
        by_va[va]['immediate'] == period for va in (0x4eb8990, 0x4eb8a20, 0x4eb8a40)),
        'dot byte or short-string threshold changed')
    float_constants = {'magnitude_mask': by_va[0x4eb9105]['immediate'],
                       'nonfinite_threshold': by_va[0x4eb9112]['immediate']}
    require(float_constants == {'magnitude_mask': 0x7fffffffffffffff,
                                'nonfinite_threshold': 0x7ff0000000000000},
            'float magnitude threshold changed')

    # The already-indexed caller is context only. Decode just these call
    # instructions; its FDE and body are not selected by this packet.
    require(len(image.context_fdes) == 1 and
            image.context_fdes[0]['start'] == 0x13b6530 and
            image.context_fdes[0]['end'] == 0x13b6c50,
            'context caller FDE changed')
    context = []
    for va, (size, kind, target) in sorted(CONTEXT_CALLS.items()):
        row = instruction(image, va, va + size)
        actual = row.get('rip_target') if kind == 'indirect_call' else row.get('target')
        require(row['size'] == size and row['kind'] == kind and actual == target,
                'context handoff changed')
        context.append({'va': va, 'file_offset': row['file_offset'], 'bytes': row['bytes'],
                        'kind': kind, 'target_or_slot': target})

    return {'functions': functions, 'instructions': instructions, 'slots': slots,
            'widths': widths, 'visitors': visitors, 'relocations': relocations,
            'context': context, 'error_bytes': error_bytes, 'template_bytes': template_bytes,
            'format_slots': formats, 'format_templates': templates, 'word_constants': word_constants,
            'period': period, 'short_max': short_max, 'float_constants': float_constants}


def selector_route(record, code):
    """Classify the input byte to this function, without assuming caller reachability."""
    require(type(code) is int and 0 <= code <= 255, 'selector byte outside range')
    if code == 0:
        return 0x13c177d, 'unsigned_payload'
    if 0xc0 <= code <= 0xe0:
        row = record['slots'][code - 0xc0]
        return row['target'], row['role']
    return DEFER, 'deferred'


def dot_scan(record, data, alignment):
    """Model the reviewed period-byte search; memory is assumed valid."""
    require(isinstance(data, bytes), 'dot-scan input must be bytes')
    require(type(alignment) is int and 0 <= alignment < 8, 'alignment outside byte domain')
    length = len(data)
    period = record['period']
    if length <= record['short_max']:
        return {'found': period in data, 'prefix': 0, 'skipped_blocks': 0,
                'word_fallback': False}
    prefix = (-alignment) & 7
    if period in data[:prefix]:
        return {'found': True, 'prefix': prefix, 'skipped_blocks': 0, 'word_fallback': False}
    constants = record['word_constants']
    high, pattern, subtract = constants['high'], constants['pattern'], constants['subtract']
    limit, index, skipped, fallback = (1 << 64) - 1, prefix, 0, False
    while index <= length - 16:
        first = int.from_bytes(data[index:index + 8], 'little')
        second = int.from_bytes(data[index + 8:index + 16], 'little')
        first_xor, second_xor = first ^ pattern, second ^ pattern
        a = ((subtract - first_xor) & limit) | first
        b = ((subtract - second_xor) & limit) | second_xor
        if (a & b & high) != high:
            fallback = True
            break
        skipped += 1
        index += 16
    return {'found': period in data[index:], 'prefix': prefix, 'skipped_blocks': skipped,
            'word_fallback': fallback}


def dot_flag(previous, found):
    require(type(previous) is int and 0 <= previous <= 255, 'prior dot flag outside byte range')
    require(type(found) is bool, 'dot detection must be boolean')
    return previous | int(found)


def character_flag(record, previous, scalar):
    require(type(scalar) is int and 0 <= scalar < 1 << 32, 'character value outside register range')
    return dot_flag(previous, scalar == record['period'])


def float_finish(record, bits, primary_status, dot_flag, suffix_status):
    """Model only the float wrapper's local branches around external writes."""
    require(type(bits) is int and 0 <= bits < 1 << 64, 'binary64 bits outside range')
    for name, value in (('primary', primary_status), ('flag', dot_flag), ('suffix', suffix_status)):
        require(type(value) is int and 0 <= value <= 255, f'{name} byte outside range')
    magnitude = bits & record['float_constants']['magnitude_mask']
    if magnitude >= record['float_constants']['nonfinite_threshold']:
        return {'class': 'nonfinite', 'suffix_call': False, 'return_byte': primary_status}
    if primary_status:
        return {'class': 'finite', 'suffix_call': False, 'return_byte': 1}
    if dot_flag:
        return {'class': 'finite', 'suffix_call': False, 'return_byte': 0}
    return {'class': 'finite', 'suffix_call': True, 'return_byte': int(suffix_status != 0)}


def dot_cases(record):
    rows = []
    lengths = (0, 1, 7, 8, 14, 15, 16, 17, 23, 24, 31, 32, 33, 47, 48, 49, 63, 64, 65)
    for n in lengths:
        for align in range(8):
            positions = sorted({-1, *({0, n // 2, n - 1} if n else set())})
            for pos in positions:
                data = bytearray(b'7' * n)
                if pos >= 0:
                    data[pos] = 0x2e
                outcome = dot_scan(record, bytes(data), align)
                rows.append({'length': n, 'alignment': align, 'dot_position': pos, **outcome})
    return rows


def float_cases(record):
    samples = (
        ('positive_zero', 0x0000000000000000), ('negative_zero', 0x8000000000000000),
        ('smallest_subnormal', 0x0000000000000001), ('largest_finite', 0x7fefffffffffffff),
        ('negative_largest_finite', 0xffefffffffffffff), ('positive_infinity', 0x7ff0000000000000),
        ('negative_infinity', 0xfff0000000000000), ('quiet_nan', 0x7ff8000000001234),
        ('signaling_nan', 0x7ff0000000000001),
    )
    rows = []
    for label, bits in samples:
        for primary in (0, 1):
            for flag in (0, 1):
                for suffix in (0, 1):
                    row = float_finish(record, bits, primary, flag, suffix)
                    rows.append({'sample': label, 'bits': f'{bits:016x}',
                                 'primary_status': primary, 'dot_flag': flag,
                                 'suffix_status': suffix, **row})
    return rows


def flag_cases(record):
    rows = []
    for initial in (0, 1, 2, 128, 255):
        for scalar in (0, 0x2e, 0x12e, 0xffffffff):
            rows.append({'kind': 'character', 'initial': initial, 'input': hx(scalar),
                         'result': character_flag(record, initial, scalar)})
        for data in (b'', b'123', b'1.2', b'1e2'):
            found = dot_scan(record, data, 0)['found']
            rows.append({'kind': 'string', 'initial': initial, 'input': data.hex(),
                         'result': dot_flag(initial, found)})
    return rows


def model(record, code, payload, remaining):
    """Conditional transfer model, not execution or emulation of the target."""
    require(type(payload) is int and 0 <= payload <= 255, 'payload byte outside range')
    require(isinstance(remaining, bytes), 'remaining input must be bytes')
    target, role = selector_route(record, code)
    result = {'selector': code, 'payload': payload, 'available': len(remaining),
              'arm': target, 'role': role, 'consumed': 0, 'remaining': len(remaining),
              'result_tag': None, 'boundary': '', 'value': '', 'raw_payload': ''}
    if role == 'deferred':
        result.update(result_tag=2, value=f'{code:02x}{payload:02x}')
        return result
    if role == 'unsigned_payload':
        result.update(boundary='unsigned_visitor', value=str(payload))
        return result
    if role in ('nil', 'false', 'true', 'signed_payload'):
        result['boundary'] = 'error_constructor'
        if role == 'signed_payload':
            result['value'] = str(payload if payload < 128 else payload - 256)
        elif role in ('false', 'true'):
            result['value'] = '0' if role == 'false' else '1'
        return result
    require(code in record['widths'], 'selected arm lacks a width contract')
    width = record['widths'][code]['width']
    consumed = min(width, len(remaining))
    result.update(consumed=consumed, remaining=len(remaining) - consumed,
                  raw_payload=remaining[:consumed].hex())
    if len(remaining) < width:
        result.update(result_tag=1, boundary='short_input')
        return result
    raw = remaining[:width]
    if role.startswith('unsigned'):
        result.update(boundary='unsigned_visitor', value=str(int.from_bytes(raw, 'big')))
    elif role.startswith('signed'):
        result.update(boundary='error_constructor', value=str(int.from_bytes(raw, 'big', signed=True)))
    elif role.startswith('float'):
        # Retain the input bits. In particular, do not predict a NaN payload
        # after the target's float32-to-float64 conversion.
        result.update(boundary='error_constructor', value=raw.hex())
    else:
        raise ValueError('unrecognized scalar role')
    return result


def model_cases(record):
    cases = []
    def add(group, code, payload, data):
        row = model(record, code, payload, data)
        row.update(group=group, input_hex=data.hex())
        cases.append(row)
    # The first group enumerates the whole input-byte domain at this function's
    # boundary, including bytes whose reachability from its caller is unknown.
    for code in range(256):
        add('selector_domain', code, 0x20, b'')
    for code, item in sorted(record['widths'].items()):
        width = item['width']
        for n in sorted({0, 1, max(0, width - 1), width, width + 1}):
            add('length_boundary', code, 0x20, bytes(range(1, n + 1)))
    for value in (0, 1, 31, 32, 33, 74, 75, 76, 127, 128, 255):
        add('unsigned_payload', 0, value, b'')
        for code, width in ((0xcc, 1), (0xcd, 2), (0xce, 4), (0xcf, 8)):
            add('unsigned_width', code, 0, value.to_bytes(width, 'big'))
    for code, width in ((0xcc, 1), (0xcd, 2), (0xce, 4), (0xcf, 8)):
        limit = (1 << (8 * width)) - 1
        for value in (limit - 1, limit):
            add('unsigned_width_limit', code, 0, value.to_bytes(width, 'big'))
    for code, width in ((0xd0, 1), (0xd1, 2), (0xd2, 4), (0xd3, 8)):
        for value in (-1, 0, 1, 32, 75, 76, 127):
            add('signed_width', code, 0, value.to_bytes(width, 'big', signed=True))
        lo, hi = -(1 << (8 * width - 1)), (1 << (8 * width - 1)) - 1
        for value in (lo, lo + 1, hi - 1, hi):
            add('signed_width_limit', code, 0, value.to_bytes(width, 'big', signed=True))
    for payload in (0x20, 0x7f, 0x80, 0xe0, 0xff):
        add('signed_payload', 0xe0, payload, b'')
    for code, data in ((0xca, bytes.fromhex('00000000')), (0xca, bytes.fromhex('7f800000')),
                       (0xca, bytes.fromhex('7fc01234')), (0xcb, bytes.fromhex('0000000000000000')),
                       (0xcb, bytes.fromhex('7ff0000000000000')),
                       (0xcb, bytes.fromhex('7ff8000000001234'))):
        add('float_raw_bits', code, 0, data)
    return cases


def tsv(columns, rows):
    buf = io.StringIO(newline='')
    writer = csv.DictWriter(buf, fieldnames=columns, delimiter='\t', lineterminator='\n',
                            extrasaction='ignore')
    writer.writeheader()
    for row in rows:
        writer.writerow({k: '' if row.get(k) is None else row.get(k, '') for k in columns})
    return buf.getvalue().encode('utf-8')


def hx(value):
    return '' if value is None else hex(value)


def output_files(image):
    r = analyze(image)
    functions = []
    for f in r['functions']:
        functions.append({'role': f['label'], 'start_va': hx(f['start']), 'end_va': hx(f['end']),
                          'fde_va': hx(f['fde']), 'cie_va': hx(f['cie']),
                          'lsda_va': hx(f['lsda']), 'file_offset': hx(f['file_offset']),
                          'body_bytes': f['byte_count'], 'instructions': f['instruction_count'],
                          'sha256': f['body_sha256']})
    instructions, branches = [], []
    for row in r['instructions']:
        mem = row.get('memory', {})
        item = {'owner_va': hx(row['owner']), 'va': hx(row['va']),
                'file_offset': hx(row['file_offset']), 'size': row['size'],
                'bytes': row['bytes'], 'opcode': hx(row['opcode']), 'kind': row['kind'],
                'condition': row.get('condition', ''), 'target_va': hx(row.get('target')),
                'rip_target_va': hx(row.get('rip_target')), 'memory_base': mem.get('base', ''),
                'memory_index': mem.get('index', ''), 'memory_scale': mem.get('scale', ''),
                'memory_disp': mem.get('disp', ''), 'immediate_raw': hx(row.get('immediate'))}
        instructions.append(item)
        if row['kind'] in ('branch', 'jump'):
            branches.append(item)
    slots = [{'code': hx(x['code']), 'slot_va': hx(x['slot']), 'file_offset': hx(x['file_offset']),
              'displacement': x['delta'], 'target_va': hx(x['target']), 'role': x['role']}
             for x in r['slots']]
    guards = []
    for code, item in sorted(r['widths'].items()):
        guards.append({'code': hx(code), 'role': ARMS[code][1], 'width': item['width'],
                       'guard_va': hx(item['guard']), 'branch_va': hx(item['branch']),
                       'condition': item['condition'], 'branch_target': hx(item['branch_target']),
                       'call_va': hx(item['call']), 'complete_call_target': hx(item['call_target'])})
    visitors = []
    for row in r['visitors']:
        visitors.append({k: hx(v) if k in ('start', 'tag_site', 'call_site', 'constructor',
                                           'expected_vtable', 'unexpected_formatter_slot', 'template')
                         else v for k, v in row.items()})
    calls = []
    for row in r['instructions']:
        if row['kind'] in ('call', 'indirect_call'):
            calls.append({'owner_va': hx(row['owner']), 'site_va': hx(row['va']),
                          'bytes': row['bytes'], 'kind': row['kind'],
                          'target_or_slot': hx(row.get('target', row.get('rip_target'))),
                          'selected_target': int(row.get('target') in FUNCTIONS)})
    examples = model_cases(r)
    case_rows = [{**row, 'selector': hx(row['selector']), 'payload': hx(row['payload']),
                  'arm': hx(row['arm']), 'result_tag': hx(row['result_tag'])} for row in examples]
    relocs = [{k: hx(v) if k in ('slot', 'rela_file_offset', 'addend') else v
               for k, v in row.items()} for row in r['relocations']]
    context = [{k: hx(v) if k in ('va', 'file_offset', 'target_or_slot') else v
                for k, v in row.items()} for row in r['context']]
    contracts = [{'name': label, 'va': hx(va), 'file_offset': hx(image.offset(va, len(bytes.fromhex(raw)))),
                  'bytes': image.read(va, len(bytes.fromhex(raw))).hex()}
                 for va, (label, raw) in sorted(PINS.items())]
    by_va = {row['va']: row for row in r['instructions']}
    flow_sites = (
        ('unsigned_small_to_numeric', 0x13c188e), ('unsigned_payload_to_numeric', 0x13c194a),
        ('signed8_to_visitor', 0x13c183e), ('signed_visitor_value_formatter', 0x1408496),
        ('signed_visitor_constructor', 0x14084c4), ('signed_value_callback', 0x4eb8f62),
        ('signed_value_template', 0x4eb900d), ('boolean_to_visitor', 0x13c1960),
        ('unit_to_visitor', 0x13c196d),
        ('float32_to_visitor', 0x13c176e), ('float64_to_visitor', 0x13c17e5),
        ('visitor_expected_descriptor', 0x1408781), ('visitor_value_formatter', 0x1408797),
        ('visitor_expected_adapter', 0x14087ad), ('visitor_template', 0x14087b9),
        ('visitor_constructor', 0x14087c5), ('value_float_callback', 0x4eb8fa0),
        ('value_float_template', 0x4eb8fb3), ('float_dot_writer_vtable', 0x4eb916b),
        ('character_flag_update', 0x4eb8956), ('character_writer_tail', 0x4eb8967),
        ('string_flag_update', 0x4eb8a54), ('string_writer_tail', 0x4eb8a68),
        ('float_suffix', 0x4eb91a1), ('float_suffix_sink', 0x4eb91ad),
        ('nested_writer_vtable', 0x4eb8af6), ('nested_format_controller', 0x4eb8afd),
    )
    flow = []
    for label, site in flow_sites:
        row = by_va[site]
        target = row.get('target', row.get('rip_target'))
        flow.append({'role': label, 'site_va': hx(site), 'bytes': row['bytes'], 'kind': row['kind'],
                     'target_or_slot': hx(target),
                     'relative_addend': hx(image.relocations[target][0]) if target in image.relocations else ''})
    fmt_slots = [{k: hx(v) if k in ('slot', 'file_offset', 'target') else v
                  for k, v in row.items()} for row in r['format_slots']]
    templates = [{k: hx(v) if k in ('site', 'va', 'file_offset') else v
                  for k, v in row.items()} for row in r['format_templates']]
    dot_rows = dot_cases(r)
    float_rows = float_cases(r)
    flag_rows = flag_cases(r)
    route_counts = {}
    for code in range(256):
        role = selector_route(r, code)[1]
        route_counts[role] = route_counts.get(role, 0) + 1
    summary = {
        'target_sha256': DIGEST,
        'coordinate_system': 'linked ELF virtual address; file offsets separately reported',
        'selected_fde_count': len(functions),
        'selected_body_bytes': sum(f['byte_count'] for f in r['functions']),
        'instruction_count': len(instructions),
        'direct_branch_and_jump_count': len(branches),
        'selected_call_count': len(calls),
        'selector_slots': len(slots),
        'selector_byte_domain': sum(route_counts.values()),
        'selector_roles': dict(sorted(route_counts.items())),
        'width_guards': len(guards),
        'rejection_visitors': len(visitors),
        'relocation_records': len(relocs),
        'context_call_sites': len(context),
        'selected_flow_witnesses': len(flow),
        'byte_contracts': len(contracts),
        'synthetic_cases': len(case_rows),
        'selected_format_kind_slots': len(fmt_slots),
        'complete_format_entries_and_slices': len(templates),
        'synthetic_dot_cases': len(dot_rows),
        'synthetic_float_cases': len(float_rows),
        'synthetic_flag_cases': len(flag_rows),
        'dot_scan_constants': {k: hx(v) for k, v in sorted(r['word_constants'].items())},
        'float_constants': {k: hx(v) for k, v in sorted(r['float_constants'].items())},
        'dot_byte': hx(r['period']),
        'dot_scalar_max_length': r['short_max'],
        'short_input_error': {'slot_va': hx(0x56668f8), 'length': len(r['error_bytes']),
                              'text_va': hx(image.relative(0x56668f8)),
                              'bytes_hex': r['error_bytes'].hex()},
        'invalid_type_template': {'va': hx(0x20193e), 'bytes_hex': r['template_bytes'].hex()},
        'expected_identifier': {'va': hx(0x264f73), 'bytes_hex': image.read(0x264f73, 18).hex()},
        'limitations': ('Selector inputs and synthetic cases are conditional models, not target execution. '
                        'The caller, unsigned visitor, shared error constructor and final sinks remain boundaries. '
                        'FDE extents do not prove source-level ownership or a complete function census.'),
    }
    json_bytes = lambda obj: (json.dumps(obj, sort_keys=True, indent=2) + '\n').encode('utf-8')
    return {
        'functions.tsv': tsv(['role','start_va','end_va','fde_va','cie_va','lsda_va','file_offset',
                              'body_bytes','instructions','sha256'], functions),
        'instructions.tsv': tsv(['owner_va','va','file_offset','size','bytes','opcode','kind',
                                 'condition','target_va','rip_target_va','memory_base','memory_index',
                                 'memory_scale','memory_disp','immediate_raw'], instructions),
        'branches.tsv': tsv(['owner_va','va','file_offset','size','bytes','kind','condition','target_va'], branches),
        'dispatch.tsv': tsv(['code','slot_va','file_offset','displacement','target_va','role'], slots),
        'width-guards.tsv': tsv(['code','role','width','guard_va','branch_va','condition',
                                 'branch_target','call_va','complete_call_target'], guards),
        'visitors.tsv': tsv(['role','start','tag_site','unexpected_kind','call_site','constructor',
                             'expected_vtable','unexpected_formatter_slot','template'], visitors),
        'calls.tsv': tsv(['owner_va','site_va','bytes','kind','target_or_slot','selected_target'], calls),
        'relocations.tsv': tsv(['slot','rela_file_offset','type','addend'], relocs),
        'context.tsv': tsv(['va','file_offset','bytes','kind','target_or_slot'], context),
        'contracts.tsv': tsv(['name','va','file_offset','bytes'], contracts),
        'cases.tsv': tsv(['group','selector','payload','input_hex','available','arm','role','consumed',
                          'remaining','result_tag','boundary','value','raw_payload'], case_rows),
        'format-dispatch.tsv': tsv(['tag','slot','file_offset','displacement','target'], fmt_slots),
        'format-entries.tsv': tsv(['role','site','va','file_offset','length','bytes'], templates),
        'dot-cases.tsv': tsv(['length','alignment','dot_position','found','prefix','skipped_blocks',
                              'word_fallback'], dot_rows),
        'float-cases.tsv': tsv(['sample','bits','primary_status','dot_flag','suffix_status',
                                'class','suffix_call','return_byte'], float_rows),
        'flag-cases.tsv': tsv(['kind','initial','input','result'], flag_rows),
        'flow.tsv': tsv(['role','site_va','bytes','kind','target_or_slot','relative_addend'], flow),
        'summary.json': json_bytes(summary),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path, help='directory for generated evidence')
    args = parser.parse_args(argv)
    image = Image(ARTIFACT.read_bytes())
    result = output_files(image)
    args.out.mkdir(parents=True, exist_ok=True)
    for name, content in sorted(result.items()):
        (args.out / name).write_bytes(content)


if __name__ == '__main__':
    main()


