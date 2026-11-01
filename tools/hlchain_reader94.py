#!/usr/bin/env python3
"""Static node94 HlChain reader evidence; no captured program is executed.

The bounded instruction walker accepts only the encodings reviewed in this path.
Its numbers come from ELF bytes, never disassembler output. It is not an x86
emulator or a general function finder. Shared error allocation/formatting is a
call boundary, not a recovered implementation.
"""
import argparse
import csv
import io
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections
from fde_extents import eh_frame_records

DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
ARTIFACT = 'artifacts/node/94/hl-node'
FUNCTIONS = {
    0x13b5360: 'error_constructor', 0x13baf20: 'marker_reader', 0x13c44d0: 'scalar_reader',
    0x13f3f50: 'byte_name_match', 0x13f4100: 'str_name_match',
    0x14010e0: 'expected_type_writer',
    0x1408060: 'reject_bool', 0x1408140: 'reject_unit',
    0x14083f0: 'reject_extension', 0x1408560: 'reject_i8',
    0x1408660: 'reject_f32', 0x14087e0: 'reject_f64',
    0x1408930: 'reject_i16', 0x1408ab0: 'reject_i32',
    0x1408c30: 'reject_i64', 0x1408e60: 'reject_map',
    0x1408fb0: 'reject_sequence', 0x1409090: 'reject_bytes_as_sequence',
}
# Bounds are reviewed selector domains, checked against guards and neighboring
# tables below; they are not a scan-until-something-looks-unlike-code heuristic.
TABLES = {
    0x212ad8: ('cached_marker', 225, 0x13baf20),
    0x212e5c: ('cached_extension', 18, 0x13baf20),
    0x212ea4: ('fresh_marker_c0_df', 32, 0x13baf20),
    0x2162e0: ('scalar_c0_e0', 33, 0x13c44d0),
    0x216364: ('u64_discriminant', 4, 0x13c44d0),
    0x216374: ('u32_discriminant', 4, 0x13c44d0),
    0x216384: ('u16_discriminant', 4, 0x13c44d0),
    0x216394: ('u8_discriminant', 4, 0x13c44d0),
    0x2163a4: ('fixint_discriminant', 4, 0x13c44d0),
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
                require(slot not in self.relocations, 'duplicate relative relocation')
                self.relocations[slot] = (addend, pos)
        _, fs = eh_frame_records(data, self.sections)
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


def table(image, base, count, starts):
    raw = image.read(base, 4 * count)
    out = []
    for i in range(count):
        delta = struct.unpack_from('<i',raw,4*i)[0]
        target = base + delta
        require(target in starts, f'table target is not an instruction start at {base+4*i:#x}')
        out.append({'slot':base+4*i,'index':i,'delta':delta,'target':target})
    return out


def collect(image):
    functions, ins = [], []
    by_function = {}
    for start, label in sorted(FUNCTIONS.items()):
        rows = walk(image,start); by_function[start] = rows; ins.extend(rows)
        f = image.fdes[start]
        functions.append(dict(f, label=label, byte_count=f['end']-start,
                              sha256=hashlib.sha256(image.read(start,f['end']-start)).hexdigest(),
                              instruction_count=len(rows)))
    tables = []
    for base,(label,count,owner) in sorted(TABLES.items()):
        for row in table(image,base,count,{r['va'] for r in by_function[owner]}):
            tables.append(dict(row,table=base,label=label,owner=owner))
    return {'target_sha256': DIGEST, 'functions':functions, 'instructions':ins, 'tables':tables}


# Reviewed byte contracts for the decisions used by the abstract transfer model.
# These are instruction bytes, not snapshots of disassembler text.
PINS = {
    0x13b5370: 'f6c201750d',
    0x13b53d3: '48894318', 0x13b53dc:'48894308',
    0x13b53e5: '48894310c60306',
    0x13c453b: '0f87ed020000', 0x13c458f: '0f8790020000',
    0x13c4608: '0f871e020000', 0x13c468e: '0f878a010000',
    0x13c4767: '0f87c1000000',
    0x13bb3ad: '0f8581000000', 0x13bb418:'751a',
    0x13bb385: '0f84d0010000', 0x13bb3f0:'0f8465010000',
    0x13bb559: '7511',

    0x13baf2a: '440fb64e200fb64e21450fb6c1c6462001',
    0x13baf6d: '4183f811',
    0x13bb019: '4929c8', 0x13bb02e: '84d2',
    0x13bb0ea: '488946104c89461884c9',
    0x13bb137: '0fb6c989cb4929d8',
    0x13bb150: '488946104c894618',
    0x13bb167: '833c2401',
    0x13bb181: '807c242009',
    0x13bb18c: '0fb64424214188470141c60709',
    0x13bb1e6: 'c6070148b8030000002500000048894708',
    0x13bb211: '4889461048c7461800000000c60701',
    0x13bb2fe: 'c60700',
    0x13bb324: '488d4424080f10000f1144244741c60707',
    0x13bb35a: '41b1e080f9df', 0x13bb366: '80f990',
    0x13bb36b: '80e10f0fb6e9',
    0x13bb371: '0fb746226685c0',
    0x13bb37e: '66ffc866894622',
    0x13bb3aa: '80f909',
    0x13bb3cd: '80f9a0',
    0x13bb3d6: '80e10f0fb6e9',
    0x13bb3e9: '66ffc866894622',
    0x13bb415: '80f909',
    0x13bb434: '0f104424220f104c2430410f114e10410f11460241880e41884601',
    0x13bb47f: '80f9c0', 0x13bb484: '80e11f',
    0x13bb495: '0fb743226683f8ff',
    0x13bb4c8: 'ffc066894322',
    0x13bb502: '440fb6c94181c140ffffff',
    0x13bb521: '66c70702c1',
    0x13bb549: '0fb746226685c0',
    0x13bb552: '66ffc866894622',
    0x13bb55b: 'c60708',
    0x13bb58f: '410fb74e226683f9ff',
    0x13bb59a: 'ffc16641894e22',
    0x13bb5fa: '0f0b',
    0x13c44d5: '440fb6c2418d8040ffffff83f820',
    0x13c4530: '4585c0', 0x13c4535: '0fb6c180f903',
    0x13c4551: 'c60702885701884f02',
    0x13c458b: '4883fa03', 0x13c4605: '83fa03',
    0x13c468a: '4883f903', 0x13c4763: '6683f803',
    0x13c472a: '48c7461800000000c60701',
    0x13c477d: '66c7070900', 0x13c478b: '66c7070902',
    0x13c4799: '66c7070903', 0x13c47a7: '66c7070901',
    0x13c4833: 'c644243801',
    0x13f4100: '4883fa0774214883fa05',
    0x13f411c: '755d', 0x13f4138:'742f',
    0x13f414b: '7425', 0x13f415e:'751b',
    0x13f411e: '66c7070900', 0x13f4160:'66c7070903',
    0x13f4169: '66c7070901', 0x13f4172:'66c7070902',
    0x14010e0: '488b3e488b4608488b4018',
}


def contracts(image, result):
    for va, expected in sorted(PINS.items()): image.pin(va,expected)
    rows={r['va']:r for r in result['instructions']}
    def rip(va):
        require(va in rows and 'rip_target' in rows[va], 'missing RIP operand')
        return rows[va]['rip_target']
    width_sites={0xca:0x13c44fd,0xcb:0x13c45ad,0xcd:0x13c4652,0xce:0x13c45eb,
                 0xcf:0x13c456b,0xd1:0x13c46e1,0xd2:0x13c46ac,0xd3:0x13c4719}
    width_expect={0xca:4,0xcb:8,0xcd:2,0xce:4,0xcf:8,0xd1:2,0xd2:4,0xd3:8}
    scalar_widths={}
    for marker,va in sorted(width_sites.items()):
        r=rows[va]
        require(r['opcode']==0x83 and ((r['modrm']>>3)&7)==7 and r['immediate']==width_expect[marker],
                'scalar width guard changed')
        scalar_widths[marker]={'width':r['immediate'],'guard':va}
    for marker,va,raw in ((0xcc,0x13c4679,'48ffc80fb60a48ffc2'),
                          (0xd0,0x13c462f,'48ffc90fb60248ffc2')):
        image.pin(va,raw);scalar_widths[marker]={'width':rows[va+3]['memory_width']//8,'guard':va}
        require(scalar_widths[marker]['width']==1,'byte read shape changed')
    for va,raw in ((0x13c4511,'0fca'),(0x13c45be,'480fca'),(0x13c4754,'66c1c208'),
                   (0x13c45fb,'0fca'),(0x13c457c,'480fca'),(0x13c46f2,'66c1c008'),
                   (0x13c46bc,'0fc8'),(0x13c47ff,'480fc8')):
        image.pin(va,raw)
    for va,expected in ((0x13bafaf,2),(0x13baff9,4),(0x13bb204,2),(0x13bb1a9,4),
                        (0x13bb10a,2),(0x13bb07c,4),(0x13bb0a7,2),(0x13bb051,4),
                        (0x13bb238,2),(0x13bb263,4)):
        require(rows[va]['opcode']==0x83 and rows[va]['immediate']==expected,
                'length-header width changed')
    # Resolve every selector table from the instruction, then validate its domain.
    for va,base in ((0x13baf3b,0x212ad8),(0x13baf77,0x212e5c),
                    (0x13bb50d,0x212ea4),(0x13c44e5,0x2162e0),
                    (0x13c4595,0x216364),(0x13c460e,0x216374),
                    (0x13c476d,0x216384),(0x13c4694,0x216394),
                    (0x13c4541,0x2163a4)):
        require(rip(va)==base, 'selector table moved')
    # Check the normalizing dispatch against the reviewed path classification.
    # Invalid cached enum states have explicit trap entries; they are not wire markers.
    cached_groups={
        0x13baf4c:(0,0xc0,0xc2,0xc3,0xca,0xcb,0xcc,0xcd,0xce,0xcf,0xd0,0xd1,0xd2,0xd3,0xe0),
        0x13bb0d0:(1,),0x13bb36e:(0x80,),0x13bb3d9:(0x90,),0x13bb133:(0xa0,),
        0x13bb521:(0xc1,),0x13bafd5:(0xc4,),0x13bafa7:(0xc5,),0x13baff1:(0xc6,),
        0x13baf64:(0xc7,0xc8,0xc9,0xd4,0xd5,0xd6,0xd7,0xd8),
        0x13bb1bd:(0xd9,),0x13bb1fc:(0xda,),0x13bb1a1:(0xdb,),
        0x13bb102:(0xdc,),0x13bb074:(0xdd,),0x13bb09f:(0xde,),0x13bb049:(0xdf,)}
    cache_expected={index:target for target,indices in cached_groups.items() for index in indices}
    fresh_expected=(0x13baf4c,0x13bb521,0x13baf4c,0x13baf4c,
                    0x13bafdd,0x13bafaf,0x13baff9,0x13baf8c,
                    0x13bb238,0x13bb263,0x13baf4c,0x13baf4c,
                    0x13baf4c,0x13baf4c,0x13baf4c,0x13baf4c,
                    0x13baf4c,0x13baf4c,0x13baf4c,0x13baf4c,
                    0x13bb53d,0x13bb544,0x13bb528,0x13bb52f,0x13bb536,
                    0x13bb1c5,0x13bb204,0x13bb1a9,0x13bb10a,0x13bb07c,0x13bb0a7,0x13bb051)
    scalar_expected={0:0x13c47cf,2:0x13c47b5,3:0x13c47b9,
                     10:0x13c44f5,11:0x13c45a5,12:0x13c4668,13:0x13c464a,
                     14:0x13c45e3,15:0x13c4563,16:0x13c461e,17:0x13c46d9,
                     18:0x13c46a4,19:0x13c4711,32:0x13c47e0}
    extension_expected={0:0x13baf88,1:0x13bb230,2:0x13bb25b,13:0x13bb53d,
                        14:0x13bb544,15:0x13bb528,16:0x13bb52f,17:0x13bb536}
    for t in result['tables']:
        if t['table']==0x212ad8:expected=cache_expected.get(t['index'],0x13bb5fa)
        elif t['table']==0x212ea4:expected=fresh_expected[t['index']]
        elif t['table']==0x2162e0:expected=scalar_expected.get(t['index'],0x13c4551)
        elif t['table']==0x212e5c:expected=extension_expected.get(t['index'],0x13bb30b)
        else:continue
        require(t['target']==expected,'marker dispatch classification changed')
    # Read output discriminants from all five numeric dispatches independently.
    maps=[]
    for base in (0x216364,0x216374,0x216384,0x216394,0x2163a4):
        selected=[r for r in result['tables'] if r['table']==base]
        outputs=[]
        for t in selected:
            raw=image.read(t['target'],5)
            require(raw[:4]==bytes.fromhex('66c70709'), 'numeric result store changed')
            outputs.append(raw[4])
        require(outputs==list(range(len(outputs))), 'numeric discriminant mapping changed')
        maps.append({'table':base,'outputs':outputs})
    # Names are recovered from immediate operands in the packed comparison leaf.
    names=[]
    for first, second, tail, store in (
            (0x13f410c,None,0x13f4117,0x13f411e),
            (0x13f4127,0x13f412e,None,0x13f4169),
            (0x13f413a,0x13f4141,None,0x13f4172),
            (0x13f414d,0x13f4154,None,0x13f4160)):
        require(rows[first]['opcode']==0xb8, 'name prefix opcode changed')
        prefix=rows[first]['immediate'].to_bytes(4,'little')
        if second is None:
            require(rows[tail]['opcode']==0x83, 'name tail opcode changed')
            name=prefix+bytes([rows[tail]['immediate']])
        else:
            require(rows[second]['opcode']==0xb9, 'name suffix opcode changed')
            suffix=rows[second]['immediate'].to_bytes(4,'little')
            require(prefix[-1:]==suffix[:1], 'overlapping name bytes disagree')
            name=prefix+suffix[1:]
        raw=image.read(store,5)
        names.append({'name':name.decode('ascii'),'tag':raw[3],'discriminant':raw[4],
                      'prefix_instruction':first,'suffix_instruction':second or tail,'store':store})
    require([n['name'] for n in names]==['Local','Sandbox','Testnet','Mainnet'],
            'name contract changed')
    seed=image.read(0x2180ff,9)
    require(seed==b'NvTestnet' and seed.decode() not in [n['name'] for n in names],
            'AwsName seed/chain boundary changed')
    for n, first, lo, hi, store in zip(names,
            (None,0x13f3fb5,0x13f3fb0,0x13f3fab),
            (0x13f3f60,0x13f3fbe,0x13f3ffb,0x13f402c),
            (0x13f3f91,0x13f3fee,0x13f401f,0x13f4050),
            (0x13f3f91,0x13f3fee,0x13f401f,0x13f4050)):
        chars={} if first is None else {0:rows[first]['immediate']}
        sites=[] if first is None else [first]
        for va,r in rows.items():
            if lo<=va<hi and r['opcode']==0x80 and r.get('memory',{}).get('base')=='rsi':
                require((r['modrm']>>3)&7==7,'byte matcher is not compare')
                offset=r['memory']['disp'];require(offset not in chars,'duplicate character comparison')
                chars[offset]=r['immediate'];sites.append(va)
        require(sorted(chars)==list(range(n['name_length'] if 'name_length' in n else len(n['name']))),
                'character comparison offsets incomplete')
        require(bytes(chars[i] for i in sorted(chars)).decode('ascii')==n['name'],
                'packed and byte matchers disagree')
        word=rows[store]['immediate']
        require(word==n['tag']+(n['discriminant']<<8),'two matcher result words disagree')
        n.update(byte_comparison_sites=sorted(sites),byte_match_store=store)

    expected_va=rip(0x14010eb); expected_size=rows[0x14010f2]['immediate']
    require(image.read(expected_va,expected_size)==b'variant identifier','expected type changed')
    # The table preceding the old AwsName table belongs to HlChain, not AwsName.
    chain_table=rip(0x13f417c)
    require(chain_table==rip(0x13f4073), 'two name errors disagree on expected names')
    for n in names:
        slot=chain_table+16*n['discriminant']; address=image.relative(slot)
        length=int.from_bytes(image.read(slot+8,8),'little')
        require(image.read(address,length).decode('ascii')==n['name'],'name relocation disagrees')
        n.update(name_slot=slot,name_va=address,name_length=length)
    require(image.relative(0x576e7e0)==0x13c44d0, 'scalar indirect call redirected')
    require(image.relative(0x5668eb0)==0x14010e0, 'expected type vtable redirected')
    reject=[]
    for f in result['functions']:
        if not f['label'].startswith('reject_'):continue
        body=[r for r in result['instructions'] if f['start']<=r['va']<f['end']]
        tags=[r for r in body if r['opcode']==0xc6 and r.get('memory',{}).get('disp')==0x38]
        require(len(tags)==1,'unexpected rejection tag stores')
        call=[r for r in body if r['kind']=='call']
        require(len(call)==1 and call[0]['target']==0x13b5360,'rejection constructor changed')
        require(any(r.get('rip_target')==0x5668e98 for r in body),'rejection vtable changed')
        reject.append({'function':f['start'],'label':f['label'],'unexpected_kind':tags[0]['immediate'],
                       'kind_store':tags[0]['va'],'constructor_call':call[0]['va'],
                       'constructor':call[0]['target']})
    return {'names':names,'seed_boundary':{'va':0x2180ff,'text':seed.decode(),'length':len(seed)},'scalar_widths':scalar_widths,'numeric_maps':maps,'rejection_visitors':reject,
            'formatted_error_tag':rows[0x13b53e9]['immediate'],
            'expected_type':{'va':expected_va,'length':expected_size,'text':image.read(expected_va,expected_size).decode()},
            'cursor':{'pointer_offset':rows[0x13bb150]['memory']['disp'],
                      'remaining_offset':rows[0x13bb154]['memory']['disp'],
                      'marker_offset':rows[0x13baf37]['memory']['disp'],
                      'empty_marker':rows[0x13baf37]['immediate'],
                      'depth_offset':rows[0x13bb381]['memory']['disp']}}


def marker_rows(result):
    tables={base:{r['index']:r['target'] for r in result['tables'] if r['table']==base}
            for base in TABLES}
    output=[]
    for byte in range(256):
        if byte<0x80: normalized,payload,route=0,byte,0x13baf4c
        elif byte<0x90: normalized,payload,route=0x80,byte&15,0x13bb36e
        elif byte<0xa0: normalized,payload,route=0x90,byte&15,0x13bb3d9
        elif byte<0xc0: normalized,payload,route=0xa0,byte&31,0x13bb133
        elif byte<0xe0: normalized,payload,route=byte,byte,tables[0x212ea4][byte-0xc0]
        else: normalized,payload,route=0xe0,byte,0x13baf4c
        scalar=None
        if route==0x13baf4c:
            scalar=tables[0x2162e0][normalized-0xc0] if 0xc0<=normalized<=0xe0 else 0x13c4530
        output.append({'wire_marker':byte,'normalized_marker':normalized,'payload':payload,
                       'fresh_route':route,'cached_route':tables[0x212ad8][normalized],
                       'scalar_route':scalar})
    return output


def transfer_model(contract, wire, *, bytes_mode=False, depth=128, cached=None):
    """Abstract normal-return model of the reviewed reader, not target execution.

External rejection constructors are opaque terminal calls. No message text or
heap object is invented for their returns. The UTF-8 dependency is represented
by Python validation solely to select the two independently recovered matchers.
"""
    require(isinstance(wire,bytes) and 0<=depth<=65535,'invalid model input')
    pos=0; initial_depth=depth; trace=[]; cache_after=contract['cursor']['empty_marker']
    def result(outcome, site, variant=None, callee=None):
        return {'outcome':outcome,'consumed':pos,'remaining':len(wire)-pos,
                'depth_before':initial_depth,'depth_after':depth,'cache_after':cache_after,
                'discriminant':variant,'terminal_site':site,'callee':callee,'result_tag':(contract['formatted_error_tag'] if outcome in ('invalid_type_call','unsigned_out_of_range') else
                    {'success':contract['names'][0]['tag'],'marker_eof':0,'payload_eof':1,
                     'declared_length_exceeds_input':1,'reserved_marker':2,'depth_limit':8}.get(outcome)),
                'trace':trace+[site]}
    def take(width):
        nonlocal pos
        if len(wire)-pos<width:
            pos=len(wire);return None
        value=int.from_bytes(wire[pos:pos+width],'big');pos+=width;return value
    if cached is None:
        if not wire:return result('marker_eof',0x13bb2fe)
        marker=take(1);trace.append(0x13bb0ea)
    else:
        tag,payload=cached
        require(tag==0 or tag in (0x80,0x90,0xa0,0xe0) or 0xc0<=tag<=0xdf,
                'model accepts only valid cached marker representations')
        require(0<=payload<=255,'invalid cached payload')
        marker=payload if tag in (0,0xe0) else ((tag|payload) if tag in (0x80,0x90,0xa0) else tag)
        require((tag!=0 or payload<0x80) and (tag!=0xe0 or payload>=0xe0), 'invalid cached fixint')
        require(tag not in (0x80,0x90) or payload<16,'invalid cached container length')
        require(tag!=0xa0 or payload<32,'invalid cached string length')
    if marker<0x80 or 0xcc<=marker<=0xcf:
        width=0 if marker<0x80 else contract['scalar_widths'][marker]['width']
        value=marker if width==0 else take(width)
        if value is None:return result('payload_eof',0x13c4732)
        if value>=len(contract['names']):return result('unsigned_out_of_range',0x13c488b,callee=0x13b5360)
        return result('success', [0x13c477d,0x13c47a7,0x13c478b,0x13c4799][value],value)
    reject={0xc0:(0,0x1408140),0xc2:(0,0x1408060),0xc3:(0,0x1408060),
            0xca:(4,0x1408660),0xcb:(8,0x14087e0),0xd0:(1,0x1408560),
            0xd1:(2,0x1408930),0xd2:(4,0x1408ab0),0xd3:(8,0x1408c30)}
    if marker>=0xe0:width,callee=0,0x1408560
    elif marker in reject:
        width,callee=reject[marker]
        if marker in contract['scalar_widths']:width=contract['scalar_widths'][marker]['width']
    else:width,callee=None,None
    if callee:
        if width and take(width) is None:return result('payload_eof',0x13c4732)
        return result('invalid_type_call',callee,callee=callee)
    if marker==0xc1:return result('reserved_marker',0x13bb521)
    if 0xa0<=marker<=0xbf or marker in (0xc4,0xc5,0xc6,0xd9,0xda,0xdb):
        binary=marker in (0xc4,0xc5,0xc6)
        if 0xa0<=marker<=0xbf:length=marker&31
        else:
            width={0xc4:1,0xc5:2,0xc6:4,0xd9:1,0xda:2,0xdb:4}[marker]
            length=take(width)
            if length is None:return result('payload_eof',0x13bb21d)
        if len(wire)-pos<length:return result('declared_length_exceeds_input',0x13bb1e6)
        value=wire[pos:pos+length];pos+=length
        if binary and not bytes_mode:return result('invalid_type_call',0x13bb472,callee=0x1409090)
        if binary:match=0x13f3f50
        else:
            try:value.decode('utf-8');match=0x13f4100
            except UnicodeDecodeError:match=0x13f3f50
        trace.append(match)
        for n in contract['names']:
            if value==n['name'].encode('ascii'):
                store=n['byte_match_store'] if match==0x13f3f50 else n['store']
                return result('success',store,n['discriminant'])
        return result('unknown_name_call',0x13f4088 if match==0x13f3f50 else 0x13f418c,callee=0x13b5050)
    if 0x80<=marker<=0x9f or marker in (0xdc,0xdd,0xde,0xdf,0xc7,0xc8,0xc9,0xd4,0xd5,0xd6,0xd7,0xd8):
        extension=marker in (0xc7,0xc8,0xc9,0xd4,0xd5,0xd6,0xd7,0xd8)
        is_map=0x80<=marker<=0x8f or marker in (0xde,0xdf)
        widths={0xdc:2,0xdd:4,0xde:2,0xdf:4,0xc7:1,0xc8:2,0xc9:4}
        if marker in widths and take(widths[marker]) is None:return result('payload_eof',0x13bb31d if extension else 0x13bb21d)
        if depth==0:return result('depth_underflow_panic',0x13bb5b7 if extension else (0x13bb5c4 if is_map else 0x13bb5d1))
        depth-=1
        if depth==0:return result('depth_limit',0x13bb55b)
        if extension:
            depth+=1
            return result('invalid_type_call',0x13bb58a,callee=0x14083f0)
        # Map/sequence rejection returns through 0x13bb434 without restoring depth.
        return result('invalid_type_call',0x13bb39b if is_map else 0x13bb406,
                      callee=0x1408e60 if is_map else 0x1408fb0)
    raise ValueError('unclassified wire marker')


def cases(contract):
    out=[]
    def add(label,wire,**options):
        r=transfer_model(contract,wire,**options)
        out.append(dict(r,label=label,input=wire.hex(),options=options))
    for marker in range(256):add(f'marker-{marker:02x}',bytes([marker])+bytes(16))
    for i,n in enumerate(contract['names']):
        name=n['name'].encode()
        add(f'fixint-{i}',bytes([i])+b'Z')
        for marker,width in ((0xcc,1),(0xcd,2),(0xce,4),(0xcf,8)):
            add(f'unsigned-{marker:02x}-{i}',bytes([marker])+i.to_bytes(width,'big')+b'Z')
        for marker,width in ((0xd0,1),(0xd1,2),(0xd2,4),(0xd3,8)):
            add(f'signed-{marker:02x}-{i}',bytes([marker])+i.to_bytes(width,'big')+b'Z')
        for marker,width in ((0xa0|len(name),0),(0xd9,1),(0xda,2),(0xdb,4),(0xc4,1),(0xc5,2),(0xc6,4)):
            for mode in (False,True):
                wire=bytes([marker])+(len(name).to_bytes(width,'big') if width else b'')+name+b'Z'
                add(f'name-{marker:02x}-{i}-mode-{int(mode)}',wire,bytes_mode=mode)
        for j in range(len(name)):
            wrong=bytearray(name);wrong[j]^=0x20
            add(f'case-sensitive-{i}-{j}',bytes([0xa0|len(wrong)])+bytes(wrong))
    for marker,width in ((0xcc,1),(0xcd,2),(0xce,4),(0xcf,8)):
        for value in sorted({3,4,127,128,(1<<(8*width-1)),(1<<(8*width))-1}):
            add(f'uint-boundary-{marker:02x}-{value}',bytes([marker])+value.to_bytes(width,'big')+b'Z')
    for marker,width in ((0xca,4),(0xcb,8),(0xcc,1),(0xcd,2),(0xce,4),(0xcf,8),
                         (0xd0,1),(0xd1,2),(0xd2,4),(0xd3,8),(0xc4,1),(0xc5,2),(0xc6,4),
                         (0xd9,1),(0xda,2),(0xdb,4),(0xdc,2),(0xdd,4),(0xde,2),(0xdf,4),
                         (0xc7,1),(0xc8,2),(0xc9,4)):
        for length in range(width):add(f'truncated-{marker:02x}-{length}',bytes([marker])+bytes(length))
    for wire in (b'\xa9NvTestnet',b'\x20',b'\xa5Loca',b'\xd9\x05Loca',b'\xc4\x05Loca',b'\xdb\xff\xff\xff\xffX',b'\xa1\xff',b'\xa0',b''):
        add('special-'+wire.hex(),wire)
    for marker in (0x80,0x81,0x90,0x91,0xc7,0xc8,0xc9,0xd4,0xd5,0xd6,0xd7,0xd8,0xdc,0xdd,0xde,0xdf):
        for depth in (0,1,2,128,65535):add(f'depth-{marker:02x}-{depth}',bytes([marker])+bytes(8),depth=depth)
    for tag,payload,wire in ((0,3,b'X'),(0xe0,0xff,b'X'),(0xa0,5,b'LocalX'),(0x80,1,b'X'),
                             (0x90,0,b'X'),(0xcc,0,b'\x03X'),(0xda,0,b'\x00\x05LocalX')):
        add(f'cached-{tag:02x}',wire,cached=(tag,payload))
    return out


def tsv(columns, rows):
    f=io.StringIO(newline='')
    writer=csv.writer(f,delimiter='\t',lineterminator='\n')
    writer.writerow(columns)
    for r in rows:
        writer.writerow(['' if r.get(c) is None else
                         (json.dumps(r[c],sort_keys=True,separators=(',',':')) if isinstance(r[c],(list,dict)) else r[c])
                         for c in columns])
    return f.getvalue()


def outputs(image):
    result=collect(image); contract=contracts(image,result)
    ins=result.pop('instructions'); tables=result.pop('tables')
    functions=result.pop('functions')
    markers=marker_rows(dict(tables=tables))
    models=cases(contract)
    branches=[dict(r,fallthrough=r['va']+r['size']) for r in ins if r['kind'] in ('branch','jump')]
    transfers=[]
    for r in ins:
        if r['kind'] not in ('call','indirect_call','indirect_jump','return','trap'):continue
        owner=next(f['start'] for f in functions if f['start']<=r['va']<f['end'])
        target=r.get('target',r.get('relocated_target'))
        transfers.append(dict(r,owner=owner,owner_label=FUNCTIONS[owner],
                              target_label=FUNCTIONS.get(target),
                              boundary=('selected_function' if target in FUNCTIONS else 'external_or_dynamic')
                              if r['kind'] in ('call','indirect_call','indirect_jump') else 'local_exit'))
    writes=[]
    for r in ins:
        if r['opcode'] in (0x88,0x89,0xc6,0xc7,0x0f11) and 'memory' in r:
            mem=r['memory']
            if mem['base'] in ('rsi','rbx','rdi','r14','r15'):
                writes.append(dict(r,base=mem['base'],offset=mem['disp'],index=mem['index']))
    result.update(contract=contract,limitations=[
        'Static instruction and table analysis; no captured execution or runtime equivalence.',
        'FDEs are unwind extents; no whole-component function coverage is claimed.',
        'External UTF-8, allocation/formatting, unknown-name construction, drop and panic implementations remain boundaries.',
        'Case rows are abstract transfer-model deductions, not observed target outputs.',
        'No code, data, relocation or vtable normalization; no Rust reconstruction.'],
        metrics={'functions':len(functions),'function_bytes':sum(f['byte_count'] for f in functions),
                 'instructions':len(ins),'branches':len(branches),'conditional_branches':sum(r['kind']=='branch' for r in branches),
                 'transfers':len(transfers),'calls':sum(r['kind'] in ('call','indirect_call') for r in transfers),
                 'selected_function_calls':sum(r['kind'] in ('call','indirect_call') and r['boundary']=='selected_function' for r in transfers),
                 'table_slots':len(tables),'marker_rows':len(markers),'model_cases':len(models),
                 'byte_contracts':len(PINS),'listed_memory_writes':len(writes)})
    files={
        'evidence.json':json.dumps(result,indent=2,sort_keys=True)+'\n',
        'functions.tsv':tsv(['label','start','end','byte_count','fde','cie','lsda','instruction_count','sha256'],functions),
        'instructions.tsv':tsv(['va','file_offset','bytes','size','opcode','kind','width','memory_width','reg','rm','register','memory','immediate','target','rip_target','relocated_target'],ins),
        'branches.tsv':tsv(['va','bytes','kind','condition','target','fallthrough'],branches),
        'transfers.tsv':tsv(['owner','owner_label','va','bytes','kind','target','rip_target','relocated_target','relocation_file_offset','target_label','boundary'],transfers),
        'jump-tables.tsv':tsv(['label','table','owner','slot','index','delta','target'],tables),
        'marker-routes.tsv':tsv(['wire_marker','normalized_marker','payload','fresh_route','cached_route','scalar_route'],markers),
        'memory-writes.tsv':tsv(['va','bytes','base','offset','index','width','reg','immediate'],writes),
        'cases.tsv':tsv(['label','input','options','outcome','consumed','remaining','depth_before','depth_after','cache_after','discriminant','result_tag','terminal_site','callee','trace'],models),
        'byte-contracts.tsv':tsv(['va','bytes'],[{'va':va,'bytes':image.read(va,len(bytes.fromhex(h))).hex()} for va,h in sorted(PINS.items())]),
    }
    return files


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,required=True)
    args=parser.parse_args()
    generated=outputs(Image((ROOT/ARTIFACT).read_bytes()))
    args.out.mkdir(parents=True,exist_ok=True)
    for name,content in sorted(generated.items()):
        (args.out/name).write_text(content,encoding='utf-8',newline='\n')
    print('Static evidence generated; captured programs were not executed.')


if __name__=='__main__':
    main()
