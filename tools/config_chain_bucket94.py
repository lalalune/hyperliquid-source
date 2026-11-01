"""Collect node 94 network-keyed configuration map and lookup evidence.

The closed x86 encoding reader is adapted from the independently authored MIT
aws_json_envelope94 research collector. ELF, CIE and FDE parsing are shared.
All observations come from authenticated file bytes; the target is never run.
"""
import argparse
import collections
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
TARGET = ROOT / 'artifacts/node/94/hl-node'

# The closed selection is not a function census. Bounds are unwind extents.
BODIES = {
    0x13aa2f0: ('binary_enum_map_gate', 0x13aa4d1, '4c86a8a2ee66a466a16f4f68e4f877bca268e1d29c7eb95af177111f9bbaee42'),
    0x13aa4e0: ('binary_optional_map', 0x13aa5e7, 'e960efecf70b2c60fc9e8fbcae12d51f52c526f619264331103c0c2ef2c24a1f'),
    0x13b8610: ('binary_map_reader', 0x13b8f3b, 'e098a98da89986ea452e462e200cce6a055811c5b5c4add45531fd0c64e1acaa'),
    0x13bdcd0: ('binary_value_reader', 0x13be453, '93e86015af32a29580a99c749cec03315ec345a801ab82a452ab339e8adb37c3'),
    0x13f3580: ('json_enum_envelope', 0x13f3817, 'fc9a2acd0ac6c7352c3cc1f93d9e66013dec722519f346218b7b1f137cd8ed35'),
    0x13f3dd0: ('binary_enum_unit', 0x13f3f49, 'ad727bfa20437adc936d5b073e620f4f8b9539dc997bbc9d07ddd3fff5460656'),
    0x13f41a0: ('json_name_classifier', 0x13f424c, '604d4829c691317d6b212d3a6352e4a95997aaef4a9607dffe2b07eec44a3a62'),
    0x1404ef0: ('global_map_lookup', 0x14050d6, 'c7c15ded799bbb33956ad7c71744bfef84123af1f50088d4ee7478c28707b557'),
    0x1441ba0: ('json_optional_map', 0x1441d0f, '799c40eda8f722a36aac533653bb1f2418f351e2ac5385dd090f96add15a08ad'),
    0x14b6c10: ('json_quoted_name', 0x14b6d33, '9cba1d4c328485c82027f9cd130adf2a668b46665a1d9441d27930a7f56ffa42'),
    0x14ba930: ('json_map_reader', 0x14baf87, 'ef32cbe90c7f2dace3e9bbb58cfbb299816c7f958bc6bb6396af7a76030b3f4a'),
    0x14cbb80: ('map_insert_replace', 0x14cbd77, 'fdef6cc251891cf6503731204dfac8579f3eaa09bbd46008498cb5713701a44f'),
}

class EvidenceError(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise EvidenceError(reason)


class Image:
    def __init__(self, data):
        require(hashlib.sha256(data).hexdigest() == DIGEST, 'node 94 digest mismatch')
        self.data = data
        self.sections = sections(data)
        _, self.fdes = eh_frame_records(data, self.sections)
        self.relocations = {}
        self.relocation_offsets = {}
        self.symbols = {}
        dynsym = next(s for s in self.sections if s['name'] == '.dynsym')
        dynstr = next(s for s in self.sections if s['name'] == '.dynstr')
        require(dynsym['type'] == 11 and dynsym['size'] % 24 == 0
                and dynstr['type'] == 3, 'unexpected dynamic symbol tables')
        string_data = data[dynstr['offset']:dynstr['offset'] + dynstr['size']]
        for section in self.sections:
            if section['type'] != 4:
                continue
            require(section['size'] % 24 == 0, 'truncated RELA section')
            for pos in range(section['offset'], section['offset'] + section['size'], 24):
                slot, info, addend = struct.unpack_from('<QQq', data, pos)
                if info == 8:
                    require(slot not in self.relocations, 'duplicate RELATIVE slot')
                    self.relocations[slot] = addend
                    self.relocation_offsets[slot] = pos
                elif info & 0xffffffff == 6:
                    index = info >> 32
                    require(index * 24 + 24 <= dynsym['size'], 'dynamic symbol outside table')
                    name_offset = struct.unpack_from('<I', data, dynsym['offset'] + index * 24)[0]
                    name_end = string_data.find(b'\0', name_offset)
                    require(name_offset < len(string_data) and name_end >= name_offset,
                            'invalid dynamic symbol name')
                    require(slot not in self.symbols, 'duplicate GLOB_DAT slot')
                    self.symbols[slot] = (index, string_data[name_offset:name_end].decode('ascii'))

    def offset(self, address, size):
        require(address >= 0 and size > 0, 'invalid address range')
        matches = [s for s in self.sections
                   if s['type'] != 8 and s['flags'] & 2
                   and s['address'] <= address
                   and address + size <= s['address'] + s['size']]
        require(len(matches) == 1, 'address range lacks unique file backing')
        section = matches[0]
        return section['offset'] + address - section['address']

    def read(self, address, size):
        offset = self.offset(address, size)
        return bytes(self.data[offset:offset + size])

    def fde(self, address):
        rows = [f for f in self.fdes if f['start'] == address]
        require(len(rows) == 1, 'selected FDE is missing or ambiguous')
        return rows[0]

    def relative(self, slot):
        require(slot in self.relocations, 'missing RELATIVE relocation')
        return self.relocations[slot]

    def relative_record(self, slot):
        require(slot in self.relocation_offsets, 'missing RELATIVE record')
        position = self.relocation_offsets[slot]
        return position, bytes(self.data[position:position + 24]).hex()

# This closed decoder admits only the encodings in the selected scalar paths.
# It describes bytes and operands; it never executes captured instructions.
REG = ['rax','rcx','rdx','rbx','rsp','rbp','rsi','rdi'] + ['r'+str(i) for i in range(8,16)]
CC = ['o','no','b','ae','e','ne','be','a','s','ns','p','np','l','ge','le','g']

def decode(body, base):
    rows = []
    p = 0
    while p < len(body):
        start = p
        prefixes = []
        rex = 0
        while p < len(body) and body[p] in (0x66,0x2e,0xf2,0xf3):
            prefixes.append(body[p]); p += 1
        if p < len(body) and 0x40 <= body[p] <= 0x4f:
            rex = body[p]; p += 1
        def take(n):
            nonlocal p
            if n < 0 or p + n > len(body):
                raise EvidenceError('truncated instruction')
            raw = body[p:p+n]; p += n
            return raw
        op = take(1)[0]
        width = 64 if rex & 8 else (16 if 0x66 in prefixes else 32)
        row = {'va':base+start,'kind':'','width':width,'opcode':op,'prefixes':prefixes}
        modrm = False
        imm = 0
        signed = False
        if op in (0xe8,0xe9,0xeb) or 0x70 <= op <= 0x7f:
            n = 1 if op == 0xeb or 0x70 <= op <= 0x7f else 4
            delta = int.from_bytes(take(n),'little',signed=True)
            row['kind'] = 'call' if op==0xe8 else ('jump' if op in (0xe9,0xeb) else 'j'+CC[op&15])
            row['target'] = base+p+delta
        elif 0x50 <= op <= 0x5f:
            row['kind'] = 'push' if op<0x58 else 'pop'
            row['reg'] = REG[(op&7)+((rex&1)<<3)]
        elif op in (0xc3,0x90):
            row['kind'] = 'ret' if op==0xc3 else 'nop'
        elif 0xb0 <= op <= 0xbf:
            row['kind']='mov_imm'; row['reg']=REG[(op&7)+((rex&1)<<3)]
            row['width']=8 if op<0xb8 else width
            imm=1 if op<0xb8 else width//8
        elif op in (0x04,0x05,0x0c,0x0d,0x24,0x25,0x2c,0x2d,0x34,0x35,0x3c,0x3d):
            row['kind']={0:'add',8:'or',0x20:'and',0x28:'sub',0x30:'xor',0x38:'cmp'}[op&0xf8]
            row['reg']='rax';row['width']=8 if op&1==0 else width
            imm=1 if op&1==0 else (2 if width==16 else 4)
        elif op==0x0f:
            op2=take(1)[0];row['opcode2']=op2
            if 0x80<=op2<=0x8f:
                delta=int.from_bytes(take(4),'little',signed=True)
                row['kind']='j'+CC[op2&15];row['target']=base+p+delta
            elif op2==0x0b:row['kind']='trap'
            elif 0xc8<=op2<=0xcf:row['kind']='bswap';row['reg']=REG[(op2&7)+((rex&1)<<3)]
            elif op2 in (0x10,0x11,0x15,0x28,0x29,0x2e,0x57,0x58,0x59,0x5c,0x5e,0x62,0x6e,0x7e):
                row['kind']='sse_'+hex(op2);modrm=True
                row['width']=64 if 0xf2 in prefixes or op2 in (0x6e,0x7e) else 128
            elif op2==0x1f:row['kind']='nop';modrm=True
            elif op2 in (0xb6,0xb7,0xbe,0xbf):row['kind']='extend';modrm=True;row['source_width']=8 if op2 in (0xb6,0xbe) else 16
            elif op2==0xa3:row['kind']='bt';modrm=True
            elif op2==0xbc:row['kind']='tzcnt' if 0xf3 in prefixes else 'bsf';modrm=True
            elif 0x40<=op2<=0x4f:row['kind']='cmov'+CC[op2&15];modrm=True
            elif 0x90<=op2<=0x9f:row['kind']='set'+CC[op2&15];modrm=True;row['width']=8
            else:raise EvidenceError('unsupported two-byte opcode '+hex(op2)+' at '+hex(base+start))
        elif op in (0x00,0x01,0x08,0x09,0x20,0x21,0x28,0x29,0x30,0x31,0x33,0x38,0x39,0x3b,0x23,0x85,0x84,0x88,0x89,0x8b,0x8d,0x63):
            row['kind']={0x00:'add',0x01:'add',0x08:'or',0x09:'or',0x20:'and',0x21:'and',0x23:'and',0x28:'sub',0x29:'sub',0x30:'xor',0x31:'xor',0x33:'xor',0x38:'cmp',0x39:'cmp',0x3b:'cmp',0x85:'test',0x84:'test',0x88:'mov_store',0x89:'mov_store',0x8b:'mov_load',0x8d:'lea',0x63:'movsxd'}[op]
            modrm=True
            if op in (0x00,0x08,0x20,0x28,0x30,0x38,0x84,0x88):row['width']=8
        elif op in (0x80,0x81,0x83,0xc6,0xc7,0xf6,0xf7,0xff,0xfe,0xc1,0x6b,0x69):
            modrm=True
            row['kind']='group'
            if op in (0x80,0xc6,0xf6):row['width']=8
            if op in (0x80,0x83,0xc6,0xc1,0x6b):imm=1
            elif op in (0x81,0xc7,0x69):imm=2 if width==16 else 4
            signed=op in (0x83,0x6b) or (width==64 and op in (0x81,0xc7,0x69))
        else:raise EvidenceError('unsupported opcode '+hex(op)+' at '+hex(base+start))
        if modrm:
            m=take(1)[0];mod=m>>6;group=(m>>3)&7;rm=m&7
            row['reg']=REG[group+(((rex>>2)&1)<<3)]
            if mod==3:
                row['rm']=REG[rm+((rex&1)<<3)]
            else:
                mem={'base':None,'index':None,'scale':1,'disp':0}
                disp=0
                if rm==4:
                    sib=take(1)[0];mem['scale']=1<<(sib>>6)
                    index=(sib>>3)&7
                    if index!=4 or rex&2:mem['index']=REG[index+((rex&2)<<2)]
                    br=sib&7
                    if mod==0 and br==5:disp=4
                    else:mem['base']=REG[br+((rex&1)<<3)]
                elif mod==0 and rm==5:
                    mem['base']='rip';disp=4
                else:mem['base']=REG[rm+((rex&1)<<3)]
                if mod==1:disp=1
                elif mod==2:disp=4
                if disp:mem['disp']=int.from_bytes(take(disp),'little',signed=True)
                row['mem']=mem
            if row['kind'] in ('sse_0x10','sse_0x11','sse_0x28','sse_0x29','sse_0x57'):
                row['reg']='xmm'+str(group+(((rex>>2)&1)<<3))
                if mod==3:row['rm']='xmm'+str(rm+((rex&1)<<3))
            if op in (0x80,0x81,0x83):row['kind']=['add','or','adc','sbb','and','sub','xor','cmp'][group]
            elif op in (0xc6,0xc7):
                if group:raise EvidenceError('invalid move group')
                row['kind']='mov_imm_store'
            elif op in (0xf6,0xf7):
                if group not in (0,2,3):raise EvidenceError('unsupported unary group')
                row['kind']={0:'test',2:'not',3:'neg'}[group]
                if group==0:
                    imm=1 if op==0xf6 else (2 if width==16 else 4)
                    signed=op==0xf7 and width==64
            elif op in (0xff,0xfe):
                if op==0xfe:row['width']=8
                if group not in ((0,1) if op==0xfe else (0,1,2,4)):raise EvidenceError('unsupported ff group')
                row['kind']={0:'inc',1:'dec',2:'call_indirect',4:'jump_indirect'}[group]
            elif op==0xc1:
                if group not in (0,1,4,5,7):raise EvidenceError('unsupported shift')
                row['kind']={0:'rol',1:'ror',4:'shl',5:'shr',7:'sar'}[group]
            elif op in (0x6b,0x69):row['kind']='imul'
            if op in (0x80,0x81,0x83,0xc6,0xc7,0xf6,0xf7,0xff,0xfe,0xc1):
                row['group']=group
                del row['reg']
        if imm:row['immediate']=int.from_bytes(take(imm),'little',signed=signed)
        row['size']=p-start
        if row['size']>15:raise EvidenceError('oversized instruction')
        row['bytes']=body[start:p].hex()
        if row.get('mem',{}).get('base')=='rip':row['memory_va']=base+p+row['mem']['disp']
        rows.append(row)
    starts={r['va'] for r in rows}
    for r in rows:
        if 'target' in r and base<=r['target']<base+len(body) and r['target'] not in starts:
            raise EvidenceError('branch targets instruction interior')
    return rows


# Each anchor pins an instruction start, encoding and an interpretation used in
# the bounded analysis. Full bodies and all direct branches are retained too.
CONTRACTS = (
    ('binary-option-null-test', 0x13aa4f4, '3dc0000000'),
    ('binary-option-null-branch', 0x13aa4f9, '0f8480000000'),
    ('binary-option-null-store', 0x13aa582, '0f1103'),
    ('binary-option-map-call', 0x13aa59c, 'e86fe00000'),
    ('binary-option-map-error-test', 0x13aa5a1, '803c2409'),
    ('binary-option-map-present', 0x13aa5b9, '48c7430801000000'),
    ('binary-option-result-store', 0x13aa5db, '488903'),
    ('binary-key-count16', 0x13aa3b6, '83f801'),
    ('binary-key-count16-reject', 0x13aa3b9, '0f85e1000000'),
    ('binary-key-cached-map8', 0x13aa346, '81f980000000'),
    ('binary-key-count8', 0x13aa355, '83f801'),
    ('binary-key-count8-accept', 0x13aa358, '7465'),
    ('binary-key-count16-available', 0x13aa367, '4883f902'),
    ('binary-key-truncated16-consume', 0x13aa36d, '4801c8'),
    ('binary-key-truncated-clear', 0x13aa415, '48c7461800000000'),
    ('binary-key-count32-available', 0x13aa408, '4883fa04'),
    ('binary-key-truncated32-consume', 0x13aa40e, '4801d1'),
    ('binary-key-count16-big-endian', 0x13aa3a3, '66c1c208'),
    ('binary-key-count32-big-endian', 0x13aa48d, '0fc8'),
    ('binary-key-count32', 0x13aa497, '83f801'),
    ('binary-key-count32-accept', 0x13aa49a, '0f841fffffff'),
    ('binary-key-invalid-length-tag', 0x13aa4a0, 'c60304'),
    ('binary-key-invalid-length-value', 0x13aa4a3, '894304'),
    ('binary-key-unit-call', 0x13aa3c9, 'e8029a0400'),
    ('binary-key-scalar-call', 0x13aa42a, 'e8f10a0100'),
    ('binary-map-depth-load', 0x13b89a1, '0fb74622'),
    ('binary-map-depth-decrement', 0x13b89ae, '66ffc8'),
    ('binary-map-depth-store', 0x13b89b1, '66894622'),
    ('binary-map-key-call', 0x13b89fb, 'e8f018ffff'),
    ('binary-map-key-error-branch', 0x13b8a0f, '0f85b9000000'),
    ('binary-map-value-call', 0x13b8a20, 'e8ab520000'),
    ('binary-map-value-error-branch', 0x13b8a2f, '0f85b7000000'),
    ('binary-map-insert-call', 0x13b8a8c, 'e8ef301100'),
    ('binary-map-old-value-sentinel', 0x13b8a96, '48b80000000000000080'),
    ('binary-map-old-value-absent', 0x13b8aa3, '0f843fffffff'),
    ('binary-map-old-value-zero', 0x13b8aac, '0f8436ffffff'),
    ('binary-map-old-value-release', 0x13b8ab9, 'ff1551553b04'),
    ('binary-map-drop-on-error', 0x13b8b2d, 'e86e0e1200'),
    ('binary-map-depth-restore', 0x13b8be6, '66894622'),
    ('binary-value-primary-table', 0x13bdcea, '488d056363e5fe'),
    ('binary-value-secondary-bound', 0x13bdd1c, '4183f811'),
    ('binary-value-secondary-table', 0x13bdd26, '488d15ab66e5fe'),
    ('binary-value-normalized-table', 0x13be329, '4c8d15f060e5fe'),
    ('binary-value-fixed-length', 0x13bdee6, '0fb6c9'),
    ('binary-value-fixed-bound', 0x13bdeeb, '4929d8'),
    ('binary-value-short-payload', 0x13bdeee, '0f82ae000000'),
    ('binary-value-slice-cursor', 0x13bdeff, '48894610'),
    ('binary-value-slice-remaining', 0x13bdf03, '4c894618'),
    ('binary-value-slice-check', 0x13bdf12, 'ff15e0043b04'),
    ('binary-value-check-branch', 0x13bdf1d, '0f851b010000'),
    ('binary-value-build-call', 0x13bdf2e, 'e84da81100'),
    ('binary-value-result-check', 0x13bdf33, '807c240809'),
    ('binary-value-success-tag', 0x13bdf51, '41c60709'),
    ('binary-value-short-payload-tag', 0x13bdfa2, 'c60701'),
    ('binary-value-short-payload-detail', 0x13bdfa5, '48b80300000025000000'),
    ('binary-value-short-prefix-consume', 0x13bdfca, '4c01c0'),
    ('binary-value-short-prefix-clear', 0x13bdfd1, '48c7461800000000'),
    ('binary-value-short-prefix-tag', 0x13bdfd9, 'c60701'),
    ('binary-value-check-nonone-builder-call', 0x13be04b, 'e840a81100'),
    ('binary-unit-name-call', 0x13f3de7, 'e83471fcff'),
    ('binary-unit-table-base', 0x13f3e00, '488d15393ce2fe'),
    ('json-enum-name-call', 0x13f35f7, 'e814360c00'),
    ('json-enum-value-table', 0x13f3609, '488d0de042e2fe'),
    ('json-enum-unit-table', 0x13f36e4, '488d0d1542e2fe'),
    ('json-enum-unit-call', 0x13f36f4, 'e877370c00'),
    ('json-name-length-seven', 0x13f41a3, '4883fa07'),
    ('json-name-length-five', 0x13f41a9, '4883fa05'),
    ('json-name-error-table', 0x13f421f, '4c8d0522402704'),
    ('json-name-error-count', 0x13f4226, 'b904000000'),
    ('json-name-error-call', 0x13f4237, 'e884130600'),
    ('json-name-quoted-call', 0x14b6cda, 'e8c1d4f3ff'),
    ('json-option-whitespace-mask', 0x1441bc7, '49b80026000001000000'),
    ('json-option-first-n', 0x1441c0c, '4183f96e'),
    ('json-option-non-null-to-map', 0x1441c10, '7577'),
    ('json-option-second-u', 0x1441c3b, '4180f875'),
    ('json-option-third-l', 0x1441c5c, '4180f86c'),
    ('json-option-fourth-l', 0x1441c74, '80f96c'),
    ('json-option-null-tag', 0x1441c79, '48c70300000000'),
    ('json-option-map-call', 0x1441c8c, 'e89f8c0700'),
    ('json-option-map-error-test', 0x1441c95, '833c2401'),
    ('json-option-error-tag', 0x1441ca3, 'b802000000'),
    ('json-option-present-tag', 0x1441cbd, 'b801000000'),
    ('json-option-output-tag-store', 0x1441cc2, '488903'),
    ('json-option-truncated-code', 0x1441cce, '48c7042405000000'),
    ('json-option-error-constructor', 0x1441cdf, 'e84ce40500'),
    ('json-option-invalid-code', 0x1441cf8, '48c7042409000000'),
    ('json-map-object-test', 0x14ba9b0, '83ff7b'),
    ('json-map-object-reject', 0x14ba9b3, '0f8589040000'),
    ('json-map-depth-decrement', 0x14ba9c6, 'feca'),
    ('json-map-depth-store', 0x14ba9c8, '41885648'),
    ('json-map-key-quote', 0x14baacf, '4180f822'),
    ('json-map-key-quote-reject', 0x14baad3, '0f85ba030000'),
    ('json-map-key-call', 0x14baadc, 'e89f8af3ff'),
    ('json-map-colon-test', 0x14bab3b, '4883fe3a'),
    ('json-map-value-call', 0x14bab5a, 'e891350000'),
    ('json-map-value-reject', 0x14bab6a, '0f80c5020000'),
    ('json-map-insert-call', 0x14babbb, 'e8c00f0100'),
    ('json-map-old-value-sentinel', 0x14babc5, '48b80000000000000080'),
    ('json-map-old-value-release-slot', 0x14babd2, '488b0537342b04'),
    ('json-map-old-value-absent', 0x14babd9, '740e'),
    ('json-map-old-value-zero', 0x14babde, '7409'),
    ('json-map-old-value-release', 0x14babe7, 'ffd0'),
    ('json-map-restore-depth', 0x14bad23, '41884648'),
    ('json-map-close-call', 0x14bad2a, 'e8c154feff'),
    ('json-map-error-priority', 0x14bad53, '7553'),
    ('json-map-drop-on-close-error', 0x14bad58, '0f850b010000'),
    ('json-map-syntax-eof', 0x14ba990, '48c744241005000000'),
    ('json-map-syntax-close', 0x14bac01, '48c744241003000000'),
    ('json-map-syntax-comma', 0x14bae78, '48c744241008000000'),
    ('json-map-syntax-trailing-comma', 0x14bae9c, '48c744241015000000'),
    ('json-map-syntax-key', 0x14baeb7, '48c744241011000000'),
    ('json-map-syntax-colon', 0x14baed2, '48c744241006000000'),
    ('map-insert-node-count', 0x14cbba5, '440fb79812010000'),
    ('map-insert-key-byte', 0x14cbbca, '460fb6bc0815010000'),
    ('map-insert-entry-stride', 0x14cbbe1, '4983c218'),
    ('map-insert-equality', 0x14cbbf5, '741c'),
    ('map-replace-old', 0x14cbc13, '498b4210'),
    ('map-replace-write', 0x14cbc25, '410f1102'),
    ('map-insert-first-node-bytes', 0x14cbca1, 'bf20010000'),
    ('map-insert-node-count-store', 0x14cbce5, '6689b812010000'),
    ('map-insert-key-store', 0x14cbcec, '4088ac1014010000'),
    ('map-insert-length', 0x14cbd07, '48ff4110'),
    ('map-insert-absent-sentinel', 0x14cbd0b, '48b80000000000000080'),
    ('global-name-slot', 0x1404efb, '488b1d269a3604'),
    ('global-name-lazy-state', 0x1404f02, '8b4350'),
    ('global-name-lazy-test', 0x1404f05, '85c0'),
    ('global-name-lazy-branch', 0x1404f07, '7519'),
    ('global-name-byte', 0x1404f09, '0fb64348'),
    ('global-name-test-first', 0x1404f0d, '83f805'),
    ('global-name-first-branch', 0x1404f10, '7453'),
    ('global-name-test-second', 0x1404f12, '83f811'),
    ('global-name-other-branch', 0x1404f15, '0f8591010000'),
    ('global-name-second-key', 0x1404f1b, 'bb03000000'),
    ('global-name-lazy-call', 0x1404f53, 'ff155f993604'),
    ('global-name-after-lazy-byte', 0x1404f5c, '0fb64348'),
    ('global-name-after-lazy-first', 0x1404f60, '83f805'),
    ('global-name-after-lazy-branch', 0x1404f63, '75ad'),
    ('global-name-first-key', 0x1404f65, 'bb02000000'),
    ('global-map-slot', 0x1404f6a, '4c8b35ff9b3604'),
    ('global-map-lazy-state', 0x1404f71, '418b8668020000'),
    ('global-map-lazy-test', 0x1404f78, '85c0'),
    ('global-map-lazy-branch', 0x1404f7a, '0f85e5000000'),
    ('global-map-present-test', 0x1404f80, '41833e01'),
    ('global-map-absent-branch', 0x1404f84, '0f8522010000'),
    ('global-map-root-test', 0x1404f8e, '4885c0'),
    ('global-map-root-empty-branch', 0x1404f91, '0f8415010000'),
    ('global-map-node-count', 0x1404f9b, '0fb7b012010000'),
    ('global-map-node-key', 0x1404fca, '440fb6941015010000'),
    ('global-map-entry-stride', 0x1404fe1, '4983c018'),
    ('global-map-match-branch', 0x1404ff4, '7421'),
    ('global-map-child-pointer', 0x140500d, '488b84d020010000'),
    ('global-map-search-miss-branch', 0x1405007, '0f829f000000'),
    ('global-map-copy-value', 0x140504c, 'ff158e8f3604'),
    ('global-map-empty-copy-branch', 0x1405024, '7417'),
    ('global-map-allocate-value', 0x1405029, 'ff15a98f3604'),
    ('global-map-allocation-failure', 0x1405032, '0f8490000000'),
    ('global-map-empty-copy-pointer', 0x140503d, '41bf01000000'),
    ('global-map-output-capacity', 0x1405055, '49891c24'),
    ('global-map-output-pointer', 0x1405059, '4d897c2408'),
    ('global-map-output-length', 0x140505e, '49895c2410'),
    ('global-map-absent', 0x14050ac, '48b80000000000000080'),
    ('global-map-absent-result-store', 0x14050b6, '488907'),
)


def row_at(rows, address, kind=None):
    row = rows.get(address)
    require(row is not None, 'required instruction is not a decoded start')
    if kind is not None:
        require(row['kind'] == kind, 'required instruction kind changed')
    return row


def little_word(row, width):
    require(row['kind'] == 'mov_imm' and row['width'] == 8 * width,
            'expected fixed-width immediate')
    return row['immediate'].to_bytes(width, 'little')


def code_names(rows):
    """Recover four exact name constraints from selected classifier bytes."""
    first = little_word(row_at(rows, 0x13f41af), 4)
    end = row_at(rows, 0x13f41ba, 'xor')['immediate']
    names = [first + bytes([end])]
    for start, tail in ((0x13f41ca, 0x13f41d1),
                        (0x13f41dd, 0x13f41e4),
                        (0x13f41f0, 0x13f41f7)):
        a = little_word(row_at(rows, start), 4)
        b = little_word(row_at(rows, tail), 4)
        require(a[3] == b[0], 'overlapping name bytes disagree')
        names.append(a + b[1:])
    require(row_at(rows, 0x13f41a3, 'cmp')['immediate'] == 7, 'seven-byte bound changed')
    require(row_at(rows, 0x13f41a9, 'cmp')['immediate'] == 5, 'five-byte bound changed')
    for va, index in ((0x13f41c1, 0), (0x13f420c, 1),
                      (0x13f4215, 2), (0x13f4203, 3)):
        row = row_at(rows, va, 'mov_imm_store')
        require(row['immediate'] == index and row['mem']['base'] == 'rax'
                and row['mem']['disp'] == 1, 'classifier result byte changed')
    return names


def classify_name(names, candidate):
    """Abstract classifier contract after JSON string decoding, not target execution."""
    if not isinstance(candidate, bytes):
        raise ValueError('candidate must be bytes')
    for index, name in enumerate(names):
        if candidate == name:
            return index
    return None


def normalized_marker(byte):
    """Model the selected optional reader's marker class; not a target execution."""
    if not isinstance(byte, int) or isinstance(byte, bool) or not 0 <= byte <= 255:
        raise ValueError('marker byte outside byte domain')
    if byte < 0x80:
        return 0
    if byte < 0x90:
        return 0x80
    if byte < 0xa0:
        return 0x90
    if byte < 0xc0:
        return 0xa0
    if byte <= 0xdf:
        return byte
    return 0xe0


def selected_key(policy, name_byte):
    """Model only the two byte tests in the selected global lookup."""
    if not isinstance(name_byte, int) or isinstance(name_byte, bool) or not 0 <= name_byte <= 255:
        raise ValueError('configuration byte outside byte domain')
    return policy.get(name_byte)


def model_binary_key_gate(encoded):
    """Model fresh marker and map-length prefix only, not the delegated reader."""
    if not isinstance(encoded, bytes):
        raise ValueError('encoded prefix must be bytes')
    if not encoded:
        return {'form': 'fresh_eof', 'prefix_consumed': 0, 'count': None, 'outcome': 'eof_tag_0'}
    marker = encoded[0]
    if 0x80 <= marker <= 0x8f:
        form, consumed, count = 'fixed_map', 1, marker & 0x0f
    elif marker in (0xde, 0xdf):
        width = 2 if marker == 0xde else 4
        form = 'map16' if width == 2 else 'map32'
        if len(encoded) - 1 < width:
            return {'form': form, 'prefix_consumed': len(encoded), 'count': None,
                    'outcome': 'truncated_delegate_scalar'}
        consumed, count = width + 1, int.from_bytes(encoded[1:1 + width], 'big')
    else:
        return {'form': 'other_marker', 'prefix_consumed': 1, 'count': None,
                'outcome': 'delegate_scalar'}
    return {'form': form, 'prefix_consumed': consumed, 'count': count,
            'outcome': 'call_unit_reader' if count == 1 else 'length_error_tag_4'}


def model_json_option_prefix(encoded):
    """Model the local null prefix gate, excluding the delegated map reader."""
    if not isinstance(encoded, bytes):
        raise ValueError('encoded prefix must be bytes')
    cursor = 0
    while cursor < len(encoded) and encoded[cursor] in b' \t\n\r':
        cursor += 1
    if cursor == len(encoded) or encoded[cursor] != ord('n'):
        return {'cursor': cursor, 'outcome': 'delegate_map', 'local_tag': None}
    for expected in b'null':
        if cursor == len(encoded):
            return {'cursor': cursor, 'outcome': 'truncated_null_code_5', 'local_tag': 2}
        actual = encoded[cursor]
        cursor += 1
        if actual != expected:
            return {'cursor': cursor, 'outcome': 'invalid_null_code_9', 'local_tag': 2}
    return {'cursor': cursor, 'outcome': 'null', 'local_tag': 0}


def model_binary_value_prefix(encoded):
    """Model selected fresh string/byte-slice markers with the caller's flag 1.

    This ends at an external slice check or value builder. It is not a decoder
    for the other marker kinds or a model of those helpers' results.
    """
    if not isinstance(encoded, bytes):
        raise ValueError('encoded prefix must be bytes')
    if not encoded:
        return {'form': 'fresh_eof', 'cursor': 0, 'length': None, 'outcome': 'eof_tag_0'}
    marker = encoded[0]
    if 0xa0 <= marker <= 0xbf:
        form, width, length = 'fixed_string', 0, marker & 0x1f
    elif marker in (0xd9, 0xda, 0xdb, 0xc4, 0xc5, 0xc6):
        form = 'string' if marker in (0xd9, 0xda, 0xdb) else 'bytes'
        width = {0xd9: 1, 0xda: 2, 0xdb: 4, 0xc4: 1, 0xc5: 2, 0xc6: 4}[marker]
        if len(encoded) - 1 < width:
            return {'form': form, 'cursor': len(encoded), 'length': None,
                    'outcome': 'short_length_tag_1'}
        length = int.from_bytes(encoded[1:1 + width], 'big')
    else:
        return {'form': 'other_marker', 'cursor': 1, 'length': None,
                'outcome': 'other_dispatch_boundary'}
    cursor = 1 + width
    if len(encoded) - cursor < length:
        return {'form': form, 'cursor': cursor, 'length': length,
                'outcome': 'short_payload_tag_1'}
    cursor += length
    return {'form': form, 'cursor': cursor, 'length': length,
            'outcome': 'slice_check_boundary' if form != 'bytes' else 'value_builder_boundary'}


def relative_table(image, base, count, valid_starts):
    require(count > 0 and count <= 256, 'invalid table size')
    raw = image.read(base, 4 * count)
    values = [base + struct.unpack_from('<i', raw, 4 * i)[0] for i in range(count)]
    require(all(value in valid_starts for value in values), 'table target is not an admitted instruction start')
    return values


def text_rows(image, base, count):
    result = []
    for index in range(count):
        slot = base + 16 * index
        entry_bytes = image.read(slot, 16)
        length = struct.unpack_from('<Q', entry_bytes, 8)[0]
        require(0 < length <= 32, 'invalid string slice length')
        address = image.relative(slot)
        raw = image.read(address, length)
        rela_offset, rela_bytes = image.relative_record(slot)
        result.append({'slot_va': slot, 'text_va': address, 'length': length,
                       'slot_file_offset': image.offset(slot, 16),
                       'text_file_offset': image.offset(address, length),
                       'slot_bytes': entry_bytes.hex(), 'bytes': raw.hex(),
                       'rela_file_offset': rela_offset, 'rela_bytes': rela_bytes,
                       'text': raw.decode('ascii')})
    return result


def control_flow(result):
    """Structural paths through selected FDEs, with external calls opaque.

    These are graph queries, not execution: condition flags and values are not
    propagated, and exceptional transfers are recorded separately. Therefore a
    witness is a possible structural path, not proof that an input reaches it.
    """
    at = {row['va']: row for row in result['instructions']}
    functions = {row['entry']: row for row in result['functions']}
    graph = {}
    for va, row in sorted(at.items()):
        function = row['function']
        end = functions[function]['end']
        following = va + row['size']
        kind = row['kind']
        if kind in ('ret', 'trap', 'jump_indirect'):
            # Table-driven transfers are excluded rather than guessed; none of
            # the following bounded queries requires an indirect jump.
            destinations = []
        elif kind == 'jump':
            target = row['target']
            destinations = [target] if target in at and at[target]['function'] == function else []
        elif kind.startswith('j') and 'target' in row:
            destinations = [row['target'], following]
        else:
            # Calls, including no-return helpers, are conservatively treated as
            # returning. Extra edges weaken absence results rather than hiding paths.
            destinations = [following] if following < end else []
        require(all(dest in at and at[dest]['function'] == function for dest in destinations),
                'CFG edge enters an instruction interior or other FDE')
        graph[va] = sorted(set(destinations))

    def reach(start, goal, blocked):
        blocked = set(blocked)
        require(start in at and goal in at and all(v in at for v in blocked),
                'unknown CFG query address')
        if start in blocked:
            return None, set()
        pending, parents = [start], {start: None}
        for node in pending:
            if node == goal:
                path = []
                while node is not None:
                    path.append(node)
                    node = parents[node]
                return list(reversed(path)), set(parents)
            for dest in graph[node]:
                if dest not in blocked and dest not in parents:
                    parents[dest] = node
                    pending.append(dest)
        return None, set(parents)

    binary_depth_stores = tuple(row['va'] for row in result['stores']
                                if row['function'] == 0x13b8610 and row['kind'] == 'mov_store'
                                and row['width'] == 16 and row['mem']['base'] in ('rsi', 'r14')
                                and row['mem']['index'] is None and row['mem']['disp'] == 0x22)
    require(0x13b89b1 in binary_depth_stores and 0x13b8be6 in binary_depth_stores,
            'binary depth-store selection changed')
    queries = (
        ('binary_null_bypasses_map_call', 0x13aa57f, 0x13aa58d, (0x13aa59c,), True),
        ('json_null_bypasses_map_call', 0x1441c79, 0x1441c88, (0x1441c8c,), True),
        ('json_non_null_reaches_map_call', 0x1441c89, 0x1441c91, (0x1441c8c,), False),
        ('binary_key_error_bypasses_depth_restore', 0x13b8ace, 0x13b8e1e, binary_depth_stores, True),
        ('binary_value_error_bypasses_depth_restore', 0x13b8aec, 0x13b8e1e, binary_depth_stores, True),
        ('binary_key_error_requires_map_drop', 0x13b8ace, 0x13b8e1e, (0x13b8b2d,), False),
        ('binary_value_error_requires_map_drop', 0x13b8aec, 0x13b8e1e, (0x13b8b2d,), False),
        ('binary_string_slice_check_required', 0x13bdee6, 0x13bdf18, (0x13bdf12,), False),
        ('binary_short_payload_bypasses_slice_check', 0x13bdfa2, 0x13be37a, (0x13bdf12,), True),
        ('binary_check_nonone_calls_builder_boundary', 0x13be03e, 0x13be053, (0x13be04b,), False),
        ('binary_success_requires_depth_restore', 0x13b8bb3, 0x13b8e72, (0x13b8be6,), False),
        ('json_key_error_requires_depth_restore', 0x14bae2b, 0x14bad2a, (0x14bad23,), False),
        ('json_value_error_requires_depth_restore', 0x14bae35, 0x14bad2a, (0x14bad23,), False),
        ('json_error_cleanup_calls_map_drain', 0x14bac1a, 0x14bad14, (0x14bac8c,), False),
        ('json_close_error_drops_map', 0x14bae69, 0x14bae16, (0x14bae71,), False),
        ('replacement_bypasses_collection_increment', 0x14cbc13, 0x14cbd18, (0x14cbd07,), True),
        ('fresh_insertion_requires_collection_increment', 0x14cbca1, 0x14cbd18, (0x14cbd07,), False),
        ('global_absent_requires_sentinel_store', 0x14050ac, 0x14050b9, (0x14050b6,), False),
        ('global_found_can_return_without_absent_sentinel', 0x1405017, 0x14050b9, (0x14050b6,), True),
    )
    propositions = []
    for label, start, goal, forbidden, expected in queries:
        path, visited = reach(start, goal, forbidden)
        require((path is not None) == expected, 'CFG proposition changed: ' + label)
        if path is None:
            require(not any(at[va]['kind'] == 'jump_indirect' for va in visited),
                    'unmodeled indirect jump invalidates CFG absence')
        propositions.append({'label': label, 'start': start, 'goal': goal,
                             'forbidden': list(forbidden), 'reachable': path is not None,
                             'witness': path or []})
    return propositions


def exception_sites(image, result):
    """Selected LSDA call-site ranges; action/type semantics remain unknown."""
    at = {row['va']: row for row in result['instructions']}
    rows = []
    headers = []
    for function in result['functions']:
        address = function['lsda']
        if address is None:
            continue
        # Bound the read by the next LSDA pointer and the exception section,
        # not by an invented object size or an adjacent section's bytes.
        section = next(s for s in image.sections if s['name'] == '.gcc_except_table')
        upper = section['address'] + section['size']
        require(section['address'] <= address < upper, 'LSDA outside exception section')
        following = [f['lsda'] for f in image.fdes
                     if f['lsda'] is not None and address < f['lsda'] < upper]
        if following:
            upper = min(following)
        raw = image.read(address, upper - address)
        require(len(raw) >= 4 and raw[0] == 0xff, 'unsupported LSDA landing-pad base')
        type_encoding = raw[1]
        require(type_encoding in (0xff, 0x9b), 'unsupported LSDA type encoding')
        pos = 2
        type_base = None
        if type_encoding != 0xff:
            displacement, pos = uleb(raw, pos, len(raw))
            type_base = pos + displacement
            require(type_base <= len(raw), 'LSDA type base outside bounded region')
        require(pos < len(raw) and raw[pos] == 1, 'unsupported LSDA call-site encoding')
        pos += 1
        length, pos = uleb(raw, pos, len(raw))
        table_end = pos + length
        require(table_end <= len(raw) and (type_base is None or table_end <= type_base),
                'LSDA call-site table exceeds bounded region')
        headers.append({'function': function['entry'], 'lsda': address,
                        'file_offset': image.offset(address, 1), 'upper_bound': upper,
                        'header_bytes': raw[:pos].hex(), 'table_bytes': length,
                        'type_encoding': type_encoding,
                        'type_base': None if type_base is None else address + type_base})
        previous_end = 0
        while pos < table_end:
            entry_offset = pos
            values = []
            for _ in range(4):
                value, pos = uleb(raw, pos, table_end)
                values.append(value)
            start, size, landing, action = values
            require(size > 0 and start >= previous_end and start + size <= function['byte_count'],
                    'invalid LSDA call-site extent')
            first, end = function['entry'] + start, function['entry'] + start + size
            require(first in at and (end in at or end == function['end']),
                    'LSDA range is not aligned to instructions')
            dest = function['entry'] + landing if landing else None
            require(dest is None or (dest in at and at[dest]['function'] == function['entry']),
                    'LSDA landing pad is not an instruction in this FDE')
            transfers = [row['va'] for row in result['calls'] if first <= row['va'] < end]
            rows.append({'function': function['entry'], 'lsda': address,
                         'record_va': address + entry_offset,
                         'record_bytes': raw[entry_offset:pos].hex(), 'start': first,
                         'end': end, 'landing': dest, 'action': action,
                         'transfers': transfers, 'type_encoding': type_encoding,
                         'type_base': None if type_base is None else address + type_base})
            previous_end = start + size
        require(pos == table_end, 'LSDA call-site table incomplete')
    return headers, rows

CONTRACTS += (
    ('marker-fresh-read', 0x13aa518, '0fb602'),
    ('marker-signed-test', 0x13aa526, '84c0'),
    ('marker-negative-branch', 0x13aa528, '7825'),
    ('marker-positive-payload', 0x13aa52a, '89c1'),
    ('marker-positive-class', 0x13aa52c, '31c0'),
    ('marker-positive-done', 0x13aa52e, 'eb5e'),
    ('marker-high-threshold', 0x13aa54f, '3cdf'),
    ('marker-high-branch', 0x13aa551, '7606'),
    ('marker-high-payload', 0x13aa553, '89c1'),
    ('marker-high-class', 0x13aa555, 'b0e0'),
    ('marker-high-done', 0x13aa557, 'eb35'),
    ('marker-map-threshold', 0x13aa559, '3c90'),
    ('marker-map-branch', 0x13aa55b, '7308'),
    ('marker-map-mask', 0x13aa55d, '240f'),
    ('marker-map-payload', 0x13aa55f, '89c1'),
    ('marker-map-class', 0x13aa561, 'b080'),
    ('marker-map-done', 0x13aa563, 'eb29'),
    ('marker-array-threshold', 0x13aa565, '3ca0'),
    ('marker-array-branch', 0x13aa567, '7308'),
    ('marker-array-mask', 0x13aa569, '240f'),
    ('marker-array-payload', 0x13aa56b, '89c1'),
    ('marker-array-class', 0x13aa56d, 'b090'),
    ('marker-array-done', 0x13aa56f, 'eb1d'),
    ('marker-string-threshold', 0x13aa571, '3cc0'),
    ('marker-string-branch', 0x13aa573, '7308'),
    ('marker-string-mask', 0x13aa575, '241f'),
    ('marker-string-payload', 0x13aa577, '89c1'),
    ('marker-string-class', 0x13aa579, 'b0a0'),
    ('marker-string-done', 0x13aa57b, 'eb11'),
    ('marker-null-or-other', 0x13aa57d, '750f'),
    ('marker-primary-table', 0x13b8635, '488d056c93e5fe'),
    ('marker-secondary-bound', 0x13b8663, '83ff11'),
    ('marker-secondary-table', 0x13b866c, '488d15b996e5fe'),
    ('map-duplicate-return', 0x14cbc31, 'e9e2000000'),
    ('map-branch-count-full', 0x14cbcd4, '4883fa0b'),
    ('classifier-local-head-xor', 0x13f41b4, '330e'),
    ('classifier-local-tail-load', 0x13f41b6, '0fb67e04'),
    ('classifier-local-combine', 0x13f41bd, '09cf'),
    ('classifier-local-reject', 0x13f41bf, '755d'),
    ('classifier-sandbox-head-xor', 0x13f41cf, '330e'),
    ('classifier-sandbox-tail-xor', 0x13f41d6, '337e03'),
    ('classifier-sandbox-combine', 0x13f41d9, '09cf'),
    ('classifier-sandbox-equal', 0x13f41db, '742f'),
    ('classifier-testnet-head-xor', 0x13f41e2, '330e'),
    ('classifier-testnet-tail-xor', 0x13f41e9, '337e03'),
    ('classifier-testnet-combine', 0x13f41ec, '09cf'),
    ('classifier-testnet-equal', 0x13f41ee, '7425'),
    ('classifier-mainnet-head-xor', 0x13f41f5, '330e'),
    ('classifier-mainnet-tail-xor', 0x13f41fc, '337e03'),
    ('classifier-mainnet-combine', 0x13f41ff, '09cf'),
    ('classifier-mainnet-reject', 0x13f4201, '751b'),
)


def collect(image, check_body_hashes=True):
    functions = []
    rows = []
    starts_by_function = {}
    for entry, (role, expected_end, expected_hash) in sorted(BODIES.items()):
        fde = image.fde(entry)
        require(fde['end'] == expected_end, 'FDE extent differs')
        body = image.read(entry, expected_end - entry)
        decoded = decode(body, entry)
        require(decoded and decoded[0]['va'] == entry, 'empty function body')
        starts_by_function[entry] = {r['va'] for r in decoded}
        digest = hashlib.sha256(body).hexdigest()
        functions.append({'entry': entry, 'end': fde['end'], 'fde': fde['fde'],
                          'cie': fde['cie'], 'lsda': fde['lsda'],
                          'file_offset': image.offset(entry, len(body)),
                          'byte_count': len(body), 'instruction_count': len(decoded),
                          'sha256': digest})
        for row in decoded:
            row['function'] = entry
            row['file_offset'] = image.offset(row['va'], row['size'])
            rows.append(row)
    by_va = {r['va']: r for r in rows}
    require(len(by_va) == len(rows), 'overlapping selected instruction starts')
    contract_rows = []
    for label, address, expected in CONTRACTS:
        row = row_at(by_va, address)
        require(row['bytes'] == expected, 'changed instruction contract: ' + label)
        contract_rows.append({'label': label, 'function': row['function'],
                              'va': address, 'file_offset': row['file_offset'],
                              'bytes': row['bytes'], 'kind': row['kind'],
                              'immediate': row.get('immediate'), 'target': row.get('target'),
                              'memory_va': row.get('memory_va')})
    if check_body_hashes:
        for f in functions:
            require(f['sha256'] == BODIES[f['entry']][2], 'selected body hash mismatch')
    names = code_names(by_va)
    count = row_at(by_va, 0x13f4226, 'mov_imm')['immediate']
    require(count == len(names), 'name count differs')
    descriptor_base = row_at(by_va, 0x13f421f, 'lea')['memory_va']
    descriptors = text_rows(image, descriptor_base, count)
    require([r['text'].encode('ascii') for r in descriptors] == names,
            'classifier immediates and relocated strings differ')
    first_name = row_at(by_va, 0x1404f0d, 'cmp')['immediate']
    second_name = row_at(by_va, 0x1404f12, 'cmp')['immediate']
    first_key = row_at(by_va, 0x1404f65, 'mov_imm')['immediate']
    second_key = row_at(by_va, 0x1404f1b, 'mov_imm')['immediate']
    require(first_name != second_name and first_key != second_key, 'policy cases collapse')
    require(first_key < count and second_key < count, 'policy key outside name domain')
    policy = {first_name: first_key, second_name: second_key}
    aws_base = 0x5668288  # Existing descriptor base, not a new 76-entry export.
    aws_rows = []
    for index in sorted(set(policy) | {32}):
        one = text_rows(image, aws_base + 16 * index, 1)[0]
        one['index'] = index
        one['role'] = 'selected' if index in policy else 'existing_default_context'
        aws_rows.append(one)
    require([r['text'] for r in aws_rows] == ['NodeTestnet', 'Ee', 'NvTestnet'],
            'selected name descriptors differ')
    global_name_slot = row_at(by_va, 0x1404efb, 'mov_load')['memory_va']
    global_map_slot = row_at(by_va, 0x1404f6a, 'mov_load')['memory_va']
    relocs = [
        {'label': 'global_configuration_pointer', 'slot': global_name_slot,
         'target': image.relative(global_name_slot)},
        {'label': 'configuration_object_pointer', 'slot': global_map_slot,
         'target': image.relative(global_map_slot)},
    ]
    require(relocs[0]['target'] == 0x577b288 and relocs[1]['target'] == 0x577a898,
            'global pointer relocation changed')
    require(image.relative(relocs[0]['target']) == 0x164ff00, 'name initializer changed')
    require(image.relative(relocs[1]['target']) == 0x13d28e0, 'map initializer changed')
    relocs.extend([
        {'label': 'global_configuration_initializer', 'slot': relocs[0]['target'],
         'target': image.relative(relocs[0]['target'])},
        {'label': 'configuration_object_initializer', 'slot': relocs[1]['target'],
         'target': image.relative(relocs[1]['target'])},
    ])
    # The slot was previously referenced by a consumer; bind that pointer to
    # this selected entry without re-claiming or copying the consumer's body.
    lookup_slots = sorted(slot for slot, addend in image.relocations.items()
                          if addend == 0x1404ef0)
    require(lookup_slots == [0x576efe8], 'lookup entry pointer relocation changed')
    require(image.relative(lookup_slots[0]) == 0x1404ef0, 'lookup entry addend changed')
    relocs.append({'label': 'lookup_entry_pointer', 'slot': lookup_slots[0],
                   'target': image.relative(lookup_slots[0])})
    cleanup_slot = row_at(by_va, 0x14babd2, 'mov_load')['memory_va']
    require(cleanup_slot == row_at(by_va, 0x13b8ab9, 'call_indirect')['memory_va'],
            'duplicate-value cleanup slots differ')
    require(image.relative(cleanup_slot) == 0x54c8cb0, 'duplicate-value cleanup target changed')
    relocs.append({'label': 'duplicate_value_cleanup_slot', 'slot': cleanup_slot,
                   'target': image.relative(cleanup_slot)})
    for relocation in relocs:
        relocation['slot_file_offset'] = image.offset(relocation['slot'], 8)
        relocation['rela_file_offset'], relocation['rela_bytes'] = image.relative_record(relocation['slot'])
    # These edges are inside selected bodies; targets may be prior-work boundaries.
    call_expectations = {
        0x13aa3c9: 0x13f3dd0, 0x13aa42a: 0x13baf20,
        0x13aa59c: 0x13b8610, 0x13b89fb: 0x13aa2f0,
        0x13b8a20: 0x13bdcd0, 0x13b8a8c: 0x14cbb80,
        0x13f35f7: 0x14b6c10, 0x13f36f4: 0x14b6e70,
        0x14b6cda: 0x13f41a0, 0x14baadc: 0x13f3580,
        0x1441c8c: 0x14ba930,
        0x14bab5a: 0x14be0f0, 0x14babbb: 0x14cbb80,
        0x14bad2a: 0x14a01f0,
    }
    for site, target in call_expectations.items():
        require(row_at(by_va, site, 'call')['target'] == target, 'selected call target changed')
    require(row_at(by_va, 0x14cbc31, 'jump')['target'] == 0x14cbd18,
            'replacement no longer bypasses length increment')
    require(row_at(by_va, 0x13f41a7, 'je')['target'] == 0x13f41ca,
            'seven-byte classifier branch changed')
    require(row_at(by_va, 0x13f41ad, 'jne')['target'] == 0x13f421e,
            'classifier failure branch changed')
    require(row_at(by_va, 0x1404f63, 'jne')['target'] == 0x1404f12,
            'post-initializer name policy changed')
    for va, kind in ((0x1404f15, 'jne'), (0x1404f84, 'jne'),
                     (0x1404f91, 'je'), (0x1405007, 'jb')):
        require(row_at(by_va, va, kind)['target'] == 0x14050ac,
                'global failure branch no longer shares absent result')
    # Count marker entries from adjacent table bases, not from a disassembler.
    marker_base = row_at(by_va, 0x13b8635, 'lea')['memory_va']
    secondary_base = row_at(by_va, 0x13b866c, 'lea')['memory_va']
    require(secondary_base > marker_base and (secondary_base - marker_base) % 4 == 0,
            'marker-table span changed')
    marker_count = (secondary_base - marker_base) // 4
    require(marker_count == 225, 'marker table no longer covers the normalized domain')
    secondary_count = row_at(by_va, 0x13b8663, 'cmp')['immediate'] + 1
    marker = relative_table(image, marker_base, marker_count, starts_by_function[0x13b8610])
    secondary = relative_table(image, secondary_base, secondary_count, starts_by_function[0x13b8610])
    value_base = row_at(by_va, 0x13bdcea, 'lea')['memory_va']
    value_secondary_base = row_at(by_va, 0x13bdd26, 'lea')['memory_va']
    value_normalized_base = row_at(by_va, 0x13be329, 'lea')['memory_va']
    require(value_base < value_secondary_base < value_normalized_base
            and (value_secondary_base - value_base) % 4 == 0
            and (value_normalized_base - value_secondary_base) % 4 == 0,
            'binary value table spans changed')
    value_count = (value_secondary_base - value_base) // 4
    value_secondary_count = (value_normalized_base - value_secondary_base) // 4
    require(value_count == marker_count
            and value_secondary_count == row_at(by_va, 0x13bdd1c, 'cmp')['immediate'] + 1,
            'binary value table count changed')
    first_normalized = row_at(by_va, 0x13be292, 'cmp')['immediate']
    last_normalized = row_at(by_va, 0x13be119, 'cmp')['immediate']
    value_normalized_count = last_normalized - first_normalized + 1
    require((first_normalized, last_normalized) == (0xc0, 0xdf), 'normalized marker range changed')
    value_starts = starts_by_function[0x13bdcd0]
    value_table = relative_table(image, value_base, value_count, value_starts)
    value_secondary = relative_table(image, value_secondary_base, value_secondary_count, value_starts)
    value_normalized = relative_table(image, value_normalized_base, value_normalized_count, value_starts)
    for marker_kind, destination in ((0xa0, 0x13bdee2), (0xc4, 0x13bdd84),
                                     (0xc5, 0x13bdd56), (0xc6, 0x13bdda0),
                                     (0xd9, 0x13bdf79), (0xda, 0x13bdfb8), (0xdb, 0x13bdf5d)):
        require(value_table[marker_kind] == destination, 'value marker dispatch changed')
    for marker_kind, destination in ((0xc4, 0x13bdd8c), (0xc5, 0x13bdd5e),
                                     (0xc6, 0x13bdda8), (0xd9, 0x13bdf81),
                                     (0xda, 0x13bdfc0), (0xdb, 0x13bdf65)):
        require(value_normalized[marker_kind - first_normalized] == destination,
                'fresh normalized value dispatch changed')
    quote_base = row_at(by_va, 0x13f3609, 'lea')['memory_va']
    unit_base = row_at(by_va, 0x13f36e4, 'lea')['memory_va']
    binary_unit_base = row_at(by_va, 0x13f3e00, 'lea')['memory_va']
    quote = relative_table(image, quote_base, count, starts_by_function[0x13f3580])
    unit = relative_table(image, unit_base, count, starts_by_function[0x13f3580])
    binary_unit = relative_table(image, binary_unit_base, count, starts_by_function[0x13f3dd0])
    for index, target in enumerate(quote):
        row = row_at(by_va, target, 'mov_imm_store')
        require(row['immediate'] == index and row['mem']['base'] == 'rbx'
                and row['mem']['disp'] == 1, 'quote dispatch does not preserve code')
    require(all(target == 0x13f36f4 for target in unit), 'unit dispatch is not shared')
    require(binary_unit[:2] == [0x13f3e10] * 2
            and binary_unit[2:] == [0x13f3e78] * 2, 'binary unit dispatch differs')
    table_rows = []
    for label, base, values in (('binary-marker', marker_base, marker),
                                ('binary-marker-secondary', secondary_base, secondary),
                                ('binary-value-marker', value_base, value_table),
                                ('binary-value-secondary', value_secondary_base, value_secondary),
                                ('binary-value-normalized', value_normalized_base, value_normalized),
                                ('json-quoted-name', quote_base, quote),
                                ('json-unit', unit_base, unit),
                                ('binary-unit', binary_unit_base, binary_unit)):
        for index, target in enumerate(values):
            slot = base + 4 * index
            table_rows.append({'table': label, 'index': index, 'slot': slot,
                               'slot_file_offset': image.offset(slot, 4),
                               'bytes': image.read(slot, 4).hex(), 'target': target})
    marker_cases = []
    for raw in range(1 << row_at(by_va, 0x13aa518, 'extend')['source_width']):
        kind = normalized_marker(raw)
        require(kind < len(marker), 'normalized marker leaves table')
        if raw == 0xc0:
            payload_mode, payload_value = 'unused_null', None
        elif 0xc1 <= raw <= 0xdf:
            payload_mode, payload_value = 'previous_cached_byte', None
        elif 0x80 <= raw < 0xa0:
            payload_mode, payload_value = 'low_four_bits', raw & 0x0f
        elif 0xa0 <= raw < 0xc0:
            payload_mode, payload_value = 'low_five_bits', raw & 0x1f
        else:
            payload_mode, payload_value = 'raw_byte', raw
        marker_cases.append({'raw_byte': raw, 'normalized_kind': kind,
                             'payload_mode': payload_mode, 'payload_value': payload_value,
                             'option_null': raw == 0xc0,
                             'map_table_target': None if raw == 0xc0 else marker[kind]})
    policy_cases = []
    for byte in (0, 4, first_name, 6, 16, second_name, 18, 31, 32, 33, 75, 76, 255):
        policy_cases.append({'configuration_byte': byte, 'selected_key': selected_key(policy, byte)})
    prefixes = ([b'', b'\x00', b'\x7f', b'\xc0'] + [bytes([0x80 | n]) for n in range(16)] +
                [bytes.fromhex(s) for s in ('de', 'de00', 'de0000', 'de0001', 'de0002',
                                            'de00ff', 'de0100', 'deffff', 'df', 'df00',
                                            'df0000', 'df000000', 'df00000000', 'df00000001',
                                            'df00000002', 'df0000ffff', 'df00010000', 'dfffffffff')])
    gate_cases = []
    for prefix in prefixes:
        case = model_binary_key_gate(prefix)
        case['prefix_hex'] = prefix.hex()
        gate_cases.append(case)
    json_prefixes = (b'', b' ', b'\t\n\r ', b'null', b'nullx', b'n', b'nu', b'nul',
                     b'nX', b'nuX', b'nulX', b'N', b'false', b'{}', b'  null',
                     b'\tnu', b' nullx', b'n\x00ll', b' null', b'\vnull')
    json_cases = []
    for prefix in json_prefixes:
        case = model_json_option_prefix(prefix)
        case['prefix_hex'] = prefix.hex()
        json_cases.append(case)
    value_prefixes = (b'', b'\x00', b'\xa0', b'\xa1', b'\xa1a', b'\xa2a', b'\xa2ab',
                      b'\xbf', b'\xd9', b'\xd9\x00', b'\xd9\x01a', b'\xd9\x02a',
                      b'\xda', b'\xda\x00', b'\xda\x00\x00', b'\xda\x00\x01a',
                      b'\xda\x01\x00', b'\xdb', b'\xdb\x00\x00\x00',
                      b'\xdb\x00\x00\x00\x00', b'\xdb\xff\xff\xff\xff',
                      b'\xc4', b'\xc4\x00', b'\xc4\x01a', b'\xc5\x00\x02a',
                      b'\xc5\x00\x02ab', b'\xc6\x00\x00\x00\x00')
    value_cases = []
    for prefix in value_prefixes:
        case = model_binary_value_prefix(prefix)
        case['prefix_hex'] = prefix.hex()
        value_cases.append(case)
    branches = [r for r in rows if r['kind'].startswith('j') and 'target' in r]
    calls = [r for r in rows if r['kind'] in ('call', 'call_indirect', 'jump_indirect')]
    stores = [r for r in rows if 'mem' in r and r['kind'] in
              ('mov_store', 'mov_imm_store', 'inc', 'dec', 'sse_0x11', 'sse_0x29')]
    indirect_slots = []
    for row in calls:
        slot = row.get('memory_va')
        if slot is None:
            continue
        if slot in image.relocations:
            kind, destination, symbol_index, symbol = 'RELATIVE', image.relative(slot), None, ''
        elif slot in image.symbols:
            symbol_index, symbol = image.symbols[slot]
            kind, destination = 'GLOB_DAT', None
        else:
            kind, destination, symbol_index, symbol = 'unresolved', None, None, ''
        indirect_slots.append({'function': row['function'], 'site': row['va'], 'slot': slot,
                               'relocation_type': kind, 'target': destination,
                               'symbol_index': symbol_index, 'symbol': symbol})
    copy_slots = [row for row in indirect_slots if row['site'] == 0x140504c]
    require(len(copy_slots) == 1 and copy_slots[0]['relocation_type'] == 'GLOB_DAT'
            and copy_slots[0]['symbol'] == 'memcpy', 'copy import binding changed')
    allocation_slots = [row for row in indirect_slots if row['site'] == 0x1405029]
    require(len(allocation_slots) == 1 and allocation_slots[0]['relocation_type'] == 'RELATIVE'
            and allocation_slots[0]['target'] == 0x54c06b0, 'allocation boundary changed')
    result = {'functions': functions, 'instructions': rows, 'contracts': contract_rows,
              'names': descriptors, 'aws_names': aws_rows, 'relocations': relocs,
              'tables': table_rows, 'marker_cases': marker_cases, 'policy_cases': policy_cases,
              'gate_cases': gate_cases,
              'json_option_cases': json_cases,
              'binary_value_cases': value_cases,
              'branches': branches, 'calls': calls, 'stores': stores, 'indirect_slots': indirect_slots,
              'policy': policy, 'marker_base': marker_base, 'secondary_base': secondary_base}
    result['control_flow'] = control_flow(result)
    result['lsda_headers'], result['exception_sites'] = exception_sites(image, result)
    return result


def fmt(value):
    if value is None:
        return ''
    if isinstance(value, bool):
        return str(value).lower()
    return str(value)


def hx(value):
    return '' if value is None else hex(value)


def tsv(path, columns, records):
    stream = io.StringIO(newline='')
    writer = csv.writer(stream, delimiter='\t', lineterminator='\n')
    writer.writerow(columns)
    for record in records:
        writer.writerow([fmt(v) for v in record])
    path.write_bytes(stream.getvalue().encode('utf-8'))


def mem_string(row):
    mem = row.get('mem')
    if not mem:
        return ''
    return (str(mem['base'] or '-') + ',' + str(mem['index'] or '-') + ','
            + str(mem['scale']) + ',' + str(mem['disp']))


def write_outputs(result, output):
    output.mkdir(parents=True, exist_ok=True)
    tsv(output / 'functions.tsv', ['role', 'entry_va', 'end_va', 'file_offset', 'fde_va',
                                  'cie_va', 'lsda_va', 'bytes', 'instructions', 'sha256'],
        ((BODIES[r['entry']][0], hx(r['entry']), hx(r['end']), hx(r['file_offset']),
          hx(r['fde']), hx(r['cie']), hx(r['lsda']), r['byte_count'],
          r['instruction_count'], r['sha256']) for r in result['functions']))
    columns = ['function_va', 'va', 'file_offset', 'bytes', 'kind', 'width',
               'encoded_reg', 'encoded_rm', 'source_width', 'immediate',
               'target_va', 'memory_va', 'memory_base_index_scale_displacement']
    def encoded(rows):
        for r in rows:
            yield (hx(r['function']), hx(r['va']), hx(r['file_offset']), r['bytes'],
                   r['kind'], r.get('width'), r.get('reg'), r.get('rm'),
                   r.get('source_width'), r.get('immediate'), hx(r.get('target')),
                   hx(r.get('memory_va')), mem_string(r))
    tsv(output / 'instructions.tsv', columns, encoded(result['instructions']))
    tsv(output / 'branches.tsv', columns, encoded(result['branches']))
    tsv(output / 'calls.tsv', columns, encoded(result['calls']))
    tsv(output / 'stores.tsv', columns, encoded(result['stores']))
    tsv(output / 'contracts.tsv', ['label', 'function_va', 'va', 'file_offset', 'bytes',
                                   'kind', 'immediate', 'target_va', 'memory_va'],
        ((r['label'], hx(r['function']), hx(r['va']), hx(r['file_offset']), r['bytes'],
          r['kind'], r['immediate'], hx(r['target']), hx(r['memory_va']))
         for r in result['contracts']))
    tsv(output / 'tables.tsv', ['table', 'index', 'slot_va', 'file_offset', 'bytes', 'target_va'],
        ((r['table'], r['index'], hx(r['slot']), hx(r['slot_file_offset']), r['bytes'], hx(r['target']))
         for r in result['tables']))
    names = []
    for index, r in enumerate(result['names']):
        names.append(('network', index, r['text'], hx(r['slot_va']), hx(r['text_va']),
                      hx(r['slot_file_offset']), hx(r['text_file_offset']),
                      r['length'], r['slot_bytes'], r['bytes'],
                      hx(r['rela_file_offset']), r['rela_bytes']))
    for r in result['aws_names']:
        names.append((r['role'], r['index'], r['text'], hx(r['slot_va']), hx(r['text_va']),
                      hx(r['slot_file_offset']), hx(r['text_file_offset']),
                      r['length'], r['slot_bytes'], r['bytes'],
                      hx(r['rela_file_offset']), r['rela_bytes']))
    tsv(output / 'names.tsv', ['role', 'index', 'text', 'slot_va', 'text_va',
                               'slot_file_offset', 'text_file_offset', 'length',
                               'slot_bytes', 'text_bytes', 'rela_file_offset', 'rela_bytes'], names)
    tsv(output / 'relocations.tsv', ['role', 'slot_va', 'slot_file_offset', 'relative_addend_va',
                                     'rela_file_offset', 'rela_bytes'],
        ((r['label'], hx(r['slot']), hx(r['slot_file_offset']), hx(r['target']),
          hx(r['rela_file_offset']), r['rela_bytes']) for r in result['relocations']))
    tsv(output / 'indirect-slots.tsv', ['function_va', 'site_va', 'slot_va', 'relocation_type',
                                        'relative_addend_va', 'symbol_index', 'symbol_name'],
        ((hx(r['function']), hx(r['site']), hx(r['slot']), r['relocation_type'],
          hx(r['target']), r['symbol_index'], r['symbol']) for r in result['indirect_slots']))
    tsv(output / 'marker-cases.tsv', ['raw_byte', 'normalized_kind', 'payload_mode', 'payload_value',
                                      'option_null', 'map_table_target_va'],
        ((hex(r['raw_byte']), hex(r['normalized_kind']), r['payload_mode'], hx(r['payload_value']),
          r['option_null'], hx(r['map_table_target']))
         for r in result['marker_cases']))
    tsv(output / 'lookup-cases.tsv', ['configuration_byte', 'selected_network_code'],
        ((r['configuration_byte'], r['selected_key']) for r in result['policy_cases']))
    tsv(output / 'binary-key-prefix-cases.tsv',
        ['input_prefix_hex', 'fresh_marker_form', 'prefix_bytes_consumed', 'map_count', 'local_outcome'],
        ((r['prefix_hex'], r['form'], r['prefix_consumed'], r['count'], r['outcome'])
         for r in result['gate_cases']))
    tsv(output / 'json-option-prefix-cases.tsv',
        ['input_prefix_hex', 'local_cursor', 'local_outcome', 'local_tag'],
        ((r['prefix_hex'], r['cursor'], r['outcome'], r['local_tag'])
         for r in result['json_option_cases']))
    tsv(output / 'binary-value-prefix-cases.tsv',
        ['input_prefix_hex', 'fresh_marker_form', 'local_cursor', 'declared_length', 'local_outcome'],
        ((r['prefix_hex'], r['form'], r['cursor'], r['length'], r['outcome'])
         for r in result['binary_value_cases']))
    tsv(output / 'cfg-propositions.tsv',
        ['proposition', 'start_va', 'goal_va', 'forbidden_va', 'reachable', 'witness_vas'],
        ((r['label'], hx(r['start']), hx(r['goal']), ','.join(map(hx, r['forbidden'])),
          r['reachable'], ','.join(map(hx, r['witness']))) for r in result['control_flow']))
    tsv(output / 'exception-sites.tsv',
        ['function_va', 'lsda_va', 'record_va', 'record_bytes', 'start_va', 'end_va',
         'landing_va', 'action_index', 'transfer_vas', 'type_encoding', 'type_base_va'],
        ((hx(r['function']), hx(r['lsda']), hx(r['record_va']), r['record_bytes'],
          hx(r['start']), hx(r['end']), hx(r['landing']), r['action'],
          ','.join(map(hx, r['transfers'])), hx(r['type_encoding']), hx(r['type_base']))
         for r in result['exception_sites']))
    tsv(output / 'lsda-headers.tsv',
        ['function_va', 'lsda_va', 'file_offset', 'next_known_upper_bound_va',
         'header_bytes', 'call_site_table_bytes', 'type_encoding', 'type_base_va'],
        ((hx(r['function']), hx(r['lsda']), hx(r['file_offset']), hx(r['upper_bound']),
          r['header_bytes'], r['table_bytes'], hx(r['type_encoding']), hx(r['type_base']))
         for r in result['lsda_headers']))
    summary = {
        'target_sha256': DIGEST,
        'scope': 'selected FDE ranges, marker words and evidence contracts only',
        'function_count': len(result['functions']),
        'function_bytes': sum(r['byte_count'] for r in result['functions']),
        'instruction_count': len(result['instructions']),
        'direct_branch_count': len(result['branches']),
        'call_and_indirect_transfer_count': len(result['calls']),
        'selected_store_count': len(result['stores']),
        'instruction_contract_count': len(result['contracts']),
        'rip_indirect_transfer_slots': len(result['indirect_slots']),
        'jump_table_slots': len(result['tables']),
        'raw_marker_cases': len(result['marker_cases']),
        'binary_key_prefix_cases': len(result['gate_cases']),
        'json_option_prefix_cases': len(result['json_option_cases']),
        'binary_value_prefix_cases': len(result['binary_value_cases']),
        'structural_cfg_propositions': len(result['control_flow']),
        'lsda_call_site_ranges': len(result['exception_sites']),
        'lsda_tables': len(result['lsda_headers']),
        'normalization_masks': [],
        'limitations': ('FDE extents are unwind ranges; marker cases and key selections are static models. '
                        'Existing initializers, shared readers, allocation, dynamic drops and target execution remain boundaries.'),
    }
    (output / 'evidence.json').write_bytes((json.dumps(summary, indent=2, sort_keys=True) + '\n').encode())
    return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args(argv)
    image = Image(TARGET.read_bytes())
    summary = write_outputs(collect(image), args.out)
    print('ok functions={function_count} instructions={instruction_count} contracts={instruction_contract_count}'.format(**summary))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (EvidenceError, ValueError, OSError, struct.error) as error:
        print('config_chain_bucket94:', error, file=sys.stderr)
        raise SystemExit(1)
