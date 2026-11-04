#!/usr/bin/env python3
"""Reproduce selected node 115 configuration-field-to-state evidence, offline.

The closed x86 length/transfer reader below adapts the MIT-licensed repository
history tools/config_chain_bucket94.py (blob b23d5808399c7b055601ca7525ddda9ae8bbf7f0).
It recognizes only the encodings exercised here and is not an x86 emulator.
"""
import argparse
import collections
import csv
import hashlib
import json
from pathlib import Path
import struct
import sys

TOOLS = Path(__file__).resolve().parent
ROOT = TOOLS.parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))
from elf_index import sections, unwind_index
from fde_extents import eh_frame_records, uleb

DIGEST = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
HISTORICAL_DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
CAPTURE = ROOT / 'artifacts/node/115/hl-node'

class EvidenceError(ValueError):
    pass

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
        while p < len(body) and body[p] in (0x66,0x2e,0xf0,0xf2,0xf3):
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
        elif op in (0xa8,0xa9):
            row['kind']='test'; row['reg']='rax'; row['width']=8 if op==0xa8 else width; imm=1 if op==0xa8 else (2 if width==16 else 4)
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
            elif op2 in (0x10,0x11,0x13,0x15,0x28,0x29,0x2e,0x57,0x58,0x59,0x5c,0x5e,0x62,0x6c,0x6e,0x6f,0x74,0x7f,0x7e,0xd7,0xdb):
                row['kind']='sse_'+hex(op2);modrm=True
                row['width']=64 if 0xf2 in prefixes or op2 in (0x13,0x6e,0x7e) else 128
            elif op2==0x1f:row['kind']='nop';modrm=True
            elif op2 in (0xb6,0xb7,0xbe,0xbf):row['kind']='extend';modrm=True;row['source_width']=8 if op2 in (0xb6,0xbe) else 16
            elif op2==0xa3:row['kind']='bt';modrm=True
            elif op2==0xbc:row['kind']='tzcnt' if 0xf3 in prefixes else 'bsf';modrm=True
            elif 0x40<=op2<=0x4f:row['kind']='cmov'+CC[op2&15];modrm=True
            elif 0x90<=op2<=0x9f:row['kind']='set'+CC[op2&15];modrm=True;row['width']=8
            else:raise EvidenceError('unsupported two-byte opcode '+hex(op2)+' at '+hex(base+start))
        elif op in (0x00,0x01,0x08,0x09,0x20,0x21,0x22,0x28,0x29,0x30,0x31,0x33,0x38,0x39,0x3b,0x23,0x85,0x84,0x88,0x89,0x8b,0x8d,0x63):
            row['kind']={0x00:'add',0x01:'add',0x08:'or',0x09:'or',0x20:'and',0x21:'and',0x22:'and',0x23:'and',0x28:'sub',0x29:'sub',0x30:'xor',0x31:'xor',0x33:'xor',0x38:'cmp',0x39:'cmp',0x3b:'cmp',0x85:'test',0x84:'test',0x88:'mov_store',0x89:'mov_store',0x8b:'mov_load',0x8d:'lea',0x63:'movsxd'}[op]
            modrm=True
            if op in (0x00,0x08,0x20,0x22,0x28,0x30,0x38,0x84,0x88):row['width']=8
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
                if group not in (0,2,3,4,5,6,7):raise EvidenceError('unsupported unary group')
                row['kind']={0:'test',2:'not',3:'neg',4:'mul',5:'imul',6:'div',7:'idiv'}[group]
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



# FDE extents and full range hashes were independently selected from the target.
FRAMES = (
    ('document_loader', 0x15016f0, 0x1501aeb, '9d1c696feae761e9270cb282abb9b05f2c9b7bf6d8066b8814bf6844e7786e8e'),
    ('json_document', 0x15750f0, 0x157523f, 'a0b7ca5f37dff63df2057a9741941ef354d82c022c3131877576bca5331e87aa'),
    ('json_root', 0x1593db0, 0x1594020, '88d3ddc4f1f303fcf487bf8a30bd29683f23741b7ccd8d8d5b4b7ae0f8144328'),
    ('json_fields', 0x157ef70, 0x1584b8c, '59bf6dde45604a827c6925da950dc27ca05577c88e522af3807bb5f50539508a'),
    ('field_classifier', 0x155e2f0, 0x155e609, '389013c8344c229537b2de4a2c719f60679d424e3648de232eaf3467be605cbf'),
    ('optional_map', 0x15d1eb0, 0x15d201d, 'dd0d7e8f380f5ccfced5c46ceb629cf211a16c070a5d3065a5cef7fc42102663'),
    ('json_map', 0x1593780, 0x1593da7, '4466139d971f24bf960b85d5af798f99fb59ba68d6a65313c0cfc82e9add732b'),
    ('chain_key_adapter', 0x14bcbe0, 0x14bcea6, '5d74d1fcdb705220437da0d81cee908d03033e7719bd99cc13d6ccdf52085900'),
    ('quoted_key', 0x15915f0, 0x1591713, '023831f45867aca45e9c7a3d0a1bfff3c74fa23913031d6caf4c2a57da93fb9d'),
    ('chain_key_classifier', 0x14be0b0, 0x14be15c, '9a7a861221de10f7b90083893199f989109dc94ddeb69f5da8d08d6fb591d250'),
    ('string_value', 0x1596700, 0x1596860, '66da081caa422d9c941d63bc1893347e7db5a1d9f49011039e1c434f27541686'),
    ('new_key_insert', 0x156e440, 0x156e59f, '641dfd08e64ca7ea5aea0d8c5959c0f07780707e096cebffa8279a1ba6f7544f'),
    ('api_initializer', 0x1568b20, 0x1568d78, '6203b442f2ed051141d3c5fb27c2db99c8b6154e6cf5595d45bcc6d7a62f0b70'),
    ('publish_callback_a', 0x1543f50, 0x1543fab, 'd955c06e1e5644e952e37868433f2f08c7aac61e07588c38c19599af5c16becf'),
    ('publish_callback_b', 0x154d160, 0x154d1bb, '40a23f798434be8104fdcdb9c0ca997268a1daef9e5b5d0864ea45d2ce323642'),
    ('configured_lookup', 0x154aa00, 0x154abe3, '9e799ad31776b216243ac235e4706126a63213f774bc347429e67309378faa8f'),
    ('caller_constructor', 0x51cf360, 0x51d0f70, 'df61191b135be90414b94836bce7d4474eef92cd6e95913d99b8a3ab265c83be'),
    ('flag_consumer', 0x51fc3e0, 0x51fc5ce, 'fd515522341aefa0611e2f3fe56ae7ce604782841c8fa04a2c5deb46c0e0239a'),
    ('consumer_state_handoff', 0x4e39e40, 0x4e3a01d, '0e593e5fa682242de50e2de6845f5e481aab4dfa43e8ced1f43c121e113868bb'),
)


def require(condition, message):
    if not condition:
        raise EvidenceError(message)


class Image:
    def __init__(self, data, digest=DIGEST):
        self.data = data
        require(hashlib.sha256(data).hexdigest() == digest, 'capture digest mismatch')
        self.secs = sections(data)
        self.byname = {}
        for s in self.secs:
            if s['name'] in self.byname:
                raise EvidenceError('duplicate section name')
            self.byname[s['name']] = s
        self.relocations = None

    def offset(self, va, size, executable=False):
        require(isinstance(va, int) and isinstance(size, int) and va >= 0 and size > 0,
                'invalid range')
        candidates = [s for s in self.secs if s['type'] != 8 and s['size'] and
                      s['address'] <= va and va + size <= s['address'] + s['size'] and
                      (not executable or s['flags'] & 4)]
        require(len(candidates) == 1, 'unmapped or ambiguous file-backed range')
        s = candidates[0]
        off = s['offset'] + va - s['address']
        require(off + size <= len(self.data), 'range outside file')
        return off

    def read(self, va, size, executable=False):
        off = self.offset(va, size, executable)
        return self.data[off:off + size]

    def rela(self):
        if self.relocations is None:
            sec = self.byname.get('.rela.dyn')
            require(sec is not None and sec['type'] != 8 and sec['size'] % 24 == 0,
                    'invalid relocation section')
            entries = {}
            for at in range(sec['offset'], sec['offset'] + sec['size'], 24):
                slot, info, addend = struct.unpack_from('<QQq', self.data, at)
                require(slot not in entries, 'duplicate relocation slot')
                entries[slot] = (at, info & 0xffffffff, info >> 32, addend)
            self.relocations = entries
        return self.relocations

    def rel(self, slot, expected=None):
        entry = self.rela().get(slot)
        require(entry is not None and entry[1:3] == (8, 0), 'missing relative relocation')
        if expected is not None:
            require(entry[3] == expected, 'unexpected relative addend')
        return entry

    def dyn_symbol(self, slot):
        entry = self.rela().get(slot)
        require(entry is not None and entry[1] == 6 and entry[2] != 0, 'missing dynamic symbol')
        sym, strings = self.byname.get('.dynsym'), self.byname.get('.dynstr')
        require(sym is not None and strings is not None and sym['type'] != 8 and
                strings['type'] != 8 and sym['size'] % 24 == 0, 'invalid dynamic tables')
        index = entry[2]
        require(index * 24 + 24 <= sym['size'], 'dynamic symbol outside table')
        pos = sym['offset'] + index * 24
        name_off = struct.unpack_from('<I', self.data, pos)[0]
        require(name_off < strings['size'], 'symbol name outside table')
        start = strings['offset'] + name_off
        end = self.data.find(b'\0', start, strings['offset'] + strings['size'])
        require(end >= 0, 'unterminated symbol name')
        try:
            name = self.data[start:end].decode('ascii')
        except UnicodeDecodeError as exc:
            raise EvidenceError('non-ASCII symbol') from exc
        return name


def selected_frames(im):
    _, fdes = eh_frame_records(im.data, im.secs)
    _, index = unwind_index(im.data)
    by_start = collections.defaultdict(list)
    for row in fdes:
        by_start[row['start']].append(row)
    idx = {row['start']: row for row in index}
    require(len(idx) == len(index), 'duplicate unwind start')
    frames, decoded = [], {}
    for name, start, end, body_sha in FRAMES:
        hits = by_start[start]
        require(len(hits) == 1 and hits[0]['end'] == end, 'selected FDE mismatch')
        fde = dict(hits[0])
        require(start in idx and idx[start]['fde'] == fde['fde'], 'FDE index mismatch')
        body = im.read(start, end - start, True)
        require(hashlib.sha256(body).hexdigest() == body_sha, 'selected body mismatch')
        rows = decode(body, start)
        require(rows and rows[0]['va'] == start, 'empty selected FDE')
        fde.update(name=name, sha256=body_sha, index=idx[start]['index'],
                   file_offset=im.offset(start, end - start, True))
        frames.append(fde)
        decoded[name] = rows
    return frames, decoded


def exceptions(im, frame, starts):
    """Read a bounded Itanium LSDA call-site table; action semantics are not decoded."""
    if frame['lsda'] is None:
        return []
    sec = im.byname.get('.gcc_except_table')
    require(sec is not None and sec['type'] != 8, 'missing exception table')
    pos = im.offset(frame['lsda'], 1)
    end = sec['offset'] + sec['size']
    require(sec['offset'] <= pos and pos + 2 <= end, 'exception header outside section')
    require(im.data[pos] == 0xff, 'unsupported landing base encoding')
    typ = im.data[pos + 1]
    pos += 2
    type_end = None
    if typ == 0x9b:
        delta, pos = uleb(im.data, pos, end)
        type_end = pos + delta
        require(type_end <= end, 'exception type table outside section')
    else:
        require(typ == 0xff, 'unsupported exception type encoding')
    require(pos < end and im.data[pos] == 1, 'unsupported call-site encoding')
    pos += 1
    size, pos = uleb(im.data, pos, end)
    table_end = pos + size
    require(table_end <= end and (type_end is None or table_end <= type_end),
            'exception table truncated')
    result, previous = [], frame['start']
    while pos < table_end:
        beginning = pos
        first, pos = uleb(im.data, pos, table_end)
        length, pos = uleb(im.data, pos, table_end)
        landing, pos = uleb(im.data, pos, table_end)
        action, pos = uleb(im.data, pos, table_end)
        first += frame['start']
        last = first + length
        pad = frame['start'] + landing if landing else None
        require(frame['start'] <= first <= last <= frame['end'] and first >= previous,
                'exception range outside or unordered')
        require(pad is None or (frame['start'] <= pad < frame['end'] and pad in starts),
                'exception landing outside or not an instruction start')
        previous = last
        result.append((beginning, first, last, pad, action, im.data[beginning:pos].hex()))
    return result

# A compact independent set of semantics-bearing instruction pins.  The full
# selected FDE hashes and admitted instruction partitions are also checked.
PINS = (
    (0x155e2f3, '488d4afa'), (0x155e2f7, '4883f91b'),
    (0x155e2fb, '0f87dc020000'), (0x155e301, '488d3d5091f0fe'),
    (0x155e308, '48630c8f'), (0x155e30f, 'ffe1'),
    (0x155e58b, 'f30f6f06'), (0x155e58f, 'f30f6f4e0a'),
    (0x155e594, '660f740da46deffe'), (0x155e59c, '660f7405ec40effe'),
    (0x155e5a4, '660fdbc1'), (0x155e5a8, '660fd7c8'),
    (0x155e5ac, '81f9ffff0000'), (0x155e5b2, '7449'),
    (0x155e5b4, 'f30f6f06'), (0x155e5b8, 'f30f6f4e0a'),
    (0x155e5bd, '660f740ddb50effe'), (0x155e5c5, '660f7405f343effe'),
    (0x155e5cd, '660fdbc1'), (0x155e5d1, '660fd7c8'),
    (0x155e5d5, '81f9ffff0000'), (0x155e5db, '7428'),
    (0x155e5dd, 'c6000d'), (0x155e5fd, 'c6001c'), (0x155e605, 'c60022'),
    (0x157f1d5, '80e916'), (0x157f1e0, '0f42ca'),
    (0x157f1ee, '488d15db8aeefe'), (0x157f1f5, '48630c8a'),
    (0x157f206, 'ffe1'), (0x157f3c4, '4883bc245801000002'),
    (0x157f3cd, '0f8585420000'), (0x157f400, '0f833e070000'),
    (0x157fb66, 'e845230500'), (0x157fb7b, '4883fa02'),
    (0x157fb96, '4889942458010000'), (0x1580245, '48c784240002000000000000'),
    (0x15802dd, '4c8b9c2458010000'), (0x15804e3, '4983fb02'),
    (0x15804fa, '480f44c2'), (0x15807bc, '0f288424e0030000'),
    (0x15807c4, '0f288c24f0030000'), (0x15807fc, '488db42480000000'),
    (0x1580804, 'ba88000000'), (0x158080c, 'ff15f6ecf504'),
    (0x1583698, '488d3d7bfeeafe'), (0x15836ff, 'e82cd70200'),
    (0x1583704, 'e96bdeffff'), (0x158157d, '48c70102000000'),
    (0x1593a17, '488d047500000000'), (0x1593a1f, '4885c0'),
    (0x1593a22, '0f844dfeffff'),
    (0x154aa1d, '83f805'), (0x154aa22, '83f812'),
    (0x154aa2b, 'bb03000000'), (0x154aa75, 'bb02000000'),
    (0x154aa81, '418b86c0010000'), (0x154aa90, '41833e01'),
    (0x154aaab, '440fb78012010000'), (0x154aada, '440fb6941015010000'),
    (0x154ab1d, '488b84d020010000'), (0x154ab27, '488b1e'),
    (0x154ab5f, '41be01000000'), (0x154abb9, '48b80000000000000080'),
    (0x51cf728, '48bd0000000000000080'), (0x51cfde6, '48bd0000000000000080'),
    (0x51d0992, 'ff15c0063101'), (0x51d0a80, '4839eb'),
    (0x51d0a83, '410f9587680b0000'), (0x51d0a8b, '7418'),
    (0x51d0a90, '7413'), (0x51fc435, '4180be680b000000'),
    (0x51fc43d, '0f84fd000000'), (0x51fc455, 'f20f100583cf25fb'),
    (0x51fc4df, '7673'), (0x51fc4fb, '7257'), (0x51fc52e, '7424'),
    (0x51fc554, 'c744244000000000'), (0x51fc59b, 'e8a0d8c3ff'),
    (0x4e39e88, '493b4648'), (0x4e39e91, '7124'),
    (0x4e39e93, '4c39ee'), (0x4e39e96, '0f843b010000'),
    (0x4e39e9c, '4885f6'), (0x4e39e9f, '0f8432010000'),
    (0x4e39eac, 'ff15ee556a01'), (0x4e39eb7, '498d5e48'),
    (0x4e39ebb, '4c39ee'), (0x4e39ebe, '0f8498000000'),
    (0x4e39f03, 'ff1517616a01'), (0x4e39f0c, 'e89f680100'),
    (0x4e39f16, '0f114340'), (0x4e39f2e, '0f115b30'),
    (0x4e39f32, '0f115320'), (0x4e39f36, '0f114b10'),
    (0x4e39f3a, '0f1103'), (0x4e39f3d, '4189ae98000000'),
    (0x4e39f49, '418886a8000000'), (0x4e39f55, '418886a9000000'),
    (0x4e39f7c, 'e85f9a2a00'), (0x4e39f85, '418986a4000000'),
    (0x4e39f8f, '4989869c000000'), (0x4e39fe9, '0f10442450'),
    (0x4e3a018, 'e8336a5b01'),
)

# Selected additional instruction starts are listed by role for review; their
# bytes and operands always come from the ELF and admitted decoder.
CONTRACTS = (
    ('source-slot', 0x1568b2f), ('source-directory-field', 0x1568b41),
    ('format-entry', 0x1568b56), ('formatter-boundary', 0x1568b65),
    ('loader-call', 0x1568b84), ('loader-error-test', 0x1568b8e),
    ('loader-error-edge', 0x1568b92), ('loader-absence-test', 0x1568bb0),
    ('loader-absence-edge', 0x1568bb4), ('default-sentinel', 0x1568bba),
    ('default-map-tag', 0x1568c7f), ('initializer-output-tag', 0x1568c82),
    ('parsed-copy-destination', 0x1568c90), ('parsed-copy-size', 0x1568c9c),
    ('parsed-copy-call', 0x1568ca1), ('parsed-tag-write', 0x1568ca7),
    ('unwrapping-diagnostic', 0x1568d17), ('panic-call', 0x1568d39),
    ('panic-trap', 0x1568d3f), ('unwind-boundary', 0x1568d6d),
    ('initial-file-test', 0x150170f), ('initial-file-branch', 0x1501717),
    ('transform-path', 0x1501727), ('second-file-test', 0x1501737),
    ('second-file-branch', 0x150173f), ('first-file-absent-tag', 0x150175f),
    ('second-file-error-tag', 0x1501943), ('format-branch-compare', 0x150189c),
    ('format-alternate-read', 0x15018b7), ('format-json-read', 0x15018fa),
    ('read-error-sentinel-test', 0x1501913), ('json-parser-call', 0x150198f),
    ('json-parser-error-test', 0x15019a4), ('json-parser-error-edge', 0x15019a8),
    ('alternate-parser-call', 0x1501a19), ('loader-copy-size', 0x1501a71),
    ('document-parser', 0x157513c), ('document-error-check', 0x1575141),
    ('trailing-whitespace-mask', 0x1575177), ('trailing-nonspace-code', 0x15751b8),
    ('root-object-test', 0x1593e25), ('root-object-error', 0x1593e28),
    ('root-depth-decrement', 0x1593e42), ('root-depth-restore', 0x1593e7f),
    ('root-field-visitor', 0x1593e66), ('root-close', 0x1593ea3),
    ('field-name-dispatch', 0x157f168), ('field-tag-base', 0x157f1d5),
    ('field-dispatch-base', 0x157f1ee), ('field-dispatch-jump', 0x157f206),
    ('field-unseen-initialize', 0x157f029), ('field-duplicate-check', 0x157f3c4),
    ('field-duplicate-edge', 0x157f3cd), ('field-value-colon-edge', 0x157f400),
    ('field-optional-map-call', 0x157fb66), ('field-value-error-check', 0x157fb7b),
    ('field-value-error-edge', 0x157fb7f), ('field-value-stash', 0x157fb96),
    ('field-default-zero', 0x1580245), ('field-value-reload', 0x15802dd),
    ('field-missing-test', 0x15804e3), ('field-default-select', 0x15804fa),
    ('field-output-block-a', 0x15807bc), ('field-output-block-b', 0x15807c4),
    ('field-output-copy-source', 0x15807fc), ('field-output-copy-size', 0x1580804),
    ('field-output-copy', 0x158080c), ('duplicate-field-text', 0x1583658),
    ('duplicate-field-text-size', 0x1583667), ('duplicate-format-reference', 0x1583698),
    ('duplicate-error-construction', 0x15836ff), ('duplicate-error-return', 0x158157d),
    ('option-first-char', 0x15d1f1c), ('option-null-store', 0x15d1f87),
    ('option-map-call', 0x15d1f9a), ('option-map-error-check', 0x15d1fa3),
    ('option-error-tag', 0x15d1fb1), ('option-some-tag', 0x15d1fcb),
    ('option-tag-store', 0x15d1fd0), ('option-eof-code', 0x15d1fdc),
    ('option-invalid-code', 0x15d2006),
    ('map-opening-object', 0x15937fd), ('map-opening-reject', 0x1593800),
    ('map-depth-read', 0x159380d), ('map-depth-exhausted', 0x1593820),
    ('map-next-entry', 0x1593880), ('map-key-call', 0x15938a9),
    ('map-value-call', 0x1593932), ('map-value-error', 0x159394c),
    ('map-root-empty', 0x159397b), ('map-key-load', 0x15939aa),
    ('map-stride', 0x15939c1), ('map-found', 0x15939d4),
    ('map-child-load', 0x15939e9), ('map-old-value', 0x1593a00),
    ('map-replace-first-word', 0x1593a07), ('map-replace-rest', 0x1593a13),
    ('map-old-value-double', 0x1593a17), ('map-old-double-test', 0x1593a1f),
    ('map-old-no-release', 0x1593a22),
    ('map-dispose-old', 0x1593a2a), ('map-new-key', 0x1593a92),
    ('map-eof-code', 0x1593a9c), ('map-colon-code', 0x1593cc2),
    ('map-success-tag', 0x1593c42), ('map-result-tag-store', 0x1593c49),
    ('key-string-adapter', 0x14bcc57), ('key-dispatch-table', 0x14bcc60),
    ('key-classifier-call', 0x15916b9), ('key-error', 0x14be11c),
    ('key-local', 0x14be0d1), ('key-mainnet', 0x14be113),
    ('key-sandbox', 0x14be14a), ('key-testnet', 0x14be153),
    ('map-node-allocation-size', 0x156e4a7), ('map-node-allocation', 0x156e4ac),
    ('map-node-allocation-failure', 0x156e4b5), ('map-node-count-zero', 0x156e4c2),
    ('map-node-count-bound', 0x156e4e5), ('map-node-count-store', 0x156e4f7),
    ('map-node-key-store', 0x156e4fe), ('map-node-size-increment', 0x156e51b),
    ('map-insert-split-boundary', 0x156e48b),
    ('callback-a-initializer', 0x1543f7a), ('callback-a-copy-size', 0x1543f7c),
    ('callback-b-initializer', 0x154d18a), ('callback-b-copy-size', 0x154d18c),
    ('lookup-source-slot', 0x154aa0b), ('lookup-name-load', 0x154aa19),
    ('lookup-name-first', 0x154aa1d), ('lookup-name-first-branch', 0x154aa20),
    ('lookup-name-second', 0x154aa22), ('lookup-name-other', 0x154aa25),
    ('lookup-key-main', 0x154aa2b), ('lookup-key-test', 0x154aa75),
    ('lookup-map-slot', 0x154aa7a), ('lookup-map-guard', 0x154aa81),
    ('lookup-map-option', 0x154aa90), ('lookup-map-missing', 0x154aa94),
    ('lookup-root', 0x154aa9a), ('lookup-root-missing', 0x154aaa1),
    ('lookup-node-count', 0x154aaab), ('lookup-node-key', 0x154aada),
    ('lookup-leaf-miss', 0x154ab17), ('lookup-child', 0x154ab1d),
    ('lookup-value-length', 0x154ab27), ('lookup-empty', 0x154ab2d),
    ('lookup-allocate', 0x154ab39), ('lookup-allocation-failure', 0x154ab42),
    ('lookup-copy', 0x154ab54), ('lookup-empty-pointer', 0x154ab5f),
    ('lookup-result-first', 0x154ab65), ('lookup-result-pointer', 0x154ab68),
    ('lookup-result-length', 0x154ab6c), ('lookup-missing-sentinel', 0x154abb9),
    ('lookup-missing-store', 0x154abc3), ('lookup-allocation-error', 0x154abdd),
    ('caller-sentinel-a', 0x51cf728), ('caller-sentinel-b', 0x51cfde6),
    ('caller-lookup', 0x51d0992), ('caller-lookup-result', 0x51d0998),
    ('caller-flag-comparison', 0x51d0a80), ('caller-flag-write', 0x51d0a83),
    ('caller-sentinel-no-free', 0x51d0a8b), ('caller-zero-no-free', 0x51d0a90),
    ('caller-result-free', 0x51d0a9f), ('consumer-tag-two', 0x51fc3f5),
    ('consumer-tag-three', 0x51fc3fb), ('consumer-flag-test', 0x51fc435),
    ('consumer-flag-zero', 0x51fc43d), ('consumer-scale', 0x51fc455),
    ('consumer-scale-call', 0x51fc45d), ('consumer-limit-a', 0x51fc4df),
    ('consumer-limit-b', 0x51fc4fb), ('consumer-helper-result', 0x51fc52e),
    ('consumer-fallback', 0x51fc554), ('consumer-state-handoff', 0x51fc59b),
    ('consumer-drop', 0x51fc5a3), ('consumer-unwind-drop', 0x51fc5bb),
    ('consumer-unwind-resume', 0x51fc5c3),
    ('handoff-input-boundary', 0x4e39e80), ('handoff-current-test', 0x4e39e88),
    ('handoff-current-branch', 0x4e39e91), ('handoff-new-sentinel', 0x4e39e93),
    ('handoff-new-zero', 0x4e39e9c), ('handoff-unused-free', 0x4e39eac),
    ('handoff-active-field', 0x4e39eb7), ('handoff-reuse-branch', 0x4e39ebe),
    ('handoff-value-construction', 0x4e39f03), ('handoff-old-drop', 0x4e39f0c),
    ('handoff-write-64', 0x4e39f16), ('handoff-write-48', 0x4e39f2e),
    ('handoff-write-32', 0x4e39f32), ('handoff-write-16', 0x4e39f36),
    ('handoff-write-0', 0x4e39f3a), ('handoff-metadata-word', 0x4e39f3d),
    ('handoff-metadata-byte-a', 0x4e39f49), ('handoff-metadata-byte-b', 0x4e39f55),
    ('handoff-update-boundary', 0x4e39f7c), ('handoff-input-high', 0x4e39f85),
    ('handoff-input-low', 0x4e39f8f), ('handoff-optional-flag', 0x4e39f96),
    ('handoff-optional-sentinel', 0x4e39fae), ('handoff-optional-call', 0x4e39fb6),
    ('handoff-repair-on-unwind', 0x4e39fe9), ('handoff-unwind-resume', 0x4e3a018),
)


def instruction_map(decoded):
    rows = {}
    for role in decoded:
        for row in decoded[role]:
            require(row['va'] not in rows, 'overlapping selected instruction')
            rows[row['va']] = row
    return rows


def verify_pins(rows):
    for va, expected in PINS:
        require(va in rows and rows[va]['bytes'] == expected,
                'semantic instruction pin differs at ' + hex(va))
    for _, va in CONTRACTS:
        require(va in rows, 'contract is not an admitted instruction start: ' + hex(va))


def table(im, base, count, starts):
    require(count > 0, 'invalid table count')
    out = []
    for i in range(count):
        va = base + i * 4
        raw = im.read(va, 4)
        delta = struct.unpack('<i', raw)[0]
        target = base + delta
        require(target in starts, 'table target is not a selected instruction start')
        out.append((i, va, raw.hex(), target))
    return out


def field_patterns(im, rows):
    """Read both overlapping 16-byte equality predicates for the 26-byte bucket."""
    verify_pins(rows)
    patterns = []
    for first_va, second_va, result_va in ((0x155e59c, 0x155e594, 0x155e5fd),
                                           (0x155e5c5, 0x155e5bd, 0x155e605)):
        first = im.read(rows[first_va]['memory_va'], 16)
        second = im.read(rows[second_va]['memory_va'], 16)
        require(first[10:] == second[:6], 'overlapping classifier constants disagree')
        patterns.append((first + second[6:], rows[result_va]['immediate']))
    require(patterns[0][0] == b'chain_to_etherscan_ws_urls' and
            patterns[1][0] == b'chain_to_replica_s3_bucket', 'unexpected field bytes')
    return patterns


def field_match(value, patterns):
    if len(value) != 26:
        return None  # Outside the selected length arm.
    for expected, tag in patterns:
        # This is the two overlapping SIMD equality masks, expressed on bytes.
        if value[:16] == expected[:16] and value[10:26] == expected[10:26]:
            return tag
    return 13


def chain_key_patterns(im, rows):
    """Reassemble the four names from the classifier's checked immediate bytes."""
    pins = {
        0x14be0b3: '4883fa07', 0x14be0b7: '7421',
        0x14be0b9: '4883fa05', 0x14be0bd: '755d',
        0x14be0bf: 'b94c6f6361', 0x14be0ca: '83f76c',
        0x14be0cf: '754b', 0x14be0d1: 'c6400100',
        0x14be0da: 'b953616e64', 0x14be0e1: 'bf64626f78',
        0x14be0eb: '745d', 0x14be0ed: 'b954657374',
        0x14be0f4: 'bf746e6574', 0x14be0fe: '7453',
        0x14be100: 'b94d61696e', 0x14be107: 'bf6e6e6574',
        0x14be111: '7509', 0x14be113: 'c6400103',
        0x14be14a: 'c6400101', 0x14be153: 'c6400102',
    }
    for va, raw in pins.items():
        require(va in rows and rows[va]['bytes'] == raw, 'chain-key instruction changed')
    local = rows[0x14be0bf]['immediate'].to_bytes(4, 'little') + bytes([rows[0x14be0ca]['immediate']])
    names = [(local, rows[0x14be0d1]['immediate'])]
    for first, second, leaf in ((0x14be0da, 0x14be0e1, 0x14be14a),
                                (0x14be0ed, 0x14be0f4, 0x14be153),
                                (0x14be100, 0x14be107, 0x14be113)):
        left = rows[first]['immediate'].to_bytes(4, 'little')
        right = rows[second]['immediate'].to_bytes(4, 'little')
        require(left[3:] == right[:1], 'chain-key compare overlap changed')
        names.append((left + right[1:], rows[leaf]['immediate']))
    for index, (name, tag) in enumerate(names):
        require(tag == index and im.read(im.rel(0x63f8748 + 16 * index)[3], len(name)) == name,
                'chain-key descriptor and classifier disagree')
    return names


def chain_key_match(value, patterns):
    for name, tag in patterns:
        if len(value) == len(name) and value == name:
            return tag
    return None


def tree_lookup(key, node, depth):
    """Search a well-formed synthetic tree under the selected map layout."""
    if not 0 <= key <= 255 or not isinstance(depth, int) or depth < 0:
        raise ValueError('invalid key or depth')
    if node is None:
        return None
    while True:
        pairs = node['pairs']
        keys = [pair[0] for pair in pairs]
        if len(keys) > 11 or keys != sorted(set(keys)):
            raise ValueError('invalid synthetic node keys')
        index = 0
        while index < len(pairs) and key > pairs[index][0]:
            index += 1
        if index < len(pairs) and key == pairs[index][0]:
            return pairs[index][1]
        if depth == 0:
            return None
        children = node.get('children', [])
        if len(children) != len(pairs) + 1 or children[index] is None:
            raise ValueError('invalid synthetic child')
        node = children[index]
        depth -= 1


def replacement_release(old_word):
    """Zero test after the selected 64-bit LEA doubles the old first word."""
    if not isinstance(old_word, int) or not 0 <= old_word < (1 << 64):
        raise ValueError('invalid synthetic 64-bit word')
    return ((old_word * 2) & ((1 << 64) - 1)) != 0


def map_update_model(pairs, key, length):
    """Finite ordered-map model for the selected replace or new-key handoff."""
    if not 0 <= key <= 3 or not isinstance(length, int) or not 0 <= length < (1 << 63):
        raise ValueError('invalid synthetic key or value length')
    keys = [k for k, _ in pairs]
    if keys != sorted(set(keys)) or any(not 0 <= k <= 3 for k in keys):
        raise ValueError('invalid synthetic entries')
    result = list(pairs)
    for i, (existing, old_length) in enumerate(result):
        if existing == key:
            result[i] = (key, length)
            return result, old_length, 'replace'
        if existing > key:
            result.insert(i, (key, length))
            return result, None, 'insert'
    result.append((key, length))
    return result, None, 'insert'


def name_constants(rows):
    verify_pins(rows)
    return (rows[0x154aa1d]['immediate'], rows[0x154aa22]['immediate'],
            rows[0x154aa75]['immediate'], rows[0x154aa2b]['immediate'])


def name_key(name, constants):
    if not 0 <= name <= 255:
        raise ValueError('name byte outside range')
    a, b, ka, kb = constants
    return ka if name == a else kb if name == b else None


def route_model(name, option_tag, entries, *, allocation_ok=True, constants=(5, 18, 2, 3)):
    """Abstract selected normal-return outcomes; no target instructions execute.

    entries is None for null root, otherwise maps chain key to synthetic value
    length. Allocation is an externally supplied outcome, never an OS action.
    """
    key = name_key(name, constants)
    if key is None or option_tag != 1 or entries is None or key not in entries:
        return {'key': key, 'outcome': 'missing', 'first_word': 1 << 63,
                'pointer': None, 'flag': 0, 'release': False}
    length = entries[key]
    if not isinstance(length, int) or not 0 <= length < (1 << 63):
        raise ValueError('synthetic length outside admitted domain')
    if length and not allocation_ok:
        return {'key': key, 'outcome': 'allocation_boundary', 'first_word': None,
                'pointer': None, 'flag': None, 'release': False}
    return {'key': key, 'outcome': 'present', 'first_word': length,
            'pointer': 'allocated' if length else 1, 'flag': 1,
            'release': bool(length)}


def handoff_model(current_word, returned_word):
    """Selected normal paths after the state-handoff input helper returns."""
    if any(not isinstance(v, int) or not 0 <= v < (1 << 64)
           for v in (current_word, returned_word)):
        raise ValueError('invalid synthetic state word')
    missing = 1 << 63
    if current_word == missing:
        return {'route': 'inactive', 'release_returned': returned_word not in (0, missing),
                'replace_current': False, 'write_forwarded': False}
    return {'route': 'reuse' if returned_word == missing else 'replace',
            'release_returned': False, 'replace_current': returned_word != missing,
            'write_forwarded': True}


def consumer_model(tag, flag, fail_a=False, fail_b=False, zero_result=False):
    """Selected tag/flag flow with externally supplied comparison outcomes."""
    if not isinstance(tag, int) or not 0 <= tag < (1 << 64):
        raise ValueError('invalid synthetic state tag')
    if not isinstance(flag, int) or not 0 <= flag <= 255:
        raise ValueError('invalid synthetic flag')
    if tag != 2:
        if tag & 0xffffffff == 3:
            return 'drop-only'
        return 'alternate-handoff'
    if flag == 0:
        return 'direct-handoff-then-drop'
    if fail_a or fail_b or zero_result:
        return 'fallback-handoff-then-drop'
    return 'converted-handoff-then-drop'


def loader_model(first_file, second_file, read_ok, parse_tag):
    """Conditional loader branches; parser and predicates are supplied outcomes."""
    if not first_file:
        return 'default-map-absent'
    if not second_file or not read_ok or parse_tag == 2:
        return 'unwrap-boundary'
    if parse_tag not in (0, 1):
        raise ValueError('unsupported abstract parser tag')
    return 'map-absent' if parse_tag == 0 else 'map-present'


def successors(row):
    kind, follow = row['kind'], row['va'] + row['size']
    if kind in ('ret', 'trap', 'jump_indirect'):
        return []
    if kind == 'jump':
        return [row['target']]
    if kind.startswith('j'):
        return [follow, row['target']]
    return [follow]  # Calls are assumed to return normally.


def witness(rows, begin, end):
    index = {r['va']: r for r in rows}
    require(begin in index and end in index, 'witness endpoints are not instructions')
    parents = {begin: None}
    queue = collections.deque([begin])
    while queue and end not in parents:
        at = queue.popleft()
        for following in successors(index[at]):
            if following in index and following not in parents:
                parents[following] = at
                queue.append(following)
    require(end in parents, 'selected normal-flow witness not found')
    path, at = [], end
    while at is not None:
        path.append(at)
        at = parents[at]
    return list(reversed(path))


def possible_rbp_writes(row):
    """Conservative operand check for register writes in this selected FDE."""
    k = row['kind']
    if row.get('reg') == 'rbp' and k in ('extend', 'mov_imm', 'mov_load', 'lea',
                                         'movsxd', 'pop', 'imul', 'bswap', 'bsf', 'tzcnt'):
        return True
    # These encodings put the destination in the ModRM reg field. Most other
    # arithmetic encodings admitted by this reader write the r/m operand.
    if row.get('reg') == 'rbp' and row.get('opcode') in (0x22, 0x23, 0x33):
        return True
    if (row.get('reg') == 'rbp' and row.get('opcode') == 0x0f and
            row.get('opcode2') == 0xd7):  # pmovmskb r32, xmm/mm
        return True
    if (row.get('rm') == 'rbp' and row.get('opcode') == 0x0f and
            row.get('opcode2') == 0x7e and 0xf3 not in row.get('prefixes', ())):
        return True  # movd/movq from SIMD to a general-purpose r/m operand
    if row.get('reg') == 'rbp' and k.startswith('cmov'):
        return True
    if row.get('rm') == 'rbp' and (k in ('mov_store', 'mov_imm_store', 'inc', 'dec',
                                        'neg', 'not', 'add', 'sub', 'xor', 'and',
                                        'or', 'adc', 'sbb', 'shl', 'shr', 'sar', 'rol', 'ror') or
                                     k.startswith('set')):
        return True
    return False


def sentinel_flow(rows):
    """Track rbp=sentinel over normal CFG paths with ABI-preserving calls."""
    index = {r['va']: r for r in rows}
    require(not any(r['kind'] == 'jump_indirect' for r in rows),
            'unmodeled indirect jump in constructor')
    writers = {r['va'] for r in rows if possible_rbp_writes(r)}
    expected = {0x51cf38f, 0x51cf728, 0x51cf8bb, 0x51cfd44,
                0x51cfde6, 0x51d0c7c, 0x51d0e4a, 0x51d0ab8}
    require(writers == expected, 'constructor rbp writer inventory changed')
    sentinel = {0x51cf728, 0x51cfde6}
    require(all(index[v]['kind'] == 'mov_imm' and
                index[v]['immediate'] == 1 << 63 for v in sentinel),
            'constructor sentinel initialization changed')
    entry, targets = 0x51cf360, {0x51d0992, 0x51d0a80}
    queue = collections.deque([(entry, False)])
    seen = {(entry, False)}
    outcomes = {target: set() for target in targets}
    while queue:
        at, valid = queue.popleft()
        row = index[at]
        if at in writers:
            valid = at in sentinel
        if at in targets:
            outcomes[at].add(valid)
        for following in successors(row):
            state = (following, valid)
            if following in index and state not in seen:
                seen.add(state)
                queue.append(state)
    require(all(outcomes[t] == {True} for t in targets),
            'sentinel is not established on every modeled normal path')
    return len(seen), {k: sorted(v) for k, v in sorted(outcomes.items())}, sorted(writers)


def descriptor(im, label, slot, expected):
    at, kind, sym, target = im.rel(slot)
    size = struct.unpack('<Q', im.read(slot + 8, 8))[0]
    text = im.read(target, size)
    require(text == expected, 'selected descriptor spelling mismatch')
    return (label, hex(slot), hex(im.offset(slot, 16)), hex(at),
            hex(target), hex(im.offset(target, size)), size, text.decode('ascii'),
            im.read(slot, 16).hex(), im.data[at:at+24].hex())


def template(im, label, va, suffix):
    prefix = im.read(va, 2)
    require(prefix[0] == 0xc0 and prefix[1] == len(suffix), 'invalid format entry header')
    raw = im.read(va, len(suffix) + 3)
    require(raw[2:-1] == suffix and raw[-1] == 0, 'invalid complete format entry')
    return (label, hex(va), hex(im.offset(va, len(raw))), raw.hex(),
            hex(va + 2), len(suffix), suffix.decode('ascii'))


RELATIVE_SLOTS = (
    ('static-config-cell', 0x64e0918, 0x64f06c0),
    ('api-config-cell', 0x64e0b40, 0x64f0210),
    ('api-config-initializer', 0x64f0210, 0x1568b20),
    ('publish-callback-b', 0x63fdb50, 0x154d160),
    ('publish-callback-a', 0x63fdb58, 0x1543f50),
    ('lookup-entry', 0x64e1058, 0x154aa00),
    ('flag-consumer-entry', 0x64ebc40, 0x51fc3e0),
    ('once-boundary', 0x64df9f0, 0x5c87d50),
    ('path-transform-boundary', 0x64e0948, 0x1500c10),
    ('json-file-read-boundary', 0x64e09c0, 0x5ca4940),
    ('alternate-file-read-boundary', 0x64e09b8, 0x5ca4d50),
    ('allocator-boundary', 0x64df480, 0x6355830),
    ('allocation-failure-boundary', 0x64df498, 0x141e264),
    ('free-boundary', 0x64df4a0, 0x635de30),
    ('scale-boundary', 0x64e0f70, 0x15ed960),
    ('conversion-boundary', 0x64e0f78, 0x162a9a0),
    ('time-boundary', 0x64e0990, 0x1629690),
    ('calendar-boundary', 0x64e0aa0, 0x16290d0),
    ('formatter-boundary', 0x64df6e8, 0x141e3a0),
)


def write_tsv(path, header, rows):
    with path.open('w', encoding='utf-8', newline='') as out:
        writer = csv.writer(out, delimiter='\t', lineterminator='\n')
        writer.writerow(header)
        writer.writerows(rows)


def hx(value):
    return '' if value is None else hex(value)


def compare_historical(path):
    """Separately authenticate and inspect four selected #94 facts; write no files."""
    data = path.read_bytes()
    im = Image(data, HISTORICAL_DIGEST)
    entries = []
    for name, va, suffix, instruction in (
        ('cham', 0x1fc0ec, b'/cham', 0x164f840),
        ('static_config', 0x1ef5f5, b'/static_config', 0x164fbae),
    ):
        evidence = template(im, name, va, suffix)
        raw = im.read(instruction, 7, True)
        require(raw[:3] == b'\x48\x8d\x35', 'historical reference encoding changed')
        target = instruction + 7 + struct.unpack_from('<i', raw, 3)[0]
        require(target == va, 'historical reference target changed')
        entries.append({'label': name, 'entry_va': hex(va), 'entry_hex': evidence[3],
                        'instruction_va': hex(instruction), 'instruction_hex': raw.hex()})
    # The prior 76-name table is not reproduced: only two selected descriptor
    # spellings and the default are checked with the historical digest.
    name_specs = (('NodeTestnet', 5), ('Ee', 17), ('NvTestnet', 32))
    names = []
    for label, index in name_specs:
        slot = 0x5668288 + index * 16
        target = im.rel(slot)[3]
        length = struct.unpack('<Q', im.read(slot + 8, 8))[0]
        require(im.read(target, length) == label.encode('ascii'), 'historical descriptor mismatch')
        names.append({'name': label, 'index': index, 'descriptor_va': hex(slot),
                      'text_va': hex(target), 'length': length})
    # Recover the historical spelling from the fixed equality branch, not
    # from a label or from the current target's literal.
    key = b'chain_to_replica_s3_bucket'
    slot = 0x216ab0 + (len(key) - 6) * 4
    target = 0x216ab0 + struct.unpack('<i', im.read(slot, 4))[0]
    require(target == 0x13c792a, 'historical field length dispatch changed')
    require(im.read(target, 3, True) == bytes((0x80, 0x3e, key[0])),
            'historical field prefix changed')
    for i in range(1, 9):
        pos = 0x13c7933 + (i-1)*10
        require(im.read(pos, 4, True) == bytes((0x80, 0x7e, i, key[i])),
                'historical field byte changed')
    require(im.read(0x13c7983, 7, True) == bytes.fromhex('0fb64e0983f972'),
            'historical field ninth-byte check changed')
    branch = im.read(0x13c798a, 6, True)
    require(branch[:2] == b'\x0f\x84' and 0x13c7990 + struct.unpack_from('<i', branch, 2)[0] == 0x13c8437,
            'historical field ninth-byte branch changed')
    for i in range(10, 26):
        pos = 0x13c8437 + (i-10)*6
        require(im.read(pos, 4, True) == bytes((0x80, 0x7e, i, key[i])),
                'historical field suffix changed')
        branch = im.read(pos+4, 2, True)
        require(branch[0] == 0x75 and pos+6+struct.unpack('b', branch[1:])[0] == 0x13c84a3,
                'historical field suffix branch changed')
    json_base_instruction = 0x13c71d1
    raw = im.read(json_base_instruction, 7, True)
    require(raw[:3] == bytes.fromhex('488d3d'), 'historical JSON table reference changed')
    json_base = json_base_instruction + 7 + struct.unpack_from('<i', raw, 3)[0]
    json_slot = json_base + (len(key) - 6) * 4
    json_arm = json_base + struct.unpack('<i', im.read(json_slot, 4))[0]
    require(json_arm == 0x13c7346, 'historical JSON length arm changed')
    require(im.read(0x13c7373, 9, True) == bytes.fromhex('f30f6f06f30f6f4e0a'),
            'historical JSON overlapping loads changed')
    vectors = []
    for site, prefix in ((0x13c7384, bytes.fromhex('660f7405')),
                         (0x13c737c, bytes.fromhex('660f740d'))):
        instruction = im.read(site, 8, True)
        require(instruction[:4] == prefix, 'historical JSON vector reference changed')
        target_va = site + 8 + struct.unpack_from('<i', instruction, 4)[0]
        vectors.append(im.read(target_va, 16))
    require(vectors[0] + vectors[1][6:] == key and vectors[0][10:] == vectors[1][:6],
            'historical JSON field bytes changed')
    require(im.read(0x13c738c, 14, True) == bytes.fromhex('660fdbc1660fd7c881f9ffff0000'),
            'historical JSON comparison changed')
    json_leaf = im.read(0x13c73a0, 3, True)
    require(json_leaf[:2] == bytes.fromhex('c600'), 'historical JSON field leaf changed')
    field_leaf = im.read(0x13c8497, 4, True)
    require(field_leaf[:3] == bytes.fromhex('c64008'), 'historical field leaf changed')
    default = im.read(0x164fc56, 3, True)
    require(default[:2] == bytes.fromhex('40b5'), 'historical default instruction changed')
    start = 0x1404ef0
    require(im.read(0x1404f0d, 3, True) == bytes.fromhex('83f805') and
            im.read(0x1404f12, 3, True) == bytes.fromhex('83f811') and
            im.read(0x1404f1b, 5, True) == bytes.fromhex('bb03000000') and
            im.read(0x1404f65, 5, True) == bytes.fromhex('bb02000000'),
            'historical lookup selection mismatch')
    _, fdes = eh_frame_records(data, im.secs)
    matches = [r for r in fdes if r['start'] == start]
    require(len(matches) == 1, 'historical FDE missing or ambiguous')
    return {'binary_sha256': HISTORICAL_DIGEST, 'templates': entries, 'names': names,
            'lookup_start_va': hex(start), 'lookup_end_va': hex(matches[0]['end']),
            'name_keys': [[im.read(0x1404f0d, 3, True)[2], im.read(0x1404f65, 5, True)[1]],
                          [im.read(0x1404f12, 3, True)[2], im.read(0x1404f1b, 5, True)[1]]],
            'default_name_tag': default[2],
            'field': {'name': key.decode('ascii'), 'length_slot_va': hex(slot),
                      'entry_va': hex(target), 'success_va': hex(0x13c8497),
                      'tag': field_leaf[3]},
            'json_field': {'length_slot_va': hex(json_slot), 'bucket_va': hex(json_arm),
                           'success_va': hex(0x13c73a0), 'tag': json_leaf[2]}}


def generate(im, out):
    frames, decoded = selected_frames(im)
    insns = instruction_map(decoded)
    verify_pins(insns)
    patterns = field_patterns(im, insns)
    chain_patterns = chain_key_patterns(im, insns)
    constants = name_constants(insns)
    require(constants == (5, 18, 2, 3), 'unexpected name selection')
    require(im.dyn_symbol(0x64df508) == 'memcpy', 'unexpected copy symbol')
    out.mkdir(parents=True, exist_ok=True)

    frame_rows = [[f['name'], hex(f['start']), hex(f['end']), f['end']-f['start'],
                   hex(f['file_offset']), hex(f['fde']), hex(f['cie']), hx(f['lsda']),
                   f['index'], f['sha256']] for f in frames]
    write_tsv(out / 'functions.tsv',
              ['role', 'start_va', 'end_va_exclusive', 'size', 'file_offset',
               'fde_va', 'cie_va', 'lsda_va', 'unwind_index', 'body_sha256'], frame_rows)

    instructions, branches, calls = [], [], []
    for frame in frames:
        for row in decoded[frame['name']]:
            va = row['va']
            instructions.append([frame['name'], hex(va), hex(im.offset(va, row['size'], True)),
                                 row['size'], row['bytes'], row['kind'], hx(row.get('target')),
                                 hx(row.get('memory_va'))])
            if row['kind'] == 'jump' or (row['kind'].startswith('j') and row['kind'] != 'jump_indirect'):
                branches.append([frame['name'], hex(va), row['bytes'], row['kind'],
                                 '' if row['kind'] == 'jump' else hex(va + row['size']), hex(row['target'])])
            if row['kind'] in ('call', 'call_indirect', 'jump_indirect'):
                calls.append([frame['name'], hex(va), row['bytes'], row['kind'],
                              hx(row.get('target')), hx(row.get('memory_va'))])
    write_tsv(out / 'instructions.tsv',
              ['role', 'va', 'file_offset', 'size', 'bytes', 'kind', 'direct_target', 'rip_memory_va'], instructions)
    write_tsv(out / 'branches.tsv', ['role', 'va', 'bytes', 'kind', 'fallthrough_va', 'target_va'], branches)
    write_tsv(out / 'transfers.tsv', ['role', 'va', 'bytes', 'kind', 'direct_target', 'rip_memory_va'], calls)

    contract_rows = []
    for label, va in CONTRACTS:
        row = insns[va]
        contract_rows.append([label, hex(va), hex(im.offset(va, row['size'], True)),
                              row['bytes'], row['kind'], hx(row.get('target')),
                              hx(row.get('memory_va')), row.get('immediate', '')])
    write_tsv(out / 'contracts.tsv',
              ['role', 'va', 'file_offset', 'bytes', 'kind', 'target_va', 'rip_memory_va', 'immediate'], contract_rows)

    desc_specs = (
        ('chain-0', 0x63f8748, b'Local'), ('chain-1', 0x63f8758, b'Sandbox'),
        ('chain-2', 0x63f8768, b'Testnet'), ('chain-3', 0x63f8778, b'Mainnet'),
        ('name-5', 0x63f87d8, b'NodeTestnet'), ('name-17', 0x63f8898, b'Ed'),
        ('name-18', 0x63f88a8, b'Ee'), ('name-33', 0x63f8998, b'NvTestnet'),
        ('source-path', 0x63fe3d8, b'base/src/api_secrets.rs'),
    )
    descriptors = [descriptor(im, *spec) for spec in desc_specs]
    write_tsv(out / 'descriptors.tsv',
              ['role', 'slot_va', 'slot_file_offset', 'rela_file_offset', 'text_va',
               'text_file_offset', 'length', 'ascii', 'slot_hex', 'rela_hex'], descriptors)
    entries = [template(im, 'cham', 0x44ab69, b'/cham'),
               template(im, 'static_config', 0x4401ef, b'/static_config'),
               template(im, 'api_config', 0x43058f, b'/api_secrets.json')]
    write_tsv(out / 'templates.tsv', ['role', 'entry_va', 'file_offset', 'bytes',
                                      'text_va', 'text_length', 'suffix'], entries)

    anchors = []
    for label, va, expected in (
        ('field-other-first', 0x452690, patterns[0][0][:16]),
        ('field-other-tail', 0x455340, patterns[0][0][10:]),
        ('field-selected-first', 0x4529c0, patterns[1][0][:16]),
        ('field-selected-tail', 0x4536a0, patterns[1][0][10:]),
        ('field-diagnostic', 0x4681b8, patterns[1][0]),
        ('duplicate-format', 0x43351a, b'\x11duplicate field `\xc0\x01`\x00'),
        ('binary64-scale', 0x4593e0, bytes.fromhex('9a9999999999b93f')),
        ('conversion-fallback', 0x4679d0, bytes.fromhex('ded6ff7f7f510100ffc99a3b')),
        ('api-lazy-guard-initial', 0x64f03d0, bytes.fromhex('03000000')),
    ):
        raw = im.read(va, len(expected))
        require(raw == expected, 'selected data anchor differs')
        anchors.append([label, hex(va), hex(im.offset(va, len(raw))), len(raw), raw.hex()])
    write_tsv(out / 'data-anchors.tsv', ['role', 'va', 'file_offset', 'length', 'raw_hex'], anchors)
    require(insns[0x1568b56]['memory_va'] == 0x43058f, 'config format reference changed')
    format_ref = insns[0x1568b56]
    write_tsv(out / 'format-references.tsv', ['role', 'instruction_va', 'file_offset',
              'bytes', 'entry_va'], [['api-config-format', hex(format_ref['va']),
              hex(im.offset(format_ref['va'], format_ref['size'], True)), format_ref['bytes'],
              hex(format_ref['memory_va'])]])

    refs = []
    for role, slot, expected in RELATIVE_SLOTS:
        at, typ, symbol, addend = im.rel(slot, expected)
        refs.append([role, hex(slot), hex(im.offset(slot, 8)), hex(at), typ, symbol,
                     hex(addend), im.read(slot, 8).hex(), im.data[at:at+24].hex(), ''])
    at, typ, symbol, addend = im.rela()[0x64df508]
    require(typ == 6 and addend == 0, 'unexpected memcpy relocation')
    refs.append(['copy-import', hex(0x64df508), hex(im.offset(0x64df508, 8)), hex(at),
                 typ, symbol, hex(addend), im.read(0x64df508, 8).hex(),
                 im.data[at:at+24].hex(), im.dyn_symbol(0x64df508)])
    write_tsv(out / 'relocations.tsv', ['role', 'slot_va', 'slot_file_offset',
              'rela_file_offset', 'type', 'symbol_index', 'addend', 'slot_hex', 'rela_hex', 'symbol'], refs)

    dispatches = []
    specs = [('field-length', 0x467458, 28, 'field_classifier', 6),
             ('field-tag', 0x467cd0, 18, 'json_fields', 22),
             ('chain-key', 0x463c98, 5, 'chain_key_adapter', 0)]
    for label, base, count, role, domain_base in specs:
        starts = {r['va'] for r in decoded[role]}
        for idx, slot, raw, target in table(im, base, count, starts):
            dispatches.append([label, idx, domain_base + idx, hex(base), hex(slot),
                               hex(im.offset(slot, 4)), raw, hex(target)])
    require(next(row for row in dispatches if row[0] == 'field-length' and row[1] == 20)[7] == hex(0x155e58b),
            '26-byte field bucket changed')
    require(next(row for row in dispatches if row[0] == 'field-tag' and row[1] == 12)[7] == hex(0x157f3c4),
            'selected field arm changed')
    require([int(row[7], 16) for row in dispatches if row[0] == 'chain-key'] ==
            [0x14bcc70, 0x14bcd16, 0x14bcd04, 0x14bcd0d, 0x14bccf2],
            'chain key dispatch changed')
    write_tsv(out / 'dispatch.tsv', ['table', 'index', 'nominal_input', 'base_va',
                                    'slot_va', 'slot_offset', 'entry_hex', 'target_va'], dispatches)

    field_rows = []
    for label, name, expect in [('other', patterns[0][0], patterns[0][1]),
                                ('selected', patterns[1][0], patterns[1][1])]:
        field_rows.append([label, 'exact', -1, name.hex(), field_match(name, patterns), expect])
        for bit in range(len(name) * 8):
            changed = bytearray(name)
            changed[bit // 8] ^= 1 << (bit % 8)
            field_rows.append([label, 'one-bit', bit, bytes(changed).hex(),
                               field_match(changed, patterns), 13])
    require(all(row[-2] == row[-1] for row in field_rows), 'field-probe expectation mismatch')
    write_tsv(out / 'field-probes.tsv', ['pattern', 'probe', 'changed_bit', 'input_hex',
                                        'actual_tag_model', 'expected_tag'], field_rows)

    key_probes = []
    for name, tag in chain_patterns:
        key_probes.append([name.decode('ascii'), 'exact', -1, name.hex(), tag, tag])
        for bit in range(len(name) * 8):
            value = bytearray(name)
            value[bit // 8] ^= 1 << (bit % 8)
            actual = chain_key_match(value, chain_patterns)
            key_probes.append([name.decode('ascii'), 'one-bit', bit, bytes(value).hex(),
                               '' if actual is None else actual, ''])
    require(all(row[-2] == row[-1] for row in key_probes), 'chain-key probe mismatch')
    write_tsv(out / 'chain-key-probes.tsv', ['name', 'probe', 'changed_bit', 'input_hex',
                                            'actual_tag_model', 'expected_tag'], key_probes)
    synthetic_trees = (
        ('empty-root', None, 0),
        ('empty-leaf', {'pairs': []}, 0),
        ('single-leaf', {'pairs': [(2, 0), (3, 9)]}, 0),
        ('two-level', {'pairs': [(2, 7)], 'children': [
            {'pairs': [(0, 1), (1, 2)]}, {'pairs': [(3, 0)]}]}, 1),
    )
    tree_cases = []
    for label, node, depth in synthetic_trees:
        for key in range(4):
            found = tree_lookup(key, node, depth)
            tree_cases.append([label, key, depth, '' if found is None else found,
                               'missing' if found is None else 'present'])
    write_tsv(out / 'tree-cases.tsv', ['shape', 'chain_key', 'depth', 'value_length', 'outcome'], tree_cases)
    releases = []
    for old in (0, 1, 2, (1 << 63) - 1, 1 << 63, (1 << 63) + 1, (1 << 64) - 1):
        releases.append([hex(old), hex((old * 2) & ((1 << 64) - 1)), int(replacement_release(old))])
    write_tsv(out / 'replacement-cases.tsv', ['old_first_word', 'doubled_mod_2_64',
                                               'reaches_free_on_normal_return'], releases)
    updates = []
    for existing in ([], [(2, 5)], [(1, 0), (3, 9)]):
        for key in range(4):
            for size in (0, 7):
                result, previous, operation = map_update_model(existing, key, size)
                updates.append([json.dumps(existing, separators=(',', ':')), key, size,
                                operation, '' if previous is None else previous,
                                json.dumps(result, separators=(',', ':'))])
    write_tsv(out / 'map-update-cases.tsv', ['entries_before', 'key', 'value_length',
              'operation', 'prior_value_length', 'entries_after'], updates)

    names = [[tag, '' if (key := name_key(tag, constants)) is None else key] for tag in range(256)]
    write_tsv(out / 'name-domain.tsv', ['input_byte', 'selected_chain_key'], names)
    testcases = (
        ('nonselected_name', 17, 1, {2: 7, 3: 8}, True),
        ('historical_default_byte', 32, 1, {2: 7, 3: 8}, True),
        ('current_default_byte', 33, 1, {2: 7, 3: 8}, True),
        ('outside_named_domain', 255, 1, {2: 7, 3: 8}, True),
        ('absent_option', 5, 0, {2: 7}, True),
        ('null_root', 5, 1, None, True),
        ('missing_key', 5, 1, {3: 9}, True),
        ('testnet_empty_value', 5, 1, {2: 0}, True),
        ('testnet_nonempty_value', 5, 1, {2: 7}, True),
        ('testnet_allocation_failure', 5, 1, {2: 7}, False),
        ('mainnet_empty_value', 18, 1, {3: 0}, True),
        ('mainnet_nonempty_value', 18, 1, {3: 9}, True),
        ('unsupported_option_tag', 18, 2, {3: 9}, True),
    )
    scenario_rows = []
    for label, tag, opt, values, ok in testcases:
        result = route_model(tag, opt, values, allocation_ok=ok, constants=constants)
        scenario_rows.append([label, tag, opt, json.dumps(values, sort_keys=True, separators=(',', ':')),
                              int(ok), '' if result['key'] is None else result['key'], result['outcome'],
                              hx(result['first_word']), result['pointer'] if result['pointer'] is not None else '',
                              '' if result['flag'] is None else result['flag'], int(result['release'])])
    write_tsv(out / 'lookup-cases.tsv', ['case', 'name_byte', 'option_tag', 'synthetic_key_lengths',
              'allocation_returns', 'selected_key', 'outcome', 'first_word', 'pointer_model',
              'caller_flag', 'free_on_normal_return'], scenario_rows)
    loaders = []
    for first in (False, True):
        for second in (False, True):
            for read_ok in (False, True):
                for tag in (0, 1, 2):
                    loaders.append([int(first), int(second), int(read_ok), tag,
                                    loader_model(first, second, read_ok, tag)])
    write_tsv(out / 'loader-cases.tsv', ['first_predicate', 'second_predicate', 'read_success',
                                        'abstract_parser_tag', 'initializer_outcome_model'], loaders)

    handoffs = []
    values = (0, 1, (1 << 63) - 1, 1 << 63, (1 << 63) + 1, (1 << 64) - 1)
    for current in values:
        for returned in values:
            model = handoff_model(current, returned)
            handoffs.append([hex(current), hex(returned), model['route'],
                             int(model['release_returned']), int(model['replace_current']),
                             int(model['write_forwarded'])])
    write_tsv(out / 'handoff-cases.tsv', ['current_word', 'returned_word', 'route',
              'release_returned', 'replace_current', 'write_forwarded_on_normal_return'], handoffs)

    consumers = []
    for tag in (0, 2, 3, 0x100000002, 0x100000003):
        for flag in (0, 1, 255):
            for fail_a, fail_b, zero in ((False, False, False), (True, False, False),
                                         (False, True, False), (False, False, True)):
                consumers.append([hex(tag), flag, int(fail_a), int(fail_b), int(zero),
                                  consumer_model(tag, flag, fail_a, fail_b, zero)])
    write_tsv(out / 'consumer-cases.tsv', ['tag_word', 'flag_byte', 'first_range_reject',
              'second_range_reject', 'helper_returns_zero', 'outcome_model'], consumers)

    ex_rows = []
    for frame in frames:
        starts = {r['va'] for r in decoded[frame['name']]}
        for at, first, last, pad, action, raw in exceptions(im, frame, starts):
            ex_rows.append([frame['name'], hex(frame['lsda']), hex(at), hex(first), hex(last),
                            hx(pad), action, raw])
    write_tsv(out / 'exception-sites.tsv', ['role', 'lsda_va', 'record_file_offset',
              'first_va', 'end_va_exclusive', 'landing_va', 'action_uleb', 'raw_hex'], ex_rows)

    checks = (
        ('loader-first-to-json', 'document_loader', 0x1501709, 0x150198f),
        ('loader-json-to-result', 'document_loader', 0x150198f, 0x1501765),
        ('field-arm-to-value', 'json_fields', 0x157f3c4, 0x157fb66),
        ('duplicate-field-to-error', 'json_fields', 0x1583658, 0x158157d),
        ('field-success-to-stash', 'json_fields', 0x157fb6b, 0x157fb96),
        ('field-stash-to-default-setup', 'json_fields', 0x157fb96, 0x1580245),
        ('field-default-setup-to-select', 'json_fields', 0x1580245, 0x15804e3),
        ('field-select-to-result-copy', 'json_fields', 0x15804e3, 0x158080c),
        ('constructor-entry-to-lookup', 'caller_constructor', 0x51cf360, 0x51d0992),
        ('constructor-lookup-to-flag', 'caller_constructor', 0x51d0992, 0x51d0a83),
        ('consumer-flag-to-handoff', 'flag_consumer', 0x51fc435, 0x51fc59b),
        ('consumer-fallback-to-handoff', 'flag_consumer', 0x51fc554, 0x51fc59b),
        ('handoff-replace-to-update', 'consumer_state_handoff', 0x4e39ec4, 0x4e39f7c),
        ('handoff-update-to-write', 'consumer_state_handoff', 0x4e39f7c, 0x4e39f8f),
        ('handoff-sentinel-to-return', 'consumer_state_handoff', 0x4e39e93, 0x4e39fd7),
    )
    graph_rows = []
    for label, role, begin, end in checks:
        path = witness(decoded[role], begin, end)
        graph_rows.append([label, role, hex(begin), hex(end), len(path),
                           ','.join(hex(v) for v in path)])
    state_count, outcomes, writers = sentinel_flow(decoded['caller_constructor'])
    write_tsv(out / 'normal-flow-witnesses.tsv', ['claim', 'role', 'begin_va', 'end_va',
              'instruction_count', 'witness_vas'], graph_rows)
    data = {'target': 'node115', 'binary_sha256': DIGEST,
            'selected_fdes': len(frames), 'selected_fde_bytes': sum(f['end']-f['start'] for f in frames),
            'decoded_instructions': len(instructions), 'direct_branches': len(branches),
            'selected_transfers': len(calls), 'semantic_pins': len(PINS),
            'review_contracts': len(contract_rows), 'exception_call_sites': len(ex_rows),
            'selected_descriptors': len(descriptors), 'selected_templates': len(entries),
            'data_anchors': len(anchors), 'format_references': 1,
            'selected_relocation_slots': len(refs), 'selected_dispatch_slots': len(dispatches),
            'field_probe_cases': len(field_rows), 'chain_key_probe_cases': len(key_probes),
            'tree_cases': len(tree_cases), 'map_update_cases': len(updates),
            'replacement_cases': len(releases), 'name_byte_cases': len(names),
            'lookup_cases': len(scenario_rows), 'loader_cases': len(loaders),
            'consumer_cases': len(consumers), 'handoff_cases': len(handoffs),
            'normal_flow_witnesses': len(graph_rows), 'constructor_cfg_states': state_count,
            'constructor_rbp_writers': [hex(v) for v in writers],
            'constructor_rbp_at_targets': {hex(k): v for k, v in outcomes.items()},
            'limitations': 'Static selected paths, not target execution, a complete CFG, helper closure, or equivalence.'}
    (out / 'summary.json').write_text(json.dumps(data, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    return data


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--compare-94', type=Path, help='optional separately authenticated historical capture')
    args = p.parse_args()
    im = Image(CAPTURE.read_bytes())
    # Do not create partial output if the optional historical image is invalid.
    historical = compare_historical(args.compare_94) if args.compare_94 else None
    generate(im, args.out)
    if historical is not None:
        print(json.dumps(historical, sort_keys=True, indent=2))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (EvidenceError, ValueError, OSError, struct.error) as exc:
        print('re015_config_gate115: ' + str(exc), file=sys.stderr)
        raise SystemExit(1)
