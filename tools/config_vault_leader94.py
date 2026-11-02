#!/usr/bin/env python3
"""Statically bind node 94 configuration-gated address-keyed vault listing.

The instruction reader adapts the independent MIT research decoder used by
RE-015 agent-timing (#1603); ELF and unwind parsing use the shared readers.
This tool never runs the captured program or invokes an external program.
"""
import argparse
import csv
import hashlib
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

class EvidenceError(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise EvidenceError(reason)


class Image:
    def __init__(self, data, *, verify=True):
        require(not verify or hashlib.sha256(data).hexdigest() == DIGEST, 'node 94 digest mismatch')
        self.data = data
        self.sections = sections(data)
        _, self.fdes = eh_frame_records(data, self.sections)
        self.relocations = {}
        self.relocation_offsets = {}
        self.symbols = {}
        self.symbol_offsets = {}
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
                    self.symbol_offsets[slot] = pos

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
        elif op == 0x98: row['kind'] = 'sign_extend_accumulator'
        elif op in (0xc3,0x90):
            row['kind'] = 'ret' if op==0xc3 else 'nop'
        elif 0xb0 <= op <= 0xbf:
            row['kind']='mov_imm'; row['reg']=REG[(op&7)+((rex&1)<<3)]
            row['width']=8 if op<0xb8 else width
            imm=1 if op<0xb8 else width//8
        elif op in (0x04,0x05,0x0c,0x0d,0x1c,0x1d,0x24,0x25,0x2c,0x2d,0x34,0x35,0x3c,0x3d):
            row['kind']={0:'add',8:'or',0x18:'sbb',0x20:'and',0x28:'sub',0x30:'xor',0x38:'cmp'}[op&0xf8]
            row['reg']='rax';row['width']=8 if op&1==0 else width
            imm=1 if op&1==0 else (2 if width==16 else 4)
        elif op==0x0f:
            op2=take(1)[0];row['opcode2']=op2
            if 0x80<=op2<=0x8f:
                delta=int.from_bytes(take(4),'little',signed=True)
                row['kind']='j'+CC[op2&15];row['target']=base+p+delta
            elif op2==0x0b:row['kind']='trap'
            elif 0xc8<=op2<=0xcf:row['kind']='bswap';row['reg']=REG[(op2&7)+((rex&1)<<3)]
            elif op2 in (0x10,0x11,0x13,0x14,0x15,0x28,0x29,0x2a,0x2c,0x2e,0x57,0x58,0x59,0x5c,0x5d,0x5e,0x5f,0x62,0x6e,0x6f,0x74,0x76,0x7e,0x7f,0xd7,0xdb):
                row['kind']='sse_'+hex(op2);modrm=True
                if op2 in (0x6e,0x7e):
                    row['width'] = 64 if rex & 8 else 32
                else:
                    row['width'] = 64 if 0xf2 in prefixes else 128
            elif op2==0x1f:row['kind']='nop';modrm=True
            elif op2 in (0xb6,0xb7,0xbe,0xbf):row['kind']='extend';modrm=True;row['source_width']=8 if op2 in (0xb6,0xbe) else 16
            elif op2==0xa3:row['kind']='bt';modrm=True
            elif op2==0xaf:row['kind']='imul';modrm=True
            elif op2 in (0xb1,0xc1):row['kind']='cmpxchg' if op2==0xb1 else 'xadd';modrm=True
            elif op2==0xbc:row['kind']='tzcnt' if 0xf3 in prefixes else 'bsf';modrm=True
            elif op2==0xbd:row['kind']='bsr';modrm=True
            elif 0x40<=op2<=0x4f:row['kind']='cmov'+CC[op2&15];modrm=True
            elif 0x90<=op2<=0x9f:row['kind']='set'+CC[op2&15];modrm=True;row['width']=8
            else:raise EvidenceError('unsupported two-byte opcode '+hex(op2)+' at '+hex(base+start))
        elif op in (0x00,0x01,0x03,0x08,0x09,0x20,0x21,0x28,0x29,0x2b,0x30,0x31,0x33,0x38,0x39,0x3b,0x23,0x85,0x84,0x88,0x89,0x8b,0x8d,0x63):
            row['kind']={0x00:'add',0x01:'add',0x03:'add',0x08:'or',0x09:'or',0x20:'and',0x21:'and',0x23:'and',0x28:'sub',0x29:'sub',0x2b:'sub',0x30:'xor',0x31:'xor',0x33:'xor',0x38:'cmp',0x39:'cmp',0x3b:'cmp',0x85:'test',0x84:'test',0x88:'mov_store',0x89:'mov_store',0x8b:'mov_load',0x8d:'lea',0x63:'movsxd'}[op]
            modrm=True
            if op in (0x00,0x08,0x20,0x28,0x30,0x38,0x84,0x88):row['width']=8
        elif op==0xa8:
            row['kind']='test';row['reg']='rax';row['width']=8;imm=1
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
                if group not in (0,2,3,4,5):raise EvidenceError('unsupported unary group')
                row['kind']={0:'test',2:'not',3:'neg',4:'mul',5:'imul'}[group]
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





# Exact instruction bytes bind each interpretation to the selected capture.
CONTRACTS = (
    ('wrapper_call', 0x2587010, 'e89b0c2500'),
    ('wrapper_duration_sum', 0x258702a, 'f20f584c2450'),
    ('wrapper_threshold_compare', 0x2587035, '660f2e0d7b3ac8fd'),
    ('wrapper_threshold_branch', 0x258703d, '762d'),
    ('config_cell_slot', 0x258703f, '4c8b35e2781e03'),
    ('config_once_state', 0x2587046, '418b4650'),
    ('config_once_branch', 0x258704c, '753a'),
    ('config_name_byte', 0x258704e, '410fb64648'),
    ('config_bound', 0x2587053, '83f81f'),
    ('config_outside_branch', 0x2587056, '7714'),
    ('config_mask', 0x2587058, 'b900603c80'),
    ('config_bit_test', 0x258705d, '0fa3c1'),
    ('config_bit_branch', 0x2587060, '730a'),
    ('build_once_state', 0x2587062, '8b05303b1f03'),
    ('build_once_branch', 0x258706a, '754f'),
    ('wrapper_return_copy_high', 0x258706c, '488b442420'),
    ('wrapper_return_copy_low', 0x2587075, '0f28442410'),
    ('wrapper_return', 0x2587087, 'c3'),
    ('config_slow_once_call', 0x25870b3, 'ff15ff771e03'),
    ('config_slow_return', 0x25870b9, 'eb93'),
    ('build_cell_address', 0x25870bb, '488d05be3a1f03'),
    ('build_once_address', 0x25870d1, '488d3dc03a1f03'),
    ('build_slow_once_call', 0x25870f0, 'ff15c2771e03'),
    ('build_slow_return', 0x25870f6, 'e971ffffff'),
    ('wrapper_unwind_cleanup', 0x2587103, 'e8383af8ff'),
    ('wrapper_unwind_resume', 0x258710b, 'e800900d03'),
    ('lock_timer_start', 0x27d7ccf, 'e82cbb7002'),
    ('lock_field', 0x27d7cd9, '4d8dbc2468050000'),
    ('lock_word_load', 0x27d7ce1, '498b842468050000'),
    ('lock_writer_bit', 0x27d7ceb, '83e108'),
    ('lock_saturation', 0x27d7cf1, '4883f8f0'),
    ('lock_fast_branch', 0x27d7cfa, '7412'),
    ('lock_slow_call', 0x27d7d06, 'ff15dc78f902'),
    ('lock_fast_update', 0x27d7d0e, '488d4810'),
    ('lock_compare_exchange', 0x27d7d12, 'f0490fb10f'),
    ('lock_retry_slow', 0x27d7d17, '75e3'),
    ('lock_timer_acquired', 0x27d7d23, 'e8d8ba7002'),
    ('lock_time_diff1', 0x27d7d5a, 'e8d1b97002'),
    ('lock_time_result1', 0x27d7d6e, '7539'),
    ('key_copy_high', 0x27d7da9, '418b4510'),
    ('key_copy_low', 0x27d7db1, '66410f104500'),
    ('map_root', 0x27d7dbd, '498b8424c0180000'),
    ('map_root_branch', 0x27d7dc8, '7411'),
    ('collector_call', 0x27d7e25, 'e8d61ed9ff'),
    ('unlock_sub16', 0x27d7e2a, '48c7c0f0ffffff'),
    ('unlock_atomic', 0x27d7e36, 'f0480fc107'),
    ('unlock_mask', 0x27d7e3b, '4883e0f2'),
    ('unlock_compare', 0x27d7e3f, '4883f812'),
    ('unlock_wake_branch', 0x27d7e43, '0f84f5000000'),
    ('lock_timer_released', 0x27d7e4e, 'e8adb97002'),
    ('lock_time_diff2', 0x27d7e7d, 'e8aeb87002'),
    ('lock_time_result2', 0x27d7e93, '7536'),
    ('optional_flag', 0x27d7e82, '0fb68424e0000000'),
    ('optional_flag_test', 0x27d7ef7, '84c0'),
    ('optional_flag_branch', 0x27d7ef9, '740b'),
    ('optional_call_value', 0x27d7efb, 'bf32000000'),
    ('optional_call', 0x27d7f00, 'ff15f269f902'),
    ('locked_result_store', 0x27d7f26, '0f1103'),
    ('locked_return', 0x27d7f3d, 'c3'),
    ('unlock_wake_call', 0x27d7f3e, 'ff15b476f902'),
    ('cleanup_after_copy', 0x27d7f51, 'e89a38faff'),
    ('cleanup_after_copy_resume', 0x27d7f59, 'e8b281e802'),
    ('unwind_unlock', 0x27d7f6a, 'f0480fc10a'),
    ('cleanup_before_copy', 0x27d7f9a, 'e881a5faff'),
    ('cleanup_before_copy_resume', 0x27d7fa2, 'e86981e802'),
    ('first_iter_call', 0x2569d17, 'e8f4742700'),
    ('first_empty', 0x2569d1f, '0f84b4000000'),
    ('first_key_pointer', 0x2569d44, '498b4748'),
    ('first_leader_vector', 0x2569d48, 'f30f6f8298000000'),
    ('first_leader_tail', 0x2569d58, '660f6e82a8000000'),
    ('first_key_tail', 0x2569d60, '660f6e5010'),
    ('first_match_mask', 0x2569d6d, '660fd7c2'),
    ('first_match_compare', 0x2569d71, '3dffff0000'),
    ('first_mismatch', 0x2569d76, '75b8'),
    ('first_closed_test', 0x2569d78, '80baac00000000'),
    ('first_closed_skip', 0x2569d7f, '75af'),
    ('first_name_length', 0x2569d81, '4c8b6230'),
    ('first_name_zero', 0x2569d88, '746b'),
    ('first_name_pointer', 0x2569d8a, '488b6a28'),
    ('first_name_allocate', 0x2569d91, 'ff1541422003'),
    ('first_name_alloc_fail', 0x2569d9a, '0f849c040000'),
    ('first_name_copy', 0x2569dac, 'ff152e422003'),
    ('first_key_out_head', 0x2569db2, 'f3410f6f06'),
    ('first_key_out_tail', 0x2569dbc, '418b4610'),
    ('first_name_sentinel', 0x2569dc4, '48b80000000000000080'),
    ('first_sentinel_compare', 0x2569dce, '4939c4'),
    ('first_sentinel_skip', 0x2569dd1, '0f8459ffffff'),
    ('first_empty_capacity', 0x2569dd9, '48c70300000000'),
    ('first_empty_pointer', 0x2569de0, '48c7430808000000'),
    ('first_empty_length', 0x2569de8, '48c7431000000000'),
    ('first_empty_name_pointer', 0x2569e07, '41bd01000000'),
    ('first_rows_allocation_size', 0x2569e25, 'bfc0000000'),
    ('first_rows_allocate', 0x2569e2a, 'ff15a8412003'),
    ('first_rows_alloc_fail', 0x2569e33, '0f8421040000'),
    ('first_row_len', 0x2569e39, '4c896010'),
    ('first_row_key_head', 0x2569e43, 'f30f7f4018'),
    ('first_row_key_tail', 0x2569e4c, '894828'),
    ('first_row_cap', 0x2569e4f, '4c8920'),
    ('first_row_name_pointer', 0x2569e52, '4c896808'),
    ('first_vector_capacity', 0x2569e56, '48c7042404000000'),
    ('first_vector_length', 0x2569e68, '48c744241001000000'),
    ('row_stride3', 0x2569eb1, '488d0476'),
    ('row_stride16', 0x2569eb5, '48c1e004'),
    ('row_next_cap', 0x2569ebe, '4c893c02'),
    ('row_next_ptr', 0x2569ec2, '4c89640208'),
    ('row_next_len', 0x2569ec7, '4c897c0210'),
    ('row_next_key_head', 0x2569ed2, 'f30f7f440218'),
    ('row_next_key_tail', 0x2569edc, '894c0228'),
    ('row_length_increment', 0x2569ee0, '48ffc6'),
    ('iterator_guard_failure', 0x2569f03, '0f8424030000'),
    ('iterator_parent_failure', 0x2569fea, '0f842e020000'),
    ('iterator_remaining_dec', 0x256a0a7, '49ffce'),
    ('next_value_stride', 0x256a0aa, '4869c2b0000000'),
    ('next_leader_vector', 0x256a0b1, 'f30f6f840198000000'),
    ('next_leader_tail', 0x256a0c7, '660f6e8401a8000000'),
    ('next_key_tail', 0x256a0d0, '660f6e5610'),
    ('next_match_mask', 0x256a0dd, '660fd7f2'),
    ('next_match_compare', 0x256a0e1, '81feffff0000'),
    ('next_mismatch', 0x256a0e7, '0f8503feffff'),
    ('next_closed_test', 0x256a0ed, '80bc01ac00000000'),
    ('next_closed_skip', 0x256a0f5, '0f85f5fdffff'),
    ('next_key_va', 0x256a103, '4981c798070000'),
    ('next_name_length', 0x256a10d, '488b7830'),
    ('next_name_zero', 0x256a114, '747c'),
    ('next_name_pointer', 0x256a11b, '4c8b6028'),
    ('next_name_allocate', 0x256a122, 'ff15b03e2003'),
    ('next_name_alloc_fail', 0x256a12b, '0f8419010000'),
    ('next_name_copy', 0x256a13d, 'ff159d3e2003'),
    ('next_name_sentinel', 0x256a156, '48b80000000000000080'),
    ('next_sentinel_compare', 0x256a160, '4939c5'),
    ('next_sentinel_skip', 0x256a16b, '0f847ffdffff'),
    ('vector_length_vs_capacity', 0x256a1c7, '483b3424'),
    ('vector_has_room', 0x256a1cb, '0f85e0fcffff'),
    ('vector_growth_request_one', 0x256a1d1, 'ba01000000'),
    ('vector_growth_alignment', 0x256a1d6, 'b908000000'),
    ('vector_growth_stride', 0x256a1db, '41b830000000'),
    ('vector_growth_call', 0x256a1e4, 'e8870efbff'),
    ('collector_return_length', 0x256a1f8, '48894310'),
    ('collector_return_capacity', 0x256a200, '488903'),
    ('collector_return_pointer', 0x256a208, '48894308'),
    ('collector_return', 0x256a21d, 'c3'),
    ('parent_failure_call', 0x256a225, 'ff1545422003'),
    ('iterator_failure_call', 0x256a234, 'ff1536422003'),
    ('name_alloc_fail_first', 0x256a244, 'ff156e3d2003'),
    ('name_alloc_fail_next', 0x256a252, 'ff15603d2003'),
    ('rows_alloc_fail', 0x256a264, 'ff154e3d2003'),
    ('failure_trap', 0x256a26a, '0f0b'),
    ('collector_pending_free', 0x256a27c, 'ff158e3d2003'),
    ('collector_first_name_free', 0x256a294, 'ff15763d2003'),
    ('collector_vector_cleanup', 0x256a2a8, 'e89308faff'),
    ('collector_unwind_resume', 0x256a2b0, 'e85b5e0f03'),
    ('cleanup_a_len', 0x277b800, '4c8b7f10'),
    ('cleanup_a_empty', 0x277b807, '7435'),
    ('cleanup_a_stride', 0x277b820, '4983c430'),
    ('cleanup_a_row_capacity', 0x277b829, '498b7424f8'),
    ('cleanup_a_row_free', 0x277b839, '41ffd5'),
    ('cleanup_a_vector_capacity', 0x277b83e, '498b06'),
    ('cleanup_a_empty_capacity', 0x277b844, '741c'),
    ('cleanup_a_backing_size_scale', 0x277b846, '48c1e004'),
    ('cleanup_a_backing_size_triple', 0x277b84a, '488d3440'),
    ('cleanup_a_backing_free', 0x277b85c, 'ff25ae27ff02'),
    ('cleanup_a_return', 0x277b86b, 'c3'),
    ('cleanup_b_len', 0x2782530, '4c8b7f10'),
    ('cleanup_b_empty', 0x2782537, '7435'),
    ('cleanup_b_stride', 0x2782550, '4983c430'),
    ('cleanup_b_row_capacity', 0x2782559, '498b7424f8'),
    ('cleanup_b_row_free', 0x2782569, '41ffd5'),
    ('cleanup_b_vector_capacity', 0x278256e, '498b06'),
    ('cleanup_b_empty_capacity', 0x2782574, '741c'),
    ('cleanup_b_backing_size_scale', 0x2782576, '48c1e004'),
    ('cleanup_b_backing_size_triple', 0x278257a, '488d3440'),
    ('cleanup_b_backing_free', 0x278258c, 'ff257ebafe02'),
    ('cleanup_b_return', 0x278259b, 'c3'),
)

# Each selected range is a decoded FDE extent; an FDE is not by itself a
# source-level function boundary or proof of complete control flow.
BODIES = {
    0x2586fd0: ('query_wrapper', 0x2587110, 'c1ea115837dab059c5e479d5a898c33ae1ffa409eeddafbe89f8d5236a3d0804'),
    0x27d7cb0: ('locked_query', 0x27d7fe0, '7ee57b0d1db93516219dbe8f6932c593357740233a84ee15c350f164b6bc6768'),
    0x2569d00: ('selected_record_collector', 0x256a2b7, '823dae0081e81ff6edbc182c214072237186671edf156d644c1962b515f7adf9'),
    0x277b7f0: ('copied_vector_cleanup', 0x277b86c, 'facf5673077a33f75a39614326be665793b87724fe0d9c1529d7cb76e75304f6'),
    0x2782520: ('original_vector_cleanup', 0x278259c, 'd9f9d96ebc8549e0a9758ec04ffbb1afc8bd3d7b8f45fc409d69fb4d9f11271f'),
}


def exception_sites(image, functions, instructions):
    """Decode selected call-site tables, leaving action/type semantics unresolved."""
    at = {row['va']: row for row in instructions}
    sections = [s for s in image.sections if s['name'] == '.gcc_except_table']
    require(len(sections) == 1 and sections[0]['type'] != 8, 'missing exception table')
    section = sections[0]
    headers, rows = [], []
    for function in functions:
        address = function['lsda']
        if address is None:
            continue
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
        pos, type_base = 2, None
        if type_encoding != 0xff:
            displacement, pos = uleb(raw, pos, len(raw))
            type_base = pos + displacement
            require(type_base <= len(raw), 'LSDA type base outside bound')
        require(pos < len(raw) and raw[pos] == 1, 'unsupported LSDA call-site encoding')
        pos += 1
        length, pos = uleb(raw, pos, len(raw))
        table_end = pos + length
        require(table_end <= len(raw) and (type_base is None or table_end <= type_base),
                'LSDA call-site table exceeds bound')
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
            require(size > 0 and start >= previous_end and start + size <= function['size'],
                    'invalid LSDA call-site extent')
            first, end = function['entry'] + start, function['entry'] + start + size
            require(first in at and (end in at or end == function['end']),
                    'LSDA range is not instruction aligned')
            dest = function['entry'] + landing if landing else None
            require(dest is None or (dest in at and at[dest]['function'] == function['entry']),
                    'LSDA landing pad outside selected FDE')
            rows.append({'function': function['entry'], 'lsda': address,
                         'record_va': address + entry_offset,
                         'record_bytes': raw[entry_offset:pos].hex(), 'start': first,
                         'end': end, 'landing': dest, 'action': action})
            previous_end = start + size
        require(pos == table_end, 'incomplete LSDA call-site table')
    return headers, rows


def relocation(image, slot):
    """Read an actual ELF64 RELA record, never an on-disk pointer as a relocated value."""
    pos = image.relocation_offsets.get(slot, image.symbol_offsets.get(slot))
    require(pos is not None, 'required relocation missing')
    actual, info, addend = struct.unpack_from('<QQq', image.data, pos)
    require(actual == slot, 'relocation slot changed')
    kind, symbol_index = info & 0xffffffff, info >> 32
    require(kind in (6, 8), 'unexpected relocation type')
    name = image.symbols.get(slot, (0, ''))[1] if kind == 6 else ''
    if kind == 8:
        require(symbol_index == 0, 'RELATIVE relocation has symbol')
    return {'slot': slot, 'file_offset': pos,
            'record_bytes': bytes(image.data[pos:pos + 24]).hex(),
            'type': kind, 'symbol_index': symbol_index, 'symbol': name, 'addend': addend}


def evaluate_gate(name, duration, threshold, mask, limit):
    """Conditional local branch model: unordered floats follow the bypass edge."""
    require(type(name) is int and 0 <= name <= 255, 'name byte outside range')
    require(type(mask) is int and 0 <= mask < (1 << 32), 'invalid mask')
    return bool(duration > threshold and name <= limit and ((mask >> name) & 1))


def matches_record(key, leader, closed):
    """Synthetic model of the two pinned 20-byte comparisons and flag test."""
    require(isinstance(key, bytes) and len(key) == 20, 'key must have 20 bytes')
    require(isinstance(leader, bytes) and len(leader) == 20, 'leader must have 20 bytes')
    require(type(closed) is int and 0 <= closed <= 255, 'flag must be a byte')
    return key == leader and closed == 0


def cfg_claims(functions, instructions):
    """Explore normal intra-FDE paths; external calls are assumed to return."""
    at = {r['va']: r for r in instructions}
    extents = {r['entry']: r['end'] for r in functions}
    queries = [
        ('wrapper_calls_then_reads_config', 0x2587010, 0x258703f, None, True),
        ('wrapper_gate_never_restarts_query', 0x258703f, 0x2587010, None, False),
        ('wrapper_config_reaches_result', 0x258703f, 0x258706c, None, True),
        ('wrapper_lazy_config_returns_to_name', 0x25870b3, 0x258704e, None, True),
        ('wrapper_lazy_build_returns_to_result', 0x25870f0, 0x258706c, None, True),
        ('locked_query_to_collector', 0x27d7cb0, 0x27d7e25, None, True),
        ('collector_returns_to_unlock', 0x27d7e25, 0x27d7e36, None, True),
        ('no_normal_return_avoids_unlock', 0x27d7e25, 0x27d7f3d, 0x27d7e36, False),
        ('wakeup_rejoins_timer', 0x27d7f3e, 0x27d7e4e, None, True),
        ('empty_result_bypasses_allocation', 0x2569dd9, 0x2569e2a, None, False),
        ('empty_result_reaches_return', 0x2569dd9, 0x256a21d, None, True),
        ('mismatch_advances_to_iterator', 0x2569d30, 0x2569d33, None, True),
        ('first_matching_record_reaches_allocation', 0x2569d81, 0x2569e2a, None, True),
        ('first_allocation_failure_reaches_trap', 0x256a23c, 0x256a26a, None, True),
        ('next_allocation_failure_reaches_trap', 0x256a24a, 0x256a26a, None, True),
        ('array_allocation_failure_reaches_trap', 0x256a25a, 0x256a26a, None, True),
        ('later_record_can_grow', 0x256a1c7, 0x256a1e4, None, True),
        ('growth_reaches_append', 0x256a1e4, 0x2569ebe, None, True),
        ('empty_cleanup_skips_row_free_a', 0x277b83e, 0x277b839, None, False),
        ('empty_cleanup_skips_row_free_b', 0x278256e, 0x2782569, None, False),
        ('cleanup_backing_free_a', 0x277b846, 0x277b85c, None, True),
        ('cleanup_backing_free_b', 0x2782576, 0x278258c, None, True),
    ]
    def successors(row):
        kind, address, owner = row['kind'], row['va'], row['function']
        following = address + row['size']
        if kind in ('ret', 'trap', 'jump_indirect'):
            return ()
        if kind == 'jump':
            return (row['target'],) if row['target'] in at and at[row['target']]['function'] == owner else ()
        choices = []
        if following in at and at[following]['function'] == owner:
            choices.append(following)
        else:
            require(following == extents[owner], 'unmodeled fallthrough')
        if kind.startswith('j'):
            target = row['target']
            if target in at and at[target]['function'] == owner:
                choices.append(target)
        return tuple(sorted(set(choices)))
    claims = []
    for label, start, target, avoid, expected in queries:
        require(start in at and target in at and at[start]['function'] == at[target]['function'],
                'CFG query endpoints missing')
        todo, previous = [start], {start: None}
        for here in todo:
            if here == target:
                break
            for there in successors(at[here]):
                if there != avoid and there not in previous:
                    previous[there] = here
                    todo.append(there)
        reached = target in previous
        require(reached == expected, 'CFG proposition changed: ' + label)
        witness = []
        if reached:
            here = target
            while here is not None:
                witness.append(here)
                here = previous[here]
            witness.reverse()
        claims.append({'label': label, 'start': start, 'target': target, 'avoid': avoid,
                       'reachable': reached, 'witness': witness})
    return claims


def collect(image, *, check_body_hashes=True):
    functions, instructions = [], []
    for entry, (name, expected_end, expected_hash) in sorted(BODIES.items()):
        fde = image.fde(entry)
        require(fde['end'] == expected_end, 'selected FDE extent changed')
        body = image.read(entry, expected_end - entry)
        actual_hash = hashlib.sha256(body).hexdigest()
        require(not check_body_hashes or actual_hash == expected_hash, 'selected FDE bytes changed')
        fn = {'name': name, 'entry': entry, 'end': expected_end, 'size': len(body),
              'file_offset': image.offset(entry, len(body)), 'sha256': actual_hash,
              'fde': fde['fde'], 'cie': fde['cie'], 'lsda': fde['lsda'], 'bytes': body.hex()}
        decoded = decode(body, entry)
        require(sum(r['size'] for r in decoded) == len(body), 'incomplete instruction partition')
        for row in decoded:
            row['function'] = entry
            row['file_offset'] = image.offset(row['va'], row['size'])
        fn['instruction_count'] = len(decoded)
        functions.append(fn)
        instructions.extend(decoded)
    at = {r['va']: r for r in instructions}
    require(len(at) == len(instructions), 'overlapping instruction rows')
    contracts = []
    for label, address, expected in CONTRACTS:
        row = at.get(address)
        require(row is not None and row['bytes'] == expected, 'instruction contract changed: ' + label)
        contracts.append({'label': label, 'va': address, 'file_offset': row['file_offset'],
                          'bytes': row['bytes'], 'kind': row['kind']})

    # Confirm structural relationships instead of trusting inferred names.
    require(at[0x2587010]['target'] == 0x27d7cb0, 'wrapper handoff changed')
    require(at[0x27d7e25]['target'] == 0x2569d00, 'collector handoff changed')
    require(at[0x27d7f51]['target'] == 0x277b7f0, 'first unwind cleanup changed')
    require(at[0x27d7f9a]['target'] == 0x2782520, 'second unwind cleanup changed')
    require(at[0x258703f]['memory_va'] == 0x576e928, 'config slot changed')
    require(at[0x2587062]['memory_va'] == 0x577ab98, 'second state changed')
    require(at[0x25870bb]['memory_va'] == 0x577ab80, 'second cell changed')
    require(at[0x2587035]['memory_va'] == 0x20aab8, 'float threshold changed')
    limit, mask = at[0x2587053]['immediate'], at[0x2587058]['immediate']
    threshold_bytes = image.read(at[0x2587035]['memory_va'], 8)
    threshold = struct.unpack('<d', threshold_bytes)[0]
    require(limit == 31 and mask == 0x803c6000 and threshold == 3.0,
            'configuration guard changed')
    slots = [0x576e928, 0x577b288, 0x577ab80, 0x576e8b8, 0x576f5e8,
             0x576f5f8, 0x576e8f8, 0x576dfd8, 0x576dfe0, 0x576dfb8,
             0x576e010, 0x576e470]
    relas = [relocation(image, slot) for slot in slots]
    require(image.relative(0x576e928) == 0x577b288, 'config relocation changed')
    require(image.relative(0x577b288) == 0x164ff00, 'config initializer relocation changed')
    require(image.relative(0x577ab80) == 0x143ef30, 'build cell initializer changed')
    require(image.symbols.get(0x576dfe0, (None, None))[1] == 'memcpy', 'copy symbol changed')

    fact_specs = [
        ('owner_lock_offset', 0x27d7cd9, 'disp'),
        ('owner_map_root_offset', 0x27d7dbd, 'disp'),
        ('iterator_key_pointer_offset', 0x2569d44, 'disp'),
        ('record_leader_head_offset', 0x2569d48, 'disp'),
        ('record_leader_tail_offset', 0x2569d58, 'disp'),
        ('input_key_tail_offset', 0x2569d60, 'disp'),
        ('record_closed_offset', 0x2569d78, 'disp'),
        ('record_name_length_offset', 0x2569d81, 'disp'),
        ('record_name_pointer_offset', 0x2569d8a, 'disp'),
        ('first_name_length_sentinel', 0x2569dc4, 'immediate'),
        ('empty_vector_capacity', 0x2569dd9, 'immediate'),
        ('empty_vector_pointer', 0x2569de0, 'immediate'),
        ('empty_vector_length', 0x2569de8, 'immediate'),
        ('first_name_length_offset_in_row', 0x2569e39, 'disp'),
        ('first_key_head_offset_in_row', 0x2569e43, 'disp'),
        ('first_key_tail_offset_in_row', 0x2569e4c, 'disp'),
        ('first_name_capacity_offset_in_row', 0x2569e4f, 'disp'),
        ('first_name_pointer_offset_in_row', 0x2569e52, 'disp'),
        ('first_row_array_bytes', 0x2569e25, 'immediate'),
        ('first_vector_capacity', 0x2569e56, 'immediate'),
        ('first_vector_length', 0x2569e68, 'immediate'),
        ('later_record_stride', 0x256a0aa, 'immediate'),
        ('later_leader_head_offset', 0x256a0b1, 'disp'),
        ('later_leader_tail_offset', 0x256a0c7, 'disp'),
        ('later_closed_offset', 0x256a0ed, 'disp'),
        ('later_name_length_offset', 0x256a10d, 'disp'),
        ('later_name_pointer_offset', 0x256a11b, 'disp'),
        ('later_name_length_sentinel', 0x256a156, 'immediate'),
        ('output_row_stride', 0x256a1db, 'immediate'),
        ('cleanup_row_stride', 0x277b820, 'immediate'),
    ]
    facts = []
    for name, va, source in fact_specs:
        row = at[va]
        value = row['mem']['disp'] if source == 'disp' else row['immediate']
        facts.append({'name':name, 'instruction':va, 'bytes':row['bytes'], 'value':value})
    values = {f['name']: f['value'] for f in facts}
    require(at[0x2569d48]['width'] == 128 and at[0x2569d58]['width'] == 32,
            'key comparison widths changed')
    require(values['record_leader_tail_offset'] - values['record_leader_head_offset'] == 16,
            'leader comparison pieces are not adjacent')
    for field in ('leader_head', 'leader_tail', 'closed', 'name_length', 'name_pointer'):
        require(values['record_' + field + '_offset'] == values['later_' + field + '_offset'],
                'first and later record layouts disagree: ' + field)
    require(values['first_row_array_bytes'] == values['first_vector_capacity'] * values['output_row_stride']
            and values['output_row_stride'] == values['cleanup_row_stride'], 'array layout changed')
    require(values['first_name_length_sentinel'] == values['later_name_length_sentinel'] == 1 << 63,
            'name-length sentinel changed')

    indices = [i for i in range(limit + 1) if (mask >> i) & 1]
    descriptor_indices = indices + [32]
    names = []
    for index in descriptor_indices:
        slot = 0x5668288 + 16 * index
        address = image.relative(slot)
        length = struct.unpack('<Q', image.read(slot + 8, 8))[0]
        require(0 < length <= 64, 'invalid descriptor length')
        raw = image.read(address, length)
        require(all(32 <= b < 127 for b in raw), 'name not printable ASCII')
        names.append({'index': index, 'slot': slot, 'pointer': address, 'length': length,
                      'bytes': raw.hex(), 'name': raw.decode('ascii'),
                      'in_mask': index in indices, 'relocation': relocation(image, slot)})
    require(names[-1]['name'] == 'NvTestnet' and names[-1]['pointer'] == 0x2180ff,
            'default descriptor changed')
    seeds = []
    for label, address, expected in [('static_config_template',0x1ef5f5,b'\xc0\x0e/static_config\x00'),
                                      ('cham_template',0x1fc0ec,b'\xc0\x05/cham\x00')]:
        data = image.read(address, len(expected))
        require(data == expected, 'template anchor changed')
        seeds.append({'label': label, 'va': address, 'file_offset': image.offset(address,len(data)),
                      'bytes': data.hex()})
    # These copies differ only in two RIP-relative displacements. Do not credit
    # the masked bytes as raw equal, and check that the masked slots resolve alike.
    a = image.read(0x277b7f0, 124)
    b = image.read(0x2782520, 124)
    masks = [(0x20, 4), (0x6e, 4)]
    aa, bb = bytearray(a), bytearray(b)
    for off, size in masks:
        aa[off:off+size] = b'\0' * size
        bb[off:off+size] = b'\0' * size
    require(aa == bb, 'cleanup bodies differ outside selected RIP displacements')
    require(at[0x277b80d]['memory_va'] == at[0x278253d]['memory_va'] == 0x576e010,
            'cleanup load targets disagree')
    require(at[0x277b85c]['memory_va'] == at[0x278258c]['memory_va'] == 0x576e010,
            'cleanup tail targets disagree')
    outside = [i for i in range(len(a)) if not any(off <= i < off+size for off,size in masks)]
    cleanup_comparison = {'compared_bytes': len(a), 'equal_bytes': sum(x == y for x,y in zip(a,b)),
                          'masks': [{'offset': off, 'length': size} for off,size in masks],
                          'outside_mask_bytes': len(outside),
                          'outside_mask_equal_bytes': sum(a[i] == b[i] for i in outside)}
    branches = [r for r in instructions if r['kind'] == 'jump' or
                (r['kind'].startswith('j') and r['kind'] != 'jump_indirect')]
    calls = [r for r in instructions if r['kind'] in ('call','call_indirect','jump_indirect')]
    lsda_headers, lsda = exception_sites(image, functions, instructions)
    cfg = cfg_claims(functions, instructions)
    return {'functions':functions, 'instructions':instructions, 'contracts':contracts,
            'branches':branches, 'calls':calls, 'relocations':relas, 'names':names,
            'seeds':seeds, 'layout':facts, 'lsda_headers':lsda_headers, 'lsda':lsda, 'cfg':cfg,
            'guard':{'limit':limit, 'mask':mask, 'threshold':threshold,
                     'threshold_bytes':threshold_bytes.hex(), 'selected_indices':indices},
            'cleanup_comparison':cleanup_comparison}


def write_tsv(path, columns, rows):
    with path.open('w', encoding='utf-8', newline='') as handle:
        writer = csv.writer(handle, delimiter='\t', lineterminator='\n')
        writer.writerow(columns)
        writer.writerows(rows)


def hx(value):
    return '' if value is None else hex(value)


def write_outputs(result, output):
    """Emit deterministic records; outputs do not include filesystem paths or time."""
    import math
    output.mkdir(parents=True, exist_ok=True)
    functions = []
    for row in result['functions']:
        data = dict(row)
        for key in ('entry', 'end', 'file_offset', 'fde', 'cie', 'lsda'):
            data[key] = hx(data[key]) or None
        functions.append(data)
    (output / 'functions.json').write_text(json.dumps(functions, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    write_tsv(output / 'instructions.tsv',
              ('function_va','instruction_va','file_offset','bytes','kind','target_va','memory_va'),
              ((hx(r['function']),hx(r['va']),hx(r['file_offset']),r['bytes'],r['kind'],
                hx(r.get('target')),hx(r.get('memory_va'))) for r in result['instructions']))
    transfer_rows = sorted(result['branches'] + result['calls'], key=lambda row: row['va'])
    write_tsv(output / 'transfers.tsv',
              ('function_va','instruction_va','bytes','kind','direct_target_va','memory_slot_va'),
              ((hx(r['function']),hx(r['va']),r['bytes'],r['kind'],hx(r.get('target')),
                hx(r.get('memory_va'))) for r in transfer_rows))
    write_tsv(output / 'contracts.tsv', ('label','instruction_va','file_offset','bytes','kind'),
              ((r['label'],hx(r['va']),hx(r['file_offset']),r['bytes'],r['kind'])
               for r in result['contracts']))
    relas = result['relocations'] + [r['relocation'] for r in result['names']]
    relas.sort(key=lambda row: row['slot'])
    write_tsv(output / 'relocations.tsv', ('slot_va','rela_file_offset','record_bytes','type','symbol_index','symbol','addend'),
              ((hx(r['slot']),hx(r['file_offset']),r['record_bytes'],r['type'],r['symbol_index'],r['symbol'],
                hx(r['addend'])) for r in relas))
    write_tsv(output / 'descriptors.tsv', ('index','slot_va','pointer_va','length','bytes','name','selected_by_mask'),
              ((r['index'],hx(r['slot']),hx(r['pointer']),r['length'],r['bytes'],r['name'],int(r['in_mask']))
               for r in result['names']))
    write_tsv(output / 'anchors.tsv', ('label','va','file_offset','bytes'),
              ((r['label'],hx(r['va']),hx(r['file_offset']),r['bytes']) for r in result['seeds']))
    write_tsv(output / 'layout.tsv', ('property','instruction_va','instruction_bytes','value_decimal','value_hex'),
              ((r['name'],hx(r['instruction']),r['bytes'],r['value'],hx(r['value'])) for r in result['layout']))
    write_tsv(output / 'exceptions.tsv', ('function_va','lsda_va','record_va','record_bytes','start_va','end_va','landing_va','action'),
              ((hx(r['function']),hx(r['lsda']),hx(r['record_va']),r['record_bytes'],hx(r['start']),
                hx(r['end']),hx(r['landing']),r['action']) for r in result['lsda']))
    heads = []
    for r in result['lsda_headers']:
        item = dict(r)
        for key in ('function','lsda','file_offset','upper_bound','type_base'):
            item[key] = hx(item[key]) or None
        heads.append(item)
    (output / 'exception-headers.json').write_text(json.dumps(heads, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    cfg = []
    for r in result['cfg']:
        cfg.append({'label':r['label'], 'start':hx(r['start']), 'target':hx(r['target']),
                    'avoid':hx(r['avoid']) or None, 'reachable':r['reachable'],
                    'witness':[hx(a) for a in r['witness']]})
    (output / 'cfg.json').write_text(json.dumps(cfg, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    guard = result['guard']
    write_tsv(output / 'name-cases.tsv', ('synthetic_name_byte','mask_selected','above_threshold_reaches_build_check'),
              ((name,int(name <= guard['limit'] and bool((guard['mask'] >> name) & 1)),
                int(evaluate_gate(name,math.inf,guard['threshold'],guard['mask'],guard['limit'])))
               for name in range(256)))
    samples = [('-infinity',-math.inf),('negative-zero',-0.0),('zero',0.0),
               ('threshold',guard['threshold']),
               ('next-above',math.nextafter(guard['threshold'],math.inf)),
               ('positive-infinity',math.inf),
               ('nan',struct.unpack('<d', bytes.fromhex('000000000000f87f'))[0])]
    write_tsv(output / 'floating-cases.tsv', ('synthetic_case','binary64_bits_le','selected_name','reaches_build_check'),
              ((label,struct.pack('<d',value).hex(),guard['selected_indices'][0],
                int(evaluate_gate(guard['selected_indices'][0],value,guard['threshold'],guard['mask'],guard['limit'])))
               for label,value in samples))
    key = bytes(range(20))
    candidates = [('equal-open',key,0),('equal-closed',key,1),('equal-closed-255',key,255)]
    for i in range(len(key)):
        altered = bytearray(key)
        altered[i] ^= 1
        candidates.append((f'mismatch-{i:02d}',bytes(altered),0))
    write_tsv(output / 'selector-cases.tsv', ('synthetic_case','key_hex','leader_hex','closed_byte','filter_passes'),
              ((label,key.hex(),leader.hex(),closed,int(matches_record(key,leader,closed)))
               for label,leader,closed in candidates))
    at = {r['va']:r for r in result['instructions']}
    all_bits = (1 << 64) - 1
    writer_mask = at[0x27d7ceb]['immediate']
    saturation = at[0x27d7cf1]['immediate'] & all_bits
    wake_mask = at[0x27d7e3b]['immediate'] & all_bits
    wake_value = at[0x27d7e3f]['immediate']
    lock_words = sorted({0,1,7,8,9,15,16,17,18,19,saturation-16,saturation-8,
                         saturation-1,saturation,all_bits})
    write_tsv(output / 'lock-cases.tsv', ('synthetic_old_word','slow_before_compare_exchange','release_boundary_from_old_word'),
              ((hx(word),int(bool(word & writer_mask) or word >= saturation),
                int((word & wake_mask) == wake_value)) for word in lock_words))
    summary = {
        'target_sha256':DIGEST,
        'coordinate_system':'linked ELF virtual addresses before load bias; FDE end is exclusive',
        'function_count':len(result['functions']),
        'selected_fde_bytes':sum(x['size'] for x in result['functions']),
        'instruction_count':len(result['instructions']),
        'instruction_contract_count':len(result['contracts']),
        'direct_branch_count':len(result['branches']),
        'call_and_indirect_transfer_count':len(result['calls']),
        'relocation_count':len(relas), 'descriptor_count':len(result['names']),
        'layout_fact_count':len(result['layout']),
        'lsda_header_count':len(result['lsda_headers']), 'lsda_entry_count':len(result['lsda']),
        'cfg_query_count':len(result['cfg']),
        'seed_anchors':result['seeds'], 'guard':result['guard'],
        'cleanup_comparison':result['cleanup_comparison'],
        'limitations':['Only selected FDE extents and fixed instruction encodings are analyzed.',
                       'FDE extents do not establish all functions or source ownership.',
                       'CFG models normal local edges with calls assumed to return.',
                       'External helper and exception action semantics are not established.',
                       'Synthetic cases are static models, not target execution.']}
    (output / 'summary.json').write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n', encoding='utf-8')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args(argv)
    image = Image(TARGET.read_bytes())
    result = collect(image)
    write_outputs(result, args.out)
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (EvidenceError, ValueError, OSError, struct.error) as error:
        print('config_vault_leader94: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
