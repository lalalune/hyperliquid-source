#!/usr/bin/env python3
"""Statically bind node 94 configuration-dependent timing and prune-agent path.

The instruction reader adapts the independent MIT research decoder used by
RE-015 chain-bucket; ELF and unwind parsing use the shared repository readers.
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
            elif op2 in (0x10,0x11,0x13,0x14,0x15,0x28,0x29,0x2a,0x2c,0x2e,0x57,0x58,0x59,0x5c,0x5d,0x5e,0x5f,0x62,0x6e,0x6f,0x74,0x76,0x7e,0xd7):
                row['kind']='sse_'+hex(op2);modrm=True
                row['width']=64 if 0xf2 in prefixes or op2 in (0x6e,0x7e) else 128
            elif op2==0x1f:row['kind']='nop';modrm=True
            elif op2 in (0xb6,0xb7,0xbe,0xbf):row['kind']='extend';modrm=True;row['source_width']=8 if op2 in (0xb6,0xbe) else 16
            elif op2==0xa3:row['kind']='bt';modrm=True
            elif op2==0xaf:row['kind']='imul';modrm=True
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




# Unwind extents are bounded selections, not a complete function census.
BODIES = {
    0x13cbdb0: ('name_timing_gate', 0x13cbee3, '7ace7cf72bedb5a543db195e0aa84d11e496ff29e028aee235935f9b91ea6605'),
    0x1f84e00: ('main_record_builder', 0x1f84f12, '9a15015ac7855e327fda875c1b8cb9d359ae939e3620c444dc719d39c27307f7'),
    0x26fb750: ('main_hour_driver', 0x26fbaa8, 'c9d9d32a50c0b4c39b4c40aa452b195b9747299c88fdfde91b3d717231431831'),
    0x33a51f0: ('record_index_insert', 0x33a5467, '66165eeb22d5a0be9724c2c7ee57289f2376e5a25668df366ac8457ac7e5c2a2'),
    0x34227e0: ('state_record_handoff', 0x3422cd4, '582badf56ae24b3a4e849d90c2aefbe9a9b6bed3ef0659f4a16e14d16a0954ff'),
    0x379fb00: ('empty_entry_cleanup', 0x379fd48, '0437ce5115b1076b43d51dc30d0654e15cbf42d6257ff3f598f5f2cb12be2a39'),
    0x3987ad0: ('cutoff_builder', 0x3987cac, '47c897d05abfcb73ad316551b4a085a365c54ce9515f5c659fedecf9be7e1c5f'),
    0x47dbf50: ('first_record_builder', 0x47dc076, 'aa89485f68bb73dd86ff37117c7095101bd7d549f0ccabbf7349c1fd770ce6b5'),
    0x47dc080: ('second_record_builder', 0x47dc1a6, '963eabdc7cac3df62dfed6b6f474cf92af490331ea7c40d01b8458100e08b7bc'),
    0x4ce1300: ('first_hour_driver', 0x4ce1658, 'f01f5b35bd5fb72b3c8860064f793bc5d20a661fcb277a0ff3ecca5e614c0cd1'),
    0x4ce1660: ('second_hour_driver', 0x4ce19b8, '9fb45bf378339d0c227ffa0d7683214dff7e16e20870cc1b38b54f0d837967d8'),
}
CONTRACTS = (
    ('name_global_slot', 0x13cbdbe, '4c8b3d632b3a04'),
    ('name_lazy_state', 0x13cbdc5, '418b4750'),
    ('name_lazy_branch', 0x13cbdcb, '0f8597000000'),
    ('name_load', 0x13cbdd1, '410fb64748'),
    ('name_subtract', 0x13cbdd6, '8d48ee'),
    ('name_range_width', 0x13cbdd9, '83f908'),
    ('name_range_branch', 0x13cbddc, '0f83d1000000'),
    ('float_zero', 0x13cbde2, '660f57c9'),
    ('float_compare', 0x13cbde6, '660f2ec1'),
    ('float_negative_or_unordered', 0x13cbdea, '0f82da000000'),
    ('timer_clock_arg', 0x13cbdf0, 'bf01000000'),
    ('timer_clock_call', 0x13cbdf5, 'e8067ab103'),
    ('timer_difference_call', 0x13cbe18, 'e81379b103'),
    ('timer_result_tag', 0x13cbe1d, '807c241800'),
    ('timer_result_zero', 0x13cbe22, '660f57c0'),
    ('timer_result_error', 0x13cbe26, '7536'),
    ('timer_conversion_divisor', 0x13cbe52, 'f20f5e05c6e3e3fe'),
    ('timer_return', 0x13cbe67, 'c3'),
    ('name_lazy_call', 0x13cbe96, 'ff151c2a3a04'),
    ('name_after_lazy', 0x13cbea2, '410fb64748'),
    ('name_range_after_lazy', 0x13cbeaa, '83f908'),
    ('name_range_after_lazy_branch', 0x13cbead, '0f822fffffff'),
    ('name_extra_high', 0x13cbeb3, '83f81f'),
    ('name_extra_high_branch', 0x13cbeb6, '0f8426ffffff'),
    ('name_extra_low', 0x13cbebc, '83f80a'),
    ('name_extra_low_branch', 0x13cbebf, '0f841dffffff'),
    ('name_bypass', 0x13cbec5, 'e926ffffff'),
    ('float_error_text', 0x13cbeca, '488d3d88e0e4fe'),
    ('float_error_length', 0x13cbed8, 'be1e000000'),
    ('float_error_call', 0x13cbedd, 'ff1525223a04'),
    ('main_builder_scan', 0x1f84e21, '660f6f00'),
    ('main_builder_mask', 0x1f84e25, '660fd7d0'),
    ('main_builder_iter', 0x1f84e53, 'e8b88e5e00'),
    ('main_builder_context', 0x1f84e64, 'e857946200'),
    ('main_builder_context_inc', 0x1f84e6c, '48ff00'),
    ('main_builder_transfer', 0x1f84ea7, 'e894bc8100'),
    ('main_builder_return_store0', 0x1f84ec2, '0f1103'),
    ('main_builder_return', 0x1f84ed0, 'c3'),
    ('main_builder_unwind', 0x1f84edf, 'e82cb26d03'),
    ('first_clone_builder_iter', 0x47dbfa3, 'e8a8ad0a00'),
    ('first_clone_builder_context', 0x47dbfb4, 'e887182300'),
    ('first_clone_builder_null', 0x47dbfbc, '7468'),
    ('first_clone_builder_transfer', 0x47dbffc, 'e85f36d7ff'),
    ('first_clone_builder_return_store', 0x47dc017, '0f1103'),
    ('first_clone_builder_panic', 0x47dc02d, 'ff15e528f900'),
    ('first_clone_builder_trap', 0x47dc033, '0f0b'),
    ('second_clone_builder_iter', 0x47dc0d3, 'e878ac0a00'),
    ('second_clone_builder_context', 0x47dc0e4, 'e857172300'),
    ('second_clone_builder_null', 0x47dc0ec, '7468'),
    ('second_clone_builder_transfer', 0x47dc12c, 'e83f37d7ff'),
    ('second_clone_builder_return_store', 0x47dc147, '0f1103'),
    ('second_clone_builder_panic', 0x47dc15d, 'ff15b527f900'),
    ('second_clone_builder_trap', 0x47dc163, '0f0b'),
    ('transfer_first_collect', 0x3422838, 'e8f3d83700'),
    ('transfer_second_collect', 0x3422885, 'e8d6db3700'),
    ('transfer_third_collect', 0x34228ef, 'e85cd43700'),
    ('transfer_iter_first', 0x3422988, 'e8b355f9ff'),
    ('transfer_iter_first_empty', 0x3422998, '0f841c010000'),
    ('transfer_stride', 0x34229a6, '488d0c89'),
    ('transfer_record_lookup', 0x34229eb, 'e810451700'),
    ('transfer_shifted_clock', 0x3422a1b, 'ff1587be3402'),
    ('transfer_time_range_error', 0x3422a43, '0f82cc010000'),
    ('transfer_time_convert', 0x3422a71, 'ffd3'),
    ('transfer_time_convert_failure', 0x3422a75, '0f849a010000'),
    ('transfer_record_call', 0x3422ab0, 'e83b27f8ff'),
    ('transfer_next_record', 0x3422ab5, 'e9c6feffff'),
    ('transfer_iter_drain', 0x3422ad6, 'e86554f9ff'),
    ('transfer_iter_drain_loop', 0x3422ae1, '75ed'),
    ('transfer_state_adjust', 0x3422af5, 'e806d03700'),
    ('transfer_second_drain', 0x3422b76, 'e805f3f8ff'),
    ('transfer_second_drain_loop', 0x3422b81, '75ed'),
    ('transfer_third_drain', 0x3422bf6, 'e885f2f8ff'),
    ('transfer_third_drain_loop', 0x3422c01, '75ed'),
    ('transfer_return', 0x3422c14, 'c3'),
    ('transfer_panic', 0x3422c28, 'ff153ab83402'),
    ('transfer_trap', 0x3422c2e, '0f0b'),
    ('transfer_unwind', 0x3422cc3, 'e848d42302'),
    ('cutoff_time_subtract_first', 0x3987af7, '48c7c280aefeff'),
    ('cutoff_normalize_first', 0x3987b00, 'ff15a26dde01'),
    ('cutoff_overflow', 0x3987b11, '0f8088010000'),
    ('cutoff_convert_first', 0x3987b60, 'ff154a6dde01'),
    ('cutoff_convert_failure', 0x3987b68, '0f8418010000'),
    ('cutoff_time_subtract_second', 0x3987b91, '48c7c280aefeff'),
    ('cutoff_normalize_second', 0x3987b9a, 'ff15086dde01'),
    ('cutoff_result_scale', 0x3987c64, '4869d0e8030000'),
    ('cutoff_clamp_zero', 0x3987c73, '480f4fc2'),
    ('cutoff_return', 0x3987c85, 'c3'),
    ('cutoff_range_panic', 0x3987c99, 'ff15c967de01'),
    ('main_flag_store', 0x26fb75e, '89542414'),
    ('main_first_time_offset', 0x26fb77e, '48c7c2f6ffffff'),
    ('main_first_time_normalize', 0x26fb787, 'ff151b310703'),
    ('main_first_time_overflow', 0x26fb798, '0f80e8020000'),
    ('main_first_time_range', 0x26fb7b9, '0f82ae020000'),
    ('main_first_time_convert', 0x26fb7e1, 'ff15c9300703'),
    ('main_first_time_invalid', 0x26fb7e9, '0f847e020000'),
    ('main_first_high_limit', 0x26fb7ef, '81fd00100e00'),
    ('main_first_high_failure', 0x26fb7f5, '0f83f4010000'),
    ('main_first_low_limit', 0x26fb7fb, '81fd905f0100'),
    ('main_first_low_failure', 0x26fb801, '0f830d020000'),
    ('main_second_time_offset', 0x26fb82c, '48c7c2f6ffffff'),
    ('main_second_time_normalize', 0x26fb835, 'ff156d300703'),
    ('main_second_time_sentinel', 0x26fb843, '0f843d020000'),
    ('main_second_time_range', 0x26fb84f, '0f8218020000'),
    ('main_second_time_convert', 0x26fb86e, 'ff153c300703'),
    ('main_second_time_invalid', 0x26fb876, '0f84f1010000'),
    ('main_second_high_limit', 0x26fb87c, '4181ff00100e00'),
    ('main_second_high_failure', 0x26fb883, '0f8366010000'),
    ('main_second_low_limit', 0x26fb889, '4181ff905f0100'),
    ('main_second_low_failure', 0x26fb890, '0f837e010000'),
    ('main_first_hour_magic', 0x26fb898, 'b9c5b3a291'),
    ('main_first_hour_multiply', 0x26fb89d, '480fafc8'),
    ('main_first_hour_shift', 0x26fb8a1, '48c1e92b'),
    ('main_second_hour_magic', 0x26fb8a8, 'bac5b3a291'),
    ('main_second_hour_multiply', 0x26fb8ad, '480fafd0'),
    ('main_second_hour_shift', 0x26fb8b1, '48c1ea2b'),
    ('main_hour_compare', 0x26fb8b5, '39d1'),
    ('main_hour_equal_exit', 0x26fb8b7, '0f8423010000'),
    ('main_clock_before_update', 0x26fb8c2, 'e8397f7e02'),
    ('main_counter_load', 0x26fb8cc, '498b86c0390000'),
    ('main_counter_original', 0x26fb8d3, '4889442448'),
    ('main_counter_increment', 0x26fb8d8, '48ffc0'),
    ('main_counter_saturated', 0x26fb8db, '48c7c1ffffffff'),
    ('main_counter_select', 0x26fb8e2, '480f45c8'),
    ('main_counter_magic', 0x26fb8e6, '48bacdcccccccccccccc'),
    ('main_counter_multiply', 0x26fb8f3, '48f7e2'),
    ('main_counter_shift', 0x26fb8f6, '48c1ea02'),
    ('main_counter_mask', 0x26fb8fa, '4883e2fc'),
    ('main_counter_factor', 0x26fb8fe, '488d0492'),
    ('main_counter_subtract', 0x26fb902, '4829c1'),
    ('main_counter_store', 0x26fb905, '49898ec0390000'),
    ('main_builder_argument', 0x26fb90c, '498db640070000'),
    ('main_builder_call', 0x26fb920, 'e8db9488ff'),
    ('main_cutoff_call', 0x26fb928, 'ff15ba8f0703'),
    ('main_state_offset', 0x26fb932, '4981c6d0360000'),
    ('main_transfer_call', 0x26fb958, 'ff15928f0703'),
    ('main_flag_test', 0x26fb95e, '807c241400'),
    ('main_flag_branch', 0x26fb963, '750a'),
    ('main_zero_flag_threshold', 0x26fb965, 'f20f100523efb0fd'),
    ('main_threshold_join', 0x26fb96d, 'eb08'),
    ('main_nonzero_flag_threshold', 0x26fb96f, 'f20f1005b9edb0fd'),
    ('main_metric_label', 0x26fb977, '488d159140cffd'),
    ('main_metric_label_length', 0x26fb985, 'b90c000000'),
    ('main_metric_call', 0x26fb98f, 'ff151b300703'),
    ('main_secondary_lazy', 0x26fb995, '8b05fdf10703'),
    ('main_secondary_lazy_branch', 0x26fb99d, '0f858a000000'),
    ('main_buffer_length', 0x26fb9a3, '488b742420'),
    ('main_buffer_empty', 0x26fb9ab, '7433'),
    ('main_buffer_free', 0x26fb9da, 'ff1530260703'),
    ('main_caller_return', 0x26fb9ee, 'c3'),
    ('main_high_failure_text', 0x26fb9ef, '488d3db4e3b1fd'),
    ('main_high_failure_call', 0x26fba0e, 'ff1534260703'),
    ('main_low_failure_text', 0x26fba14, '488d3d0eb5b1fd'),
    ('main_low_failure_call', 0x26fba27, 'ff15db260703'),
    ('main_caller_lazy_call', 0x26fba62, 'ff15502e0703'),
    ('main_caller_range_text', 0x26fba6d, '488d3dd1e5b1fd'),
    ('main_caller_range_call', 0x26fba80, 'ff15e2290703'),
    ('main_caller_overflow_call', 0x26fba8d, 'ff15a5300703'),
    ('main_caller_unwind_resume', 0x26fbaa3, 'e86846f602'),
    ('first_flag_store', 0x4ce130e, '89542414'),
    ('first_first_time_offset', 0x4ce132e, '48c7c2f6ffffff'),
    ('first_first_time_normalize', 0x4ce1337, 'ff156bd5a800'),
    ('first_first_time_overflow', 0x4ce1348, '0f80e8020000'),
    ('first_first_time_range', 0x4ce1369, '0f82ae020000'),
    ('first_first_time_convert', 0x4ce1391, 'ff1519d5a800'),
    ('first_first_time_invalid', 0x4ce1399, '0f847e020000'),
    ('first_first_high_limit', 0x4ce139f, '81fd00100e00'),
    ('first_first_high_failure', 0x4ce13a5, '0f83f4010000'),
    ('first_first_low_limit', 0x4ce13ab, '81fd905f0100'),
    ('first_first_low_failure', 0x4ce13b1, '0f830d020000'),
    ('first_second_time_offset', 0x4ce13dc, '48c7c2f6ffffff'),
    ('first_second_time_normalize', 0x4ce13e5, 'ff15bdd4a800'),
    ('first_second_time_sentinel', 0x4ce13f3, '0f843d020000'),
    ('first_second_time_range', 0x4ce13ff, '0f8218020000'),
    ('first_second_time_convert', 0x4ce141e, 'ff158cd4a800'),
    ('first_second_time_invalid', 0x4ce1426, '0f84f1010000'),
    ('first_second_high_limit', 0x4ce142c, '4181ff00100e00'),
    ('first_second_high_failure', 0x4ce1433, '0f8366010000'),
    ('first_second_low_limit', 0x4ce1439, '4181ff905f0100'),
    ('first_second_low_failure', 0x4ce1440, '0f837e010000'),
    ('first_first_hour_magic', 0x4ce1448, 'b9c5b3a291'),
    ('first_first_hour_multiply', 0x4ce144d, '480fafc8'),
    ('first_first_hour_shift', 0x4ce1451, '48c1e92b'),
    ('first_second_hour_magic', 0x4ce1458, 'bac5b3a291'),
    ('first_second_hour_multiply', 0x4ce145d, '480fafd0'),
    ('first_second_hour_shift', 0x4ce1461, '48c1ea2b'),
    ('first_hour_compare', 0x4ce1465, '39d1'),
    ('first_hour_equal_exit', 0x4ce1467, '0f8423010000'),
    ('first_clock_before_update', 0x4ce1472, 'e889232000'),
    ('first_counter_load', 0x4ce147c, '498b8640440000'),
    ('first_counter_original', 0x4ce1483, '4889442448'),
    ('first_counter_increment', 0x4ce1488, '48ffc0'),
    ('first_counter_saturated', 0x4ce148b, '48c7c1ffffffff'),
    ('first_counter_select', 0x4ce1492, '480f45c8'),
    ('first_counter_magic', 0x4ce1496, '48bacdcccccccccccccc'),
    ('first_counter_multiply', 0x4ce14a3, '48f7e2'),
    ('first_counter_shift', 0x4ce14a6, '48c1ea02'),
    ('first_counter_mask', 0x4ce14aa, '4883e2fc'),
    ('first_counter_factor', 0x4ce14ae, '488d0492'),
    ('first_counter_subtract', 0x4ce14b2, '4829c1'),
    ('first_counter_store', 0x4ce14b5, '49898e40440000'),
    ('first_builder_argument', 0x4ce14bc, '498db6c0110000'),
    ('first_builder_call', 0x4ce14d0, 'e87baaafff'),
    ('first_cutoff_call', 0x4ce14d8, 'ff150a34a900'),
    ('first_state_offset', 0x4ce14e2, '4981c650410000'),
    ('first_transfer_call', 0x4ce1508, 'ff15e233a900'),
    ('first_flag_test', 0x4ce150e, '807c241400'),
    ('first_flag_branch', 0x4ce1513, '750a'),
    ('first_zero_flag_threshold', 0x4ce1515, 'f20f1005739352fb'),
    ('first_threshold_join', 0x4ce151d, 'eb08'),
    ('first_nonzero_flag_threshold', 0x4ce151f, 'f20f1005099252fb'),
    ('first_metric_label', 0x4ce1527, '488d15f638a3fb'),
    ('first_metric_label_length', 0x4ce1535, 'b90c000000'),
    ('first_metric_call', 0x4ce153f, 'ff156bd4a800'),
    ('first_secondary_lazy', 0x4ce1545, '8b054d96a900'),
    ('first_secondary_lazy_branch', 0x4ce154d, '0f858a000000'),
    ('first_buffer_length', 0x4ce1553, '488b742420'),
    ('first_buffer_empty', 0x4ce155b, '7433'),
    ('first_buffer_free', 0x4ce158a, 'ff1580caa800'),
    ('first_caller_return', 0x4ce159e, 'c3'),
    ('first_high_failure_text', 0x4ce159f, '488d3d048853fb'),
    ('first_high_failure_call', 0x4ce15be, 'ff1584caa800'),
    ('first_low_failure_text', 0x4ce15c4, '488d3d5e5953fb'),
    ('first_low_failure_call', 0x4ce15d7, 'ff152bcba800'),
    ('first_caller_lazy_call', 0x4ce1612, 'ff15a0d2a800'),
    ('first_caller_range_text', 0x4ce161d, '488d3d218a53fb'),
    ('first_caller_range_call', 0x4ce1630, 'ff1532cea800'),
    ('first_caller_overflow_call', 0x4ce163d, 'ff15f5d4a800'),
    ('first_caller_unwind_resume', 0x4ce1653, 'e8b8ea9700'),
    ('second_flag_store', 0x4ce166e, '89542414'),
    ('second_first_time_offset', 0x4ce168e, '48c7c2f6ffffff'),
    ('second_first_time_normalize', 0x4ce1697, 'ff150bd2a800'),
    ('second_first_time_overflow', 0x4ce16a8, '0f80e8020000'),
    ('second_first_time_range', 0x4ce16c9, '0f82ae020000'),
    ('second_first_time_convert', 0x4ce16f1, 'ff15b9d1a800'),
    ('second_first_time_invalid', 0x4ce16f9, '0f847e020000'),
    ('second_first_high_limit', 0x4ce16ff, '81fd00100e00'),
    ('second_first_high_failure', 0x4ce1705, '0f83f4010000'),
    ('second_first_low_limit', 0x4ce170b, '81fd905f0100'),
    ('second_first_low_failure', 0x4ce1711, '0f830d020000'),
    ('second_second_time_offset', 0x4ce173c, '48c7c2f6ffffff'),
    ('second_second_time_normalize', 0x4ce1745, 'ff155dd1a800'),
    ('second_second_time_sentinel', 0x4ce1753, '0f843d020000'),
    ('second_second_time_range', 0x4ce175f, '0f8218020000'),
    ('second_second_time_convert', 0x4ce177e, 'ff152cd1a800'),
    ('second_second_time_invalid', 0x4ce1786, '0f84f1010000'),
    ('second_second_high_limit', 0x4ce178c, '4181ff00100e00'),
    ('second_second_high_failure', 0x4ce1793, '0f8366010000'),
    ('second_second_low_limit', 0x4ce1799, '4181ff905f0100'),
    ('second_second_low_failure', 0x4ce17a0, '0f837e010000'),
    ('second_first_hour_magic', 0x4ce17a8, 'b9c5b3a291'),
    ('second_first_hour_multiply', 0x4ce17ad, '480fafc8'),
    ('second_first_hour_shift', 0x4ce17b1, '48c1e92b'),
    ('second_second_hour_magic', 0x4ce17b8, 'bac5b3a291'),
    ('second_second_hour_multiply', 0x4ce17bd, '480fafd0'),
    ('second_second_hour_shift', 0x4ce17c1, '48c1ea2b'),
    ('second_hour_compare', 0x4ce17c5, '39d1'),
    ('second_hour_equal_exit', 0x4ce17c7, '0f8423010000'),
    ('second_clock_before_update', 0x4ce17d2, 'e829202000'),
    ('second_counter_load', 0x4ce17dc, '498b86c0390000'),
    ('second_counter_original', 0x4ce17e3, '4889442448'),
    ('second_counter_increment', 0x4ce17e8, '48ffc0'),
    ('second_counter_saturated', 0x4ce17eb, '48c7c1ffffffff'),
    ('second_counter_select', 0x4ce17f2, '480f45c8'),
    ('second_counter_magic', 0x4ce17f6, '48bacdcccccccccccccc'),
    ('second_counter_multiply', 0x4ce1803, '48f7e2'),
    ('second_counter_shift', 0x4ce1806, '48c1ea02'),
    ('second_counter_mask', 0x4ce180a, '4883e2fc'),
    ('second_counter_factor', 0x4ce180e, '488d0492'),
    ('second_counter_subtract', 0x4ce1812, '4829c1'),
    ('second_counter_store', 0x4ce1815, '49898ec0390000'),
    ('second_builder_argument', 0x4ce181c, '498db640070000'),
    ('second_builder_call', 0x4ce1830, 'e84ba8afff'),
    ('second_cutoff_call', 0x4ce1838, 'ff15aa30a900'),
    ('second_state_offset', 0x4ce1842, '4981c6d0360000'),
    ('second_transfer_call', 0x4ce1868, 'ff158230a900'),
    ('second_flag_test', 0x4ce186e, '807c241400'),
    ('second_flag_branch', 0x4ce1873, '750a'),
    ('second_zero_flag_threshold', 0x4ce1875, 'f20f1005139052fb'),
    ('second_threshold_join', 0x4ce187d, 'eb08'),
    ('second_nonzero_flag_threshold', 0x4ce187f, 'f20f1005a98e52fb'),
    ('second_metric_label', 0x4ce1887, '488d159635a3fb'),
    ('second_metric_label_length', 0x4ce1895, 'b90c000000'),
    ('second_metric_call', 0x4ce189f, 'ff150bd1a800'),
    ('second_secondary_lazy', 0x4ce18a5, '8b05ed92a900'),
    ('second_secondary_lazy_branch', 0x4ce18ad, '0f858a000000'),
    ('second_buffer_length', 0x4ce18b3, '488b742420'),
    ('second_buffer_empty', 0x4ce18bb, '7433'),
    ('second_buffer_free', 0x4ce18ea, 'ff1520c7a800'),
    ('second_caller_return', 0x4ce18fe, 'c3'),
    ('second_high_failure_text', 0x4ce18ff, '488d3da48453fb'),
    ('second_high_failure_call', 0x4ce191e, 'ff1524c7a800'),
    ('second_low_failure_text', 0x4ce1924, '488d3dfe5553fb'),
    ('second_low_failure_call', 0x4ce1937, 'ff15cbc7a800'),
    ('second_caller_lazy_call', 0x4ce1972, 'ff1540cfa800'),
    ('second_caller_range_text', 0x4ce197d, '488d3dc18653fb'),
    ('second_caller_range_call', 0x4ce1990, 'ff15d2caa800'),
    ('second_caller_overflow_call', 0x4ce199d, 'ff1595d1a800'),
    ('second_caller_unwind_resume', 0x4ce19b3, 'e858e79700'),
)

CONTRACTS += (
    ('main_high_failure_length', 0x26fba09, 'be2b000000'),
    ('main_low_failure_length', 0x26fba22, 'be1c000000'),
    ('main_caller_range_length', 0x26fba7b, 'be26000000'),
    ('transfer_panic_text', 0x3422c15, '488d3d0374dffc'),
    ('transfer_panic_length', 0x3422c23, 'be26000000'),
    ('transfer_time_offset', 0x3422a09, 'ba02000000'),
    ('insert_root_load', 0x33a5204, '4c8b3f'),
    ('insert_empty_root_branch', 0x33a520a, '0f840d010000'),
    ('insert_memcmp_slot', 0x33a5236, '4c8b254b923c02'),
    ('insert_node_count', 0x33a523d, '410fb7af6a010000'),
    ('insert_node_stride', 0x33a524a, 'c1e505'),
    ('insert_key_prefix_length', 0x33a526d, 'ba14000000'),
    ('insert_memcmp_call', 0x33a5275, '41ffd4'),
    ('insert_prefix_non_equal', 0x33a5286, '7548'),
    ('insert_signed_compare', 0x33a528d, '39442414'),
    ('insert_signed_component', 0x33a5291, '0f9cc1'),
    ('insert_signed_greater', 0x33a5294, '0f9fc0'),
    ('insert_signed_non_equal', 0x33a5297, '7537'),
    ('insert_middle_compare', 0x33a52a2, '39ca'),
    ('insert_unsigned_component', 0x33a52a4, '0f97c0'),
    ('insert_middle_borrow', 0x33a52a7, '1c00'),
    ('insert_middle_non_equal', 0x33a52ab, '7513'),
    ('insert_final_component', 0x33a52b1, '433b442f1c'),
    ('insert_final_greater', 0x33a52b6, '0f97c0'),
    ('insert_final_borrow', 0x33a52b9, '1c00'),
    ('insert_continue_test', 0x33a52c7, '3c01'),
    ('insert_continue_branch', 0x33a52c9, '7495'),
    ('insert_equality_test', 0x33a52e0, '85c0'),
    ('insert_not_equal_branch', 0x33a52e2, '7511'),
    ('insert_equal_return_value', 0x33a5316, 'b001'),
    ('insert_equal_return_jump', 0x33a5318, 'e905010000'),
    ('insert_existing_node_branch', 0x33a535b, '745f'),
    ('insert_existing_helper', 0x33a53b0, 'e89bbcb6ff'),
    ('insert_allocation_size', 0x33a53bf, 'bf70010000'),
    ('insert_allocation_call', 0x33a53c4, 'ff150e8c3c02'),
    ('insert_allocation_failure', 0x33a53cd, '746f'),
    ('insert_initialize_header', 0x33a53cf, '48c7806001000000000000'),
    ('insert_initialize_count', 0x33a53da, '66c7806a0100000000'),
    ('insert_install_root', 0x33a53e3, '488903'),
    ('insert_initialize_height', 0x33a53e6, '48c7430800000000'),
    ('insert_node_limit', 0x33a53f5, '4883f90b'),
    ('insert_node_limit_failure', 0x33a53f9, '7353'),
    ('insert_node_count_write', 0x33a53fe, '6689906a010000'),
    ('insert_copy_first', 0x33a5418, '0f110408'),
    ('insert_copy_second', 0x33a5413, '0f114c0810'),
    ('insert_owner_count', 0x33a541c, '48ff4310'),
    ('insert_new_return_value', 0x33a5420, '31c0'),
    ('insert_alloc_failure_call', 0x33a5448, 'ff15d28b3c02'),
    ('insert_limit_failure_text', 0x33a544e, '488d3d0b76e6fc'),
    ('insert_limit_failure_length', 0x33a545c, 'be20000000'),
    ('insert_limit_failure_call', 0x33a5461, 'ff15a18c3c02'),
    ('cleanup_count_load', 0x379fb16, '488b4718'),
    ('cleanup_empty_branch', 0x379fb22, '0f840e020000'),
    ('cleanup_control_group_load', 0x379fb38, '660f6f4500'),
    ('cleanup_control_mask', 0x379fb3d, '66440fd7e0'),
    ('cleanup_growth_count_write', 0x379fb85, '48895610'),
    ('cleanup_empty_control', 0x379fb89, 'b2ff'),
    ('cleanup_control_write', 0x379fb90, '881407'),
    ('cleanup_mirror_write', 0x379fb93, '88540f10'),
    ('cleanup_count_decrement', 0x379fb9c, '48ffc8'),
    ('cleanup_count_write', 0x379fba4, '48894618'),
    ('cleanup_entry_call', 0x379fbad, 'e86e47c5ff'),
    ('cleanup_loop_exit_test', 0x379fbb2, '48837c243800'),
    ('cleanup_loop_exit_branch', 0x379fbb8, '0f8478010000'),
    ('cleanup_group_nonempty_branch', 0x379fbc2, '752c'),
    ('cleanup_next_control', 0x379fbf0, 'f3410fbcc4'),
    ('cleanup_value_load', 0x379fc16, '488b7405e8'),
    ('cleanup_value_empty_branch', 0x379fc28, '7436'),
    ('cleanup_value_helper', 0x379fc40, 'e80b0e84ff'),
    ('cleanup_remaining_decrement', 0x379fc79, '48ff4c2438'),
    ('cleanup_current_pointer_address', 0x379fc7e, '488d4af8'),
    ('cleanup_current_pointer_save', 0x379fc82, '48894c2450'),
    ('cleanup_predicate_call', 0x379fcab, 'e8e0adc1ff'),
    ('cleanup_predicate_bit', 0x379fcb0, 'a801'),
    ('cleanup_predicate_loop', 0x379fcb2, '75ec'),
    ('cleanup_pointer_compare', 0x379fcb9, '48833800'),
    ('cleanup_retained_branch', 0x379fcbd, '0f85effeffff'),
    ('cleanup_deleted_control', 0x379fd20, 'b280'),
    ('cleanup_empty_control_branch', 0x379fd26, '0f8647feffff'),
)


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




def relocation(image, slot):
    """Decode one previously indexed ELF64 RELA record and its dynamic name."""
    pos = image.relocation_offsets.get(slot, image.symbol_offsets.get(slot))
    require(pos is not None, 'relocation missing')
    require(pos + 24 <= len(image.data), 'relocation outside file')
    actual_slot, info, addend = struct.unpack_from('<QQq', image.data, pos)
    require(actual_slot == slot, 'relocation slot changed')
    kind, index = info & 0xffffffff, info >> 32
    row = {'slot': slot, 'relocation_file_offset': pos,
           'record_bytes': bytes(image.data[pos:pos + 24]).hex(),
           'relocation_type': kind, 'symbol_index': index, 'addend': addend,
           'symbol': ''}
    if kind == 8:
        require(index == 0, 'relative relocation has symbol')
    elif kind == 6:
        dynsym = next(s for s in image.sections if s['name'] == '.dynsym')
        dynstr = next(s for s in image.sections if s['name'] == '.dynstr')
        require(dynsym['type'] == 11 and dynstr['type'] == 3, 'bad symbol tables')
        require(index * 24 + 24 <= dynsym['size'], 'symbol index outside table')
        name_index = struct.unpack_from('<I', image.data, dynsym['offset'] + index * 24)[0]
        require(name_index < dynstr['size'], 'symbol name outside table')
        string_start = dynstr['offset'] + name_index
        string_end = image.data.find(b'\0', string_start, dynstr['offset'] + dynstr['size'])
        require(string_end >= string_start, 'unterminated dynamic symbol')
        row['symbol'] = bytes(image.data[string_start:string_end]).decode('ascii')
    else:
        raise EvidenceError('unexpected relocation type')
    return row


def check_slots(image):
    rows = []
    for slot, (kind, expected) in sorted(SLOTS.items()):
        row = relocation(image, slot)
        if kind == 'relative':
            require(row['relocation_type'] == 8 and row['addend'] == expected,
                    'RELATIVE target changed')
        else:
            require(row['relocation_type'] == 6 and row['symbol'] == expected,
                    'dynamic symbol changed')
        rows.append(row)
    return rows



SLOTS = {
    0x576e010: ('relative', 0x54c8cb0),
    0x576e048: ('relative', 0x157aa10),
    0x576e108: ('relative', 0x157b7f0),
    0x576e468: ('relative', 0x157a9b0),
    0x576dfd8: ('relative', 0x54c06b0),
    0x576e020: ('relative', 0x1345e2a),
    0x576e488: ('symbol', 'memcmp'),
    0x576e8a8: ('relative', 0x15206e0),
    0x576e8b0: ('relative', 0x151f870),
    0x576e8b8: ('relative', 0x4ee3b20),
    0x576e928: ('relative', 0x577b288),
    0x576e9b0: ('relative', 0x13cbdb0),
    0x576eb38: ('relative', 0x157b4c0),
    0x57748e8: ('relative', 0x3987ad0),
    0x57748f0: ('relative', 0x34227e0),
}


def name_entries(image, tags):
    bound_slot = 0x5668778
    marker = relocation(image, bound_slot)
    require(marker['relocation_type'] == 8, 'missing variant bound relocation')
    length = struct.unpack('<Q', image.read(bound_slot + 8, 8))[0]
    text = image.read(marker['addend'], length)
    prefix = b'variant index 0 <= i < '
    require(text.startswith(prefix) and text[len(prefix):].isdigit(), 'bad variant bound text')
    limit = int(text[len(prefix):])
    require(limit == 76, 'unexpected name bound')
    rows = []
    for tag in tags:
        slot = 0x5668288 + 16 * tag
        rel = relocation(image, slot)
        require(rel['relocation_type'] == 8, 'name descriptor is not relative')
        size = struct.unpack('<Q', image.read(slot + 8, 8))[0]
        require(0 < size < 64, 'invalid name descriptor size')
        name = image.read(rel['addend'], size)
        rows.append({'tag': tag, 'name': name.decode('ascii'), 'descriptor_va': slot,
                     'descriptor_file_offset': image.offset(slot, 16),
                     'descriptor_bytes': image.read(slot, 16).hex(),
                     'relocation_file_offset': rel['relocation_file_offset'],
                     'relocation_bytes': rel['record_bytes'],
                     'text_va': rel['addend'], 'text_file_offset': image.offset(rel['addend'], size),
                     'length': size, 'text_bytes': name.hex()})
    expected = ['Ea2', 'SoloTestnet', 'SoloMainnet', 'LockerTestnet', 'LockerMainnet',
                'RpcTestnet', 'RpcSandbox', 'RpcMainnet', 'RpcMainnet2', 'SoloSandbox']
    require([r['name'] for r in rows] == expected, 'selected name descriptors changed')
    return limit, marker, text, rows


def timer_guard(tag, bits, lower, width, extras):
    """Abstract UCOMISD/branch decision, assuming masked FP exceptions."""
    require(0 <= tag <= 255 and 0 <= bits < (1 << 64), 'expected u8 and binary64 bits')
    selected = lower <= tag < lower + width or tag in extras
    exponent = (bits >> 52) & 0x7ff
    fraction = bits & ((1 << 52) - 1)
    unordered = exponent == 0x7ff and fraction != 0
    negative = bool(bits >> 63) and (bits & ((1 << 63) - 1)) != 0
    return 'assertion' if selected and (unordered or negative) else 'clock_path'


def counter_step(old, magic, shift, mask, scale):
    """The exact u64 register arithmetic in the selected counter block."""
    require(0 <= old < (1 << 64), 'expected u64')
    maximum = (1 << 64) - 1
    saturated = maximum if old == maximum else old + 1
    high = (saturated * magic) >> 64
    rounded = (high >> shift) & (mask & maximum)
    return saturated - rounded * (1 + scale)


def hour_bucket(value, magic, shift):
    require(0 <= value <= 0xffffffff, 'expected u32')
    return (value * magic) >> shift


def record_compare(left, right):
    """Model the selected ordering, assuming standard unsigned-byte memcmp."""
    require(len(left) == len(right) == 32, 'expected two 32-byte records')
    def key(record):
        return (record[:20], *struct.unpack('<iII', record[20:]))
    a, b = key(left), key(right)
    return (a > b) - (a < b)


def control_flow(result):
    """Over-approximate intra-FDE normal flow, assuming external calls return."""
    at = {r['va']: r for r in result['instructions']}
    extents = {r['entry']: r['end'] for r in result['functions']}
    queries = []
    for label, start in (('main', 0x26fb750), ('first', 0x4ce1300), ('second', 0x4ce1660)):
        queries.extend((
            (label + '_equal_hour_skips_counter', start + 0x290, start + 0x1b5, False),
            (label + '_new_hour_reaches_counter', start + 0x16d, start + 0x1b5, True),
            (label + '_counter_reaches_builder', start + 0x1b5, start + 0x1d0, True),
            (label + '_builder_reaches_transfer', start + 0x1d0, start + 0x208, True),
            (label + '_transfer_reaches_timing', start + 0x208, start + 0x23f, True),
        ))
    queries.extend((
        ('name_bypass_skips_float_check', 0x13cbec5, 0x13cbde6, False),
        ('name_panic_reaches_error_call', 0x13cbeca, 0x13cbedd, True),
        ('time_error_returns_without_conversion', 0x13cbe5e, 0x13cbe52, False),
        ('handoff_record_loop', 0x3422ab5, 0x3422988, True),
        ('handoff_empty_reaches_state_adjust', 0x3422aba, 0x3422af5, True),
        ('handoff_return_bypasses_record_loop', 0x3422c03, 0x3422988, False),
        ('insert_duplicate_skips_count', 0x33a5316, 0x33a541c, False),
        ('insert_empty_root_reaches_allocation', 0x33a531d, 0x33a53c4, True),
        ('insert_new_reaches_count', 0x33a53bc, 0x33a541c, True),
        ('cleanup_empty_return_skips_stores', 0x379fd36, 0x379fb90, False),
        ('cleanup_remove_reaches_count', 0x379fb90, 0x379fba4, True),
        ('cleanup_predicate_loop', 0x379fcb2, 0x379fcab, True),
    ))
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
    for label, start, target, expected in queries:
        require(start in at and target in at and at[start]['function'] == at[target]['function'],
                'CFG query endpoints missing')
        todo = [start]
        previous = {start: None}
        for here in todo:
            if here == target:
                break
            for there in successors(at[here]):
                if there not in previous:
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
        claims.append({'label': label, 'start': start, 'target': target,
                       'reachable': int(reached), 'witness': witness})
    return claims


def collect(image, check_body_hashes=True):
    functions, instructions, branches, calls = [], [], [], []
    for entry, (role, expected_end, expected_digest) in sorted(BODIES.items()):
        fde = image.fde(entry)
        require(fde['end'] == expected_end, 'selected FDE end changed')
        body = image.read(entry, fde['end'] - entry)
        actual = hashlib.sha256(body).hexdigest()
        require(not check_body_hashes or actual == expected_digest, 'selected FDE bytes changed')
        functions.append({'role': role, 'entry': entry, 'end': fde['end'],
                          'file_offset': image.offset(entry, len(body)), 'byte_count': len(body),
                          'fde': fde['fde'], 'cie': fde['cie'], 'lsda': fde['lsda'], 'sha256': actual})
        for row in decode(body, entry):
            row['function'] = entry
            row['file_offset'] = image.offset(row['va'], row['size'])
            instructions.append(row)
            if row['kind'].startswith('j') and row['kind'] != 'jump_indirect':
                target = row['target']
                branches.append({'function': entry, 'va': row['va'], 'file_offset': row['file_offset'],
                                 'bytes': row['bytes'], 'kind': row['kind'], 'target': target,
                                 'fallthrough': None if row['kind'] == 'jump' else row['va'] + row['size'],
                                 'within_fde': int(entry <= target < fde['end'])})
            if row['kind'] in ('call', 'call_indirect', 'jump_indirect') or (
                    row['kind'] == 'jump' and not entry <= row['target'] < fde['end']):
                target = row.get('target')
                calls.append({'function': entry, 'va': row['va'], 'file_offset': row['file_offset'],
                              'bytes': row['bytes'], 'kind': row['kind'], 'target': target,
                              'memory_va': row.get('memory_va'), 'register': row.get('rm', ''),
                              'selected_target': BODIES[target][0] if target in BODIES else ''})
    at = {r['va']: r for r in instructions}
    require(len(at) == len(instructions), 'overlapping instruction partitions')
    contracts = []
    for label, address, expected in CONTRACTS:
        require(address in at and at[address]['bytes'] == expected, 'byte contract changed: ' + label)
        row = at[address]
        contracts.append({'label': label, 'function': row['function'], 'va': address,
                          'file_offset': row['file_offset'], 'bytes': row['bytes'],
                          'kind': row['kind'], 'target': row.get('target'),
                          'memory_va': row.get('memory_va')})
    named = {r['label']: at[r['va']] for r in contracts}
    require(len(named) == len(contracts), 'duplicate contract label')
    lower = -named['name_subtract']['mem']['disp']
    width = named['name_range_width']['immediate']
    extras = sorted([named['name_extra_high']['immediate'], named['name_extra_low']['immediate']])
    require((lower, width, extras) == (18, 8, [10, 31]), 'name predicates changed')
    require(named['name_range_branch']['target'] == named['name_extra_high']['va'], 'name range edge changed')
    require(named['float_negative_or_unordered']['target'] == named['float_error_text']['va'], 'float failure edge changed')
    require(named['name_range_after_lazy_branch']['target'] == named['float_zero']['va'], 'lazy range edge changed')
    require(named['name_extra_high_branch']['target'] == named['float_zero']['va'], 'high extra edge changed')
    require(named['name_extra_low_branch']['target'] == named['float_zero']['va'], 'low extra edge changed')
    require(named['name_bypass']['target'] == named['timer_clock_arg']['va'], 'name bypass edge changed')
    require(named['name_global_slot']['memory_va'] == 0x576e928, 'global cell slot changed')
    require(named['cutoff_time_subtract_first']['immediate'] == -86400, 'cutoff interval changed')
    require(named['transfer_record_call']['target'] == 0x33a51f0, 'record insertion edge changed')
    require(named['transfer_state_adjust']['target'] == 0x379fb00, 'state cleanup edge changed')
    require(named['insert_memcmp_slot']['memory_va'] == 0x576e488, 'comparison slot changed')
    require(named['insert_empty_root_branch']['target'] == 0x33a531d, 'empty root edge changed')
    require(named['insert_not_equal_branch']['target'] == 0x33a52f5, 'comparison edge changed')
    require(named['cleanup_empty_branch']['target'] == 0x379fd36, 'empty cleanup edge changed')
    require(named['cleanup_retained_branch']['target'] == 0x379fbb2, 'retained entry edge changed')
    slots = check_slots(image)
    state_properties = []
    for scope, property_name, label, method, expected in (
            ('index', 'key_prefix_bytes', 'insert_key_prefix_length', 'immediate', 20),
            ('index', 'node_entry_stride_bytes', 'insert_node_stride', 'power_of_two', 32),
            ('index', 'node_count_offset', 'insert_node_count', 'displacement', 362),
            ('index', 'new_allocation_bytes', 'insert_allocation_size', 'immediate', 368),
            ('index', 'node_limit', 'insert_node_limit', 'immediate', 11),
            ('index', 'owner_count_offset', 'insert_owner_count', 'displacement', 16),
            ('cleanup', 'entry_count_offset', 'cleanup_count_load', 'displacement', 24),
            ('cleanup', 'growth_counter_offset', 'cleanup_growth_count_write', 'displacement', 16),
            ('cleanup', 'empty_control_byte', 'cleanup_empty_control', 'immediate', 255),
            ('cleanup', 'deleted_control_byte', 'cleanup_deleted_control', 'immediate', 128),
            ('cleanup', 'mirror_bias', 'cleanup_mirror_write', 'displacement', 16),
            ('cleanup', 'predicate_bit_mask', 'cleanup_predicate_bit', 'immediate', 1),
            ('cleanup', 'current_pointer_delta', 'cleanup_current_pointer_address', 'displacement', -8)):
        row = named[label]
        value = (row['mem']['disp'] if method == 'displacement' else
                 1 << row['immediate'] if method == 'power_of_two' else row['immediate'])
        require(value == expected, 'state property changed: ' + property_name)
        state_properties.append({'scope': scope, 'property': property_name, 'value': value,
                                 'va': row['va'], 'file_offset': row['file_offset'], 'bytes': row['bytes']})
    failure_literals = []
    for role, text_name, length_name, expected in (
            ('timing_assertion', 'float_error_text', 'float_error_length', b'assertion failed: self.0 >= 0.'),
            ('hour_unwrap', 'main_high_failure_text', 'main_high_failure_length', b'called `Result::unwrap()` on an `Err` value'),
            ('hour_bound', 'main_low_failure_text', 'main_low_failure_length', b'assertion failed: hour <= 24'),
            ('index_capacity', 'insert_limit_failure_text', 'insert_limit_failure_length', b'assertion failed: idx < CAPACITY'),
            ('driver_time_overflow', 'main_caller_range_text', 'main_caller_range_length', b'`NaiveDateTime - TimeDelta` overflowed'),
            ('handoff_time_overflow', 'transfer_panic_text', 'transfer_panic_length', b'`NaiveDateTime + TimeDelta` overflowed')):
        address = named[text_name]['memory_va']
        size = named[length_name]['immediate']
        raw = image.read(address, size)
        require(raw == expected, 'failure text changed')
        failure_literals.append({'role': role, 'va': address, 'file_offset': image.offset(address, size),
                                 'length': size, 'bytes': raw.hex(), 'text': raw.decode('ascii')})
    require(named['transfer_time_offset']['immediate'] == 2, 'handoff time offset changed')
    tags = sorted(set(range(lower, lower + width)) | set(extras))
    limit, marker, text, names = name_entries(image, tags)
    # The adjacent unselected descriptor contextualizes the existing default.
    default_tag = max(extras) + 1
    default_slot = 0x5668288 + 16 * default_tag
    default_rel = relocation(image, default_slot)
    default_len = struct.unpack('<Q', image.read(default_slot + 8, 8))[0]
    default_text = image.read(default_rel['addend'], default_len)
    require(default_rel['relocation_type'] == 8 and default_text == b'NvTestnet', 'default descriptor changed')
    context_default = {'tag': default_tag, 'name': default_text.decode('ascii'),
                       'descriptor_va': hex(default_slot), 'descriptor_bytes': image.read(default_slot, 16).hex(),
                       'relocation_bytes': default_rel['record_bytes'], 'text_va': hex(default_rel['addend']),
                       'text_bytes': default_text.hex()}

    drivers = []
    for prefix, entry, expected_builder in (('main', 0x26fb750, 0x1f84e00),
                                             ('first', 0x4ce1300, 0x47dbf50),
                                             ('second', 0x4ce1660, 0x47dc080)):
        n = lambda label: named[prefix + '_' + label]
        require(n('first_time_offset')['immediate'] == n('second_time_offset')['immediate'] == -10,
                'time offsets differ')
        require(n('first_hour_magic')['immediate'] == n('second_hour_magic')['immediate'], 'hour multipliers differ')
        require(n('first_hour_shift')['immediate'] == n('second_hour_shift')['immediate'], 'hour shifts differ')
        require(n('first_low_limit')['immediate'] == n('second_low_limit')['immediate'], 'hour bounds differ')
        require(n('first_high_limit')['immediate'] == n('second_high_limit')['immediate'], 'high bounds differ')
        require(n('hour_equal_exit')['target'] == entry + 0x290, 'hour-equal exit changed')
        require(n('builder_call')['target'] == expected_builder, 'record builder edge changed')
        require(n('cutoff_call')['memory_va'] == 0x57748e8, 'cutoff slot changed')
        require(n('transfer_call')['memory_va'] == 0x57748f0, 'handoff slot changed')
        require(n('metric_call')['memory_va'] == 0x576e9b0, 'timing slot changed')
        require(n('flag_branch')['target'] == n('nonzero_flag_threshold')['va'], 'flag decision changed')
        require(n('threshold_join')['target'] == n('metric_label')['va'], 'threshold join changed')
        require(n('counter_load')['mem']['disp'] == n('counter_store')['mem']['disp'], 'counter slot changed')
        require(n('counter_factor')['mem']['base'] == n('counter_factor')['mem']['index'] == 'rdx',
                'counter multiplication form changed')
        hour_magic, hour_shift = n('first_hour_magic')['immediate'], n('first_hour_shift')['immediate']
        hour_bound = n('first_low_limit')['immediate']
        divisor = ((1 << hour_shift) + hour_magic // 2) // hour_magic
        require(divisor == 3600 and all(hour_bucket(v, hour_magic, hour_shift) == v // divisor
                                       for v in range(hour_bound)), 'hour arithmetic mismatch')
        magic, shift = n('counter_magic')['immediate'], n('counter_shift')['immediate']
        mask, scale = n('counter_mask')['immediate'], n('counter_factor')['mem']['scale']
        count_divisor = -mask * (1 + scale)
        require((magic, shift, mask, scale, count_divisor) == (0xcccccccccccccccd, 2, -4, 4, 20),
                'counter arithmetic changed')
        require(5 * magic - (1 << 66) == 1, 'counter reciprocal relation changed')
        vals = []
        for label in ('zero_flag_threshold', 'nonzero_flag_threshold'):
            address = n(label)['memory_va']
            raw = image.read(address, 8)
            vals.append({'va': address, 'file_offset': image.offset(address, 8), 'bytes': raw.hex(),
                         'seconds': repr(struct.unpack('<d', raw)[0])})
        require([v['seconds'] for v in vals] == ['5.0', '1.0'], 'threshold constants changed')
        metric_va = n('metric_label')['memory_va']
        metric_len = n('metric_label_length')['immediate']
        metric = image.read(metric_va, metric_len)
        require(metric == b'prune agents', 'metric bytes changed')
        drivers.append({'role': prefix, 'entry': entry, 'counter_offset': n('counter_store')['mem']['disp'],
                        'state_offset': n('state_offset')['immediate'], 'builder': expected_builder,
                        'hour_magic': hour_magic, 'hour_shift': hour_shift, 'hour_bound': hour_bound,
                        'hour_divisor': divisor, 'counter_magic': magic, 'counter_shift': shift,
                        'counter_mask': mask, 'counter_scale': scale, 'counter_divisor': count_divisor,
                        'zero_flag_va': vals[0]['va'], 'zero_flag_file_offset': vals[0]['file_offset'],
                        'zero_flag_bytes': vals[0]['bytes'], 'zero_flag_seconds': vals[0]['seconds'],
                        'nonzero_flag_va': vals[1]['va'], 'nonzero_flag_file_offset': vals[1]['file_offset'],
                        'nonzero_flag_bytes': vals[1]['bytes'], 'nonzero_flag_seconds': vals[1]['seconds'],
                        'metric_va': metric_va, 'metric_file_offset': image.offset(metric_va, metric_len),
                        'metric_bytes': metric.hex(), 'metric': metric.decode('ascii')})
    require(all(d['hour_magic'] == drivers[0]['hour_magic'] and d['counter_magic'] == drivers[0]['counter_magic']
                for d in drivers), 'driver arithmetic differs')
    first = drivers[0]
    maximum = (1 << 64) - 1
    counter_inputs = sorted({0, 1, first['counter_divisor'] - 1, first['counter_divisor'],
                             first['counter_divisor'] + 1, maximum - 1, maximum})
    counter_cases = []
    for old in counter_inputs:
        value = counter_step(old, first['counter_magic'], first['counter_shift'], first['counter_mask'], first['counter_scale'])
        expected = min(old + 1, maximum) % first['counter_divisor']
        require(value == expected, 'counter arithmetic case disagrees')
        counter_cases.append({'old': old, 'new': value})
    hour_inputs = sorted({0, first['hour_divisor'] - 1, first['hour_divisor'],
                          first['hour_divisor'] + 1, first['hour_bound'] - 1})
    hour_cases = [{'input': value, 'bucket': hour_bucket(value, first['hour_magic'], first['hour_shift'])}
                  for value in hour_inputs]
    guard_tags = sorted({v for tag in tags + [default_tag] for v in (tag - 1, tag, tag + 1) if 0 <= v <= 255})
    guard_cases = []
    for tag in guard_tags:
        for flag, item in ((0, first['zero_flag_va']), (1, first['nonzero_flag_va'])):
            bits = struct.unpack('<Q', image.read(item, 8))[0]
            guard_cases.append({'tag': tag, 'flag': flag, 'input_va': item, 'input_bits': hex(bits),
                                'result': timer_guard(tag, bits, lower, width, extras)})
    def record(prefix, signed, middle, final):
        require(len(prefix) == 20, 'bad synthetic record prefix')
        return prefix + struct.pack('<iII', signed, middle, final)
    z = bytes(20)
    one = b'\x01' + bytes(19)
    comparison_specs = (
        ('equal', record(z, 0, 0, 0), record(z, 0, 0, 0), 0),
        ('prefix_greater', record(one, 0, 0, 0), record(z, 0, 0, 0), 1),
        ('prefix_less', record(z, 0, 0, 0), record(one, 0, 0, 0), -1),
        ('signed_min', record(z, -(1 << 31), 0, 0), record(z, 0, 0, 0), -1),
        ('signed_max', record(z, (1 << 31) - 1, 0, 0), record(z, -1, 0, 0), 1),
        ('middle_unsigned_high', record(z, 0, 1 << 31, 0), record(z, 0, (1 << 31) - 1, 0), 1),
        ('middle_unsigned_low', record(z, 0, 0, 0), record(z, 0, (1 << 32) - 1, 0), -1),
        ('final_unsigned_high', record(z, 0, 0, 1 << 31), record(z, 0, 0, (1 << 31) - 1), 1),
        ('final_unsigned_low', record(z, 0, 0, 0), record(z, 0, 0, (1 << 32) - 1), -1),
        ('prefix_priority', record(one, -(1 << 31), 0, 0), record(z, (1 << 31) - 1, 0, 0), 1),
        ('signed_priority', record(z, 1, 0, 0), record(z, 0, (1 << 32) - 1, (1 << 32) - 1), 1),
    )
    comparison_cases = []
    for label, left, right, expected in comparison_specs:
        value = record_compare(left, right)
        require(value == expected, 'synthetic comparison case mismatch')
        comparison_cases.append({'label': label, 'left_bytes': left.hex(),
                                 'right_bytes': right.hex(), 'result': value})
    result = {'functions': functions, 'instructions': instructions, 'branches': branches,
              'calls': calls, 'contracts': contracts, 'relocations': slots, 'names': names,
              'drivers': drivers, 'counter_cases': counter_cases, 'hour_cases': hour_cases,
              'guard_cases': guard_cases, 'failure_literals': failure_literals,
              'state_properties': state_properties, 'comparison_cases': comparison_cases}
    headers, exception_rows = exception_sites(image, result)
    result['lsda_headers'], result['exception_sites'] = headers, exception_rows
    result['cfg_claims'] = control_flow(result)
    result['summary'] = {
        'target': 'node94', 'sha256': hashlib.sha256(image.data).hexdigest(),
        'functions': len(functions), 'selected_body_bytes': sum(r['byte_count'] for r in functions),
        'instruction_rows': len(instructions), 'direct_branches': len(branches),
        'call_and_tail_rows': len(calls), 'byte_contracts': len(contracts), 'slot_records': len(slots), 'failure_literals': len(failure_literals),
        'state_properties': len(state_properties),
        'modeled_comparisons': len(comparison_cases),
        'lsda_headers': len(headers), 'lsda_ranges': len(exception_rows), 'cfg_claims': len(result['cfg_claims']),
        'name_guard': {'range_start': lower, 'range_width': width, 'extra_tags': extras, 'selected_tags': tags,
                       'name_domain_bound': limit, 'bound_descriptor': hex(marker['slot']),
                       'bound_relocation_bytes': marker['record_bytes'], 'bound_text': text.decode('ascii'),
                       'default_context': context_default, 'modeled_cases': len(guard_cases)},
        'hour': {'magic': hex(first['hour_magic']), 'shift': first['hour_shift'],
                 'bound': first['hour_bound'], 'divisor': first['hour_divisor'],
                 'complete_domain_comparisons': first['hour_bound']},
        'counter': {'magic': hex(first['counter_magic']), 'shift': first['counter_shift'],
                    'mask': first['counter_mask'], 'scale': first['counter_scale'],
                    'divisor': first['counter_divisor'], 'modeled_cases': len(counter_cases)},
        'limitations': 'Selected FDEs and static models only; external helper semantics, target runtime, Rust reconstruction and whole-component equivalence remain open.'}
    return result


HEX_COLUMNS = {'entry','end','file_offset','function','va','fde','cie','lsda','target',
               'fallthrough','memory_va','slot','relocation_file_offset','descriptor_va',
               'descriptor_file_offset','text_va','text_file_offset','upper_bound','type_base',
               'record_va','start','landing','builder','zero_flag_va','zero_flag_file_offset',
               'nonzero_flag_va','nonzero_flag_file_offset','metric_va','metric_file_offset','input_va'}


def write_table(path, columns, rows):
    with path.open('w', encoding='utf-8', newline='') as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, delimiter='\t', lineterminator='\n', extrasaction='ignore')
        writer.writeheader()
        for row in rows:
            formatted = {}
            for key in columns:
                value = row.get(key)
                if value is None:
                    value = ''
                elif key in HEX_COLUMNS and isinstance(value, int):
                    value = hex(value)
                elif isinstance(value, list):
                    value = ','.join(hex(item) if isinstance(item, int) else str(item) for item in value)
                formatted[key] = value
            writer.writerow(formatted)


def write_outputs(result, output):
    output.mkdir(parents=True, exist_ok=True)
    tables = (
        ('failure-literals.tsv', ('role','va','file_offset','length','bytes','text'), 'failure_literals'),
        ('state-properties.tsv', ('scope','property','value','va','file_offset','bytes'), 'state_properties'),
        ('comparison-cases.tsv', ('label','left_bytes','right_bytes','result'), 'comparison_cases'),
        ('functions.tsv', ('role','entry','end','file_offset','byte_count','fde','cie','lsda','sha256'), 'functions'),
        ('instructions.tsv', ('function','va','file_offset','bytes','kind','target','memory_va'), 'instructions'),
        ('branches.tsv', ('function','va','file_offset','bytes','kind','target','fallthrough','within_fde'), 'branches'),
        ('calls.tsv', ('function','va','file_offset','bytes','kind','target','memory_va','register','selected_target'), 'calls'),
        ('contracts.tsv', ('label','function','va','file_offset','bytes','kind','target','memory_va'), 'contracts'),
        ('relocations.tsv', ('slot','relocation_file_offset','record_bytes','relocation_type','symbol_index','addend','symbol'), 'relocations'),
        ('selected-names.tsv', ('tag','name','descriptor_va','descriptor_file_offset','descriptor_bytes','relocation_file_offset','relocation_bytes','text_va','text_file_offset','length','text_bytes'), 'names'),
        ('drivers.tsv', ('role','entry','counter_offset','state_offset','builder','hour_magic','hour_shift','hour_bound','hour_divisor','counter_magic','counter_shift','counter_mask','counter_scale','counter_divisor','zero_flag_va','zero_flag_file_offset','zero_flag_bytes','zero_flag_seconds','nonzero_flag_va','nonzero_flag_file_offset','nonzero_flag_bytes','nonzero_flag_seconds','metric_va','metric_file_offset','metric_bytes','metric'), 'drivers'),
        ('guard-cases.tsv', ('tag','flag','input_va','input_bits','result'), 'guard_cases'),
        ('hour-cases.tsv', ('input','bucket'), 'hour_cases'),
        ('counter-cases.tsv', ('old','new'), 'counter_cases'),
        ('lsda-headers.tsv', ('function','lsda','file_offset','upper_bound','header_bytes','table_bytes','type_encoding','type_base'), 'lsda_headers'),
        ('exception-sites.tsv', ('function','lsda','record_va','record_bytes','start','end','landing','action','transfers','type_encoding','type_base'), 'exception_sites'),
        ('cfg-claims.tsv', ('label','start','target','reachable','witness'), 'cfg_claims'),
    )
    for filename, columns, key in tables:
        write_table(output / filename, columns, result[key])
    (output / 'summary.json').write_text(json.dumps(result['summary'], indent=2, sort_keys=True) + '\n',
                                         encoding='utf-8', newline='\n')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args(argv)
    image = Image(TARGET.read_bytes())
    result = collect(image)
    write_outputs(result, args.out)
    print('node94 static configuration timing evidence generated')


if __name__ == '__main__':
    try:
        main()
    except (EvidenceError, ValueError, OSError, struct.error) as exc:
        print('config_agent_prune94: ' + str(exc), file=sys.stderr)
        raise SystemExit(1)
