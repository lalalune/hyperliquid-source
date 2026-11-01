"""Digest-bound static AwsName JSON envelope analysis; never executes the target.

The restricted instruction reader adapts the independently authored MIT
config_number_path94 research collector. ELF and unwind parsing stay shared.
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
from fde_extents import eh_frame_records, uleb

DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
ENTRIES = {
    0x13f3820: 'enum_envelope', 0x14b6d40: 'quoted_identifier',
    0x14b6e70: 'unit_payload', 0x149fe20: 'unexpected_value',
    0x149edb0: 'error_after_cursor', 0x14a0130: 'error_at_cursor',
    0x14470d0: 'attach_missing_position', 0x14af190: 'drop_error_payload',
    0x14ae7c0: 'drop_io_payload', 0x1401120: 'expected_identifier',
    0x14c3ef0: 'expected_unit',
    0x1441d10: 'optional_name_map',
    0x14bb200: 'name_string_map',
    0x14be0f0: 'owned_string_value',
    0x14a01f0: 'map_close',
    0x14caf40: 'map_insert_or_replace',
    0x14ccb20: 'map_drain_step',
    0x14d99a0: 'drop_name_string_map',
    0x14ada40: 'drop_map_result',
    0x14c3eb0: 'expected_map',
    0x14c3f10: 'expected_string',
}
class EvidenceError(ValueError):
    pass

class Image:
    def __init__(self, data, authenticate=True):
        if authenticate and hashlib.sha256(data).hexdigest() != DIGEST:
            raise EvidenceError('node94 SHA-256 mismatch')
        self.data = data
        self.sections = sections(data)
        _, self.fdes = eh_frame_records(data, self.sections)
        self.relocations = {}
        self.symbols = {}
        dynsym = next(s for s in self.sections if s['name']=='.dynsym')
        dynstr = next(s for s in self.sections if s['name']=='.dynstr')
        strings = data[dynstr['offset']:dynstr['offset']+dynstr['size']]
        for s in self.sections:
            if s['type'] == 4:
                if s['size'] % 24:
                    raise EvidenceError('unaligned RELA section')
                for p in range(s['offset'], s['offset'] + s['size'], 24):
                    slot, info, addend = struct.unpack_from('<QQq', data, p)
                    if info == 8:
                        if slot in self.relocations:
                            raise EvidenceError('duplicate RELATIVE slot')
                        self.relocations[slot] = addend
                    elif info & 0xffffffff == 6:
                        index=info>>32
                        require(index*24+24<=dynsym['size'], 'GLOB_DAT symbol outside dynsym')
                        name=struct.unpack_from('<I',data,dynsym['offset']+index*24)[0]
                        end=strings.find(b'\0',name)
                        require(name<len(strings) and end>=name, 'invalid dynamic symbol name')
                        require(slot not in self.symbols, 'duplicate GLOB_DAT slot')
                        self.symbols[slot]=strings[name:end].decode('ascii')
    def offset(self, va, size):
        if size < 0 or va < 0:
            raise EvidenceError('negative range')
        matches = [s for s in self.sections if s['type'] != 8 and s['flags'] & 2
                   and s['address'] <= va and va + size <= s['address'] + s['size']]
        if len(matches) != 1:
            raise EvidenceError('range lacks unique file backing')
        s = matches[0]
        return s['offset'] + va - s['address']
    def read(self, va, size):
        p = self.offset(va, size)
        return self.data[p:p + size]
    def fde(self, va):
        rows = [f for f in self.fdes if f['start'] == va]
        if len(rows) != 1:
            raise EvidenceError('missing or duplicate selected FDE')
        return rows[0]

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
        elif op in (0x00,0x01,0x08,0x09,0x20,0x21,0x28,0x29,0x30,0x31,0x38,0x39,0x3b,0x23,0x85,0x84,0x88,0x89,0x8b,0x8d,0x63):
            row['kind']={0x00:'add',0x01:'add',0x08:'or',0x09:'or',0x20:'and',0x21:'and',0x23:'and',0x28:'sub',0x29:'sub',0x30:'xor',0x31:'xor',0x38:'cmp',0x39:'cmp',0x3b:'cmp',0x85:'test',0x84:'test',0x88:'mov_store',0x89:'mov_store',0x8b:'mov_load',0x8d:'lea',0x63:'movsxd'}[op]
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
                if group not in (4,5,7):raise EvidenceError('unsupported shift')
                row['kind']={4:'shl',5:'shr',7:'sar'}[group]
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


BODY_GATES = {
    0x1441d10: (0x1441e7f, 'f2752de7cf5827fc4fb6ba104fc3a68a851b9d750562cecf110eec5f9a9e7a2d'),
    0x14bb200: (0x14bb857, '3cb1f6df43d14119d54b7676109a0c34f705b4a8f03e1e79676b1eb9c5d106fb'),
    0x14be0f0: (0x14be248, '6f2e0cc2a53ec6e0852a1b1386d9f0f7c916b2f98302f01fcbd2b9fbd16f5ac9'),
    0x14a01f0: (0x14a02a3, 'bdc3132ec1146a181757b4612f787d7724725ae4f57d628df38e20ae31f3d88f'),
    0x14caf40: (0x14cb137, '54641a0f2fd9cdc6506966b29d8c10786d4c533b28997f925b5cbc61ea857e21'),
    0x14ccb20: (0x14ccecd, '8a4e8e9c36cb124add589cf33dddab11181cba53b28e3056b5fcbd967bafff71'),
    0x14d99a0: (0x14d9a64, '67a8ad204f06c368f6d367928dcdd838f7c419c63461ff909b8cfe500a6ab451'),
    0x14ada40: (0x14adb7f, '0fb0eb06285d0d7621c25e4a9bb3dc10171a4a7dfa7675975dc7ffd93266237f'),
    0x14c3eb0: (0x14c3ec9, '8504d9ebe8c454e61c170b1e8c775fce8370d8c057a403031a59b46d4c22f240'),
    0x14c3f10: (0x14c3f29, '797a34da7836ac791de7102e4849b6c73a54ee8c369ab8d9f467b3200b30b940'),
    0x13f3820: (0x13f3dca, '2bbe2b212b4e2ba2b52d7368377f523c926ffe3040b96dd5fe0ade2ae20d65d0'),
    0x14b6d40: (0x14b6e63, '4d6e45118cd1108767013d71962b8f565bfd954aa48de0417977acd04c22e190'),
    0x14b6e70: (0x14b6f9a, '5b16b85b6495473059f17a19360f9a0adff9ca774fef5e0716a8e79490371cca'),
    0x149fe20: (0x14a0127, 'dd005551d1064545e0b4d3d4303c8f1e2ab286d6e6076b12b07a8ceb8d7ef90a'),
    0x149edb0: (0x149ee68, '34fcecdd7615c8e2baebd44e6dd6ef63e07fb44de0866aa2f058f3fee93e3170'),
    0x14a0130: (0x14a01f0, '022dc65af0b513a910813b3c6b49e9f2755da4ad3659083d8b0a1442cf97a38c'),
    0x14470d0: (0x1447125, 'c492a6d2b905ef3730b6c70cf982099a14d6e3201b16e7e63b4a953c2315c14f'),
    0x14af190: (0x14af1bc, '00c05717d431451beaafab9181cb9ef3f965440765a059174514fd430088f31c'),
    0x14ae7c0: (0x14ae889, '6007d63f3caaaae152f1eefbaf576e62a5310d4e8c333f6b16d0d31cc18b68bb'),
    0x1401120: (0x1401139, '15460c9be9dbf3e65b62f14d8263864d15a7a377c3d2900ca2e43cd80f7f8c78'),
    0x14c3ef0: (0x14c3f09, '772aaa64cb5e0190770f70b501f370bff1a27dc6dc2928b670015d4833552773'),
}

SLOT_GATES = {
    0x576dfb8: 0x1346068, 0x576dfd8: 0x54c06b0,
    0x576e020: 0x1345e2a, 0x576e108: 0x157b7f0,
    0x576e470: 0x157a9f0,
    0x576e118: 0x157b480, 0x576e150: 0x157b520,
    0x576e010: 0x54c8cb0, 0x576ef80: 0x4ebcd70,
    0x576e128: 0x157b63b, 0x576eca0: 0x4ebf970,
    0x576fc18: 0x4ebd240, 0x576fc90: 0x4eb9dd0,
    0x576e2e0: 0x157a6f0,
}

ERROR_SEEDS = {
    0x1441e3e: 'optional_map_truncated_null',
    0x1441e68: 'optional_map_invalid_null',
    0x14bb260: 'map_empty_input',
    0x14bb4d1: 'map_eof_in_entries',
    0x14bb65d: 'map_eof_after_comma',
    0x14bb6ac: 'map_eof_before_colon',
    0x14bb72b: 'map_depth_exhausted',
    0x14bb748: 'map_missing_comma',
    0x14bb76c: 'map_close_after_comma',
    0x14bb787: 'map_unquoted_key_or_initial_comma',
    0x14bb7a2: 'map_wrong_colon',
    0x14be150: 'string_empty_input',
    0x14a023b: 'map_close_eof',
    0x14a0256: 'map_close_comma',
    0x14a0281: 'map_close_wrong_token',
    0x13f3873: 'envelope_empty_after_whitespace',
    0x13f3951: 'object_missing_colon_at_eof',
    0x13f39f3: 'object_missing_close_at_eof',
    0x13f3d62: 'envelope_wrong_start',
    0x13f3d6f: 'object_depth_exhausted',
    0x13f3d7c: 'object_wrong_colon',
    0x13f3d89: 'object_wrong_close',
    0x14b6da6: 'identifier_empty_after_whitespace',
    0x14b6ec4: 'unit_empty_after_whitespace',
    0x14b6f44: 'unit_truncated_null',
    0x14b6f5d: 'unit_invalid_null_suffix',
    0x14a0045: 'unexpected_truncated_literal',
    0x14a0093: 'unexpected_invalid_literal',
    0x14a00f8: 'unexpected_invalid_start',
}

# Fixed entry points identify the scope. Operands, bounds and tables below are
# read from bytes; no binutils output or inferred reference implementation is
# consumed. Body gates are checked after structural/semantic extraction so that
# targeted corruption controls can also exercise those deeper checks.
def require(ok, message):
    if not ok:
        raise EvidenceError(message)


def collect(image, body_gates=True):
    functions = []
    instructions = []
    for entry, role in sorted(ENTRIES.items()):
        f = image.fde(entry)
        require(f['end'] == BODY_GATES[entry][0], 'selected FDE endpoint changed')
        body = image.read(entry, f['end'] - entry)
        rows = decode(body, entry)
        functions.append(dict(entry=entry, end=f['end'], fde=f['fde'],
                              role=role, byte_count=len(body),
                              instruction_count=len(rows),
                              sha256=hashlib.sha256(body).hexdigest()))
        for row in rows:
            row['function'] = entry
            row['file_offset'] = image.offset(row['va'], row['size'])
            if row['kind'] in ('call_indirect', 'jump_indirect') and 'memory_va' in row:
                slot = row['memory_va']
                if slot in image.relocations:
                    row['resolved_target'] = image.relocations[slot]
                else:
                    require(slot in image.symbols, 'call slot lacks admitted relocation')
                    row['external_symbol'] = image.symbols[slot]
            instructions.append(row)
    require({r['memory_va']: r['resolved_target'] for r in instructions
             if 'resolved_target' in r} == SLOT_GATES, 'external call relocation changed')
    require({r['memory_va']:r['external_symbol'] for r in instructions if 'external_symbol' in r}
            == {0x576dfe0:'memcpy'}, 'external symbol relocation changed')
    at = {r['va']: r for r in instructions}
    def ins(va, kind):
        require(va in at and at[va]['kind'] == kind, 'required instruction changed')
        return at[va]
    def imm(va, kind):
        return ins(va, kind)['immediate']
    def memory(va, kind, base, disp):
        r = ins(va, kind)
        require(r.get('mem', {}).get('base') == base and r['mem']['disp'] == disp,
                'required state field changed')
        return r
    mask = imm(0x13f3844, 'mov_imm')
    require(mask == imm(0x14b6d68, 'mov_imm') == imm(0x14b6e90, 'mov_imm'),
            'whitespace masks disagree')
    whitespace = [i for i in range(64) if mask >> i & 1]
    require(whitespace == [9, 10, 13, 32], 'whitespace set changed')
    require(ins(0x13f385d, 'jae')['target'] == 0x13f388e, 'entry whitespace branch changed')
    require(imm(0x13f388e, 'cmp') == 34 and imm(0x13f38c4, 'cmp') == 123,
            'envelope delimiters changed')
    require(imm(0x13f3963, 'cmp') == 58 and imm(0x13f3a08, 'cmp') == 125,
            'object delimiters changed')
    depth_load = memory(0x13f38cd, 'extend', 'rsi', 0x48)
    depth_store = memory(0x13f38db, 'mov_store', 'rsi', 0x48)
    ins(0x13f38d9, 'dec')
    require(ins(0x13f38d3, 'je')['target'] == 0x13f3da3 and
            ins(0x13f38de, 'je')['target'] == 0x13f3d6f, 'depth guards changed')
    memory(0x13f39b3, 'mov_store', 'r15', 0x48)
    ins(0x13f39b1, 'inc')
    require(imm(0x13f39a6, 'cmp') == 255, 'depth restore guard changed')
    require(ins(0x13f3982, 'je')['target'] == 0x13f399a, 'unit error split changed')
    require(ins(0x13f3900, 'jne')['target'] == 0x13f3909, 'identifier error split changed')
    require(imm(0x13f3988, 'mov_imm') == 1 and
            imm(0x13f399e, 'mov_imm_store') == 0, 'result tags changed')
    memory(0x13f3984, 'mov_store', 'rbx', 8)
    memory(0x13f398a, 'mov_store', 'rbx', 0)
    # The envelope's own code leaves, not the pre-existing spelling table.
    leaves = {r['va']: r for r in instructions if r['function'] == 0x13f3820
              and r['kind'] == 'mov_imm_store' and r['width'] == 8
              and r.get('mem', {}).get('base') == 'rbx'
              and r['mem']['disp'] == 1}
    require(len(leaves) == 76, 'enum leaf domain changed')
    table = ins(0x13f38a9, 'lea')['memory_va']
    dispatch = []
    for tag, delta in enumerate(struct.unpack('<' + 'i' * len(leaves),
                                              image.read(table, 4 * len(leaves)))):
        target = table + delta
        require(target in leaves, 'dispatch leaves selected instruction boundaries')
        leaf = leaves[target]
        require(leaf['immediate'] == tag, 'non-identity enum remapping')
        zero = at.get(target + leaf['size'])
        require(zero and zero['kind'] == 'xor' and zero.get('reg') == 'rax'
                and zero.get('rm') == 'rax', 'enum leaf no longer clears result tag')
        jump = at.get(zero['va'] + zero['size'])
        require(jump and jump['kind'] == 'jump' and jump['target'] == 0x13f398a,
                'enum leaf no longer reaches result write')
        dispatch.append(dict(index=tag, slot=table+tag*4, target=target,
                             output_tag=leaf['immediate'], bytes=leaf['bytes']))
    require(len({r['target'] for r in dispatch}) == len(leaves), 'duplicate enum leaf')
    # Each explicit syntax-code store is followed along unconditional edges to
    # its actual position constructor, with no assumed source-level error name.
    errors = []
    for seed, role in sorted(ERROR_SEEDS.items()):
        r = ins(seed, 'mov_imm_store')
        va = seed + r['size']
        path = [seed]
        seen = {seed}
        while True:
            require(va in at and va not in seen, 'error route not closed')
            step = at[va]; seen.add(va); path.append(va)
            if step['kind'] == 'call':
                require(step['target'] in (0x149edb0, 0x14a0130), 'error route callee changed')
                break
            require(not step['kind'].startswith('j') or step['kind'] == 'jump',
                    'conditional error route needs review')
            va = step['target'] if step['kind'] == 'jump' else va + step['size']
        errors.append(dict(role=role, seed=seed, code=r['immediate'],
                           constructor=step['target'], call=step['va'], path=path))
    # Wrong-type classifier table bounds come from its subtraction/compare.
    classifier_base = -ins(0x149fe4a, 'lea')['mem']['disp']
    classifier_count = imm(0x149fe4e, 'cmp') + 1
    classifier_table = ins(0x149fe57, 'lea')['memory_va']
    classifier = []
    for index, delta in enumerate(struct.unpack('<'+'i'*classifier_count,
                                               image.read(classifier_table, classifier_count*4))):
        target = classifier_table + delta
        require(target in at and at[target]['function'] == 0x149fe20,
                'wrong-type classifier target outside body')
        classifier.append(dict(byte=classifier_base+index, slot=classifier_table+index*4,
                               target=target))
    require({r['byte']:r['target'] for r in classifier if r['byte'] in (91,102,110,116,123)} ==
            {91:0x14a00a6,102:0x149fe68,110:0x149ffdb,116:0x149ff67,123:0x14a009d},
            'wrong-type classifier changed')
    texts = []
    for entry, site, size_site, vtable_site in (
            (0x1401120,0x140112b,0x1401132,0x14b6e2a),
            (0x14c3ef0,0x14c3efb,0x14c3f02,0x14b6f68),
            (0x14c3eb0,0x14c3ebb,0x14c3ec2,0x14bb712),
            (0x14c3f10,0x14c3f1b,0x14c3f22,0x14be20b)):
        va = ins(site,'lea')['memory_va']; n = imm(size_site,'mov_imm')
        vtable = ins(vtable_site,'lea')['memory_va']
        require(image.relocations.get(vtable+24) == entry, 'expected-type vtable retargeted')
        raw = image.read(va,n)
        require(raw in (b'variant identifier',b'unit',b'a map',b'a string'), 'expected-type text changed')
        texts.append(dict(writer=entry, vtable=vtable, slot=vtable+24, text_va=va,
                          length=n, text=raw.decode('ascii'), sha256=hashlib.sha256(raw).hexdigest()))
    # State fields used for assigning source coordinates to an unpositioned box.
    require(memory(0x14470d7,'cmp','rdi',24)['immediate'] == 0,
            'position-presence gate changed')
    require(ins(0x14470dc,'jne')['target'] == 0x14470ff, 'positioned-box fast return changed')
    require(ins(0x14470e4,'call')['target'] == 0x14a0130, 'position repair target changed')
    require(imm(0x14470ec,'mov_imm') == 40, 'old error box size changed')
    require(ins(0x14a0142,'ja')['target'] == 0x14a01bb, 'cursor range guard changed')
    require(ins(0x149edbf,'je')['target'] == 0x149ee46, 'after-cursor overflow guard changed')
    if body_gates:
        for f in functions:
            require(f['sha256'] == BODY_GATES[f['entry']][1], 'selected body bytes changed')
    branches = [r for r in instructions if r['kind'].startswith('j') and 'target' in r]
    calls = [r for r in instructions if r['kind'] in ('call','call_indirect','jump_indirect')]
    stores = [r for r in instructions if r['kind'] in ('mov_store','mov_imm_store','sse_0x11','sse_0x29','inc','dec') and 'mem' in r]
    return dict(target_sha256=DIGEST, coordinates='linked ELF virtual addresses',
                functions=functions, instructions=instructions, branches=branches,
                calls=calls, stores=stores, enum_dispatch=dispatch,
                classifier=classifier, explicit_errors=errors, expected_texts=texts,
                whitespace=whitespace, depth_offset=depth_load['mem']['disp'],
                depth_store=depth_store['va'])



def entry_partition(result):
    at={r['va']:r for r in result['instructions']}
    for va,kind,target in [(0x13f3857,'ja',0x13f38c4),
                           (0x13f3892,'jne',0x13f38c4),
                           (0x13f38c7,'jne',0x13f3d62)]:
        require(at[va]['kind']==kind and at[va]['target']==target,
                'entry byte routing changed')
    quote=at[0x13f388e]['immediate'];brace=at[0x13f38c4]['immediate']
    require(at[0x13f3853]['immediate']==quote, 'entry compare threshold changed')
    groups={'whitespace':[], 'quoted_identifier':[], 'tagged_unit_object':[], 'syntax_error':[]}
    for byte in range(256):
        if byte in result['whitespace']:role='whitespace'
        elif byte==quote:role='quoted_identifier'
        elif byte==brace:role='tagged_unit_object'
        else:role='syntax_error'
        groups[role].append(byte)
    return dict(scope='one available byte at the enum entry; not whole-input acceptance',
                routes=groups, syntax_error_seed=at[0x13f38c7]['target'],
                syntax_error_code=at[0x13f3d62]['immediate'])


def contracts(result):
    """Byte-grounded operand observations; role strings are analyst inferences."""
    at={r['va']:r for r in result['instructions']}
    specs=[
        ('map_key_must_be_quote',0x14bb39f,'cmp',34),
        ('map_initial_first_key_flag',0x14bb2d2,'mov_imm',1),
        ('map_separator_byte',0x14bb32e,'cmp',44),
        ('map_close_byte',0x14bb38b,'cmp',125),
        ('optional_null_first_byte',0x1441d7c,'cmp',110),
        ('optional_null_second_byte',0x1441dab,'cmp',117),
        ('optional_null_third_byte',0x1441dcc,'cmp',108),
        ('optional_null_last_byte',0x1441de4,'cmp',108),
        ('optional_none_tag',0x1441de9,'mov_imm_store',0),
        ('optional_some_tag',0x1441e2d,'mov_imm',1),
        ('optional_error_tag',0x1441e13,'mov_imm',2),
        ('string_error_sentinel',0x14be1a3,'mov_imm',1<<63),
        ('empty_string_pointer',0x14be1dc,'mov_imm',1),
        ('new_key_no_old_value_sentinel',0x14cb0cb,'mov_imm',1<<63),
        ('leaf_allocation_size',0x14cb061,'mov_imm',288),
        ('node_capacity_guard',0x14cb094,'cmp',11),
        ('drain_leaf_free_size',0x14cce66,'mov_imm',288),
        ('drain_internal_free_size',0x14cce6b,'mov_imm',384),
        ('identifier_quote',0x14b6dbf,'cmp',34),
        ('scanner_error_tag',0x14b6de6,'cmp',2),
        ('matcher_error_tag',0x14b6e0f,'cmp',1),
        ('unit_first_byte',0x14b6edd,'cmp',110),
        ('unit_second_byte',0x14b6f07,'cmp',117),
        ('unit_third_byte',0x14b6f1f,'cmp',108),
        ('unit_fourth_byte',0x14b6f37,'cmp',108),
        ('at_line_initial',0x14a0149,'mov_imm',1),
        ('after_line_initial',0x149edd8,'mov_imm',1),
        ('at_newline_byte',0x14a0198,'cmp',10),
        ('after_newline_byte',0x149ee18,'cmp',10),
        ('after_cursor_overflow',0x149edbb,'cmp',-1),
        ('at_line_overflow',0x14a019f,'cmp',-1),
        ('at_column_overflow',0x14a01b0,'cmp',-1),
        ('after_line_overflow',0x149ee1f,'cmp',-1),
        ('after_column_overflow',0x149ee30,'cmp',-1),
        ('error_payload_io_tag_low32',0x14af198,'cmp',1),
        ('io_pointer_tag_mask',0x14ae7cd,'and',3),
        ('io_pointer_heap_tag',0x14ae7d0,'cmp',1),
        ('io_outer_free_bytes_normal',0x14ae827,'mov_imm',24),
        ('io_outer_free_bytes_unwind',0x14ae871,'mov_imm',24),
        ('error_box_free_bytes_normal',0x14470ec,'mov_imm',40),
        ('error_box_free_bytes_unwind',0x144710d,'mov_imm',40),
    ]
    rows=[]
    for role,va,kind,value in specs:
        r=at[va]
        require(r['kind']==kind and r.get('immediate')==value,
                'semantic operand changed: '+role)
        rows.append(dict(role=role,va=va,kind=kind,width=r['width'],
                         observed=value,bytes=r['bytes']))
    memory_specs=[
        ('map_entry_count_increment',0x14cb0c7,'rcx',16),
        ('leaf_key_count_read',0x14caf65,'rax',274),
        ('leaf_key_count_store',0x14cb0a5,'rax',274),
        ('leaf_key_byte_store',0x14cb0ac,'rax',276),
        ('map_depth_decrement_store',0x14bb298,'r14',72),
        ('map_depth_restore_store',0x14bb5f3,'r14',72),
        ('map_result_payload',0x14bb641,'rbx',8),
        ('map_result_tag',0x14bb645,'rbx',0),
        ('string_capacity_store',0x14be1f1,'rbx',0),
        ('string_pointer_store',0x14be1f4,'rbx',8),
        ('string_length_store',0x14be1f8,'rbx',16),
        ('drain_remaining_count',0x14ccb3e,'rsi',64),
        ('identifier_cursor_consumes_quote',0x14b6dce,'r14',40),
        ('identifier_resets_scratch_length',0x14b6dd2,'r14',16),
        ('unit_cursor_after_n',0x14b6ef5,'rdi',40),
        ('unit_cursor_before_u_compare',0x14b6f03,'rdi',40),
        ('unit_cursor_before_first_l_compare',0x14b6f1b,'rdi',40),
        ('unit_cursor_before_last_l_compare',0x14b6f33,'rdi',40),
        ('unit_result_byte_before_closing_delimiter',0x13f399a,'rbx',1),
        ('unit_result_tag_before_closing_delimiter',0x13f399e,'rbx',0),
        ('payload_string_size',0x14af1a6,'rdi',16),
        ('payload_string_pointer',0x14af1af,'rdi',8),
        ('io_vtable_size',0x14ae7fb,'r12',8),
        ('io_vtable_align',0x14ae805,'r12',16),
    ]
    for role,va,base,disp in memory_specs:
        r=at[va]
        require(r.get('mem',{}).get('base')==base and r['mem']['disp']==disp,
                'semantic state field changed: '+role)
        rows.append(dict(role=role,va=va,kind=r['kind'],width=r['width'],
                         observed=r['mem'],bytes=r['bytes']))
    for role,va,target in [
        ('optional_calls_map',0x1441dfc,0x14bb200),
        ('map_calls_key_envelope',0x14bb3ac,0x13f3820),
        ('map_calls_owned_string',0x14bb42a,0x14be0f0),
        ('map_calls_insert_replace',0x14bb48b,0x14caf40),
        ('map_calls_close',0x14bb5fa,0x14a01f0),
        ('late_close_failure_drops_map',0x14bb741,0x14d99a0),
        ('map_drop_calls_drain',0x14d9a01,0x14ccb20),
        ('result_drop_calls_drain',0x14adaf2,0x14ccb20),
    ]:
        r=at[va]
        require(r['kind']=='call' and r['target']==target, 'selected call edge changed')
        rows.append(dict(role=role,va=va,kind=r['kind'],width=r['width'],
                         observed=target,bytes=r['bytes']))
    require(at[0x14bb3a3]['kind']=='jne' and at[0x14bb3a3]['target']==0x14bb763,
            'quoted map key guard changed')
    require(at[0x14cb0c7]['kind']=='inc' and at[0x14cb0c7]['width']==64,
            'map entry count increment changed')
    return sorted(rows,key=lambda r:r['va'])


def control_flow(result):
    """Normal-return CFG only. Calls are opaque; LSDA edges are not invented."""
    at = {r['va']:r for r in result['instructions']}
    selected = {f['entry']:f for f in result['functions']}
    no_return = {0x157b480,0x157b520,0x157a6f0,0x157b63b,0x5660110,0x1346068,0x1345e2a,0x157b7f0,0x157a9f0}
    tables = {0x13f38b7:[r['target'] for r in result['enum_dispatch']],
              0x149fe65:sorted({r['target'] for r in result['classifier']})}
    graph = {}
    for va,r in sorted(at.items()):
        end=selected[r['function']]['end']; after=va+r['size']; kind=r['kind']
        target=r.get('target',r.get('resolved_target'))
        if kind in ('ret','trap') or (kind in ('call','call_indirect') and target in no_return):
            edges=[]
        elif kind=='jump':
            edges=[target] if target in at and at[target]['function']==r['function'] else []
        elif kind=='jump_indirect':
            edges=tables.get(va,[])
        elif kind.startswith('j'):
            edges=[target,after]
        else:
            edges=[after] if after<end else []
        require(all(x in at and at[x]['function']==r['function'] for x in edges),
                'CFG edge crosses instruction or function boundary')
        graph[va]=sorted(set(edges))
    def reachable(start, goal, forbidden=()):
        forbidden=set(forbidden);todo=[start];parent={start:None}
        if start in forbidden:return None
        for va in todo:
            if va==goal:
                path=[]
                while va is not None:path.append(va);va=parent[va]
                return path[::-1]
            for dest in graph[va]:
                if dest not in parent and dest not in forbidden:
                    parent[dest]=va;todo.append(dest)
        return None
    query_specs = [
        ('map_key_error_requires_depth_restore',0x14bb6fb,0x14bb65c,[0x14bb5f3],False),
        ('map_value_error_requires_depth_restore',0x14bb705,0x14bb65c,[0x14bb5f3],False),
        ('map_close_requires_depth_restore',0x14bb5be,0x14bb5fa,[0x14bb5f3],False),
        ('map_key_error_drains_accumulated_values',0x14bb4ea,0x14bb5e4,[0x14bb55c],False),
        ('duplicate_key_replacement_bypasses_count_increment',0x14cafd3,0x14cb0e9,[0x14cb0c7],True),
        ('new_map_value_requires_count_increment',0x14cb052,0x14cb0e9,[0x14cb0c7],False),
        ('late_close_error_drops_successful_map',0x14bb739,0x14bb65c,[0x14bb741],False),
        ('optional_null_bypasses_map_parser',0x1441de9,0x1441df8,[0x1441dfc],True),
        ('identifier_failure_to_error_return',0x13f3902,0x13f3999,[0x13f39b3],True),
        ('unit_failure_to_error_return',0x13f3984,0x13f3999,[0x13f39b3],True),
        ('depth_limit_to_error_return',0x13f3d6f,0x13f3999,[0x13f39b3],True),
        ('close_error_requires_prior_restore',0x13f399a,0x13f3d89,[0x13f39b3],False),
        ('close_eof_requires_prior_restore',0x13f399a,0x13f39f3,[0x13f39b3],False),
        ('object_success_requires_restore',0x13f399a,0x13f3a1e,[0x13f39b3],False),
        ('object_payload_written_before_close_error',0x13f399a,0x13f3d89,[],True),
        ('object_close_error_rewrites_result_tag',0x13f3d89,0x13f3999,[0x13f398a],False),
        ('plain_quote_success_bypasses_depth_restore',0x13f38b9,0x13f3999,[0x13f39b3],True),
    ]
    queries=[]
    for label,start,goal,forbidden,expected in query_specs:
        path=reachable(start,goal,forbidden)
        require((path is not None)==expected,'control-flow proposition changed: '+label)
        queries.append(dict(proposition=label,start=start,goal=goal,forbidden=forbidden,
                            reachable=path is not None,witness=path))
    # Position constructors agree on byte counting; the after variant selects
    # min(cursor + 1, length), whereas at-position checks cursor <= length.
    return dict(scope='normal-return CFG; external calls assumed to return unless fixed panic/unwind target',
                assumed_noreturn_targets=sorted(no_return),
                nodes=[dict(va=va,successors=edges) for va,edges in graph.items()],
                propositions=queries)

def exception_sites(image, result):
    """Read selected LSDA call-site records; action/type semantics stay unresolved."""
    at = {r['va']:r for r in result['instructions']}
    tables=[]
    for f in result['functions']:
        lsda=image.fde(f['entry'])['lsda']
        if lsda is None:continue
        # All selected headers and call-site tables fit this file-backed window.
        raw=image.read(lsda,256)
        require(raw[0]==255, 'explicit LSDA landing-pad base unsupported')
        encoding=raw[1]; p=2; type_base=None
        require(encoding in (255,155), 'unsupported LSDA type encoding')
        if encoding!=255:
            offset,p=uleb(raw,p,len(raw));type_base=lsda+p+offset
        require(raw[p]==1, 'unsupported LSDA call-site encoding');p+=1
        length,p=uleb(raw,p,len(raw));end=p+length
        require(end<=len(raw), 'LSDA call-site table exceeds bounded window')
        sites=[];last_end=0
        while p<end:
            values=[]
            for _ in range(4):
                v,p=uleb(raw,p,end);values.append(v)
            start,size,landing,action=values
            require(start>=last_end and start+size<=f['byte_count'], 'LSDA call-site range invalid')
            require(f['entry']+start in at and
                    (f['entry']+start+size in at or f['entry']+start+size==f['end']),
                    'LSDA call-site endpoint is not an instruction boundary')
            last_end=start+size
            dest=f['entry']+landing if landing else None
            require(dest is None or (dest in at and at[dest]['function']==f['entry']),
                    'LSDA landing pad is not a selected instruction start')
            sites.append(dict(start=f['entry']+start,end=f['entry']+start+size,
                              landing=dest,action_index=action,
                              transfer_sites=[r['va'] for r in result['calls']
                                 if f['entry']+start<=r['va']<f['entry']+start+size]))
        require(p==end, 'LSDA call-site table incomplete')
        tables.append(dict(function=f['entry'],lsda=lsda,type_encoding=encoding,
                           type_table_base=type_base,raw_through_callsites=raw[:end].hex(),sites=sites))
    return tables


def tsv(rows, columns):
    buf = io.StringIO(newline='')
    writer = csv.writer(buf, delimiter='\t', lineterminator='\n')
    writer.writerow(columns)
    for row in rows:
        writer.writerow([json.dumps(row.get(c,''),sort_keys=True,separators=(',',':'))
                         if isinstance(row.get(c), (dict,list)) else row.get(c,'') for c in columns])
    return buf.getvalue().encode()


def outputs(image):
    result = collect(image)
    summary = {k:v for k,v in result.items() if k not in ('branches','calls','stores')}
    summary['control_flow'] = control_flow(result)
    summary['exception_tables'] = exception_sites(image,result)
    summary['operand_contracts'] = contracts(result)
    summary['entry_partition'] = entry_partition(result)
    extents=[(f['entry'],f['end']) for f in result['functions']]
    transfers=[r for r in result['instructions']
               if r['kind'] in ('call','jump','call_indirect','jump_indirect')]
    targets={r.get('target',r.get('resolved_target')) for r in transfers}
    summary['dependency_boundaries']={
        'statically_resolved_targets_outside_selected_ranges': sorted(t for t in targets
            if t is not None and not any(lo<=t<hi for lo,hi in extents)),
        'dynamic_symbol_slots': sorted({(r['memory_va'],r['external_symbol'])
            for r in transfers if 'external_symbol' in r}),
        'register_indirect_sites_without_dataflow_resolution': [r['va'] for r in transfers
            if r['kind'] in ('call_indirect','jump_indirect')
            and 'resolved_target' not in r and 'external_symbol' not in r
            and r['va'] not in (0x13f38b7,0x149fe65)],
        'excluded': ['whole-ELF equivalence','dynamic formatter/destructor behavior',
                     'nonempty-node split/rebalance','external matcher and scanner semantics']}

    summary['metrics'] = { 'selected_functions':len(result['functions']),
        'lsda_tables':len(summary['exception_tables']),
        'lsda_callsite_ranges':sum(len(t['sites']) for t in summary['exception_tables']),
        'selected_bytes':sum(f['byte_count'] for f in result['functions']),
        'decoded_instructions':len(result['instructions']),
        'direct_branches':len(result['branches']), 'call_or_indirect_transfer_sites':len(result['calls']),
        'memory_store_sites':len(result['stores']), 'enum_code_leaves':len(result['enum_dispatch']),
        'explicit_syntax_error_routes':len(result['explicit_errors']) }
    return {
        'evidence.json':(json.dumps(summary,indent=2,sort_keys=True)+'\n').encode(),
        'operand-contracts.tsv':tsv(summary['operand_contracts'],
            ['role','va','kind','width','observed','bytes']),
        'exception-sites.tsv':tsv([dict(function=t['function'],lsda=t['lsda'],**r)
            for t in summary['exception_tables'] for r in t['sites']],
            ['function','lsda','start','end','landing','action_index','transfer_sites']),
        'functions.tsv':tsv(result['functions'],['role','entry','end','fde','byte_count','instruction_count','sha256']),
        'branches.tsv':tsv(result['branches'],['function','va','kind','target','bytes']),
        'calls.tsv':tsv(result['calls'],['function','va','kind','target','memory_va','resolved_target','external_symbol','bytes']),
        'stores.tsv':tsv(result['stores'],['function','va','kind','width','mem','reg','immediate','bytes']),
        'error-routes.tsv':tsv(result['explicit_errors'],['role','seed','code','constructor','call','path']),
        'expected-texts.tsv':tsv(result['expected_texts'],['writer','vtable','slot','text_va','length','text','sha256']),
    }


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,required=True)
    args=parser.parse_args()
    image=Image((ROOT/'artifacts/node/94/hl-node').read_bytes())
    files=outputs(image)
    args.out.mkdir(parents=True,exist_ok=True)
    for name,content in sorted(files.items()):
        (args.out/name).write_bytes(content)
    print('generated',len(files),'static evidence files')

if __name__=='__main__':
    main()
