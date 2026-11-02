"""Static node94 configuration-number path; no target or external tool execution."""
import argparse
import csv
from fractions import Fraction
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
ENTRIES = {
    0x164db50: 'integer_prefix', 0x164d800: 'fraction_or_finish',
    0x164df30: 'exponent', 0x164dce0: 'syntax_only_number',
    0x164e4d0: 'error_at_cursor', 0x4ebbe20: 'shared_error_cleanup',
    0x164e5e0: 'error_payload_drop', 0x4eb9e40: 'shared_error_after_cursor',
    0x4eb9f00: 'overflow_integer_fraction', 0x4eba440: 'shared_exponent',
    0x4ebaa20: 'overflow_integer_tail', 0x4ebac00: 'overflow_fraction_tail',
    0x4ebad60: 'overflow_exponent_tail', 0x4ebae10: 'shared_error_at_cursor',
    0x4ebcd70: 'boxed_error_constructor', 0x4ebce50: 'shared_error_payload_drop',
}

BODY_GATES = {
    0x164d800: (0x164db42, '78214501f32ac2bc4ee083c0bb1b0f0a571406ea9f718f6ac300402d2e59aba3'),
    0x164db50: (0x164dcd7, '74c2fa54b1b5536331291355c606a93feff1b8958805b5c9a9de0126aeb6d5e2'),
    0x164dce0: (0x164df2a, 'eee246dbf8e80021ea64e124b82aad773718eb45f238b24f2555d10b3286d991'),
    0x164df30: (0x164e1b8, 'b1868bfb46bd209a5c0a3aa6b6f83e2b8dc86c940e0224f13e0a34788261e644'),
    0x164e4d0: (0x164e590, '68648d3c70b4f522d24b344f3a8d68e3586df141bbe150f8874cdc8942f72224'),
    0x164e5e0: (0x164e6c6, '9b233099210adcd8b4cca3eec84c9a7df587c8fd60ae7fdfd1305d24cb76d306'),
    0x4eb9e40: (0x4eb9ef8, '8489209144053f529edeab8869fdd2ac4064df8f44f9fd775902236c9e89729a'),
    0x4eb9f00: (0x4eba1ba, '42c83b745dbe963bb754f6aac3989d15f8fe14a62e2338904ece87a740bb81d5'),
    0x4eba440: (0x4eba6c8, 'f08448cdd154d55a031c89b2f20ad2f721e4fe4fa7925249687034d50a3f6940'),
    0x4ebaa20: (0x4ebabf7, '033b7fe6e55a1dd295c5e76c9081a68e54f90cb07798c32dc016ea10320fd126'),
    0x4ebac00: (0x4ebad53, '688e4034288681693fcda6e30b1470067c7d6ace7b9a16d851be7bd9da36bbf4'),
    0x4ebad60: (0x4ebae07, '2e5eaa4fecfafddffaa1171d313e8c26e152bdac7c2f42ae7434de9a2b1626f9'),
    0x4ebae10: (0x4ebaed0, 'dd3d0d12df0a8d56c41a69d975432c9a6a67b7b07bf8a67e923ec84e66aa906f'),
    0x4ebbe20: (0x4ebbf06, 'ece7c75dbbce3d9dfbc835eeabc4039f841835285f140f2dd4a92a33d4261959'),
    0x4ebcd70: (0x4ebcde9, '2f74f262f13778616914224a480d3491d538ae0d716232d13d32b126f9bd16ae'),
    0x4ebce50: (0x4ebcf37, 'b1d7f989201f0e1307d5604106b3eeeac803d577fc75450ae508e3e167ec5644'),
}

SLOT_GATES = {
    0x576dfd8: 0x54c06b0,
    0x576e010: 0x54c8cb0,
    0x576e020: 0x1345e2a,
    0x576e118: 0x157b480,
    0x576e128: 0x157b63b,
    0x576e150: 0x157b520,
    0x576e1b0: 0x157b4a0,
    0x576e2e0: 0x157a6f0,
    0x576ef80: 0x4ebcd70,
    0x576fc70: 0x7c9740,
    0x576fc78: 0x4ebac00,
    0x576fc80: 0x4ebaa20,
    0x576fc88: 0x4ebad60,
}
DATA_GATES = {
    0x203e80: '00003043000030450000000000000000',
    0x202ea0: '00000000000030430000000000003045',
    0x2082f0: '00000000000000800000000000000080',
    0x20a350: 'a0c8eb85f3cce17f',
    0x20a910: '0000000000000080',
}
SOURCE_GATES = {
    0x1f890d: (94, '1e310a16d71a1cbc1136009c2c03c1499261e0edbfe5f0427a4cc4940e18923b'),
    0x1df9be: (96, 'a9df5347b9398eb85a48c1dec7baa2cd080fb94beed66851d0c703fbd3c11d2f'),
}
# Boundary references only: these callers belong to an existing packet and are
# not selected, counted as recovered bodies, or exported as disassembly.
CONTEXT_CALLS = {
    0x164e41d: (0x164e1c0, 0x164db50, 'e82ef7ffff'),
    0x164e485: (0x164e1c0, 0x164db50, 'e8c6f6ffff'),
    0x164edee: (0x164e930, 0x164dce0, 'e8edeeffff'),
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
            elif op2==0xbc:row['kind']='tzcnt' if 0xf3 in prefixes else 'bsf';modrm=True
            elif 0x40<=op2<=0x4f:row['kind']='cmov'+CC[op2&15];modrm=True
            elif 0x90<=op2<=0x9f:row['kind']='set'+CC[op2&15];modrm=True;row['width']=8
            else:raise EvidenceError('unsupported two-byte opcode '+hex(op2)+' at '+hex(base+start))
        elif op in (0x00,0x01,0x08,0x09,0x20,0x21,0x28,0x29,0x30,0x31,0x38,0x39,0x3b,0x23,0x85,0x84,0x88,0x89,0x8b,0x8d,0x63):
            row['kind']={0x00:'add',0x01:'add',0x08:'or',0x09:'or',0x20:'and',0x21:'and',0x23:'and',0x28:'sub',0x29:'sub',0x30:'xor',0x31:'xor',0x38:'cmp',0x39:'cmp',0x3b:'cmp',0x85:'test',0x84:'test',0x88:'mov_store',0x89:'mov_store',0x8b:'mov_load',0x8d:'lea',0x63:'movsxd'}[op]
            modrm=True
            if op in (0x00,0x08,0x20,0x28,0x30,0x38,0x84,0x88):row['width']=8
        elif op in (0x80,0x81,0x83,0xc6,0xc7,0xf6,0xf7,0xff,0xc1,0x6b,0x69):
            modrm=True
            row['kind']='group'
            if op in (0x80,0xc6,0xf6):row['width']=8
            if op in (0x80,0x83,0xc6,0xc1,0x6b):imm=1
            elif op in (0x81,0xc7,0x69):imm=2 if width==16 else 4
            signed=op in (0x83,0x6b)
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
            if op in (0x80,0x81,0x83):row['kind']=['add','or','adc','sbb','and','sub','xor','cmp'][group]
            elif op in (0xc6,0xc7):
                if group:raise EvidenceError('invalid move group')
                row['kind']='mov_imm_store'
            elif op in (0xf6,0xf7):
                if group not in (0,2,3):raise EvidenceError('unsupported unary group')
                row['kind']={0:'test',2:'not',3:'neg'}[group]
                if group==0:imm=1 if op==0xf6 else (2 if width==16 else 4)
            elif op==0xff:
                if group not in (0,1,2,4):raise EvidenceError('unsupported ff group')
                row['kind']={0:'inc',1:'dec',2:'call_indirect',4:'jump_indirect'}[group]
            elif op==0xc1:
                if group not in (4,5,7):raise EvidenceError('unsupported shift')
                row['kind']={4:'shl',5:'shr',7:'sar'}[group]
            elif op in (0x6b,0x69):row['kind']='imul'
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

def collect(image):
    functions=[];instructions=[]
    for entry,role in sorted(ENTRIES.items()):
        f=image.fde(entry);body=image.read(entry,f['end']-entry)
        rows=decode(body,entry)
        functions.append({'entry':entry,'end':f['end'],'fde':f['fde'],'role':role,'bytes':len(body),'sha256':hashlib.sha256(body).hexdigest(),'instructions':len(rows)})
        for row in rows:
            row['function']=entry;row['file_offset']=image.offset(row['va'],row['size'])
            if row['kind'] in ('call_indirect','jump_indirect') and 'memory_va' in row:
                slot=row['memory_va']
                if slot not in image.relocations:raise EvidenceError('missing call relocation')
                row['resolved_target']=image.relocations[slot]
            instructions.append(row)
    return {'target_sha256':DIGEST,'coordinate_system':'linked ELF virtual address','functions':functions,'instructions':instructions}

def rounded_div(n, d):
    q, r = divmod(n, d)
    return q + (2*r > d or (2*r == d and q & 1))

def binary64(value):
    """Round a nonnegative rational to IEEE binary64, ties to even; no host FPU."""
    value=Fraction(value)
    if value<0:raise EvidenceError('negative magnitude')
    if not value:return 0
    n,d=value.numerator,value.denominator
    e=n.bit_length()-d.bit_length()
    if (n < d<<e) if e>=0 else (n<<-e < d):e-=1
    if e < -1022:return rounded_div(n<<1074,d)
    shift=52-e
    q=rounded_div(n<<shift,d) if shift>=0 else rounded_div(n,d<<-shift)
    if q==1<<53:q>>=1;e+=1
    if e>1023:return 0x7ff0000000000000
    return ((e+1023)<<52)|(q-(1<<52))

def rational(bits):
    if bits>>63 or bits>>52==0x7ff:raise EvidenceError('nonfinite or negative operand')
    exponent=(bits>>52)&0x7ff
    mantissa=bits&((1<<52)-1)
    if exponent:mantissa|=1<<52;power=exponent-1023-52
    else:power=-1074
    return Fraction(mantissa<<power,1) if power>=0 else Fraction(mantissa,1<<-power)

class Contract:
    """Constants obtained only from admitted instructions and data references."""
    def __init__(self, image, records):
        self.rows={r['va']:r for r in records['instructions']}
        def immediate(va,kind):
            r=self.rows[va]
            if r['kind']!=kind or 'immediate' not in r:raise EvidenceError('contract instruction changed')
            return r['immediate']
        self.uint_quotient=immediate(0x164dbc3,'mov_imm')+1
        self.uint_last_digit=immediate(0x164dc2c,'cmp')
        self.uint_max=self.uint_quotient*10+self.uint_last_digit
        self.exp_quotient=immediate(0x164dfdd,'cmp')
        self.exp_last_digit=immediate(0x164dfea,'cmp')
        self.exp_max=self.exp_quotient*10+self.exp_last_digit
        self.pow_count=immediate(0x164e06f,'cmp')
        self.scale_chunk=immediate(0x164e0a1,'add')
        self.unsigned_tag=immediate(0x164d865,'mov_imm')
        self.signed_tag=immediate(0x164d968,'mov_imm')
        self.error_tag=immediate(0x164dc9c,'mov_imm_store')
        self.eof_code=immediate(0x164dc7c,'mov_imm_store')
        self.syntax_code=immediate(0x164db94,'mov_imm_store')
        self.range_code=immediate(0x164e145,'mov_imm_store')
        self.cursor_offset=self.rows[0x164db73]['mem']['disp']
        self.length_offset=self.rows[0x164db55]['mem']['disp']
        self.pointer_offset=self.rows[0x164db6a]['mem']['disp']
        self.sign_mask=immediate(0x164d8a8,'mov_imm')
        self.infinity=immediate(0x164e0e5,'mov_imm')
        self.table_slot=self.rows[0x164e0be]['memory_va']
        if self.table_slot not in image.relocations:raise EvidenceError('power table relocation missing')
        self.table_va=image.relocations[self.table_slot]
        self.power_bits=list(struct.unpack('<'+'Q'*self.pow_count,image.read(self.table_va,self.pow_count*8)))
        if self.pow_count!=self.scale_chunk+1 or self.power_bits[0]!=binary64(1):raise EvidenceError('power table boundary')
        for i,bits in enumerate(self.power_bits):
            if bits!=binary64(10**i):raise EvidenceError('power table contents')
        self.parameters={k:v for k,v in vars(self).items() if isinstance(v,int)}
    def scale(self,mantissa,exponent,positive):
        bits=binary64(mantissa)
        while abs(exponent)>=self.pow_count:
            if bits==0:break
            if exponent>=0:return None
            exponent+=self.scale_chunk
            bits=binary64(rational(bits)/rational(self.power_bits[self.scale_chunk]))
        else:
            factor=rational(self.power_bits[abs(exponent)])
            value=rational(bits)/factor if exponent<0 else rational(bits)*factor
            bits=binary64(value)
            if bits==self.infinity:return None
        return bits | (0 if positive else self.sign_mask)

def location(data, position, peek=False):
    if not 0<=position<=len(data):raise EvidenceError('cursor outside slice')
    end=min(position+int(peek),len(data));line=1;column=0
    for byte in data[:end]:
        if byte==10:line+=1;column=0
        else:column+=1
    return {'line':line,'column':column}

def number_model(contract, data, positive=True, position=0, syntax_only=False):
    """Abstract transfer, not captured instruction execution. Sign already consumed.

    Finite conversions assume nearest-even gradual-underflow binary64. No claim
    is made about the captured process's MXCSR or dynamic allocator behavior.
    Positions at the owned local after-cursor helper assume the convention of
    the separately selected shared helper; that boundary is not re-proved here.
    """
    if type(positive) is not bool or not 0<=position<=len(data):
        raise EvidenceError('invalid model input')
    n=len(data)
    if n>contract.exp_max:
        raise EvidenceError('model input exceeds reviewed scale-counter domain')
    p=position;route=[]
    def digit(c):return 48<=c<=57
    def error(code,peek=False):
        return {'kind':'error','tag':None if syntax_only else contract.error_tag,
                'code':code,'cursor':p,'position':location(data,p,peek),'route':route[:]}
    def floating(m,e):
        result=contract.scale(m,e,positive)
        if result is None:return error(contract.range_code)
        return {'kind':'binary64','tag':0,'bits':f'{result:016x}','cursor':p,'route':route[:]}
    if syntax_only:
        route.append('syntax_only_number')
        if p==n:return error(contract.syntax_code)
        first=data[p];p+=1
        if first==48:
            if p<n and digit(data[p]):return error(contract.syntax_code,True)
        elif 49<=first<=57:
            while p<n and digit(data[p]):p+=1
        else:return error(contract.syntax_code)
        if p<n and data[p]==46:
            p+=1
            if p==n or not digit(data[p]):return error(contract.syntax_code,True)
            while p<n and digit(data[p]):p+=1
        if p<n and data[p] in (69,101):
            p+=1
            if p<n and data[p] in (43,45):p+=1
            if p==n:return error(contract.syntax_code)
            c=data[p];p+=1
            if not digit(c):return error(contract.syntax_code)
            while p<n and digit(data[p]):p+=1
        return {'kind':'syntax_success','return_word':0,'cursor':p,'route':route[:]}
    route.append('integer_prefix')
    if p==n:return error(contract.eof_code)
    first=data[p];p+=1
    if first==48:
        mantissa=0
        if p<n and digit(data[p]):return error(contract.syntax_code,True)
    elif 49<=first<=57:mantissa=first-48
    else:return error(contract.syntax_code)
    integer_overflow=False;exponent=0
    while p<n and digit(data[p]):
        d=data[p]-48
        if mantissa>contract.uint_quotient or (mantissa==contract.uint_quotient and d>contract.uint_last_digit):
            integer_overflow=True;route.append('overflow_integer_tail')
            while p<n and digit(data[p]):p+=1;exponent+=1
            break
        mantissa=mantissa*10+d;p+=1
    if not integer_overflow:route.append('fraction_or_finish')
    fraction=False
    if p<n and data[p]==46:
        fraction=True;route.append('overflow_integer_fraction' if integer_overflow else 'fraction')
        p+=1
        if p==n:return error(contract.eof_code,True)
        if not digit(data[p]):return error(contract.syntax_code,True)
        while p<n and digit(data[p]):
            d=data[p]-48
            if mantissa>contract.uint_quotient or (mantissa==contract.uint_quotient and d>contract.uint_last_digit):
                route.append('overflow_fraction_tail')
                while p<n and digit(data[p]):p+=1
                break
            mantissa=mantissa*10+d;p+=1;exponent-=1
    if p<n and data[p] in (69,101):
        route.append('exponent');p+=1;exp_positive=True
        if p<n and data[p] in (43,45):exp_positive=data[p]==43;p+=1
        if p==n:return error(contract.eof_code)
        c=data[p];p+=1
        if not digit(c):return error(contract.syntax_code)
        magnitude=c-48
        while p<n and digit(data[p]):
            d=data[p]-48;p+=1
            if magnitude>contract.exp_quotient or (magnitude==contract.exp_quotient and d>contract.exp_last_digit):
                route.append('overflow_exponent_tail')
                if exp_positive and mantissa!=0:return error(contract.range_code)
                while p<n and digit(data[p]):p+=1
                return {'kind':'binary64','tag':0,'bits':f'{(0 if positive else contract.sign_mask):016x}','cursor':p,'route':route[:]}
            magnitude=magnitude*10+d
        exponent=max(-contract.exp_max-1,min(contract.exp_max,exponent+(magnitude if exp_positive else -magnitude)))
        return floating(mantissa,exponent)
    if fraction or integer_overflow:return floating(mantissa,exponent)
    if positive:return {'kind':'unsigned','tag':contract.unsigned_tag,'integer':str(mantissa),'cursor':p,'route':route[:]}
    if 0<mantissa<=contract.sign_mask:
        return {'kind':'signed','tag':contract.signed_tag,'integer':str(-mantissa),'cursor':p,'route':route[:]}
    return floating(mantissa,0)


def qualify(image, records):
    for f in records['functions']:
        expected_end,expected_digest=BODY_GATES[f['entry']]
        if f['end']!=expected_end or f['sha256']!=expected_digest:
            raise EvidenceError('reviewed body or FDE endpoint changed')
    for slot,target in SLOT_GATES.items():
        if image.relocations.get(slot)!=target:raise EvidenceError('reviewed relocation changed')
    for va,raw in DATA_GATES.items():
        if image.read(va,len(raw)//2).hex()!=raw:raise EvidenceError('reviewed floating constant changed')
    for r in records['instructions']:
        f=next(f for f in records['functions'] if f['entry']==r['function'])
        if r['kind'].startswith('j') and r['kind'] not in ('jump','jump_indirect'):
            if not f['entry']<=r['target']<f['end']:raise EvidenceError('conditional leaves function')


def source_locations(image, records):
    """Read selected RIP-relative Location objects, retaining no build prefix."""
    result=[]
    for row in records['instructions']:
        va=row.get('memory_va',0)
        if row['kind']!='lea' or va<0x5600000:
            continue
        raw=image.read(va,24)
        pointer,length,line,column=struct.unpack('<QQII',raw)
        pointer=image.relocations.get(va,pointer)
        if pointer not in SOURCE_GATES:
            raise EvidenceError('unreviewed diagnostic source pointer')
        expected_length,expected_digest=SOURCE_GATES[pointer]
        if length!=expected_length:
            raise EvidenceError('diagnostic source length changed')
        path=image.read(pointer,length)
        if hashlib.sha256(path).hexdigest()!=expected_digest:
            raise EvidenceError('diagnostic source bytes changed')
        start=path.find(b'serde_json-')
        if start<0 or not line or not column:
            raise EvidenceError('invalid diagnostic source coordinates')
        result.append({'function':row['function'],'site':row['va'],'location_va':va,
                       'location_bytes':raw.hex(),'pool_va':pointer,'pool_length':length,
                       'pool_sha256':expected_digest,'source_suffix':path[start:].decode('ascii'),
                       'line':line,'column':column})
    return result


def context_links(image):
    result=[]
    for site,(caller,target,expected) in sorted(CONTEXT_CALLS.items()):
        raw=image.read(site,5)
        fde=image.fde(caller)
        if raw.hex()!=expected or not caller<=site<site+5<=fde['end']:
            raise EvidenceError('owned caller boundary reference changed')
        actual=site+5+struct.unpack_from('<i',raw,1)[0]
        if raw[0]!=0xe8 or actual!=target:
            raise EvidenceError('owned caller target changed')
        result.append({'caller':caller,'site':site,'target':actual,'bytes':raw.hex(),
                       'ownership':'constants-aws-name-parse-94; context only'})
    return result


def model_cases(contract):
    tokens=[b'',b'0',b'1',b'9',b'00',b'01',b'09',b'0x',b'1x',b'1.',b'1.x',b'1.0',b'0.0',
            b'1e',b'1e+',b'1e-',b'1e+x',b'1e-x',b'1e0',b'1E+2',b'1E-2',b'1.0e2',b'1.0ex',
            b'123,',b'1.2.3',b'1e1e1',b'1 2',b'NaN',b'Infinity',b'-1',b'+1',b' 1',
            b'184467440737095516159.9',b'0.'+b'9'*50,b'9'*400,b'1e-99999999999999999999',
            b'1e99999999999999999999',b'0e99999999999999999999',b'0e-99999999999999999999',
            b'1e2147483648999',b'0e2147483648999',b'1e-2147483648999']
    for value in (contract.sign_mask-1,contract.sign_mask,contract.sign_mask+1,
                  contract.uint_max-1,contract.uint_max,contract.uint_max+1):
        tokens.append(str(value).encode())
    for exp in (contract.scale_chunk-1,contract.scale_chunk,contract.pow_count,
                contract.exp_max-1,contract.exp_max,contract.exp_max+1):
        for prefix in (b'0e',b'1e',b'1e-'):tokens.append(prefix+str(exp).encode())
    tokens+= [bytes([i]) for i in range(256)]
    tokens=sorted(set(tokens))
    rows=[]
    for token in tokens:
        for mode,positive in [('typed_positive',True),('typed_negative',False),('syntax_only',True)]:
            prediction=number_model(contract,token,positive,syntax_only=mode=='syntax_only')
            rows.append({'input_hex':token.hex(),'mode':mode,'prediction':prediction})
    return rows


def generate(data):
    image=Image(data)
    record=collect(image)
    qualify(image,record)
    contract=Contract(image,record)
    record['interpretation']={
        'scope':'static digit-entry helpers and numeric/error dependencies; caller sign and whitespace handling excluded',
        'binary_execution':False,
        'model_assumptions':'IEEE binary64 nearest-even, gradual underflow; owned local after-cursor error helper assumed to use the selected shared helper convention; allocation and panic boundaries remain external',
        'fde_limit':'unwind-described extents, not source-function ownership',
        'old_error_boundary':'0x164d740 is previously owned and not selected or re-exported',
    }
    record['parameters']=contract.parameters
    record['data_constants']=[{'va':va,'bytes':image.read(va,len(raw)//2).hex()} for va,raw in sorted(DATA_GATES.items())]
    record['relocations']=[{'slot':slot,'addend':image.relocations[slot]} for slot in sorted(SLOT_GATES)]
    diagnostics=source_locations(image,record)
    record['diagnostic_source_locations']=diagnostics
    record['owned_caller_context_links']=context_links(image)
    calls=[];branches=[];stores=[]
    by_entry={f['entry']:f for f in record['functions']}
    for r in record['instructions']:
        f=by_entry[r['function']]
        dest=r.get('resolved_target',r.get('target'))
        tail=(r['kind']=='jump' and not f['entry']<=r['target']<f['end']) or r['kind']=='jump_indirect'
        if r['kind'].startswith('call') or tail:
            boundary='selected' if dest in ENTRIES else ('previously_owned' if dest==0x164d740 else ('dynamic' if dest is None else 'external'))
            calls.append({'function':r['function'],'site':r['va'],'kind':r['kind'],'slot':r.get('memory_va'),
                          'target':dest,'boundary':boundary})
        if r['kind'].startswith('j') and r['kind']!='jump_indirect':
            branches.append({'function':r['function'],'site':r['va'],'kind':r['kind'],'target':r['target'],
                             'fallthrough':None if r['kind']=='jump' else r['va']+r['size']})
        if 'mem' in r and (r['kind'] in ('mov_store','mov_imm_store','sse_0x11','sse_0x29') or r['kind'].startswith('set')):
            stores.append({'function':r['function'],'site':r['va'],'kind':r['kind'],'width':r['width'],
                           'base':r['mem']['base'],'index':r['mem']['index'],'scale':r['mem']['scale'],
                           'displacement':r['mem']['disp'],'immediate':r.get('immediate')})
    cases=model_cases(contract)
    record['metrics']={'selected_fdes':len(record['functions']),
                       'selected_bytes':sum(f['bytes'] for f in record['functions']),
                       'decoded_instructions':len(record['instructions']),
                       'direct_branches':len(branches),'call_and_tail_sites':len(calls),
                       'memory_store_instructions':len(stores),'power_table_entries':len(contract.power_bits),
                       'diagnostic_source_sites':len(diagnostics),
                       'model_cases':len(cases)}
    def tsv(rows, columns, hex_columns=()):
        import io
        out=io.StringIO();w=csv.writer(out,delimiter='\t',lineterminator='\n');w.writerow(columns)
        for row in rows:
            w.writerow(['' if row.get(k) is None else hex(row[k]) if k in hex_columns else row[k] for k in columns])
        return out.getvalue()
    powers=[{'index':i,'va':contract.table_va+i*8,'bits':f'{bits:016x}'} for i,bits in enumerate(contract.power_bits)]
    flat_cases=[{'input_hex':r['input_hex'],'mode':r['mode'],
                 'prediction':json.dumps(r['prediction'],sort_keys=True,separators=(',',':'))} for r in cases]
    return {
        'evidence.json':json.dumps(record,indent=2,sort_keys=True)+'\n',
        'functions.tsv':tsv(record['functions'],['entry','end','fde','role','bytes','instructions','sha256'],['entry','end','fde']),
        'branches.tsv':tsv(branches,['function','site','kind','target','fallthrough'],['function','site','target','fallthrough']),
        'calls.tsv':tsv(calls,['function','site','kind','slot','target','boundary'],['function','site','slot','target']),
        'memory-stores.tsv':tsv(stores,['function','site','kind','width','base','index','scale','displacement','immediate'],['function','site']),
        'powers.tsv':tsv(powers,['index','va','bits'],['va']),
        'source-locations.tsv':tsv(diagnostics,['function','site','location_va','location_bytes','pool_va','pool_length','pool_sha256','source_suffix','line','column'],['function','site','location_va','pool_va']),
        'context-links.tsv':tsv(record['owned_caller_context_links'],['caller','site','target','bytes','ownership'],['caller','site','target']),
        'model-cases.tsv':tsv(flat_cases,['input_hex','mode','prediction']),
    }


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--out',type=Path,required=True)
    args=parser.parse_args()
    outputs=generate((ROOT/'artifacts/node/94/hl-node').read_bytes())
    args.out.mkdir(parents=True,exist_ok=True)
    for name,text in sorted(outputs.items()):
        (args.out/name).write_bytes(text.encode('utf-8'))

if __name__=='__main__':main()
