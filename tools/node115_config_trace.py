#!/usr/bin/env python3
"""Statically trace node #115 configuration selection and name conversion.

No captured instructions are executed. A deliberately restricted abstract
interpreter propagates constants and symbolic input-byte XOR expressions along
straight-line comparison chains. Branch predicates become exact byte equality
constraints, independently of the formatter's spelling pool.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

from elf_index import sections, unwind_index
from fde_extents import eh_frame_records, uleb

DIGEST = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
PARSER = 0x1775500
RENDERER = 0x1774e60
JSON_PARSER = 0x1774100


def require(ok, message):
    if not ok:
        raise ValueError(message)


def verify_digest(blob):
    require(len(blob) == 105896032 and hashlib.sha256(blob).hexdigest() == DIGEST,
            'node #115 size or SHA-256 mismatch')


class Image:
    def __init__(self, blob, *, authenticate=True):
        if authenticate:
            verify_digest(blob)
        self.blob = blob
        self.sections = sections(blob)
        _, fdes = eh_frame_records(blob, self.sections)
        self.fdes = {f['start']: f for f in fdes}
        require(len(self.fdes) == len(fdes), 'duplicate FDE starts')
        _, index_rows = unwind_index(blob)
        selected = {start for _, start, _, _ in BODIES}
        self.index_entries = {r['start']:r for r in index_rows if r['start'] in selected}
        require(len(self.index_entries) == len(selected), 'selected FDE missing from unwind index')
        self.relocations = {}
        self.symbols = {}
        symsecs = [s for s in self.sections if s['name'] == '.dynsym' and s['type'] == 11]
        strsecs = [s for s in self.sections if s['name'] == '.dynstr' and s['type'] == 3]
        require(len(symsecs) == len(strsecs) == 1, 'missing dynamic symbol tables')
        sym, strings = symsecs[0], strsecs[0]
        require(sym['size'] % 24 == 0, 'invalid dynamic symbol table')
        string_data = blob[strings['offset']:strings['offset']+strings['size']]
        rs = [s for s in self.sections if s['name'] == '.rela.dyn' and s['type'] != 8]
        require(len(rs) == 1 and rs[0]['size'] % 24 == 0, 'invalid RELA section')
        s = rs[0]
        for p in range(s['offset'], s['offset'] + s['size'], 24):
            slot, info, addend = struct.unpack_from('<QQq', blob, p)
            if info == 8:
                require(slot not in self.relocations, 'duplicate relative relocation')
                self.relocations[slot] = (p, addend)
            elif (info & 0xffffffff) == 6:
                symbol_index = info >> 32
                require(symbol_index*24+24 <= sym['size'], 'dynamic symbol index outside table')
                name_offset = struct.unpack_from('<I', blob, sym['offset']+symbol_index*24)[0]
                require(name_offset < len(string_data), 'dynamic symbol name outside table')
                name_end = string_data.find(b'\0', name_offset)
                require(name_end >= name_offset and slot not in self.symbols, 'invalid dynamic symbol name or slot')
                self.symbols[slot] = (p, symbol_index, string_data[name_offset:name_end].decode('ascii'))

    def offset(self, address, size):
        require(type(address) is int and type(size) is int and address >= 0 and size > 0 and address + size <= 1 << 64, 'invalid byte range')
        matches = [s for s in self.sections if s['type'] != 8 and s['flags'] & 2 and
                   s['address'] <= address and address + size <= s['address'] + s['size']]
        require(len(matches) == 1, 'byte range has no unique file-backed section')
        return matches[0]['offset'] + address - matches[0]['address']

    def read(self, address, size):
        off = self.offset(address, size)
        return self.blob[off:off + size]

    def exact(self, address, expected):
        require(self.read(address, len(expected)) == expected, f'encoding mismatch at {address:#x}')

    def s32(self, address):
        return struct.unpack('<i', self.read(address, 4))[0]

    def rel32(self, address, size):
        return address + size + self.s32(address + size - 4)

    def function(self, start):
        require(start in self.fdes, 'missing FDE')
        f = self.fdes[start]
        body = self.read(start, f['end'] - start)
        return {'start': hex(start), 'end': hex(f['end']), 'fde': hex(f['fde']),
                'file_offset': hex(self.offset(start, len(body))), 'size': len(body),
                'sha256': hashlib.sha256(body).hexdigest()}


# The bounded predicate decoder below adapts the repository MIT research tool
# aws_name_codec94.py (commit 01454ff2358ad2edb367ee52108bcc79dd046bab).
# Expressions are byte lanes. A lane is a frozenset of XOR terms; integer terms
# are XOR constants and ('input', offset) is an uninterpreted byte. OR is kept as
# a separate tuple of expressions, because OR==0 requires every child==0.
def constant(value, width):
    return tuple(frozenset([value >> (8 * i) & 255]) - {0} for i in range(width))


def numeric(value):
    require(isinstance(value, tuple) and all(isinstance(x, frozenset) for x in value), 'not a scalar constant')
    out = 0
    for i, terms in enumerate(value):
        require(all(type(t) is int for t in terms), 'arithmetic on symbolic input')
        byte = 0
        for term in terms:
            byte ^= term
        out |= byte << (8 * i)
    return out


def resize(value, width):
    require(isinstance(value, tuple) and all(isinstance(x, frozenset) for x in value), 'unsupported expression resize')
    return (value + constant(0, width))[:width]


def xor(a, b, width):
    return tuple(x ^ y for x, y in zip(resize(a, width), resize(b, width)))


def constraints(value, length):
    """Prove expression==0 is exactly one full-length string equality."""
    todo = list(value[1:]) if isinstance(value, list) and value[0] == 'or' else [value]
    result = {}
    while todo:
        v = todo.pop()
        if isinstance(v, list) and v[0] == 'or':
            todo.extend(v[1:])
            continue
        for terms in v:
            byte = 0
            variables = []
            for term in terms:
                if type(term) is int:
                    byte ^= term
                else:
                    require(term[0] == 'input', 'unknown symbolic variable')
                    variables.append(term[1])
            if not variables:
                require(byte == 0, 'unsatisfiable constant equality')
                continue
            require(len(variables) == 1, 'unsupported relation between input bytes')
            index = variables[0]
            require(0 <= index < length, 'comparison reads beyond length bucket')
            require(index not in result or result[index] == byte, 'inconsistent overlapping loads')
            result[index] = byte
    require(set(result) == set(range(length)), 'predicate does not constrain every input byte')
    return bytes(result[i] for i in range(length))


class Chain:
    """Recognize the finite instruction forms actually present in this one body.

    This is not an x86 emulator or a general disassembler. All memory operands
    must be input-relative, all arithmetic must be on constants, and every
    conditional success must terminate in a proven scalar return.
    """
    def __init__(self, im, end, length, start=PARSER, input_reg=7, mode='plain'):
        self.im, self.end, self.length = im, end, length
        self.start, self.input_reg, self.mode = start, input_reg, mode
        self.regs = {}
        self.flag = None
        self.flag_site = None
        self.rows = []
        self.instructions = {}
        self.reads = []

    def record(self, address, size, operation):
        require(self.start <= address < address + size <= self.end, 'instruction outside parser FDE')
        row = {'va': hex(address), 'bytes': self.im.read(address, size).hex(), 'operation': operation}
        require(address not in self.instructions or self.instructions[address] == row, 'conflicting instruction decode')
        self.instructions[address] = row

    def reg(self, r, width):
        require(r in self.regs, f'read of unknown register {r}')
        return resize(self.regs[r], width)

    def setreg(self, r, value, width):
        # For the admitted narrow writes, later predicates use only those lanes.
        self.regs[r] = value if width == 8 or isinstance(value, list) else resize(value, 8)

    def memory(self, displacement, width, site):
        require(0 <= displacement and displacement + width <= self.length, 'input load outside length bucket')
        self.reads.append({'site': hex(site), 'offset': displacement, 'width': width})
        return tuple(frozenset([('input', displacement + i)]) for i in range(width))

    def terminal(self, address):
        raw = self.im.read(address, 3)
        if self.mode == 'json' and address == 0x1774946:
            items=[(1,'push'),(7,'list-address'),(5,'list-count'),(3,'input-pointer'),(3,'input-length'),(3,'list-argument'),(3,'save-output'),(5,'call-error'),(3,'error-value'),(3,'output-pointer'),(4,'store-error'),(2,'error-tag'),(1,'pop'),(2,'store-tag'),(1,'ret')]
            p=address
            for size,desc in items:
                self.record(p,size,desc); p+=size
            self.im.exact(address,bytes.fromhex('534c8d059ac3c904b94f0000004889f74889d64c89c24889c3e86c3600004889c14889d848894b08b1015b8808c3'))
            return 0x4f
        if self.mode == 'json':
            full=self.im.read(address,9)
            if full[:3]==bytes.fromhex('c64001') and full[4:]==bytes.fromhex('31c98808c3'):
                self.record(address,4,'success-value-store'); self.record(address+4,2,'zero-result-tag'); self.record(address+6,2,'store-result-tag'); self.record(address+8,1,'ret'); return full[3]
        if address == 0x1775c3e and raw[0] == 0xc3:
            self.record(address, 1, 'return-initial-sentinel'); return 0x4f
        if raw[0] == 0xb0 and raw[2] == 0xc3:
            self.record(address, 2, 'return-byte'); self.record(address + 2, 1, 'ret')
            return raw[1]
        if raw == bytes.fromhex('31c0c3'):
            self.record(address, 2, 'return-zero'); self.record(address + 2, 1, 'ret')
            return 0
        raise ValueError(f'nonterminal branch target {address:#x}')

    def accept(self, site, target, failure, kind):
        require(self.flag is not None and self.flag_site is not None, 'unsupported zero-flag producer')
        text = constraints(self.flag, self.length)
        code = self.terminal(target) if type(target) is int else target[0]
        self.rows.append({'length': self.length, 'predicate_site': hex(site),
                          'zero_flag_site': hex(self.flag_site),
                          'success_va': hex(target) if type(target) is int else hex(site),
                          'unequal_successor': hex(failure) if failure is not None else None,
                          'result': code, 'text_hex': text.hex(), 'predicate': kind,
                          'text': text.decode('ascii')})

    def run(self, pc):
        seen = set()
        while True:
            require(pc not in seen, 'unexpected loop in comparison chain')
            seen.add(pc)
            raw = self.im.read(pc, min(16, self.end - pc))
            if (self.mode == 'json' and (pc == 0x1774946 or raw[:3] == bytes.fromhex('c64001'))) or pc == 0x1775c3e or raw[0] == 0xb0 or raw[:3] == bytes.fromhex('31c0c3'):
                failure = self.terminal(pc)
                return failure
            if raw[:2] in [b'\x0f\x84', b'\x0f\x85'] or raw[0] in [0x74, 0x75]:
                long = raw[0] == 0x0f
                size = 6 if long else 2
                eq = raw[1] == 0x84 if long else raw[0] == 0x74
                target = pc + size + (struct.unpack_from('<i', raw, 2)[0] if long else struct.unpack_from('<b', raw, 1)[0])
                self.record(pc, size, 'je' if eq else 'jne')
                if eq:
                    self.accept(pc, target, pc + size, 'exact equality')
                    pc += size
                    continue
                self.accept(pc, pc + size, target, 'exact equality')
                return self.terminal(target)
            p = 0; width = 4; rex = 0
            if 0x40 <= raw[0] <= 0x4f:
                rex=raw[0]; width = 8 if rex & 8 else 4; p += 1
            elif raw[0] == 0x66:
                width = 2; p += 1
            op = raw[p]; p += 1
            require(width != 2 or op in [0x81, 0x09], 'unsupported 16-bit instruction form')
            if 0xb8 <= op <= 0xbf:
                size = 8 if width == 8 else 4
                value = int.from_bytes(raw[p:p+size], 'little'); p += size
                self.setreg(op-0xb8+(8 if rex & 1 else 0), constant(value,width),width)
                self.record(pc,p,'mov-immediate'); pc += p; continue
            if op in [0x05,0x35]:
                v = int.from_bytes(raw[p:p+4],'little',signed=width==8); p += 4
                if op == 0x05:
                    self.setreg(0,constant((numeric(self.reg(0,width))+v) % (1 << (width*8)),width),width)
                else:
                    self.setreg(0,xor(self.reg(0,width),constant(v,width),width),width)
                self.flag = None
                self.record(pc,p,'add-constant' if op==0x05 else 'xor-immediate');pc+=p;continue
            load_width = width
            if op == 0x0f:
                op2 = raw[p]; p += 1
                require(op2 in [0xb6,0xb7], 'unsupported two-byte opcode')
                load_width = 1 if op2==0xb6 else 2
            require(op in [0x8b,0x31,0x33,0x39,0x81,0x83,0x09,0x8d,0x0f], f'unsupported opcode {op:#x} at {pc:#x}')
            modrm=raw[p];p+=1;mod=modrm>>6;reg=((modrm>>3)&7)+(8 if rex & 4 else 0);rm=(modrm&7)+(8 if rex & 1 else 0)
            disp=0
            require(rm != 4, 'SIB not supported in predicate chains')
            if mod == 1:
                disp=struct.unpack_from('<b',raw,p)[0];p+=1
            elif mod == 2:
                disp=struct.unpack_from('<i',raw,p)[0];p+=4
            require(mod != 0 or rm != 5, 'RIP-relative operand in predicate chain')
            if op == 0x8d:
                require(mod in [1,2], 'unexpected LEA form')
                value=numeric(self.reg(rm,width))+disp
                self.setreg(reg,constant(value%(1<<(width*8)),width),width)
                self.record(pc,p,'lea-constant');pc+=p;continue
            if op in [0x81,0x83]:
                size=1 if op==0x83 else 2 if width==2 else 4
                v=int.from_bytes(raw[p:p+size],'little',signed=(op==0x83 or width==8));p+=size
                if mod==3:
                    require(width != 2, 'unsupported partial-register arithmetic')
                    require(reg in [0,6], 'unsupported immediate register operation')
                    value=constant(v,width)
                    if reg==0:value=constant((numeric(self.reg(rm,width))+v)%(1<<(width*8)),width)
                    else:value=xor(self.reg(rm,width),value,width)
                    self.setreg(rm,value,width)
                    self.flag = None
                else:
                    require(reg==7 and rm==self.input_reg, 'unsupported immediate memory operation')
                    self.flag=xor(self.memory(disp,width,pc),constant(v,width),width)
                    self.flag_site=pc
                self.record(pc,p,'immediate-compare' if mod!=3 else 'constant-operation');pc+=p;continue
            if mod != 3:
                require(rm==self.input_reg, 'memory base is not input pointer')
                operand=self.memory(disp,load_width,pc)
            else:
                operand=self.reg(rm,width)
            if op in [0x8b,0x0f]:
                require(mod!=3, 'unexpected register MOV')
                self.setreg(reg,resize(operand,width),width)
            elif op==0x33:
                self.setreg(reg,xor(self.reg(reg,width),operand,width),width)
                self.flag=None
            elif op==0x31:
                require(mod==3, 'XOR would modify input')
                self.setreg(rm,xor(operand,self.reg(reg,width),width),width)
                self.flag=None
            elif op==0x39:
                self.flag=xor(operand,self.reg(reg,width),width)
                self.flag_site=pc
            elif op==0x09:
                require(mod==3, 'OR would modify input')
                self.flag=['or',operand,self.reg(reg,width)]
                self.flag_site=pc
                self.setreg(rm,self.flag,width)
            self.record(pc,p,{0x8b:'load',0x0f:'zero-extend-load',0x33:'xor-load',0x31:'xor-register',0x39:'compare',0x09:'or-zero-predicate'}[op]);pc+=p


def parser(im):
    f=im.fdes[PARSER]; end=f['end']
    im.exact(PARSER,bytes.fromhex('b04f4883c6fe4883fe0b0f87'))
    failure=im.rel32(PARSER+10,6)
    im.exact(PARSER+16,bytes.fromhex('488d0d'))
    table=im.rel32(PARSER+16,7)
    im.exact(PARSER+23,bytes.fromhex('486314b14801caffe2'))
    low=(-struct.unpack('<b',im.read(PARSER+5,1))[0])&255
    count=im.read(PARSER+9,1)[0]+1
    header=[(PARSER,2,'initial-failure-byte'),(PARSER+2,4,'length-minus-two'),(PARSER+6,4,'unsigned-length-bound'),
            (PARSER+10,6,'ja-failure'),(PARSER+16,7,'table-address'),
            (PARSER+23,4,'load-signed-relative-slot'),(PARSER+27,3,'add-table-base'),(PARSER+30,2,'jump-slot')]
    coverage={};rows=[];buckets=[];reads=[]
    invalid=Chain(im,end,0).terminal(failure)
    for i in range(count):
        entry=table+im.s32(table+4*i)
        require(PARSER<=entry<end,'length table target outside FDE')
        chain=Chain(im,end,i+low)
        status=chain.run(entry)
        require(status==invalid,'inconsistent rejection sentinel')
        for a,r in chain.instructions.items():
            require(a not in coverage or coverage[a]==r,'conflicting chain boundary')
            coverage[a]=r
        rows.extend(chain.rows);reads.extend(chain.reads)
        buckets.append({'length':i+low,'slot':hex(table+4*i),'entry':hex(entry),'accepted':len(chain.rows),'rejection':status})
    for a,size,label in header:
        coverage[a]={'va':hex(a),'bytes':im.read(a,size).hex(),'operation':label}
    rows.sort(key=lambda r:r['result'])
    require([r['result'] for r in rows]==list(range(invalid)),'success results do not partition values below sentinel')
    require(len({r['text_hex'] for r in rows})==len(rows),'shadowed duplicate recognition predicate')
    cursor=PARSER
    for a,r in sorted(coverage.items()):
        require(a==cursor,f'uncovered or overlapping parser instructions at {cursor:#x}, next {a:#x}')
        cursor+=len(bytes.fromhex(r['bytes']))
    require(cursor==end,'uncovered parser tail')
    return {'table':hex(table),'minimum_length':low,'maximum_length':low+count-1,
            'failure_va':hex(failure),'failure_value':invalid,'rows':rows,'buckets':buckets,
            'instructions':[r for _,r in sorted(coverage.items())],
            'reads':sorted({(r['site'],r['offset'],r['width']) for r in reads},key=lambda r:int(r[0],16))}

def json_parser(im):
    start=JSON_PARSER; end=im.fdes[start]['end']; mode='json'
    im.exact(start,bytes.fromhex('4889f8488d4afe4883f90b0f87'))
    failure=im.rel32(start+11,6)
    im.exact(start+17,bytes.fromhex('488d3d'))
    table=im.rel32(start+17,7)
    im.exact(start+24,bytes.fromhex('48630c8f4801f9ffe1'))
    low=(-struct.unpack('<b',im.read(start+6,1))[0])&255
    count=im.read(start+10,1)[0]+1
    header=[(start,3,'output-pointer'),(start+3,4,'length-minus-two'),(start+7,4,'unsigned-length-bound'),(start+11,6,'ja-failure'),(start+17,7,'table-address'),(start+24,4,'load-signed-relative-slot'),(start+28,3,'add-table-base'),(start+31,2,'jump-slot')]
    coverage={};rows=[];buckets=[]
    invalid=Chain(im,end,0,start,6,mode).terminal(failure)
    for i in range(count):
        entry=table+im.s32(table+4*i)
        require(start<=entry<end,'length table target outside FDE')
        chain=Chain(im,end,i+low,start,6,mode)
        status=chain.run(entry)
        require(status==invalid,'inconsistent rejection sentinel')
        for a,r in chain.instructions.items():
            require(a not in coverage or coverage[a]==r,'conflicting chain boundary')
            coverage[a]=r
        rows.extend(chain.rows);buckets.append({'length':i+low,'slot':hex(table+4*i),'entry':hex(entry),'accepted':len(chain.rows)})
    for a,size,label in header: coverage[a]={'va':hex(a),'bytes':im.read(a,size).hex(),'operation':label}
    rows.sort(key=lambda r:r['result'])
    require([r['result'] for r in rows]==list(range(invalid)),'missing or duplicate result')
    cursor=start
    for a,r in sorted(coverage.items()):
        require(a==cursor,f'json uncovered or overlapping instructions at {cursor:#x}, next {a:#x}')
        cursor+=len(bytes.fromhex(r['bytes']))
    require(cursor==end,'uncovered parser tail')
    return {'table':hex(table),'failure_va':hex(failure),'rows':rows,'buckets':buckets,'instructions':[r for _,r in sorted(coverage.items())]}

def renderer(im):
    f=im.fdes[RENDERER];end=f['end']
    count,remainder=divmod(end-RENDERER-22,21)
    require(count>0 and remainder==0,'renderer FDE does not contain complete leaves')
    im.exact(RENDERER,bytes.fromhex('4889f00fb60f488d15'))
    table=im.rel32(RENDERER+6,7)
    im.exact(RENDERER+13,bytes.fromhex('48630c8a4801d1ffe1'))
    rows=[];arms=[]
    for tag in range(count):
        slot=table+4*tag;arm=table+im.s32(slot)
        require(RENDERER+22<=arm and arm+21<=end,'renderer arm outside FDE')
        im.exact(arm,bytes.fromhex('488d35'));im.exact(arm+7,b'\xba')
        im.exact(arm+12,bytes.fromhex('4889c7ff25'))
        textva=im.rel32(arm,7);length=struct.unpack('<I',im.read(arm+8,4))[0]
        sink=im.rel32(arm+15,6)
        require(sink in im.relocations,'unresolved rendering sink relocation')
        relocation,target=im.relocations[sink]
        require(any(sec['type'] != 8 and sec['flags'] & 4 and
                    sec['address'] <= target < sec['address'] + sec['size']
                    for sec in im.sections), 'rendering sink outside executable sections')
        text=im.read(textva,length)
        rows.append({'tag':tag,'slot':hex(slot),'arm':hex(arm),'bytes':im.read(arm,21).hex(),
                     'text_va':hex(textva),'length':length,'text_hex':text.hex(),'text':text.decode('ascii'),
                     'tail_slot':hex(sink),'relocation_file_offset':hex(relocation),'tail_target':hex(target)})
        arms.append(arm)
    require(sorted(arms)==list(range(RENDERER+22,end,21)),'renderer leaves do not partition full FDE')
    require(len({r['tail_slot'] for r in rows})==1,'renderer leaves disagree on sink')
    return {'table':hex(table),'entry_bytes':im.read(RENDERER,22).hex(),'input_domain':'valid tags only; no range check in body','rows':rows}




# Restricted structural instruction reader adapted from the repository MIT
# research collector aws_json_envelope94.py (commit 2310f67dee7c52f45886472e17c3682072446fea).
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
                raise ValueError('truncated instruction')
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
            row['kind']='test'; row['reg']='rax'; row['width']=8 if op==0xa8 else width
            imm=1 if op==0xa8 else (2 if width==16 else 4)
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
            else:raise ValueError('unsupported two-byte opcode '+hex(op2)+' at '+hex(base+start))
        elif op in (0x00,0x01,0x02,0x03,0x08,0x09,0x0a,0x0b,0x20,0x21,0x22,0x28,0x29,0x2a,0x2b,0x30,0x31,0x32,0x33,0x38,0x39,0x3a,0x3b,0x23,0x85,0x84,0x88,0x89,0x8a,0x8b,0x8d,0x63):
            row['kind']={0x00:'add',0x01:'add',0x02:'add',0x03:'add',0x08:'or',0x09:'or',0x0a:'or',0x0b:'or',0x20:'and',0x21:'and',0x22:'and',0x23:'and',0x28:'sub',0x29:'sub',0x2a:'sub',0x2b:'sub',0x30:'xor',0x31:'xor',0x32:'xor',0x33:'xor',0x38:'cmp',0x39:'cmp',0x3a:'cmp',0x3b:'cmp',0x85:'test',0x84:'test',0x88:'mov_store',0x89:'mov_store',0x8a:'mov_load',0x8b:'mov_load',0x8d:'lea',0x63:'movsxd'}[op]
            modrm=True
            if op in (0x00,0x02,0x08,0x0a,0x20,0x22,0x28,0x2a,0x30,0x32,0x38,0x3a,0x84,0x88,0x8a):row['width']=8
        elif op in (0x80,0x81,0x83,0xc6,0xc7,0xf6,0xf7,0xff,0xfe,0xc0,0xc1,0xd0,0xd1,0xd2,0xd3,0x6b,0x69):
            modrm=True
            row['kind']='group'
            if op in (0x80,0xc6,0xf6,0xc0,0xd0,0xd2):row['width']=8
            if op in (0x80,0x83,0xc6,0xc0,0xc1,0x6b):imm=1
            elif op in (0x81,0xc7,0x69):imm=2 if width==16 else 4
            signed=op in (0x83,0x6b) or (width==64 and op in (0x81,0xc7,0x69))
        else:raise ValueError('unsupported opcode '+hex(op)+' at '+hex(base+start))
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
                if group:raise ValueError('invalid move group')
                row['kind']='mov_imm_store'
            elif op in (0xf6,0xf7):
                if group not in (0,2,3):raise ValueError('unsupported unary group')
                row['kind']={0:'test',2:'not',3:'neg'}[group]
                if group==0:
                    imm=1 if op==0xf6 else (2 if width==16 else 4)
                    signed=op==0xf7 and width==64
            elif op in (0xff,0xfe):
                if op==0xfe:row['width']=8
                if group not in ((0,1) if op==0xfe else (0,1,2,4)):raise ValueError('unsupported ff group')
                row['kind']={0:'inc',1:'dec',2:'call_indirect',4:'jump_indirect'}[group]
            elif op in (0xc0,0xc1,0xd0,0xd1,0xd2,0xd3):
                if group not in (4,5,7):raise ValueError('unsupported shift')
                row['kind']={4:'shl',5:'shr',7:'sar'}[group]
                if op in (0xd0,0xd1): row['count']=1
                elif op in (0xd2,0xd3): row['count']='cl'
            elif op in (0x6b,0x69):row['kind']='imul'
            if op in (0x80,0x81,0x83,0xc6,0xc7,0xf6,0xf7,0xff,0xfe,0xc0,0xc1,0xd0,0xd1,0xd2,0xd3):
                row['group']=group
                del row['reg']
        if imm:row['immediate']=int.from_bytes(take(imm),'little',signed=signed)
        row['size']=p-start
        if row['size']>15:raise ValueError('oversized instruction')
        row['bytes']=body[start:p].hex()
        if row.get('mem',{}).get('base')=='rip':row['memory_va']=base+p+row['mem']['disp']
        rows.append(row)
    starts={r['va'] for r in rows}
    for r in rows:
        if 'target' in r and base<=r['target']<base+len(body) and r['target'] not in starts:
            raise ValueError('branch targets instruction interior')
    return rows


# Each retained body is an independently selected unwind-described extent.
# These digests bind the reviewed instruction partitions; they are not function
# ownership or compiler-equivalence claims.
BODIES = (
    ('directory_create_helper', 0x5c8f4c0, 0x5c902df, '4b349f6d6a9c6f11868e4fdd24faf25aa2c056f75a0b5d5963ae1cf1aebaa7e2'),
    ('directory_metadata_helper', 0x5c9c810, 0x5c9ca28, '6ce20119c3543cdfeae06be3764719ec70f24c7d0ef15dc381c455f2c39f47cd'),
    ('file_read_loop', 0x5c75580, 0x5c75843, 'd51015d2b09fa18101a8dae94532a9d3984a95470688679b2f6ffa146633f3be'),
    ('file_open_helper', 0x5c97060, 0x5c97226, '6551052b49f6ff4e640e3f8b7aa79995e951bafc3517e6accbda0c200c59efee'),
    ('file_read_and_validate', 0x5ca4940, 0x5ca4d49, 'f69929f3441513d73ac7b86fba8a7a303ad434ca39c31eb3e2307ff180bac674'),
    ('name_path_adapter', 0x1772f80, 0x1772f94, '9a57bc927e04afc12cb361ff623314f1b1fd83a58a841ea2308de6e81a9884a2'),
    ('name_file_path', 0x1772fa0, 0x1773069, '7c497e6f15e4c2ee0590a024dfb63d523537baf1e36713cb01e784800f9376e6'),
    ('enum_envelope', 0x1773070, 0x1773fc4, '3ea72c0fc3741f921c0e08196b9bdcaf5f3d086c6d8c9f254f99bd34ab9c95f4'),
    ('name_file_reader', 0x1773fd0, 0x17740fe, '3bfcd3df6b901ea1b74b739105c22160b31622c5895dcf6627ea2687887bede5'),
    ('quoted_name_matcher', 0x1774100, 0x1774be1, '4cd254433c8dd8f0dd875627092a576ab7c5ddef35ed68236f2b7e53e9601efd'),
    ('name_renderer', 0x1774e60, 0x17754f1, '6eaae33a999399c0a2701a3ff73ff1675a0c2dc2b89545d5e8d4bc6addc48a98'),
    ('plain_name_matcher', 0x1775500, 0x1775dc6, '861cb1d5be13f5e90b4966562794dcca3cdc8d536ef55825c4b719989cc5359f'),
    ('config_parser_wrapper', 0x1775dd0, 0x1775ede, 'd2ceaf7114480ea94fc1c0bd12b470ebbfd44b55dc493d1d5a0d2a7c53e7a700'),
    ('quoted_name_reader', 0x1777080, 0x17771a3, '8ec6f1fa1a8a1b1cab7152db0c7cb981e0a814741d8f735005eda982e306cf6f'),
    ('config_struct_parser', 0x17771b0, 0x1777faf, 'd6c39509e09bad05a57a97a3e9f7b8f998ff3f9bf050195c12ae43dc8c03fe43'),
    ('owned_string_adapter', 0x1777fb0, 0x1777fc4, '06a26620f7331533fb79449547e1ff62fd7137a329a229d5460c777ca93f308c'),
    ('directory_selector', 0x17780c0, 0x1778265, '2b3e2a62a16e690dd8c4c53d2babefdfc26c6fc50c51c603a3e4ef6800691077'),
    ('directory_create_failure', 0x1778270, 0x17782d7, 'd9c2547275f100843351d20921a13d586f519707f2dacabd4688f73c012258bd'),
    ('home_value', 0x17782e0, 0x17783dd, '5a0d87828ee7b3113eda4b4f097b5066f76c6ff1b1aa1583bc54b4fa0627f83f'),
    ('config_file_reader', 0x17783e0, 0x177858d, '6f0589087ea82d69f8cac913f36689828a988183c23f3a705e748b1eaa1cb278'),
    ('slice_adapter', 0x1778590, 0x17785a3, '7a3d949ea45254675320e6ff191dc3f07f906784d54d18216a83b1be40833464'),
    ('config_initializer', 0x17785f0, 0x177876f, '1c04f9f946029ae870d6ab540bc152f32c46879db0027a061566da50d69dfceb'),
    ('name_trim_boundary', 0x1778840, 0x1778ad7, 'b5af75ae260769495dee130ef17e79e5a11f89c5be4ce121aa03ff4a81c140d9'),
)

# Selected landmarks supplement the complete decoded bodies and their full
# transfer list. These are instruction starts, not a whole-text xref scan.
# Format: descriptive key, site, exact bytes, expected direct/slot target, and
# expected RELATIVE addend for an indirect slot where the path needs it.
LANDMARKS = (
    ('initializer_home', 0x1778608, 'ff15da9dd604', 0x64e23e8, 0x17782e0),
    ('initializer_select', 0x1778621, 'ff15c99dd604', 0x64e23f0, 0x17780c0),
    ('initializer_stat', 0x1778636, 'ff15f482d604', 0x64e0930, 0x5c9c810),
    ('initializer_stat_error', 0x1778641, '0f849f000000', 0x17786e6, None),
    ('initializer_non_directory', 0x1778655, '0f8595000000', 0x17786f0, None),
    ('initializer_code_template', 0x177866c, '488d35bc57ccfe', 0x43de2f, None),
    ('initializer_config_reader', 0x1778698, 'ff157a9dd604', 0x64e2418, 0x17783e0),
    ('initializer_name_store', 0x17786ce, '41884648', None, None),
    ('select_cham_template', 0x17780f3, '488d356f2acdfe', 0x44ab69, None),
    ('select_first_stat_result', 0x177812d, '750c', 0x177813b, None),
    ('select_first_mode_mismatch', 0x1778149, '7510', 0x177815b, None),
    ('select_hl_template', 0x1778164, '488d35be5cccfe', 0x43de29, None),
    ('select_second_stat_result', 0x17781a7, '750c', 0x17781b5, None),
    ('select_second_mode_match', 0x17781c3, '7423', 0x17781e8, None),
    ('select_creation_mode', 0x17781c5, 'c7442428ff010000', None, None),
    ('select_recursive_flag', 0x17781cd, 'c644242c01', None, None),
    ('select_create_directory', 0x17781dd, 'ff155d87d604', 0x64e0940, 0x5c8f4c0),
    ('select_create_error', 0x17781e6, '7539', 0x1778221, None),
    ('select_failure_handler', 0x1778227, 'e844000000', 0x1778270, None),
    ('config_template', 0x177840e, '488d35da7dccfe', 0x4401ef, None),
    ('config_read_boundary', 0x177843c, 'ff157e85d604', 0x64e09c0, 0x5ca4940),
    ('config_read_success', 0x1778452, '712f', 0x1778483, None),
    ('config_read_error_default', 0x177845c, '40b521', None, None),
    ('config_parse', 0x17784ae, 'e81dd9ffff', 0x1775dd0, None),
    ('config_result_tag_test', 0x1778529, '4584ed', None, None),
    ('config_parse_error_default', 0x177852c, 'bd21000000', None, None),
    ('config_choose_parsed', 0x1778531, '0f44e8', None, None),
    ('wrapper_struct_parse', 0x1775e19, 'e892130000', 0x17771b0, None),
    ('wrapper_preserve_parse_error', 0x1775e21, '7557', 0x1775e7a, None),
    ('wrapper_whitespace_mask', 0x1775e3d, '48be0026000001000000', None, None),
    ('wrapper_trailing_above_space', 0x1775e59, '773f', 0x1775e9a, None),
    ('wrapper_trailing_not_whitespace', 0x1775e5f, '7339', 0x1775e9a, None),
    ('wrapper_trailing_error_code', 0x1775e9a, '48c744245816000000', None, None),
    ('wrapper_trailing_error_tag', 0x1775eb6, 'b001', None, None),
    ('struct_sequence_token', 0x177722c, '83ff5b', None, None),
    ('struct_sequence_branch', 0x177722f, '0f8450070000', 0x1777985, None),
    ('struct_map_token', 0x1777235, '83ff7b', None, None),
    ('struct_other_token', 0x1777238, '0f85fc0a0000', 0x1777d3a, None),
    ('struct_empty_field_marker', 0x1777277, 'c64424074f', None, None),
    ('struct_field_length', 0x1777357, '48837c241808', None, None),
    ('struct_field_name', 0x177735f, '48b86177735f6e616d65', None, None),
    ('struct_field_match', 0x177736d, '0f8445050000', 0x17778b8, None),
    ('struct_duplicate_guard', 0x17778b8, '807c24074f', None, None),
    ('struct_duplicate_route', 0x17778bd, '0f85a7050000', 0x1777e6a, None),
    ('struct_value_reader', 0x1777927, 'e844b7ffff', 0x1773070, None),
    ('sequence_empty_name_fallback', 0x1777a21, 'ff15d1a9d604', 0x64e23f8, 0x1773fd0),
    ('map_missing_name_guard', 0x1777a37, '3c4f', None, None),
    ('map_present_name', 0x1777a39, '7506', 0x1777a41, None),
    ('map_missing_name_fallback', 0x1777a3b, 'ff15b7a9d604', 0x64e23f8, 0x1773fd0),
    ('struct_result_value_store', 0x1777d21, '884301', None, None),
    ('struct_result_success_tag', 0x1777d24, '31c0', None, None),
    ('enum_quoted_reader', 0x17730ef, 'e88c3f0000', 0x1777080, None),
    ('enum_quoted_error_guard', 0x17730f8, '83f84f', None, None),
    ('enum_quoted_success_branch', 0x17730fb, '7578', 0x1773175, None),
    ('enum_quoted_dispatch', 0x1773177, '488d0daae7d0fe', 0x481928, None),
    ('enum_object_dispatch', 0x177319e, '488d0dbfe8d0fe', 0x481a64, None),
    ('enum_object_result_flag', 0x1773ebb, '4084ed', None, None),
    ('enum_error_store', 0x1773ec4, 'c60301', None, None),
    ('enum_closing_brace', 0x1773f1b, '4183f87d', None, None),
    ('enum_invalid_close', 0x1773f1f, '7552', 0x1773f73, None),
    ('enum_close_bounds_error', 0x1773f24, '7457', 0x1773f7d, None),
    ('enum_value_store', 0x1773f2a, '884301', None, None),
    ('enum_success_zero', 0x1773f2d, '31c0', None, None),
    ('enum_success_store', 0x1773f2f, '8803', None, None),
    ('quoted_reader_matcher', 0x1777149, 'e8b2cfffff', 0x1774100, None),
    ('fallback_name_path', 0x1773fde, 'ff15fce3d604', 0x64e23e0, 0x1772fa0),
    ('name_path_home', 0x1772faf, 'ff1533f4d604', 0x64e23e8, 0x17782e0),
    ('name_path_select', 0x1772fca, 'ff1520f4d604', 0x64e23f0, 0x17780c0),
    ('name_path_template', 0x1772fe1, '488d3575f0ccfe', 0x44205d, None),
    ('fallback_read', 0x1773ff6, 'ff15c4c9d604', 0x64e09c0, 0x5ca4940),
    ('fallback_read_error', 0x177401c, '7043', 0x1774061, None),
    ('fallback_trim', 0x177402b, 'e810480000', 0x1778840, None),
    ('fallback_plain_matcher', 0x1774036, 'ff15c4e3d604', 0x64e2400, 0x1775500),
    ('fallback_rejected_value', 0x177403c, '3c4f', None, None),
    ('fallback_rejected_route', 0x177403e, '7452', 0x1774092, None),
    ('fallback_read_unwrap', 0x177408a, 'ff1510b6d604', 0x64df6a0, None),
    ('fallback_name_unwrap', 0x17740b1, 'ff15e9b5d604', 0x64df6a0, None),
    ('fallback_unwrap_trap', 0x17740b7, '0f0b', None, None),
    ('quoted_error_list', 0x1774947, '4c8d059ac3c904', 0x6410ce8, None),
    ('quoted_error_list_count', 0x177494e, 'b94f000000', None, None),
    ('duplicate_field_literal', 0x1777e6a, '488d054711cefe', 0x458fb8, None),
    ('duplicate_field_length', 0x1777e76, '48c744243008000000', None, None),
    ('duplicate_field_template', 0x1777e95, '488d3d7eb6cbfe', 0x43351a, None),
    ('duplicate_field_error', 0x1777ea1, 'e82a0d0000', 0x1778bd0, None),
    ('non_directory_template', 0x1778701, '488d3d81d4ccfe', 0x445b89, None),
    ('non_directory_failure', 0x1778714, 'ff159e6fd604', 0x64df6b8, None),
    ('create_failure_template', 0x17782a1, '488d3d0572cdfe', 0x44f4ad, None),
    ('create_failure_call', 0x17782b4, 'ff15fe73d604', 0x64df6b8, None),
    ('create_helper_options_pointer', 0x5c8f4d7, '4989ff', None, None),
    ('create_helper_recursive_test', 0x5c8f4da, '807f0400', None, None),
    ('create_helper_single_route', 0x5c8f4de, '0f84ca060000', 0x5c8fbae, None),
    ('create_helper_save_options', 0x5c8f4ed, '4c897da0', None, None),
    ('create_helper_options_reload', 0x5c8f6d7, '488b45a0', None, None),
    ('create_helper_load_mode', 0x5c8f6db, '8b00', None, None),
    ('create_helper_save_mode', 0x5c8f6dd, '8945c4', None, None),
    ('create_first_mode', 0x5c8fa9f, '8b75c4', None, None),
    ('create_first_mkdir', 0x5c8faa2, 'ff15e8cb8500', 0x64ec690, None),
    ('create_first_mkdir_failed', 0x5c8faa8, '83f8ff', None, None),
    ('create_first_error_branch', 0x5c8faab, '7414', 0x5c8fac1, None),
    ('create_first_errno', 0x5c8fac1, 'ff1501058500', 0x64dffc8, None),
    ('create_second_mode', 0x5c8fcdc, '418b37', None, None),
    ('create_second_mkdir', 0x5c8fce6, 'ff15a4c98500', 0x64ec690, None),
    ('create_third_mode', 0x5c90126, '8b75c4', None, None),
    ('create_third_mkdir', 0x5c90129, 'ff1561c58500', 0x64ec690, None),
    ('stat64_slot', 0x5c9c99e, 'ff15d4ff8400', 0x64ec978, None),
    ('stat64_failed', 0x5c9c9a4, '83f8ff', None, None),
    ('stat64_error_branch', 0x5c9c9a7, '7459', 0x5c9ca02, None),
    ('read_open_helper', 0x5ca4a9b, 'e8c025ffff', 0x5c97060, None),
    ('read_open_error_tag', 0x5ca4aa0, '837dc001', None, None),
    ('read_open_error_branch', 0x5ca4aa4, '741a', 0x5ca4ac0, None),
    ('read_error_sentinel', 0x5ca4ac8, '48b80000000000000080', None, None),
    ('read_error_store', 0x5ca4ad2, '488903', None, None),
    ('read_fstat_slot', 0x5ca4b6f, 'ff1573648400', 0x64eafe8, None),
    ('read_loop_call', 0x5ca4c08, 'e87309fdff', 0x5c75580, None),
    ('read_validation_call', 0x5ca4c25, 'ff157db08300', 0x64dfca8, 0x16815e0),
    ('read_validation_success', 0x5ca4c33, '7418', 0x5ca4c4d, None),
    ('read_result_success', 0x5ca4c55, '7428', 0x5ca4c7f, None),
    ('read_result_sentinel', 0x5ca4c5f, '48b80000000000000080', None, None),
    ('read_result_error_store', 0x5ca4c69, '488903', None, None),
    ('read_close_slot', 0x5ca4c91, 'ff15e1b18300', 0x64dfe78, None),
    ('open64_slot', 0x5c97140, 'ff1582578500', 0x64ec8c8, None),
    ('open64_failed', 0x5c97146, '83f8ff', None, None),
    ('open64_success_branch', 0x5c97149, '7558', 0x5c971a3, None),
    ('open64_errno_slot', 0x5c9714f, 'ff15738e8400', 0x64dffc8, None),
    ('open64_interrupted_code', 0x5c97177, '83f904', None, None),
    ('open64_non_interrupted', 0x5c9717a, '0f85a0000000', 0x5c97220, None),
    ('open64_retry_indirect', 0x5c97194, '41ffd5', None, None),
    ('read_slot', 0x5c756c9, 'ff1541cc8600', 0x64e2310, None),
    ('read_failed', 0x5c756cf, '4883f8ff', None, None),
    ('read_success_branch', 0x5c756d3, '751b', 0x5c756f0, None),
    ('read_errno_slot', 0x5c756d5, 'ff15eda88600', 0x64dffc8, None),
    ('read_interrupted_code', 0x5c756de, '4883f904', None, None),
    ('read_interrupted_retry', 0x5c756e2, '74dc', 0x5c756c0, None),
    ('read_eof_test', 0x5c756fb, '4885c0', None, None),
    ('read_eof_branch', 0x5c756fe, '0f8415010000', 0x5c75819, None),
)



def exception_table(im, fde):
    """Decode selected LSDA call-site rows, retaining raw action indices."""
    address = fde['lsda']
    if address is None:
        return None
    sections_found = [s for s in im.sections if s['name'] == '.gcc_except_table'
                      and s['type'] != 8 and s['address'] <= address < s['address'] + s['size']]
    require(len(sections_found) == 1, 'LSDA lacks unique file-backed section')
    sec = sections_found[0]
    pos = im.offset(address, 2)
    origin, end = pos, sec['offset'] + sec['size']
    lp_encoding, type_encoding = im.blob[pos], im.blob[pos+1]
    pos += 2
    require(lp_encoding == 0xff and type_encoding in (0xff, 0x9b), 'unsupported LSDA header')
    type_base = None
    if type_encoding != 0xff:
        delta, pos = uleb(im.blob, pos, end)
        type_base = pos+delta
        require(type_base <= end, 'LSDA type table exceeds section')
    require(pos < end and im.blob[pos] == 1, 'unsupported call-site encoding')
    size, pos = uleb(im.blob, pos+1, end)
    stop = pos+size
    require(stop <= end and (type_base is None or stop <= type_base), 'LSDA sites exceed bounds')
    rows, previous_end = [], 0
    while pos < stop:
        begin = pos
        values = []
        for _ in range(4):
            value, pos = uleb(im.blob, pos, stop)
            values.append(value)
        start, length, landing, action = values
        require(length > 0 and start >= previous_end and start+length <= fde['end']-fde['start'],
                'invalid or overlapping LSDA site range')
        require(not landing or landing < fde['end']-fde['start'], 'LSDA landing outside FDE')
        previous_end = start+length
        rows.append({'start_va':hex(fde['start']+start), 'end_va':hex(fde['start']+start+length),
                     'landing_va':hex(fde['start']+landing) if landing else None,
                     'action_index':action, 'entry_file_offset':hex(begin),
                     'entry_bytes':im.blob[begin:pos].hex()})
    return {'function_va':hex(fde['start']), 'lsda_va':hex(address), 'file_offset':hex(origin),
            'lpstart_encoding':hex(lp_encoding), 'type_encoding':hex(type_encoding),
            'callsite_encoding':'0x1', 'header_and_site_bytes':im.blob[origin:stop].hex(), 'sites':rows}


def enum_dispatch(im, index, count):
    """Bind both envelope dispatch tables to the returned discriminant byte.

    For the object form, the zero-r14 route is conditional on the external
    value helper and the later closing-token check; it is not an execution test.
    """
    require(index[0x1773177]['bytes'] == '488d0daae7d0fe', 'quoted envelope dispatch changed')
    require(index[0x177319e]['bytes'] == '488d0dbfe8d0fe', 'object envelope dispatch changed')
    direct = index[0x1773177]['memory_va']
    obj = index[0x177319e]['memory_va']
    result = []
    for tag in range(count):
        direct_slot, obj_slot = direct+tag*4, obj+tag*4
        a = direct + im.s32(direct_slot)
        b = obj + im.s32(obj_slot)
        require(a in index and b in index, 'envelope table target is not an instruction start')
        store = index[a]
        require(store['bytes'] == (bytes.fromhex('c64301')+bytes([tag])).hex(), 'quoted envelope tag store changed')
        jump = index.get(a+store['size'])
        require(jump is not None and jump['kind'] == 'jump' and jump['target'] == 0x1773f2d,
                'quoted envelope success destination changed')

        require(index[b]['bytes'] == '4d85f6' and index.get(b+3, {}).get('bytes') == '4c89ef',
                'object envelope guard changed')
        branch = index.get(b+6)
        require(branch is not None and branch['kind'] in ('jne','je'), 'object envelope branch changed')
        if branch['kind'] == 'jne':
            require(branch['target'] == 0x1773ea0, 'object error target changed')
            success = b+6+branch['size']
        else:
            require(branch['target'] == 0x1773f43 and b+6+branch['size'] == 0x1773ea0,
                    'special object guard changed')
            success = branch['target']
        require(success in index, 'object success is not an instruction start')
        if tag == 0:
            expected = bytes.fromhex('41b40131c031ed')
        elif tag == 1:
            expected = bytes.fromhex('b00131ed41b401')
        else:
            expected = bytes.fromhex('41b401b0')+bytes([tag])+bytes.fromhex('31ed')
        im.exact(success, expected)
        cmp_addr = success+len(expected)
        require(index[cmp_addr]['bytes'] == '807f4800', 'object depth test changed')
        conditional = index[cmp_addr+4]
        require(conditional['kind'] == 'je' and conditional['target'] == 0x1773ea9,
                'object depth branch changed')
        after = index[cmp_addr+4+conditional['size']]
        require(after['kind'] == 'jump' and after['target'] == 0x1773ebb,
                'object return join changed')
        result.append({'tag':tag, 'quoted_slot_va':hex(direct_slot), 'quoted_arm_va':hex(a),
                       'object_slot_va':hex(obj_slot), 'object_arm_va':hex(b),
                       'object_success_va':hex(success), 'object_success_bytes':expected.hex()})
    require(len({x['quoted_arm_va'] for x in result}) == count, 'duplicate quoted envelope arm')
    require(len({x['object_arm_va'] for x in result}) == count, 'duplicate object envelope arm')
    im.exact(0x1773f2a, bytes.fromhex('88430131c08803'))
    return result


def read_only_open_case(index):
    """Prove the selected short, NUL-free path's fixed open options."""
    sites = (
        (0x5ca495a,'48b800000000b6010000'),(0x5ca4964,'488945b0'),
        (0x5ca4968,'c745b800000000'),(0x5ca496f,'66c745bc0000'),(0x5ca4975,'c645b801'),
        (0x5ca4981,'4881fa7f010000'),(0x5ca4988,'0f874c010000'),
        (0x5ca4a87,'4c39f2'),(0x5ca4a8a,'751c'),(0x5ca4a97,'488d55b0'),
        (0x5ca4a9b,'e8c025ffff'),(0x5c97077,'0fb64a09'),(0x5c9707b,'0fb6420a'),
        (0x5c9707f,'807a0800'),(0x5c97083,'7415'),(0x5c97085,'84c9'),
        (0x5c97087,'7431'),(0x5c970ba,'84c0'),(0x5c970bc,'0f84e6000000'),
        (0x5c971a8,'807a0b00'),(0x5c971ac,'753f'),(0x5c971ae,'807a0c00'),
        (0x5c971b2,'7539'),(0x5c971b4,'4531ff'),(0x5c971b7,'807a0d00'),
        (0x5c971bb,'b900000000'),(0x5c971c0,'b800000000'),(0x5c971c5,'0f8427ffffff'),
        (0x5c970f2,'807a0c00'),(0x5c970f6,'7410'),(0x5c97108,'f6c101'),
        (0x5c9710b,'7407'),(0x5c97114,'0fb6c0'),(0x5c97117,'c1e009'),
        (0x5c9711a,'b9fcfff7ff'),(0x5c9711f,'230a'),(0x5c97121,'4109cf'),
        (0x5c97124,'4109c7'),(0x5c97127,'4181cf00000800'),(0x5c9712e,'448b6204'),
        (0x5c97138,'4489fe'),(0x5c9713b,'4489e2'),(0x5c97140,'ff1582578500'),
    )
    for va, expected in sites:
        require(va in index and index[va]['bytes'] == expected, 'open-option instruction changed')
    options = bytearray(14)
    options[:8] = index[0x5ca495a]['immediate'].to_bytes(8, 'little')
    options[8:12] = index[0x5ca4968]['immediate'].to_bytes(4, 'little')
    options[12:14] = index[0x5ca496f]['immediate'].to_bytes(2, 'little')
    options[8] = index[0x5ca4975]['immediate']
    require(options[8:] == bytes.fromhex('010000000000'), 'open-option branch premises changed')
    supplied_flags = int.from_bytes(options[:4], 'little')
    require(supplied_flags == 0, 'open-option input flags changed')
    mode = int.from_bytes(options[4:8], 'little')
    mask = index[0x5c9711a]['immediate']
    additional = index[0x5c97127]['immediate']
    flags = (supplied_flags & mask) | additional
    return {'conditions':'path byte length at most bound, no interior NUL, normal helper returns',
            'short_path_max_bytes':index[0x5ca4981]['immediate'],
            'option_bytes':bytes(options).hex(), 'access_flag_masked_value':flags & 3,
            'open64_flags':hex(flags), 'open64_mode_argument':hex(mode),
            'steps':[{'site_va':hex(va), 'bytes':index[va]['bytes'], 'kind':index[va]['kind'],
                      **({'target_va':hex(index[va]['target'])} if 'target' in index[va] else {})}
                     for va, _ in sites]}

def collect(im):
    body_records, instructions, index = [], {}, {}
    for role, start, end, digest in BODIES:
        require(start in im.fdes and im.fdes[start]['end'] == end, 'selected FDE extent changed')
        require(start in im.index_entries and im.index_entries[start]['fde'] == im.fdes[start]['fde'],
                'selected unwind index and FDE disagree')
        body = im.read(start, end-start)
        require(hashlib.sha256(body).hexdigest() == digest, 'selected FDE body changed')
        row = im.function(start)
        row['role'] = role
        row['unwind_index'] = im.index_entries[start]['index']
        row['lsda'] = hex(im.fdes[start]['lsda']) if im.fdes[start]['lsda'] is not None else None
        decoded = decode(body, start)
        row['instruction_count'] = len(decoded)
        body_records.append(row)
        instructions[role] = decoded
        for ins in decoded:
            require(ins['va'] not in index, 'overlapping selected instruction bodies')
            index[ins['va']] = ins

    exceptions = []
    for _, start, _, _ in BODIES:
        table = exception_table(im, im.fdes[start])
        if table is not None:
            for site in table['sites']:
                landing = site['landing_va']
                require(landing is None or int(landing, 16) in index, 'landing pad is not a decoded instruction start')
            exceptions.append(table)

    open_case = read_only_open_case(index)

    landmarks = []
    for name, va, expected, target, addend in LANDMARKS:
        require(va in index, 'landmark is not a decoded instruction start')
        ins = index[va]
        require(ins['bytes'] == expected, 'landmark bytes changed')
        resolved = ins.get('target', ins.get('memory_va'))
        if target is not None:
            require(resolved == target, 'landmark target changed')
        record = {'name': name, 'site_va': hex(va), 'file_offset': hex(im.offset(va, ins['size'])),
                  'bytes': ins['bytes'], 'kind': ins['kind']}
        if resolved is not None:
            record['target_or_slot_va'] = hex(resolved)
        if ins['kind'] in ('call_indirect', 'jump_indirect') and resolved in im.relocations:
            rel_offset, actual = im.relocations[resolved]
            record['relative_relocation_file_offset'] = hex(rel_offset)
            record['relative_addend_va'] = hex(actual)
            if addend is not None:
                require(actual == addend, 'RELATIVE addend changed')
        else:
            require(addend is None, 'missing expected RELATIVE relocation')
        if resolved in im.symbols:
            rel_offset, symbol_index, symbol_name = im.symbols[resolved]
            record['glob_dat_file_offset'] = hex(rel_offset)
            record['dynamic_symbol_index'] = symbol_index
            record['dynamic_symbol'] = symbol_name
        if 'immediate' in ins:
            record['immediate'] = ins['immediate']
        landmarks.append(record)

    for slot, name in ((0x64ec8c8,'open64'), (0x64e2310,'read'),
                       (0x64dffc8,'__errno_location'), (0x64eafe8,'fstat64'), (0x64dfe78,'close'),
                       (0x64ec690,'mkdir'), (0x64ec978,'stat64')):
        require(slot in im.symbols and im.symbols[slot][2] == name, 'dynamic symbol binding changed')

    entries = []
    entry_sites = [('cham', 0x17780f3, b'/cham'), ('hl', 0x1778164, b'/hl'),
                   ('code', 0x177866c, b'/code'), ('static_config', 0x177840e, b'/static_config'),
                   ('aws_name', 0x1772fe1, b'/aws_name')]
    for name, site, expected in entry_sites:
        ins = index[site]
        target = ins['memory_va']
        header = im.read(target, 2)
        require(header[0] == 0xc0, 'unexpected template prefix')
        literal = im.read(target+2, header[1])
        terminal = im.read(target+2+header[1], 1)
        require(literal == expected and terminal == b'\x00', 'template entry changed')
        entries.append({'name': name, 'reference_va': hex(site), 'entry_va': hex(target),
                        'entry_file_offset': hex(im.offset(target, len(literal)+3)),
                        'literal_va': hex(target+2), 'length': len(literal),
                        'entry_bytes': (header+literal+terminal).hex(), 'literal': literal.decode('ascii')})

    diagnostic_specs = (
        ('duplicate_field', index[0x1777e95]['memory_va'], b'\x11duplicate field `\xc0\x01`\x00'),
        ('field_name', index[0x1777e6a]['memory_va'], b'aws_name'),
        ('missing_directory', index[0x1778701]['memory_va'], b'\x19cham_dir does not exist: \xc0\x00'),
        ('create_directory', index[0x17782a1]['memory_va'], b'\x11could not create \xc0\x02: \xc0\x00'),
        ('unwrap_failure', index[0x177406b]['memory_va'], b'called `Result::unwrap()` on an `Err` value'),
    )
    diagnostics = []
    for name, va, expected in diagnostic_specs:
        actual = im.read(va, len(expected))
        require(actual == expected, 'diagnostic bytes changed')
        diagnostics.append({'name':name, 'data_va':hex(va), 'file_offset':hex(im.offset(va, len(actual))),
                            'length':len(actual), 'bytes':actual.hex()})

    plain, quoted, render = parser(im), json_parser(im), renderer(im)
    # A second, independent structural decoder must partition both matchers at
    # the same instruction starts. This does not invoke a disassembler.
    for symbolic, role in ((plain, 'plain_name_matcher'), (quoted, 'quoted_name_matcher')):
        a = [(int(x['va'], 16), x['bytes']) for x in symbolic['instructions']]
        b = [(x['va'], x['bytes']) for x in instructions[role]]
        require(a == b, 'independent instruction partitions disagree')
    require(len(plain['rows']) == len(quoted['rows']) == len(render['rows']), 'name count mismatch')
    envelope = enum_dispatch(im, index, len(render['rows']))

    # The JSON error path references this pointer/length list. It is read from
    # #115 RELATIVE records, then compared with both code-derived matchers and
    # the independently decoded renderer; no reference source is an input.
    pool_base = index[0x1774947]['memory_va']
    pool_count = index[0x177494e]['immediate']
    require(pool_count == len(render['rows']), 'JSON error list count mismatch')
    names = []
    for p, q, r, e in zip(plain['rows'], quoted['rows'], render['rows'], envelope):
        tag = p['result']
        require(tag == q['result'] == r['tag'] and p['text_hex'] == q['text_hex'] == r['text_hex'],
                'plain, quoted and rendering paths disagree')
        slot = pool_base + 16*tag
        require(slot in im.relocations, 'missing name list relocation')
        reloc_offset, ptr = im.relocations[slot]
        n = struct.unpack('<Q', im.read(slot+8, 8))[0]
        require(n == p['length'] and im.read(ptr, n).hex() == p['text_hex'], 'name list disagrees')
        names.append({'tag':tag, 'name':p['text'], 'length':n,
                      'plain_predicate_va':p['predicate_site'], 'plain_success_va':p['success_va'],
                      'quoted_predicate_va':q['predicate_site'], 'quoted_success_va':q['success_va'],
                      'renderer_arm_va':r['arm'], 'renderer_text_va':r['text_va'],
                      'list_slot_va':hex(slot), 'list_pointer_va':hex(ptr),
                      'list_relocation_file_offset':hex(reloc_offset),
                      'quoted_envelope_arm_va':e['quoted_arm_va'],
                      'object_envelope_arm_va':e['object_arm_va'],
                      'object_envelope_success_va':e['object_success_va']})

    transfers = []
    for role, rows in instructions.items():
        for ins in rows:
            kind = ins['kind']
            if 'target' not in ins and kind not in ('call_indirect', 'jump_indirect', 'ret', 'trap'):
                continue
            item = {'body':role, 'site_va':hex(ins['va']), 'bytes':ins['bytes'], 'kind':kind}
            if 'target' in ins:
                item['target_va'] = hex(ins['target'])
            if 'memory_va' in ins:
                slot = ins['memory_va']
                item['slot_va'] = hex(slot)
                if slot in im.relocations:
                    item['relative_addend_va'] = hex(im.relocations[slot][1])
                if slot in im.symbols:
                    item['dynamic_symbol'] = im.symbols[slot][2]
            transfers.append(item)

    # The rejection return uses the initial AL value. The only other writes to
    # RAX in this body are terminal success leaves immediately followed by RET.
    plain_index = {r['va']:r for r in instructions['plain_name_matcher']}
    for ins in plain_index.values():
        if ins['va'] != PARSER and ('rax' in (ins.get('reg'), ins.get('rm')) or
                                    ins.get('mem', {}).get('base') == 'rax'):
            successor = plain_index.get(ins['va'] + ins['size'])
            require((ins['bytes'].startswith('b0') or ins['bytes'] == '31c0') and
                    successor is not None and successor['kind'] == 'ret',
                    'plain rejection AL can be overwritten before return')

    mask = index[0x1775e3d]['immediate']
    whitespace_limit = index[0x1775e55]['immediate']
    whitespace = [n for n in range(whitespace_limit+1) if mask & (1 << n)]
    default_1 = index[0x177845c]['immediate']
    default_2 = index[0x177852c]['immediate']
    require(default_1 == default_2 and names[default_1]['name'] == 'NvTestnet', 'default and renderer disagree')
    require(whitespace == [9, 10, 13, 32], 'unexpected trailing whitespace mask')
    metrics = {'selected_fde_bodies':len(body_records), 'lsda_tables':len(exceptions),
               'lsda_callsite_ranges':sum(len(x['sites']) for x in exceptions),
               'selected_body_bytes':sum(x['size'] for x in body_records),
               'structurally_decoded_instructions':sum(len(x) for x in instructions.values()),
               'decoded_transfers':len(transfers), 'selected_landmarks':len(landmarks),
               'complete_template_entries':len(entries), 'plain_matcher_bytes':im.fdes[PARSER]['end']-PARSER,
               'quoted_matcher_bytes':im.fdes[JSON_PARSER]['end']-JSON_PARSER,
               'renderer_bytes':im.fdes[RENDERER]['end']-RENDERER,
               'length_buckets':len(plain['buckets']), 'name_paths_agree':len(names),
               'envelope_paths_agree':len(envelope),
               'plain_rejection_value':plain['failure_value'], 'config_default_tag':default_1,
               'renderer_and_error_list_same_pointer':sum(int(n['renderer_text_va'], 16) == int(n['list_pointer_va'], 16) for n in names)}
    return {'target':'node #115', 'sha256':DIGEST,
            'coordinate_system':'linked ELF virtual addresses; offsets are file offsets',
            'functions':body_records, 'templates':entries, 'diagnostics':diagnostics, 'landmarks':landmarks,
            'names':names, 'plain':plain, 'quoted':quoted, 'renderer':render, 'envelope':envelope,
            'instructions':instructions, 'transfers':transfers, 'exceptions':exceptions, 'open_case':open_case,
            'trailing_whitespace_bytes':whitespace, 'metrics':metrics}


def write_outputs(record, out):
    out.mkdir(parents=True, exist_ok=True)
    for name, obj in (
        ('summary.json', {k:record[k] for k in ('target','sha256','coordinate_system','metrics','functions','templates','diagnostics','landmarks','trailing_whitespace_bytes')}),
        ('codec.json', {k:record[k] for k in ('plain','quoted','renderer')}),
        ('instructions.json', record['instructions']),
        ('transfers.json', record['transfers']),
        ('exceptions.json', record['exceptions']),
        ('name-paths.json', record['names']),
        ('envelope-paths.json', record['envelope']),
        ('open-case.json', record['open_case']),
    ):
        (out/name).write_text(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True)+'\n',
                              encoding='utf-8', newline='\n')


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--out', type=Path, required=True)
    args = ap.parse_args()
    blob = (ROOT/'artifacts/node/115/hl-node').read_bytes()
    image = Image(blob)
    record = collect(image)
    write_outputs(record, args.out)
    print(json.dumps(record['metrics'], sort_keys=True))


if __name__ == '__main__':
    main()
