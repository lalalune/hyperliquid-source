#!/usr/bin/env python3
"""Static bitvector expressions for two digest-admitted #115 scalar readers.

No target/emulator/native code execution. Abstract disjoint input, output,
optional overflow destination and stack; only decoded instructions below.
"""
import argparse
import bisect
import hashlib
import io
import json
from pathlib import Path
import platform
import struct

import capstone as cs
from capstone.x86 import X86_OP_REG, X86_OP_IMM, X86_OP_MEM
import elftools
from elftools.elf.elffile import ELFFile
from elftools.dwarf.callframe import FDE
import z3 as z

ROOT = Path(__file__).resolve().parents[3]
TARGET = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ENTRIES = (0x6321680, 0x6330f50)
LENGTH = 285
BODY_SHA = '5bfa12c91507b12120e2bab824f10448a08e0ec6b88ad40d60c4e4e10f6da9d2'
ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141


def require(ok, why):
    if not ok:
        raise ValueError(why)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def bv(n, width=64):
    return z.BitVecVal(n, width)


ALIASES = {}
for full, dword, byte in [('rax','eax','al'), ('rbx','ebx','bl'), ('rcx','ecx','cl'),
                          ('rdx','edx','dl'), ('rsi','esi','sil'), ('rdi','edi','dil'),
                          ('rbp','ebp','bpl'), ('rsp','esp','spl')]:
    for name, width in [(full,64),(dword,32),(byte,8)]:
        ALIASES[name] = full, width
for i in range(8,16):
    for suffix,width in [('',64),('d',32),('b',8)]:
        ALIASES[f'r{i}{suffix}'] = f'r{i}',width


class Expressions:
    """Finite transfer functions, not a CPU emulator. Pointers are tuples."""
    def __init__(self, words, with_overflow):
        self.regs = {name:z.BitVec('initial_'+name,64) for name,width in ALIASES.values() if width==64}
        self.initial = dict(self.regs)
        self.regs.update(rdi=('output',0), rsi=('input',0),
                         rdx=('overflow',0) if with_overflow else bv(0), rsp=('stack',0))
        self.mem = {('input',8*i):w for i,w in enumerate(words)}
        self.loads, self.stores, self.branches = [], [], []
        self.stack_accesses = []
        self.cf = self.zf = None
        self.with_overflow = with_overflow

    def reg(self, name):
        full,width = ALIASES[name]
        value = self.regs[full]
        require(not isinstance(value,tuple) or width==64,'partial pointer read')
        return value if width==64 else z.Extract(width-1,0,value)

    def putreg(self,name,value):
        full,width = ALIASES[name]
        if isinstance(value,tuple):
            require(width==64,'partial pointer store')
        else:
            require(value.size()==width,'register width')
            if width==32:
                value = z.ZeroExt(32,value)
            elif width==8:
                require(not isinstance(self.regs[full],tuple),'partial pointer write')
                value = z.Concat(z.Extract(63,8,self.regs[full]),value)
            value = z.simplify(value)
        self.regs[full] = value

    def address(self,ins,op):
        m = op.mem
        require(not m.segment,'segment outside model')
        value = self.reg(ins.reg_name(m.base)) if m.base else bv(0)
        if m.index:
            index = self.reg(ins.reg_name(m.index))
            require(not isinstance(value,tuple) and not isinstance(index,tuple),'indexed pointer')
            value = value + index*m.scale
        return (value[0],value[1]+m.disp) if isinstance(value,tuple) else value+m.disp

    def read(self,ins,op,width=None):
        if op.type==X86_OP_REG:
            return self.reg(ins.reg_name(op.reg))
        if op.type==X86_OP_IMM:
            return bv(op.imm,width or op.size*8)
        require(op.type==X86_OP_MEM,'operand kind')
        address = self.address(ins,op)
        require(isinstance(address,tuple) and address in self.mem,'uninitialized read')
        self.loads.append([ins.address,*address,op.size])
        value = self.mem[address]
        require(not isinstance(value,tuple) and value.size()==op.size*8,'load width')
        return value

    def write(self,ins,op,value):
        if op.type==X86_OP_REG:
            self.putreg(ins.reg_name(op.reg),value)
        else:
            require(op.type==X86_OP_MEM,'destination kind')
            address = self.address(ins,op)
            require(isinstance(address,tuple) and address[0] in ('output','overflow'),'write region')
            require(value.size()==op.size*8,'store width')
            self.mem[address] = value
            self.stores.append([ins.address,*address,op.size])

    def run(self,instructions):
        skip = None
        for ins in instructions:
            if skip is not None and ins.address < skip:
                continue
            op,m = ins.operands,ins.mnemonic
            if m=='ret':
                require(ins is instructions[-1],'early return')
                return
            if m=='push':
                p = self.regs['rsp']
                self.regs['rsp'] = (p[0],p[1]-8)
                self.mem[self.regs['rsp']] = self.read(ins,op[0])
                self.stack_accesses.append([ins.address,'write',self.regs['rsp'][1],8])
            elif m=='pop':
                p = self.regs['rsp']
                self.write(ins,op[0],self.mem[p])
                self.stack_accesses.append([ins.address,'read',p[1],8])
                self.regs['rsp'] = (p[0],p[1]+8)
            elif m in ('mov','movabs','movzx','movsxd'):
                value = self.read(ins,op[1])
                if m in ('movzx','movsxd'):
                    value = (z.ZeroExt if m=='movzx' else z.SignExt)(op[0].size*8-value.size(),value)
                self.write(ins,op[0],value)
            elif m=='bswap':
                a = self.read(ins,op[0])
                self.write(ins,op[0],z.Concat(*[z.Extract(i+7,i,a) for i in range(0,64,8)]))
            elif m=='lea':
                self.write(ins,op[0],self.address(ins,op[1]))
            elif m.startswith('set'):
                flag = {'sete':self.zf,'setne':z.Not(self.zf) if self.zf is not None else None,
                        'setb':self.cf,'setbe':z.Or(self.cf,self.zf) if self.cf is not None else None,
                        'setae':z.Not(self.cf) if self.cf is not None else None}.get(m)
                require(flag is not None,'unsupported/undefined SETcc')
                self.write(ins,op[0],z.If(flag,bv(1,8),bv(0,8)))
            elif m=='test' and isinstance(self.read(ins,op[0]),tuple):
                require(op[0].type==op[1].type==X86_OP_REG and op[0].reg==op[1].reg,'pointer test')
                self.zf,self.cf = z.BoolVal(False),z.BoolVal(False)
            elif m=='je':
                require(self.zf is not None,'undefined branch')
                flag = z.simplify(self.zf)
                require(z.is_true(flag) or z.is_false(flag),'symbolic control flow outside model')
                require(op[0].imm==instructions[-3].address,'optional overflow branch target')
                self.branches.append([ins.address,op[0].imm,z.is_true(flag)])
                if z.is_true(flag):
                    skip = op[0].imm
            elif m in ('cmp','test','add','adc','and','or','xor','not','neg','sar'):
                a = self.read(ins,op[0])
                require(not isinstance(a,tuple),'integer operation on pointer')
                b = self.read(ins,op[1],a.size()) if len(op)>1 else None
                if m in ('cmp','add','adc'):
                    if m=='cmp':
                        value = a-b
                        self.cf = z.ULT(a,b)
                    else:
                        carry = z.If(self.cf,bv(1,a.size()+1),bv(0,a.size()+1)) if m=='adc' else bv(0,a.size()+1)
                        wide = z.ZeroExt(1,a)+z.ZeroExt(1,b)+carry
                        value = z.Extract(a.size()-1,0,wide)
                        self.cf = z.Extract(a.size(),a.size(),wide)==1
                    self.zf = value==0
                elif m=='not':
                    value = ~a  # NOT preserves flags.
                elif m=='neg':
                    value = -a
                    self.cf,self.zf = a!=0,value==0
                elif m=='sar':
                    value = a >> (b & (63 if a.size()==64 else 31))
                    self.cf,self.zf = None,value==0  # CF is dead before any later consumer.
                else:
                    value = {'and':lambda:a&b,'test':lambda:a&b,'or':lambda:a|b,'xor':lambda:a^b}[m]()
                    self.cf,self.zf = z.BoolVal(False),value==0
                if m not in ('cmp','test'):
                    self.write(ins,op[0],value)
            else:
                raise ValueError(f'unsupported {ins.address:x}: {m}')
        raise ValueError('missing terminal return')


def query(name,condition,want='unsat'):
    solver = z.Solver()
    solver.set(timeout=60000)
    solver.add(condition)
    result = str(solver.check())
    require(result==want,f'{name}: expected {want}, got {result}')
    print(f'{name}: {result}',flush=True)
    record = {'name':name,'result':result,'timeout_ms':60000}
    if result=='sat':
        model = solver.model()
        record['model'] = {d.name():str(model[d]) for d in model.decls()}
    return record


def admit(data):
    require(len(data)==105896032 and sha(data)==TARGET,'target size/digest')
    elf = ELFFile(io.BytesIO(data))
    require(elf.elfclass==64 and elf.little_endian and elf['e_machine']=='EM_X86_64','ELF identity')
    frames = [f for f in elf.get_dwarf_info().EH_CFI_entries() if isinstance(f,FDE)]
    decoder = cs.Cs(cs.CS_ARCH_X86,cs.CS_MODE_64)
    decoder.detail = True
    records,decoded = [],{}
    for entry in ENTRIES:
        sec = [s for s in elf.iter_sections() if s['sh_flags']&4 and s['sh_addr']<=entry and entry+LENGTH<=s['sh_addr']+s['sh_size']]
        require(len(sec)==1,'executable section')
        s = sec[0]
        offset = s['sh_offset']+entry-s['sh_addr']
        body = data[offset:offset+LENGTH]
        require(sha(body)==BODY_SHA,'body digest')
        fs = [f for f in frames if f['initial_location']==entry]
        require(len(fs)==1 and fs[0]['address_range']==LENGTH,'unique complete FDE')
        segments = [p for p in elf.iter_segments() if p['p_type']=='PT_LOAD' and p['p_flags']&1 and p['p_vaddr']<=entry and entry+LENGTH<=p['p_vaddr']+p['p_filesz']]
        require(len(segments)==1 and segments[0]['p_offset']+entry-segments[0]['p_vaddr']==offset,'PT_LOAD mapping')
        ins = list(decoder.disasm(body,entry))
        require(sum(i.size for i in ins)==LENGTH and ins[-1].mnemonic=='ret','complete decode/return')
        require(not any(i.mnemonic.startswith('call') for i in ins),'unexpected helper call')
        next_start = min(f['initial_location'] for f in frames if f['initial_location']>=entry+LENGTH)
        gap = data[offset+LENGTH:offset+next_start-entry]
        require(gap==b'\xcc'*len(gap),'INT3 gap')
        relocs = [hex(r['r_offset']) for section in elf.iter_sections() if section['sh_type'] in ('SHT_RELA','SHT_REL') for r in section.iter_relocations() if entry<=r['r_offset']<entry+LENGTH]
        require(not relocs,'unexpected body relocation')
        frame_data = elf.get_section_by_name('.eh_frame').data()
        f = fs[0]
        records.append({'entry':hex(entry),'end':hex(entry+LENGTH),'file_offset':hex(offset),'length':LENGTH,'sha256':sha(body),'bytes':body.hex(),
                        'fde_offset':hex(f.offset),'fde_bytes':frame_data[f.offset:f.offset+f['length']+4].hex(),
                        'cie_offset':hex(f.cie.offset),'cie_bytes':frame_data[f.cie.offset:f.cie.offset+f.cie['length']+4].hex(),
                        'next_fde':hex(next_start),'int3_gap':len(gap),'relocations':relocs,
                        'instructions':[{'va':hex(i.address),'bytes':bytes(i.bytes).hex(),'mnemonic':i.mnemonic,'operands':i.op_str} for i in ins]})
        decoded[entry] = ins
    # Focused, whole-.text E8/E9 pattern scan, then enclosing-FDE boundary checks.
    text = elf.get_section_by_name('.text')
    raw = text.data()
    starts = sorted(set(f['initial_location'] for f in frames))
    xrefs = []
    for opcode in (0xe8,0xe9):
        at = raw.find(bytes([opcode]))
        while at>=0:
            if at+5<=len(raw):
                site = text['sh_addr']+at
                target = site+5+struct.unpack_from('<i',raw,at+1)[0]
                if target in ENTRIES:
                    a = starts[bisect.bisect_right(starts,site)-1]
                    fs = [f for f in frames if f['initial_location']==a]
                    require(len(fs)==1 and site+5<=a+fs[0]['address_range'],'xref enclosing FDE')
                    off = a-text['sh_addr']
                    parent = list(decoder.disasm(raw[off:off+fs[0]['address_range']],a))
                    match = [i for i in parent if i.address==site]
                    require(sum(i.size for i in parent)==fs[0]['address_range'] and len(match)==1 and match[0].operands[0].imm==target,'xref instruction boundary')
                    xrefs.append({'site':hex(site),'target':hex(target),'enclosing_fde':hex(a),'length':fs[0]['address_range'],'opcode':hex(opcode),
                                  'context':[{'va':hex(i.address),'bytes':bytes(i.bytes).hex(),'mnemonic':i.mnemonic,'operands':i.op_str} for i in parent if site-20<=i.address<=site+5]})
            at = raw.find(bytes([opcode]),at+1)
    return decoded,records,{'text_scan_bytes':len(raw),'e8_e9_xrefs':xrefs}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',required=True,type=Path)
    args = p.parse_args()
    require(cs.__version__=='5.0.7' and elftools.__version__=='0.32' and z.get_version_string()=='4.15.4','pinned analysis versions')
    data = (ROOT/'artifacts/node/115/hl-node').read_bytes()
    decoded,records,xrefs = admit(data)
    # Four input qwords in native little-endian memory order.
    words = [z.BitVec(f'input{i}',64) for i in range(4)]
    # Input bytes are interpreted as one big-endian 256-bit integer.
    swapped = [z.Concat(*[z.Extract(i+7,i,w) for i in range(0,64,8)]) for w in words]
    integer = z.Concat(*swapped)
    reduced = z.If(z.UGE(integer,bv(ORDER,256)),integer-bv(ORDER,256),integer)
    expected = [z.Extract(64*i+63,64*i,reduced) for i in range(4)]
    overflow = z.If(z.UGE(integer,bv(ORDER,256)),bv(1,32),bv(0,32))
    proofs,models = [],[]
    for entry in ENTRIES:
        for present in (False,True):
            lift = Expressions(words,present)
            lift.run(decoded[entry])
            outputs = [lift.mem['output',8*i] for i in range(4)]
            proofs.append(query(f'{entry:x}, overflow pointer {present}: all-256-bit output',z.Or(*[a!=b for a,b in zip(outputs,expected)])))
            if present:
                proofs.append(query(f'{entry:x}: overflow flag equals input >= order',lift.mem['overflow',0]!=overflow))
            for reg in ('rbx','rbp','r12','r13','r14','r15'):
                require(z.is_true(z.simplify(lift.regs[reg]==lift.initial[reg])),'callee-saved '+reg)
            require(lift.regs['rsp']==('stack',0),'balanced stack')
            require(all(r=='input' and 0<=o and o+n<=32 for _,r,o,n in lift.loads),'input read footprint')
            require(all((r=='output' and 0<=o and o+n<=32) or (present and r=='overflow' and o==0 and n==4) for _,r,o,n in lift.stores),'write footprint')
            models.append({'entry':hex(entry),'overflow_pointer_present':present,'loads':lift.loads,'stores':lift.stores,'branches':lift.branches,'preserved':['rbx','rbp','r12','r13','r14','r15'],'stack_balanced':True,'stack_accesses':lift.stack_accesses})
    proofs.append(query('single-subtraction result is always below order',z.UGE(reduced,bv(ORDER,256))))
    # Independent arbitrary-precision integer oracle on boundary cases and bits.
    cases = sorted({0,1,ORDER-1,ORDER,ORDER+1,(1<<256)-1} | {1<<i for i in range(256)} |
                   {((ORDER+delta) & ((1<<256)-1)) for delta in range(-8,9)} |
                   {((1<<k)+delta) for k in (64,128,192) for delta in (-1,0,1)})
    oracle_lift = Expressions(words,True)
    oracle_lift.run(decoded[ENTRIES[0]])
    outputs = [oracle_lift.mem['output',8*i] for i in range(4)]
    lines = ['input_be_hex\toutput_le_hex\toverflow']
    for n in cases:
        blob = n.to_bytes(32,'big')
        substitutions = [(w,bv(int.from_bytes(blob[8*i:8*i+8],'little'))) for i,w in enumerate(words)]
        out = b''.join(z.simplify(z.substitute(v,*substitutions)).as_long().to_bytes(8,'little') for v in outputs)
        flag = z.simplify(z.substitute(oracle_lift.mem['overflow',0],*substitutions)).as_long()
        require(int.from_bytes(out,'little')==n%ORDER and flag==int(n>=ORDER),'integer oracle')
        lines.append(f'{blob.hex()}\t{out.hex()}\t{flag}')
    # Actual immediate mutations, statically re-decoded. Neither is executed.
    controls = []
    for relative,old,new,name in [(0x13,0x40,0x41,'low comparison threshold +1'),
                                   (0x87,0xbf,0xbe,'low reduction addend -1')]:
        entry = ENTRIES[0]
        body = bytearray.fromhex(records[0]['bytes'])
        require(body[relative]==old,'mutation original byte '+name)
        body[relative] = new
        dec = cs.Cs(cs.CS_ARCH_X86,cs.CS_MODE_64)
        dec.detail = True
        changed = list(dec.disasm(bytes(body),entry))
        require(sum(i.size for i in changed)==LENGTH,'mutation decode')
        lift = Expressions(words,True)
        lift.run(changed)
        mismatch = z.Or(*[lift.mem['output',8*i]!=v for i,v in enumerate(expected)],lift.mem['overflow',0]!=overflow)
        boundary = ORDER.to_bytes(32,'big')
        fixed_words = [int.from_bytes(boundary[i:i+8],'little') for i in range(0,32,8)]
        bindings = [(w,bv(n)) for w,n in zip(words,fixed_words)]
        record = query(name,z.And(mismatch,*[w==n for w,n in zip(words,fixed_words)]),'sat')
        record['input_be_hex'] = boundary.hex()
        record['expected_integer'] = str(ORDER % ORDER)
        record['mutated_limbs'] = [z.simplify(z.substitute(lift.mem['output',8*i],*bindings)).as_long() for i in range(4)]
        record['mutated_overflow'] = z.simplify(z.substitute(lift.mem['overflow',0],*bindings)).as_long()
        require(record['mutated_limbs'] != [0]*4 or record['mutated_overflow'] != 1,'control replay')
        record.update(qualified_target=False,byte_offset=hex(relative),original=old,mutated=new,sha256=sha(body))
        controls.append(record)
    bad = bytearray(data)
    bad[ENTRIES[0]-0x1000] ^= 1
    try:
        admit(bytes(bad))
    except ValueError as error:
        require(str(error)=='target size/digest','digest rejection reason')
        controls.append({'name':'same-size full-target mutation','result':'rejected','sha256':sha(bad)})
    else:
        raise ValueError('modified target accepted')
    corpus = ('\n'.join(lines)+'\n').encode()
    result = {'target_sha256':TARGET,'target_size':len(data),'base_commit':'0781ce04826eeefd89fe336cb8ea073be0c1de30',
              'versions':{'python':platform.python_version(),'capstone':cs.__version__,'pyelftools':elftools.__version__,'z3':z.get_version_string()},
              'scope':'static bitvector expressions only; disjoint input/output/overflow/stack; no captured execution',
              'order':hex(ORDER),'bodies':records,'xrefs':xrefs,'models':models,'proofs':proofs,'controls':controls,
              'oracle':{'cases':len(cases),'sha256':sha(corpus)}}
    args.output.mkdir(parents=True,exist_ok=True)
    (args.output/'records.json').write_text(json.dumps(result,indent=2)+'\n')
    (args.output/'boundaries.tsv').write_bytes(corpus)
    print(json.dumps({'proofs':len(proofs),'controls':len(controls),'oracle_cases':len(cases)}))


if __name__=='__main__':
    main()
