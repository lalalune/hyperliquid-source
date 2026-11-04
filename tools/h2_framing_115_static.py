#!/usr/bin/env python3
"""Bind node115 H2 length framing, construction and ordinary buffer slicing.

Static decoding only. No captured instructions or system-call models are executed.
"""
import argparse
import bisect
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import tempfile

from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_GRP_JUMP
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP
from elf_index import sections
from fde_extents import eh_frame_records, uleb

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'
PACKET = ROOT / 'research/work-items/RE-012-h2-framing-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
def require(condition, message):
    if not condition:
        raise ValueError(message)

def digest(data):
    return hashlib.sha256(data).hexdigest()

def unique(pairs):
    result = dict(pairs)
    require(len(result) == len(pairs), 'duplicate JSON key')
    return result

class Image:
    def __init__(self, data):
        self.data = bytes(data)
        self.sections = sections(self.data)
        self.by_name = {s['name']: s for s in self.sections}
        require(len(self.by_name) == len(self.sections), 'duplicate section name')
        require(struct.unpack_from('<H', self.data, 18)[0] == 62, 'not x86-64')
        self.cies, self.fdes = eh_frame_records(self.data, self.sections)
        self.fdes.sort(key=lambda f: f['start'])
        self.starts = [f['start'] for f in self.fdes]
        require(len(set(self.starts)) == len(self.starts), 'duplicate FDE start')
        self.relocations = {}
        for sec in self.sections:
            if sec['type'] != 4:
                continue
            require(sec['size'] % 24 == 0, 'partial RELA')
            for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
                dst, info, addend = struct.unpack_from('<QQq', self.data, off)
                require(dst not in self.relocations, 'duplicate relocation destination')
                self.relocations[dst] = dict(slot=hex(dst), kind=info & 0xffffffff,
                    symbol_index=info >> 32, addend=addend, file_offset=hex(off),
                    record_hex=self.data[off:off + 24].hex())
        self.md = Cs(CS_ARCH_X86, CS_MODE_64)
        self.md.detail = True

    def offset(self, va, length):
        require(type(length) is int and length > 0, 'nonpositive read')
        hits = [s['offset'] + va - s['address'] for s in self.sections
                if s['type'] != 8 and s['address'] <= va and va + length <= s['address'] + s['size']]
        require(len(hits) == 1, f'unmapped/ambiguous read {va:#x}+{length}')
        return hits[0]

    def read(self, va, length):
        off = self.offset(va, length)
        return self.data[off:off + length]

    def owner(self, va):
        index = bisect.bisect_right(self.starts, va) - 1
        if index >= 0 and va < self.fdes[index]['end']:
            return self.fdes[index]
        return None

    def decode(self, start, end):
        raw = self.read(start, end - start)
        decoded = list(self.md.disasm(raw, start))
        require(decoded and sum(i.size for i in decoded) == len(raw), 'incomplete decode')
        starts = {i.address for i in decoded}
        for ins in decoded:
            if ins.group(CS_GRP_JUMP) and ins.operands[0].type == X86_OP_IMM:
                target = ins.operands[0].imm
                require(not start <= target < end or target in starts, 'branch inside instruction')
        return decoded

    def binding(self, slot):
        row = self.relocations.get(slot)
        if row is None:
            return None
        row = dict(row)
        if row['symbol_index']:
            sym = self.by_name['.dynsym']
            index = row['symbol_index']
            require(index * 24 + 24 <= sym['size'], 'dynsym out of bounds')
            name = struct.unpack_from('<I', self.data, sym['offset'] + index * 24)[0]
            strings = self.by_name['.dynstr']
            require(name < strings['size'], 'dynstr out of bounds')
            off = strings['offset'] + name
            end = self.data.find(b'\0', off, strings['offset'] + strings['size'])
            require(end >= 0, 'unterminated dynsym name')
            row['symbol'] = self.data[off:end].decode('ascii')
        elif row['kind'] == 8:
            row['target'] = hex(row['addend'])
            owner = self.owner(row['addend'])
            if owner:
                row['target_fde'] = [hex(owner['start']), hex(owner['end'])]
        return row

def instruction(ins):
    return {'va': hex(ins.address), 'bytes': bytes(ins.bytes).hex(),
            'mnemonic': ins.mnemonic, 'operands': ins.op_str}

def exception_sites(image, frame, starts):
    """Read the bounded LSDA header/call-site table; action semantics stay open."""
    va = frame['lsda']
    if va is None:
        return None
    sec = image.by_name['.gcc_except_table']
    require(sec['address'] <= va < sec['address'] + sec['size'], 'LSDA outside section')
    begin = image.offset(va, 1)
    pos, limit, data = begin, sec['offset'] + sec['size'], image.data
    require(data[pos] == 0xff, 'unsupported LPStart encoding')
    typ = data[pos + 1]
    pos += 2
    type_base = None
    if typ == 0x9b:
        delta, pos = uleb(data, pos, limit)
        type_base = pos + delta
        require(type_base <= limit, 'LSDA type table outside section')
    else:
        require(typ == 0xff, 'unsupported type encoding')
    require(data[pos] == 1, 'unsupported call-site encoding')
    size, pos = uleb(data, pos + 1, limit)
    end = pos + size
    require(end <= limit, 'truncated call-site table')
    rows, previous = [], frame['start']
    while pos < end:
        first, values = pos, []
        for _ in range(4):
            value, pos = uleb(data, pos, end)
            values.append(value)
        offset, length, landing, action = values
        start = frame['start'] + offset
        pad = frame['start'] + landing if landing else None
        require(previous <= start <= start + length <= frame['end'], 'LSDA interval invalid')
        require(pad is None or pad in starts, 'landing pad not an instruction')
        previous = start + length
        rows.append({'start': hex(start), 'end_exclusive': hex(start + length),
                     'landing_pad': hex(pad) if pad else None, 'action_index': action,
                     'hex': data[first:pos].hex()})
    require(pos == end, 'LSDA table overrun')
    return {'va': hex(va), 'header_and_call_sites_hex': data[begin:end].hex(),
            'type_encoding': typ, 'type_table_file_offset': hex(type_base) if type_base else None,
            'action_records_decoded': False, 'rows': rows}


def load_json(path):
    return json.loads(Path(path).read_bytes(), object_pairs_hook=unique)

def selected_writer(image, address, size):
    rows=[]
    for destination,row in image.relocations.items():
        # All selected writers in this ELF are 8-byte RELATIVE/GLOB_DAT/JUMP_SLOT.
        if destination < address+size and address < destination+8:
            require(row['kind'] in (6,7,8), 'unclassified selected relocation width')
            require(address <= destination and destination+8 <= address+size, 'partial selected writer')
            rows.append(image.binding(destination))
    return rows

def incoming_census(image):
    targets={0x16e4bc0,0x5cff0b0};slots={slot for slot,r in image.relocations.items() if r['kind']==8 and r['addend'] in targets}
    sec=image.by_name['.text'];raw=image.read(sec['address'],sec['size']);decoded={};result=[]
    for pattern,size,disp_offset,indirect in [(rb'[\xe8\xe9]',5,1,False),(rb'\xff[\x15\x25]',6,2,True)]:
        for match in re.finditer(pattern,raw):
            pos=match.start()
            if pos+size>len(raw):continue
            va=sec['address']+pos;dst=va+size+struct.unpack_from('<i',raw,pos+disp_offset)[0]
            if dst not in (slots if indirect else targets):continue
            owner=image.owner(va)
            if not owner:continue
            start=owner['start']
            if start not in decoded:decoded[start]={i.address:i for i in image.decode(start,owner['end'])}
            ins=decoded[start].get(va)
            if ins is None or ins.mnemonic not in ('call','jmp'):continue
            result.append(dict(site=hex(va),owner=[hex(start),hex(owner['end'])],target_or_slot=hex(dst),indirect_slot=indirect,bytes=bytes(ins.bytes).hex()))
    result.sort(key=lambda x:int(x['site'],16))
    return result

def analyze(data, *, identity=True):
    if identity:
        require(len(data)==105896032 and digest(data)==SHA256,'target identity differs')
    image=Image(data);spec=load_json(PACKET/'spec.json');bodies={};bindings={};branches=0
    for name,row in spec['ranges'].items():
        a,z=row['start'],row['end'];fdes=[f for f in image.fdes if f['start']<z and a<f['end']]
        require(len(fdes)==1 and fdes[0]['start']==a and fdes[0]['end']==z,'selected FDE overlap/extent differs')
        raw=image.read(a,z-a);require(digest(raw)==row['sha256'],'body bytes differ: '+name)
        require(not selected_writer(image,a,z-a),'selected text relocation')
        ins=image.decode(a,z);starts={i.address for i in ins};calls=[];rip=[]
        for i in ins:
            if i.group(CS_GRP_JUMP):branches+=1
            for op in i.operands:
                if op.type==X86_OP_MEM and op.mem.base==X86_REG_RIP:
                    dst=i.address+i.size+op.mem.disp;binding=image.binding(dst)
                    if binding:
                        selected=selected_writer(image,dst,8);require(len(selected)==1,'ambiguous slot')
                        bindings[hex(dst)]=binding
                    rip.append(dict(site=hex(i.address),target=hex(dst),binding=binding))
            if i.mnemonic in ('call','jmp'):
                op=i.operands[0];edge=dict(site=hex(i.address),instruction=instruction(i))
                if op.type==X86_OP_IMM:
                    target=op.imm;owner=image.owner(target);edge.update(target=hex(target),fde=owner)
                calls.append(edge)
        f=fdes[0];cie=image.cies[f['cie']]
        bodies[name]=dict(start=hex(a),end=hex(z),bytes=z-a,sha256=digest(raw),fde=f,cie=cie,
            fde_bytes=image.read(f['fde'],struct.unpack('<I',image.read(f['fde'],4))[0]+4).hex(),cie_bytes=image.read(cie['va'],struct.unpack('<I',image.read(cie['va'],4))[0]+4).hex(),
            instructions=[instruction(i) for i in ins],calls=calls,rip=rip,
            lsda=exception_sites(image,f,starts))
    mapped={}
    for key,row in spec['data'].items():
        a=int(key,16);raw=image.read(a,row['length']);require(digest(raw)==row['sha256'],'data bytes differ: '+key)
        writers=selected_writer(image,a,len(raw));mapped[key]=dict(bytes=raw.hex(),writers=writers)
        for w in writers:bindings[w['slot']]=w
    for name,row in spec['anchors'].items():
        raw=bytes.fromhex(row['bytes']);require(image.read(row['start'],len(raw))==raw,'semantic anchor differs: '+name)
    # Actual selected entry pointer, not a guessed text xref.
    bd=image.binding(0x64e0c00);require(bd and bd['kind']==8 and bd['addend']==0x5cff0b0,'decoder slot binding')
    require(len(selected_writer(image,0x64e0c00,8))==1,'decoder slot writer');bindings['0x64e0c00']=bd
    return dict(target_sha256=SHA256,incoming_census=incoming_census(image),bodies=bodies,bindings=bindings,data=mapped,
        complete_bytes=sum(v['bytes']for v in bodies.values()),instructions=sum(len(v['instructions'])for v in bodies.values()),
        selected_branch_instructions=branches,limits='Static ordinary buffer/field relation; no target execution, original ABI, async readiness, allocator, ownership-concurrency or full unwind theorem.')

def native_rows(text,start,end):
    rows=[]
    for line in text.splitlines():
        match=re.match(r'^\s*([0-9a-fA-F]+):\s*((?:[0-9a-fA-F]{2}\s+)+)(.*)$',line)
        if not match:continue
        address=int(match[1],16)
        if not start<=address<end:continue
        raw=bytes.fromhex(match[2]);rows.append((address,raw))
    # Apple LLVM displays a LOCK prefix independently. Join only an exact F0
    # record followed by a contiguous instruction; all bytes remain compared.
    out=[];joins=[];i=0
    while i<len(rows):
        a,raw=rows[i]
        if raw==b'\xf0':
            require(i+1<len(rows) and rows[i+1][0]==a+1,'unpaired LOCK prefix')
            raw+=rows[i+1][1];joins.append(hex(a));i+=1
        out.append((a,raw));i+=1
    require(out and out[0][0]==start and out[-1][0]+len(out[-1][1])==end,'incomplete native export')
    require(all(a+len(x)==b for (a,x),(b,_) in zip(out,out[1:])),'native gap')
    return out,joins

def export(output,gnu,llvm):
    require(not output.exists(),'output already exists');output.mkdir(parents=True)
    report=analyze(TARGET.read_bytes());commands=[]
    for name,b in report['bodies'].items():
        a,z=int(b['start'],16),int(b['end'],16)
        want=[(int(i['va'],16),bytes.fromhex(i['bytes'])) for i in b['instructions']]
        for provider,exe in [('gnu',gnu),('llvm',llvm)]:
            if provider=='gnu':argv=[exe,'-d','-w','-Mintel','--show-raw-insn',f'--start-address={a}',f'--stop-address={z}',str(TARGET)]
            else:argv=[exe,'--disassemble','--x86-asm-syntax=intel',f'--start-address={a}',f'--stop-address={z}',str(TARGET)]
            p=subprocess.run(argv,capture_output=True);out=output/f'{name}.{provider}.txt';err=output/f'{name}.{provider}.stderr';out.write_bytes(p.stdout);err.write_bytes(p.stderr)
            row=dict(name=name,provider=provider,argv=argv,exit_code=p.returncode,stdout_sha256=digest(p.stdout),stderr_sha256=digest(p.stderr));commands.append(row);(output/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
            require(p.returncode==0,'native decoder failed');got,joins=native_rows(p.stdout.decode(),a,z);row['lock_prefix_joins']=joins;row['instruction_rows']=len(got)
            require(got==want,'native boundary/byte disagreement '+name+' '+provider)
    (output/'commands.json').write_text(json.dumps(commands,indent=2)+'\n');(output/'records.json').write_text(json.dumps(report,indent=2)+'\n');return report

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--export',type=Path);p.add_argument('--gnu',default='/opt/homebrew/opt/binutils/bin/objdump');p.add_argument('--llvm',default='/usr/bin/objdump');args=p.parse_args()
    report=export(args.export,args.gnu,args.llvm) if args.export else analyze(TARGET.read_bytes())
    print(json.dumps(dict(bodies=len(report['bodies']),bytes=report['complete_bytes'],instructions=report['instructions'],writers=len(report['bindings']))))

if __name__=='__main__':main()
