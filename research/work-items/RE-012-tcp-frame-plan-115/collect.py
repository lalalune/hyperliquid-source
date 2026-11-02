#!/usr/bin/env python3
"""Authenticate #115 TCP framing facts without executing captured code."""
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'tools'))
from elf_index import sections
from fde_extents import eh_frame_records
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from capstone.x86 import X86_OP_IMM,X86_OP_MEM,X86_REG_RIP

TARGET=ROOT/'artifacts/node/115/hl-node'
SHA='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
SIZE=105896032
RANGES=[(0x2b780d0,0x2b782d5),(0x2b788e0,0x2b79e2e)]


def need(ok,message):
    if not ok:raise ValueError(message)


def digest(raw):return hashlib.sha256(raw).hexdigest()


def dump(value):return json.dumps(value,indent=2,sort_keys=True)+'\n'


class Image:
    def __init__(self,data,overlay=None):
        self.data=data;self.ss=sections(data);self.overlay=overlay or {}
    def offset(self,va,n):
        hits=[s for s in self.ss if s['type']!=8 and s['address']<=va and va+n<=s['address']+s['size']]
        need(n>=0 and len(hits)==1,'expected unique file-backed VA interval')
        return hits[0]['offset']+va-hits[0]['address']
    def read(self,va,n):
        off=self.offset(va,n);raw=bytearray(self.data[off:off+n])
        for at,value in self.overlay.items():
            if va<=at<va+n:raw[at-va]=value
        return bytes(raw)


# Structural argument and output transfers. The parameter operands below are
# extracted separately, so counterfactual changes can reach the scalar model.
PINS={
 0x2b78100:'c7435000000000c6435400',
 0x2b7810b:'48890348895308',
 0x2b78225:'8b4b50',0x2b7822a:'0fb64354',0x2b7822e:'31d2',
 0x2b78230:'41891641894e0449894608',
 0x2b78c34:'488d7350488d7c2450488b542428',
 0x2b78c6c:'488b6c2458a801',0x2b78c79:'448b742454',
 0x2b78f25:'448b742454488b6c2458',
 0x2b79038:'4589f64c897358',0x2b7903f:'4c397328',
 0x2b791ca:'0f944350',0x2b791ce:'4d85f6',
 0x2b791d3:'bf010000004c89f6',
 0x2b79217:'4c897360488943684c897370c6434901',
 0x2b79227:'48c7437800000000',
 0x2b799e6:'498b3e488b43584829f8',
 0x2b79a05:'48898b800000004801f9',
 0x2b79aa3:'807b5000',
 0x2b79abd:'488b4b28488b7368488b5370488d7c2450',
}


def parameters(img):
    for at,hexed in PINS.items():
        expected=bytes.fromhex(hexed);need(img.read(at,len(expected))==expected,f'transfer changed at {at:#x}')
    # Exact supported opcodes/registers, with numeric policy operands extracted.
    need(img.read(0x2b78112,4)==bytes.fromhex('48c74310'),'header-length destination changed')
    header_bytes=struct.unpack('<I',img.read(0x2b78116,4))[0]
    need(img.read(0x2b78122,1)==b'\xb9','initial read length register changed')
    initial_request=struct.unpack('<I',img.read(0x2b78123,4))[0]
    swap=img.read(0x2b78228,2);need(swap in [b'\x0f\xc9',b'\x66\x90'],'unsupported header conversion')
    branch=img.read(0x2b79043,2);need(branch in [b'\x0f\x83',b'\x0f\x87'],'unsupported admission branch')
    need(0x2b79049+struct.unpack('<i',img.read(0x2b79045,4))[0]==0x2b791c6,'admission destination changed')
    need(img.read(0x2b791c6,3)==bytes.fromhex('4080fd'),'flag comparison register changed')
    flag=img.read(0x2b791c9,1)[0]
    need(img.read(0x2b799f6,2)==bytes.fromhex('483d') and img.read(0x2b799fc,1)==b'\xb9','chunk bound opcodes changed')
    compare_bound=struct.unpack('<I',img.read(0x2b799f8,4))[0];move_bound=struct.unpack('<I',img.read(0x2b799fd,4))[0]
    need(compare_bound==move_bound,'inconsistent chunk bounds')
    cmov=img.read(0x2b79a01,4);need(cmov in [bytes.fromhex('480f42c8'),bytes.fromhex('480f47c8')],'unsupported chunk select')
    need(img.read(0x2b799f0,2)==bytes.fromhex('0f86') and 0x2b799f6+struct.unpack('<i',img.read(0x2b799f2,4))[0]==0x2b79aa3,'completion branch changed')
    return {'header_bytes':header_bytes,'initial_request':initial_request,'big_endian':swap==b'\x0f\xc9',
            'inclusive_limit':branch==b'\x0f\x83','decompression_flag':flag,
            'chunk_cap':compare_bound,'minimum_chunk':cmov==bytes.fromhex('480f42c8')}


def relation(header,limit,completed,p):
    need(len(header)==5 and 0<=limit<1<<64 and 0<=completed<1<<64,'outside declared corpus domain')
    length=int.from_bytes(header[:4],'big' if p['big_endian'] else 'little')
    accepted=length<=limit if p['inclusive_limit'] else length<limit
    if not accepted:return f'0 {length} 0 0 0 0'
    compressed=int(header[4]==p['decompression_flag'])
    if completed>=length:return f'1 {length} {compressed} 0 0 0'
    remaining=length-completed
    chunk=min(remaining,p['chunk_cap']) if p['minimum_chunk'] else max(remaining,p['chunk_cap'])
    return f'1 {length} {compressed} 1 {completed} {completed+chunk}'


def native_rows(text):
    rows=[];prefix=None
    for line in text.splitlines():
        m=re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)(.*)',line)
        if not m:continue
        at,raw=int(m[1],16),bytes.fromhex(m[2])
        if raw==b'\xf0' and m[3].strip()=='lock':
            need(prefix is None,'consecutive split LOCK');prefix=at;continue
        if prefix is not None:
            need(at==prefix+1,'noncontiguous split LOCK');at,raw,prefix=prefix,b'\xf0'+raw,None
        rows.append((at,raw))
    need(prefix is None,'unterminated split LOCK');return rows


def collect(data,native=False):
    need(len(data)==SIZE and digest(data)==SHA,'wrong node115 capture')
    img=Image(data);p=parameters(img)
    need(p=={'header_bytes':5,'initial_request':5,'big_endian':True,'inclusive_limit':True,'decompression_flag':1,'chunk_cap':4000000,'minimum_chunk':True},'selected framing policy differs')
    cies,fs=eh_frame_records(data,img.ss);md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True
    owners=[];all_calls=[];all_branches=[];slots=set();native_exports={}
    for a,b in RANGES:
        matches=[f for f in fs if f['start']==a]
        need(len(matches)==1 and matches[0]['end']==b,'missing/duplicate/wrong owner FDE')
        need([f for f in fs if f['start']<b and a<f['end']]==matches,'overlapping owner FDE')
        f=matches[0];body=img.read(a,b-a);ins=list(md.disasm(body,a));rows=[(i.address,bytes(i.bytes)) for i in ins]
        need(b''.join(raw for _,raw in rows)==body and all(x[0]+len(x[1])==y[0] for x,y in zip(rows,rows[1:])),'incomplete decoder coverage')
        boundaries={i.address for i in ins}
        for i in ins:
            if i.mnemonic=='call':
                row={'site':hex(i.address),'raw':bytes(i.bytes).hex(),'operand':i.op_str}
                op=i.operands[0]
                if op.type==X86_OP_IMM:row['target']=hex(op.imm)
                elif op.type==X86_OP_MEM and op.mem.base==X86_REG_RIP:
                    slot=i.address+i.size+op.mem.disp;row['slot']=hex(slot);slots.add(slot)
                else:row['unclosed_dynamic']=True
                all_calls.append(row)
            if i.mnemonic.startswith('j') and i.operands[0].type==X86_OP_IMM:
                target=i.operands[0].imm
                need(target in boundaries,'selected direct branch leaves owner or misses instruction boundary')
                all_branches.append({'site':hex(i.address),'op':i.mnemonic,'target':hex(target)})
        frames={}
        for key in ['fde','cie']:
            va=f[key];n=struct.unpack('<I',img.read(va,4))[0]+4;frames[key]={'va':hex(va),'raw':img.read(va,n).hex()}
        owners.append({'start':hex(a),'end_exclusive':hex(b),'bytes':b-a,'instructions':len(ins),'sha256':digest(body),'fde_record':f,'frames':frames,'cie_profile':cies[f['cie']]})
        if native:
            for label,command in [('gnu',['objdump','-d','-M','intel','--insn-width=16']),('llvm',['llvm-objdump','-d','--x86-asm-syntax=intel'])]:
                text=subprocess.check_output([*command,f'--start-address={a}',f'--stop-address={b}',str(TARGET)],text=True)
                need(native_rows(text)==rows,label+' full-owner instruction partition differs')
                native_exports[f'{a:x}.{label}.txt']=text.replace(str(TARGET),'<authenticated-node115>')
    calls={int(c['site'],16):c for c in all_calls}
    for site,target in [(0x2b78c42,0x2b780d0),(0x2b78ec4,0x2b780d0),(0x2b78198,0x5cdfa50)]:
        need(calls[site].get('target')==hex(target),'actual header/read call binding changed')
    need(calls[0x2b79ace].get('slot')=='0x64e7790','decompression call slot changed')
    sec=next(s for s in img.ss if s['name']=='.rela.dyn');relocs={}
    for off in range(sec['offset'],sec['offset']+sec['size'],24):
        slot,info,addend=struct.unpack_from('<QQq',data,off)
        if slot in slots or slot in [0x644afa8,0x644afc0,0x644afd8]:
            need(slot not in relocs,'duplicate selected relocation writer')
            relocs[slot]={'file_offset':hex(off),'slot':hex(slot),'info':info,'kind':info&0xffffffff,'symbol_index':info>>32,'addend':hex(addend),'raw':data[off:off+24].hex()}
    need(all(s in relocs for s in slots),'missing captured call-slot relocation')
    locations=[]
    for slot,line,col in [(0x644afa8,24,77),(0x644afc0,35,13),(0x644afd8,51,47)]:
        rel=relocs[slot];need(rel['info']==8,'source Location not RELATIVE')
        n,l,c=struct.unpack('<QII',img.read(slot+8,16));path=img.read(int(rel['addend'],16),n).decode()
        need(path=='net_utils/src/tcp/read.rs' and (l,c)==(line,col),'reader source Location changed')
        locations.append({'slot':hex(slot),'path':path,'line':l,'column':c})
    for va,text in [(0x606ecc,b'tcp_bytes'),(0x606ed5,b'tcp read bytes over limit'),(0x606f08,b'tcp_read_exact'),(0x94d48e,b'early eof')]:need(img.read(va,len(text))==text,'reader literal changed')
    # Explicit numeric data for computed state-dispatch edges; native enum validity is unproved.
    tables=[]
    for a,n in [(0x604bf0,4),(0x604c00,4),(0x604c44,6),(0x604c5c,4),(0x604c6c,4),(0x604c7c,4),(0x604c8c,4)]:
        raw=img.read(a,4*n)
        table_owner=RANGES[0] if a<0x604c44 else RANGES[1]
        table_boundaries={i.address for i in md.disasm(img.read(table_owner[0],table_owner[1]-table_owner[0]),table_owner[0])}
        need(all(a+v in table_boundaries for v in struct.unpack('<'+'i'*n,raw)),'state-table edge misses its actual owner boundary')
        tables.append({'va':hex(a),'raw':raw.hex(),'relative_targets':[hex(a+v) for v in struct.unpack('<'+'i'*n,raw)]})
    result={'schema':'node115-tcp-frame-plan/1','base':'8fd8db680ec4bfef40996e5616bce3d5156d0b86','target_sha256':SHA,'target_size':SIZE,'parameters':p,'owners':owners,'calls':all_calls,'branches':all_branches,'relocations':[relocs[s] for s in sorted(relocs)],'locations':locations,'dispatch_tables':tables,
            'premises':['Complete valid five-byte header, ordinary successful header return and valid owner regions.','Selected unsigned limit branch and ordinary allocation/field transfers are reached.','Chunk planning projects the selected arithmetic over a supplied completed count; no I/O/helper postcondition or concurrency is inferred.'],
            'limits':['No native state-machine/Result/Vec ABI, pending/error/unwind execution, timeout behavior, allocation, read effects, LZ4 decoding, other reader copies or full-node recovery.','Complete listings are context, not a claim to implement all paths or close every recorded helper.'],
            'captured_code_executed':False}
    return result,native_exports


if __name__=='__main__':
    result,exports=collect(TARGET.read_bytes(),native=True)
    output=Path(sys.argv[1]);output.mkdir(exist_ok=False,parents=True)
    (output/'evidence.json').write_text(dump(result))
    for name,text in exports.items():(output/name).write_text(text)
    print(dump({'owners':result['owners'],'parameters':result['parameters']}))
