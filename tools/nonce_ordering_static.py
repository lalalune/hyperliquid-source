#!/usr/bin/env python3
"""RE-001: node115 nonce-associated strict ring ordering, static only."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile
from artifacts import ROOT
from elf_index import sections
from fde_extents import fde_extents
from foundation_millis import decode_export

TARGET=ROOT/'artifacts/node/115/hl-node'
PACKET=ROOT/'research/work-items/RE-001-node115-nonce-ordering'
SHA='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
SPEC_SHA='b68096709b712eead27b4787dfedf360317865e9ddf63b0371d7497d6c3e5977'
BRANCHES={0x2923c30:(0x2923d30,0x2923d52),0x2923da0:(0x2923e80,0x2923ea2),
          0x4227d30:(0x4227e20,0x4227e42),0x4227e90:(0x4227f70,0x4227f92),
          0x5b07c50:(0x5b07d50,0x5b07d72)}
U64=(1<<64)-1


def specification():
    raw=(PACKET/'spec.json').read_bytes()
    if hashlib.sha256(raw).hexdigest()!=SPEC_SHA:raise ValueError('nonce specification changed')
    return json.loads(raw)


def read(data,va,n):
    matches=[s for s in sections(data) if s['type']!=8 and s['address']<=va and va+n<=s['address']+s['size']]
    if len(matches)!=1:raise ValueError('expected unique file-backed mapping')
    s=matches[0];off=s['offset']+va-s['address'];return off,bytes(data[off:off+n])


def parameters(data,a):
    first,second=BRANCHES[a]
    for site,raw in [(first-11,'4c8b4af84c3b0a488d5208'),(second-13,'488b12483b164889f2488d7608')]:
        b=bytes.fromhex(raw)
        if read(data,site,len(b))[1]!=b:raise ValueError('nonce comparison/load/advance changed')
    return [read(data,first,1)[1][0],read(data,second,1)[1][0]]


def obligations(capacity,head,count):
    """Logical pair obligations of the two observed spans, not a CPU model."""
    if not 0<=capacity<=((1<<63)-1)//8 or not 0<=count<=capacity or not (0<=head<capacity if capacity else head==0):
        raise ValueError('outside valid raw ring domain')
    if not count:return []
    first_end=min(capacity,head+count);second_count=max(0,count-(capacity-head))
    pairs=[(0,i-1,i) for i in range(head+1,first_end)]
    previous=first_end-1
    for i in range(second_count):
        pairs.append((1,previous,i));previous=i
    return pairs


def relation(op,left,right):
    if not 0<=left<=U64 or not 0<=right<=U64:raise ValueError('outside raw u64 content domain')
    if op==0x72:return left<right
    if op==0x76:return left<=right
    if op==0x7c:
        signed=lambda x:x-(1<<64) if x&(1<<63) else x
        return signed(left)<signed(right)
    raise ValueError('unsupported static comparison condition')


def ordered(params,physical,head,count):
    return all(relation(params[kind],physical[a],physical[b]) for kind,a,b in obligations(len(physical),head,count))


def analyze(data):
    spec=specification();params={}
    for a,(first,second) in BRANCHES.items():
        p=parameters(data,a)
        if p!=[0x72,0x72]:raise ValueError('nonce strict unsigned relation changed')
        params[hex(a)]=p
        for site,target in [(first,first-16),(second,second-18)]:
            code=read(data,site,2)[1]
            if site+2+struct.unpack('<b',code[1:])[0]!=target:raise ValueError('nonce comparison backedge changed')
        code=read(data,first+2,2)[1]
        if code[0]!=0xeb or first+4+struct.unpack('<b',code[1:])[0]!=second+2:raise ValueError('nonce failure convergence changed')
    for o in spec['owners']:
        for site,target in o['direct_calls'].items():
            site=int(site);code=read(data,site,5)[1]
            if code[0]!=0xe8 or site+5+struct.unpack_from('<i',code,1)[0]!=target:raise ValueError('nonce direct call changed')
        for site,row in o['rip_bindings'].items():
            site=int(site);prefix=bytes.fromhex(row['prefix']);code=read(data,site,len(prefix)+4)[1]
            if code[:len(prefix)]!=prefix or site+len(code)+struct.unpack_from('<i',code,len(prefix))[0]!=row['target']:raise ValueError('nonce RIP binding changed')
    s=next(s for s in sections(data) if s['name']=='.rela.dyn')
    rels={a:(i,v) for a,i,v in struct.iter_unpack('<QQq',data[s['offset']:s['offset']+s['size']])}
    if any(rels.get(int(a))!=tuple(row) for a,row in spec['relocations'].items()):raise ValueError('nonce relocation changed')
    path=b'l1/src/nonce_set.rs'
    if read(data,0x4424eb,len(path))[1]!=path or read(data,0x6484000,16)[1]!=struct.pack('<QII',len(path),141,13):raise ValueError('nonce source Location changed')
    if read(data,0x7c958c,15)[1]!=b'nonce invariant':raise ValueError('nonce diagnostic anchor changed')
    _,fs,_=fde_extents(data);frames={(f['start'],f['end']):f for f in fs};owners=[]
    for o in spec['owners']:
        a,b=o['start'],o['end']
        if (a,b) not in frames:raise ValueError('nonce FDE changed')
        off,body=read(data,a,b-a)
        if hashlib.sha256(body).hexdigest()!=o['sha256']:raise ValueError('nonce instruction/dataflow changed')
        raw={}
        for kind in ['fde','cie']:
            va=frames[a,b][kind];n=struct.unpack('<I',read(data,va,4)[1])[0]+4
            raw[kind]={'va':hex(va),'bytes_hex':read(data,va,n)[1].hex()}
        owners.append({'start':hex(a),'end':hex(b),'bytes':b-a,'instructions':o['instructions'],'file_offset':hex(off),'sha256':o['sha256'],'frames':raw})
    return {'target_sha256':SHA,'spec_sha256':SPEC_SHA,'owners':owners,'parameters':params,
            'branch_sites':{hex(a):[hex(x) for x in sites] for a,sites in BRANCHES.items()},
            'theorem':'Conditional on normal input-provider success and valid ring metadata/buffer, both observed spans plus their boundary require every logical neighboring u64 pair to be strictly increasing. Empty/singleton contents require no pair comparisons.',
            'assumptions':'0<=count<=capacity, 0<=head<capacity (or head=0 if capacity=0), 8*capacity<=ISIZE_MAX, valid nonwrapping buffer memory; concrete decoder/collection ABI not fully recovered',
            'captured_code_executed':False,
            'limits':'Local five-body invariant only; provider/error ABI variants, full decoder formats, allocation/ownership/unwind, caller reachability, nonce admission/window/replay policies, Rust reconstruction, runtime equivalence and component gates remain unproved.'}


def generate(binary,output):
    data=binary.read_bytes()
    if len(data)!=105896032 or hashlib.sha256(data).hexdigest()!=SHA:raise ValueError('expected pinned node115')
    report=analyze(data);spec=specification();output.mkdir(parents=True,exist_ok=True);frame_lines=[]
    with tempfile.TemporaryDirectory() as directory:
        snapshot=Path(directory)/'node115.elf';snapshot.write_bytes(data)
        frames=subprocess.check_output(['readelf','-wf',str(snapshot)],text=True)
        for o in spec['owners']:
            a,b=o['start'],o['end'];rows=[l for l in frames.splitlines() if f'pc={a:016x}..{b:016x}' in l]
            if len(rows)!=1:raise ValueError('native nonce FDE disagreement')
            frame_lines.extend(rows)
            asm=subprocess.check_output(['objdump','-d','-M','intel','--insn-width=16',f'--start-address={a:#x}',f'--stop-address={b:#x}',str(snapshot)],text=True)
            ins=decode_export(asm,a,b,read(data,a,b-a)[1]);required={int(v) for v in o['direct_calls']}|{int(v) for v in o['rip_bindings']}
            first,second=BRANCHES[a];required|={first,first-11,first-7,second,second-13,second-10,second-18}
            if len(ins)!=o['instructions'] or not required<=set(ins):raise ValueError('native nonce instruction disagreement')
            (output/f'{a:x}.objdump.txt').write_bytes(asm.replace(str(snapshot),'<authenticated-node115>').encode('utf-8'))
        raw=subprocess.check_output(['readelf','-rW',str(snapshot)],text=True)
        rows=[l for l in raw.splitlines() if any(l.startswith(f'{int(a):016x} ') for a in spec['relocations'])]
        if len(rows)!=len(spec['relocations']):raise ValueError('native nonce relocation disagreement')
        (output/'selected-relocations.txt').write_bytes(('\n'.join(rows)+'\n').encode('utf-8'))
    (output/'frames.txt').write_bytes(('\n'.join(frame_lines)+'\n').encode('utf-8'))
    (output/'records.json').write_bytes((json.dumps(report,indent=2)+'\n').encode('utf-8'))
    return report


if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--binary',type=Path,default=TARGET)
    ap.add_argument('--output',type=Path,default=ROOT/'work/nonce-ordering115');args=ap.parse_args()
    r=generate(args.binary,args.output);print(json.dumps({'functions':len(r['owners']),'bytes':sum(x['bytes'] for x in r['owners']),'executed':False}))
