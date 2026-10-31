#!/usr/bin/env python3
"""RE-001: node115 latency-associated two observers and uncapped record, static only."""
import argparse
import hashlib
import json
import math
from pathlib import Path
import struct
import subprocess
import tempfile
from artifacts import ROOT
from elf_index import sections
from fde_extents import fde_extents
from foundation_millis import decode_export

TARGET=ROOT/'artifacts/node/115/hl-node'
PACKET=ROOT/'research/work-items/RE-001-node115-latency-projection'
SHA='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
START,END=0x51c9a70,0x51c9cad
BODY_SHA='a426a545391855818dae5d702ed7e0001862df9cd4e40da48f4591fe53607e58'
BINDINGS={0x64a3618:0x44bf3e,0x64a3630:0x44bf3e,0x64e0990:0x1629690,
          0x64e0fc0:0x162a290,0x64e1010:0x1547530}
DIRECT={0x51c9c63:0x4e3d2c0,0x51c9c7d:0x14c3950,0x51c9c85:0x1533e80,0x51c9c99:0x14c4d00}
RIP={0x51c9a99:(b'\xff\x15',0x64e0990),0x51c9b20:(b'\xff\x15',0x64e0fc0),
     0x51c9b84:(b'\xff\x15',0x64e1010),0x51c9b95:(b'\xff\x15',0x64e0fc0),
     0x51c9c12:(b'\xff\x15',0x64e1010),
     0x51c9b53:(b'\xf2\x0f\x5e\x0d',0x458d50),0x51c9bcb:(b'\xf2\x0f\x5e\x05',0x458d50),
     0x51c9b67:(b'\x66\x0f\x2e\x0d',0x459010),0x51c9bdf:(b'\x66\x0f\x2e\x05',0x459010),
     0x51c9bfa:(b'\xf2\x0f\x10\x05',0x459718),
     0x51c9b75:(b'\x48\x8d\x15',0x64a3618),0x51c9c06:(b'\x48\x8d\x15',0x64a3630)}


def read(data,va,n):
    matches=[s for s in sections(data) if s['type']!=8 and s['address']<=va and va+n<=s['address']+s['size']]
    if len(matches)!=1:raise ValueError('expected unique file-backed mapping')
    s=matches[0];off=s['offset']+va-s['address'];return off,bytes(data[off:off+n])


def parameters(data):
    return {'divisor':struct.unpack('<d',read(data,0x458d50,8)[1])[0],
            'positive_infinity_hex':read(data,0x459010,8)[1].hex(),
            'cap':struct.unpack('<d',read(data,0x459718,8)[1])[0],
            'first_correction':struct.unpack('<i',read(data,0x51c9b3e,4)[1])[0],
            'second_correction':struct.unpack('<i',read(data,0x51c9bb3,4)[1])[0],
            'saved_value_stack_offset':read(data,0x51c9bf2,1)[1][0],
            'reload_stack_offset':read(data,0x51c9c54,1)[1][0],
            'record_stack_offset':read(data,0x51c9c5a,1)[1][0],
            'record_base_stack_offset':read(data,0x51c9c5f,1)[1][0]}


def corrected_pair(s,n,correction=-1000000000):
    if not -(1<<63)<=s<(1<<63) or not -(1<<31)<=n<(1<<31):
        raise ValueError('outside raw signed return-pair domain')
    return (s+1,n+correction) if s<0 and n>0 else (s,n)


def numeric_projection(p,s,n):
    """Finite raw-pair algebra under ordinary binary64 rounding, not a clock model."""
    s,n=corrected_pair(s,n,p['second_correction'])
    value=max(0.0,float(s)+float(n)/p['divisor'])
    if not math.isfinite(value):raise ValueError('outside finite projection')
    return {'observer_value':min(p['cap'],value),'record_value':value}


def analyze(data):
    p=parameters(data)
    if p!={'divisor':1e9,'positive_infinity_hex':'000000000000f07f','cap':60.0,
           'first_correction':-1000000000,'second_correction':-1000000000,
           'saved_value_stack_offset':72,'reload_stack_offset':72,'record_stack_offset':40,'record_base_stack_offset':16}:
        raise ValueError('latency projection parameters changed')
    for site,(prefix,target) in RIP.items():
        code=read(data,site,len(prefix)+4)[1]
        if code[:len(prefix)]!=prefix or site+len(code)+struct.unpack_from('<i',code,len(prefix))[0]!=target:
            raise ValueError('latency RIP binding changed')
    for site,target in DIRECT.items():
        code=read(data,site,5)[1]
        if code[0]!=0xe8 or site+5+struct.unpack_from('<i',code,1)[0]!=target:raise ValueError('latency direct call changed')
    for site,target in [(0x51c9aa6,0x51c9c9e),(0x51c9ac9,0x51c9b8a)]:
        code=read(data,site,6)[1]
        if code[:2]!=b'\x0f\x84' or site+6+struct.unpack_from('<i',code,2)[0]!=target:raise ValueError('latency guard transfer changed')
    sec=next(s for s in sections(data) if s['name']=='.rela.dyn')
    rels={a:(i,v) for a,i,v in struct.iter_unpack('<QQq',data[sec['offset']:sec['offset']+sec['size']])}
    if any(rels.get(a)!=(8,v) for a,v in BINDINGS.items()):raise ValueError('latency relocation changed')
    path=b'node/src/abci_latency_sampler.rs'
    if read(data,0x44bf3e,len(path))[1]!=path:raise ValueError('latency source path changed')
    for slot,line,col in [(0x64a3618,70,38),(0x64a3630,73,48)]:
        if read(data,slot+8,16)[1]!=struct.pack('<QII',len(path),line,col):raise ValueError('latency source Location changed')
    _,fs,_=fde_extents(data);matches=[f for f in fs if (f['start'],f['end'])==(START,END)]
    if len(matches)!=1:raise ValueError('latency FDE changed')
    off,body=read(data,START,END-START)
    if hashlib.sha256(body).hexdigest()!=BODY_SHA:raise ValueError('latency instruction/dataflow changed')
    rawframes={}
    for kind in ['fde','cie']:
        va=matches[0][kind];n=struct.unpack('<I',read(data,va,4)[1])[0]+4
        rawframes[kind]={'va':hex(va),'bytes_hex':read(data,va,n)[1].hex()}
    return {'target_sha256':SHA,'start':hex(START),'end':hex(END),'bytes':END-START,'instructions':143,
            'file_offset':hex(off),'body_sha256':BODY_SHA,'frames':rawframes,'parameters':p,
            'relocations':{hex(a):hex(v) for a,v in BINDINGS.items()},
            'rip_bindings':{hex(a):hex(v) for a,(_,v) in RIP.items()},
            'direct_calls':{hex(a):hex(v) for a,v in DIRECT.items()},
            'observations':['initial tuple-provider call precedes inactive-anchor guard',
                            'optional first observer at object+0x260 receives zero for earlier anchor, else nonnegative projected pair; no local cap',
                            'normal second observer at object+0x4c0 receives min(60,nonnegative projected pair)',
                            'same second value is saved before MINSD, reloaded, and stored at record-relative+0x18 for opaque helper at object+0x720'],
            'captured_code_executed':False,
            'limits':'Source-associated local argument/dataflow only. Raw return-pair ABI, timebase, clock source, complete helper/observer/record effects, caller reachability, Rust reconstruction, runtime equivalence and all component gates remain unproved.'}


def generate(binary,output):
    data=binary.read_bytes()
    if len(data)!=105896032 or hashlib.sha256(data).hexdigest()!=SHA:raise ValueError('expected pinned node115')
    report=analyze(data);output.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory() as directory:
        snapshot=Path(directory)/'node115.elf';snapshot.write_bytes(data)
        frames=subprocess.check_output(['readelf','-wf',str(snapshot)],text=True)
        rows=[l for l in frames.splitlines() if f'pc={START:016x}..{END:016x}' in l]
        if len(rows)!=1:raise ValueError('native latency FDE disagreement')
        asm=subprocess.check_output(['objdump','-d','-M','intel','--insn-width=16',f'--start-address={START:#x}',f'--stop-address={END:#x}',str(snapshot)],text=True)
        ins=decode_export(asm,START,END,read(data,START,END-START)[1])
        if len(ins)!=143 or not set(RIP)|set(DIRECT)<=set(ins):raise ValueError('native latency instruction disagreement')
        raw=subprocess.check_output(['readelf','-rW',str(snapshot)],text=True)
        rels=[l for l in raw.splitlines() if any(l.startswith(f'{a:016x} ') for a in BINDINGS)]
        if len(rels)!=len(BINDINGS):raise ValueError('native latency relocations disagreement')
        for name,value in [('entry.objdump.txt',asm.replace(str(snapshot),'<authenticated-node115>')),('frames.txt','\n'.join(rows)+'\n'),('selected-relocations.txt','\n'.join(rels)+'\n')]:
            (output/name).write_bytes(value.encode('utf-8'))
    (output/'records.json').write_bytes((json.dumps(report,indent=2)+'\n').encode('utf-8'))
    return report


if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--binary',type=Path,default=TARGET)
    ap.add_argument('--output',type=Path,default=ROOT/'work/latency-projection115');args=ap.parse_args()
    r=generate(args.binary,args.output);print(json.dumps({'functions':1,'bytes':r['bytes'],'executed':False}))
