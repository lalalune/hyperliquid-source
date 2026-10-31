#!/usr/bin/env python3
"""RE-001: node115 capacity guard, encoded state and conditional CAS step."""
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
PACKET=ROOT/'research/work-items/RE-001-node115-ip-permit-state'
SHA='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
OWNERS={'step':(0x4770f40,0x47710d9,'085721faf2d6da872af52d3a7d41f276d7e77f54dd112d73fe2ce593453d7c1a'),
        'constructor':(0x47710e0,0x477165a,'42a37dbf8d9b6a146327b41470416cde070ebc827dfadb5eab9e9f24132ab677')}
BINDINGS={0x6496548:0x432e0f,0x6496560:0x432e0f,0x64e21f8:0x5ce88c0,
          0x64e01f8:0x5bb59d0,0x64e1078:0x154c700,0x64df480:0x6355830}
DIRECT={0x4770fe7:0x4774c50,0x477106e:0x5ce5310,0x47710c6:0x47707a0,0x47710ce:0x63f0a50}
U64=(1<<64)-1


def read(data,va,n):
    rows=[s for s in sections(data) if s['type']!=8 and s['address']<=va and va+n<=s['address']+s['size']]
    if len(rows)!=1:
        raise ValueError('expected one file-backed mapping')
    s=rows[0];off=s['offset']+va-s['address']
    return off,bytes(data[off:off+n])


def parameters(data):
    for va,raw in [(0x47710fe,'48c1e8'),(0x4771128,'4d01e4'),(0x4770f62,'498b47'),
                   (0x4770f70,'a8'),(0x4770f78,'4883f8'),(0x4770f82,'488d48'),
                   (0x4770f86,'f0490fb14f'),(0x4771145,'4c8960')]:
        code=bytes.fromhex(raw)
        if read(data,va,len(code))[1]!=code:
            raise ValueError('permit parameter opcode changed')
    return {'capacity_shift':read(data,0x4771101,1)[1][0],
            'state_read_offset':read(data,0x4770f65,1)[1][0],
            'state_init_offset':read(data,0x4771148,1)[1][0],
            'cas_offset':read(data,0x4770f8b,1)[1][0],
            'closed_mask':read(data,0x4770f71,1)[1][0],
            'threshold':read(data,0x4770f7b,1)[1][0],
            'delta':struct.unpack('<b',read(data,0x4770f85,1)[1])[0]}


def guard_passes(p,capacity):
    """Projection of the captured SHR/JNE guard, not target execution."""
    if not 0<=capacity<=U64 or not 0<=p['capacity_shift']<64:
        raise ValueError('outside static u64 guard domain')
    return capacity>>p['capacity_shift']==0


def attempt_projection(p,word):
    """Local bit predicates and proposed update, conditional on a winning CAS."""
    if not 0<=word<=U64:
        raise ValueError('outside static state-word domain')
    if word&p['closed_mask']:
        return 'flag-gate',word
    if word<p['threshold']:
        return 'empty-gate',word
    return 'eligible',(word+p['delta'])&U64


def analyze(data):
    p=parameters(data)
    if p!={'capacity_shift':61,'state_read_offset':48,'state_init_offset':48,'cas_offset':48,'closed_mask':1,'threshold':2,'delta':-2}:
        raise ValueError('permit guard/encoding/step relation changed')
    # Constructor shift guard and conditional CAS retry destinations.
    for site,opcode,target in [(0x4771102,b'\x0f\x85',0x4771527),
                               (0x4770f72,b'\x0f\x85',0x477100d),
                               (0x4770f7c,b'\x0f\x82',0x4771039)]:
        code=read(data,site,6)[1]
        if code[:2]!=opcode or site+6+struct.unpack_from('<i',code,2)[0]!=target:
            raise ValueError('permit guard transfer changed')
    code=read(data,0x4770f8c,2)[1]
    if code[0]!=0x75 or 0x4770f8e+struct.unpack('<b',code[1:])[0]!=0x4770f70:
        raise ValueError('CAS retry transfer changed')
    sec=next(s for s in sections(data) if s['name']=='.rela.dyn')
    rels={a:(i,v) for a,i,v in struct.iter_unpack('<QQq',data[sec['offset']:sec['offset']+sec['size']])}
    if any(rels.get(a)!=(8,v) for a,v in BINDINGS.items()):
        raise ValueError('permit source/code relocation changed')
    path=b'net_utils/src/ip_semaphore.rs'
    if read(data,0x432e0f,len(path))[1]!=path:
        raise ValueError('permit source path changed')
    for slot,line,col,site in [(0x6496548,37,51,0x4770fd4),(0x6496560,28,35,0x4771264)]:
        if read(data,slot+8,16)[1]!=struct.pack('<QII',len(path),line,col):
            raise ValueError('permit source Location changed')
        code=read(data,site,7)[1]
        if code[:2]!=b'\x48\x8d' and code[:2]!=b'\x4c\x8d':
            raise ValueError('permit source LEA opcode changed')
        if site+7+struct.unpack_from('<i',code,3)[0]!=slot:
            raise ValueError('permit source LEA target changed')
    for site,target in DIRECT.items():
        code=read(data,site,5)[1]
        if code[0]!=0xe8 or site+5+struct.unpack_from('<i',code,1)[0]!=target:
            raise ValueError('permit provider/cleanup call changed')
    _,fs,_=fde_extents(data);fdes={(f['start'],f['end']):f for f in fs};owners=[]
    for role,(a,b,sha) in OWNERS.items():
        if (a,b) not in fdes:
            raise ValueError('permit FDE extent changed')
        off,raw=read(data,a,b-a)
        if hashlib.sha256(raw).hexdigest()!=sha:
            raise ValueError('permit instruction/argument dataflow changed')
        frames={}
        for kind in ['fde','cie']:
            va=fdes[(a,b)][kind];n=struct.unpack('<I',read(data,va,4)[1])[0]+4
            frames[kind]={'va':hex(va),'bytes_hex':read(data,va,n)[1].hex()}
        owners.append({'role':role,'start':hex(a),'end':hex(b),'bytes':b-a,'instructions':101 if role=='step' else 255,'file_offset':hex(off),'sha256':sha,'frames':frames})
    return {'target_sha256':SHA,'owners':owners,'parameters':p,
            'capacity_guard_pass_domain':[0,(1<<61)-1],
            'initial_state_equation':'word=2*capacity; even, <=2^62-2; bit0 clear',
            'conditional_success_equation':'even word>=2 and winning CAS: word becomes word-2; abstract word/2 decreases by1',
            'local_failure_output_tags':{'odd_gate':0,'empty_gate':1,'provider_zero':'provider byte propagated'},
            'provider_success_output':'owner pointer at+0; dword1 at+8; provider word at+0x10 and dword at+0x18',
            'provider_failure_followup':'after raw output stores, byte CAS at owner+0x10 then opaque call5ce5310 with (owner+0x10,1,owner+0x10), then owner decrement',
            'relative_bindings':{hex(a):hex(v) for a,v in BINDINGS.items()},
            'direct_bindings':{hex(a):hex(v) for a,v in DIRECT.items()},
            'captured_code_executed':False,
            'limits':'Static constructor initialization prefix and conditional packed-state attempt only. No complete constructor return, IP/key/cache policy, original Rust layout/error ABI, all callers, helper/rollback/unwind closure, concurrency fairness/exclusion guarantee or gate. No post-INC signed-value interpretation of JLE is assumed.'}


def generate(binary,output):
    data=binary.read_bytes()
    if len(data)!=105896032 or hashlib.sha256(data).hexdigest()!=SHA:
        raise ValueError('expected pinned node115')
    report=analyze(data);output.mkdir(parents=True,exist_ok=True);lines=[]
    with tempfile.TemporaryDirectory() as directory:
        snapshot=Path(directory)/'node115.elf';snapshot.write_bytes(data)
        frames=subprocess.check_output(['readelf','-wf',str(snapshot)],text=True)
        for role,(a,b,_) in OWNERS.items():
            rows=[l for l in frames.splitlines() if f'pc={a:016x}..{b:016x}' in l]
            if len(rows)!=1:
                raise ValueError('native permit FDE disagreement')
            lines.extend(rows)
            asm=subprocess.check_output(['objdump','-d','-M','intel','--insn-width=16',f'--start-address={a:#x}',f'--stop-address={b:#x}',str(snapshot)],text=True)
            ins=decode_export(asm,a,b,read(data,a,b-a)[1])
            required=({0x4770f62,0x4770f70,0x4770f78,0x4770f82,0x4770f86,0x4770f8c,0x4770fd4,0x4770fe7,0x477106e}
                      if role=='step' else {0x47710fe,0x4771102,0x4771128,0x4771145,0x4771264})
            if len(ins)!=(101 if role=='step' else 255) or not required<=set(ins):
                raise ValueError('permit certificate site not native instruction start')
            (output/f'{role}.objdump.txt').write_bytes(asm.replace(str(snapshot),'<authenticated-node115>').encode('utf-8'))
    (output/'frames.txt').write_bytes(('\n'.join(lines)+'\n').encode('utf-8'))
    (output/'records.json').write_bytes((json.dumps(report,indent=2)+'\n').encode('utf-8'))
    return report


if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--binary',type=Path,default=TARGET)
    ap.add_argument('--output',type=Path,default=ROOT/'work/ip-permit-state115')
    args=ap.parse_args();r=generate(args.binary,args.output)
    print(json.dumps({'functions':len(r['owners']),'bytes':sum(x['bytes'] for x in r['owners']),'executed':False}))
