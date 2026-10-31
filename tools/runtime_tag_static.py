#!/usr/bin/env python3
"""RE-002: node115 runtime mask tag and two source-associated initializers, static only."""
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
PACKET=ROOT/'research/work-items/RE-002-node115-runtime-tag'
SHA='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
SPEC_SHA='d84ce3fb8f1d82bc498a34f4380d48201248c5006c5f6ef22d6cfd8152d2bcf4'
CALLERS=[0x38d2920,0x38d2b00]
BRANCHES={0x160beee:0x160bf2a,0x160bef5:0x160bf09,0x160befd:0x160bf4b,
          0x160bf07:0x160bf5e,0x160bf0f:0x160bf39,0x160bf16:0x160bf5e,
          0x160bf1e:0x160bf60,0x160bf35:0x160bef7,0x160bf37:0x160bf09,
          0x160bf47:0x160bf18,0x160bf49:0x160bf5e,0x160bf5c:0x160bf09,0x160bf66:0x160bf20}
U64=(1<<64)-1


def specification():
    raw=(PACKET/'spec.json').read_bytes()
    if hashlib.sha256(raw).hexdigest()!=SPEC_SHA:raise ValueError('runtime-tag specification changed')
    return json.loads(raw)


def read(data,va,n):
    matches=[s for s in sections(data) if s['type']!=8 and s['address']<=va and va+n<=s['address']+s['size']]
    if len(matches)!=1:raise ValueError('expected unique file-backed mapping')
    s=matches[0];off=s['offset']+va-s['address'];return off,bytes(data[off:off+n])


def parameters(data):
    for site,raw in [(0x160bef0,'a9'),(0x160bf01,'f7c1'),(0x160bf13,'6685c9'),
                     (0x160bf20,'c1e8'),(0x160bf23,'83e0'),(0x160bf26,'fec0')]:
        b=bytes.fromhex(raw)
        if read(data,site,len(b))[1]!=b:raise ValueError('runtime tag opcode changed')
    return {'first_mask':struct.unpack('<I',read(data,0x160bef1,4)[1])[0],
            'second_mask':struct.unpack('<I',read(data,0x160bf03,4)[1])[0],
            'word_sign_condition':read(data,0x160bf16,1)[1][0],
            'fallback_shift':read(data,0x160bf22,1)[1][0],
            'fallback_mask':read(data,0x160bf25,1)[1][0],
            'high_tag':read(data,0x160bf00,1)[1][0],
            'word_sign_tag':read(data,0x160bf12,1)[1][0]}


def stable_tag(p,mask):
    """Stable nonzero cache-word relation, not a processor/feature detector."""
    if not 0<mask<=U64:raise ValueError('requires stable nonzero raw cache word')
    if (mask&p['first_mask']) and (mask&p['second_mask']):return p['high_tag']
    sign=bool(mask&(1<<15))
    if p['word_sign_condition']==0x79:sign=not sign
    elif p['word_sign_condition']!=0x78:raise ValueError('unsupported word sign condition')
    if sign:return p['word_sign_tag']
    return (((mask&0xffffffff)>>p['fallback_shift'])&p['fallback_mask'])+1


def analyze(data):
    p=parameters(data)
    if p!={'first_mask':1<<19,'second_mask':1<<25,'word_sign_condition':0x78,
           'fallback_shift':10,'fallback_mask':1,'high_tag':4,'word_sign_tag':3}:
        raise ValueError('runtime tag relation changed')
    for site,dst in BRANCHES.items():
        code=read(data,site,2)[1]
        if code[0] not in [0x74,0x75,0x78,0x79,0xeb] or site+2+struct.unpack('<b',code[1:])[0]!=dst:
            raise ValueError('runtime tag branch transfer changed')
    # Repeated cold-arm predicates/tags and ordinary return sites.
    for site,raw in [(0x160bf30,'a900000800'),(0x160bf42,'b003'),(0x160bf54,'b004'),
                     (0x160bf56,'f7c100000002'),(0x160bf28,'5bc3'),(0x160bf5e,'5bc3')]:
        b=bytes.fromhex(raw)
        if read(data,site,len(b))[1]!=b:raise ValueError('runtime cold/return control changed')
    for a in CALLERS:
        # AL is not overwritten between the selector call and its byte store.
        for off,raw in [(0xe6,'888424cb000000'),(0xf8,'488d7c2460'),(0x109,'488d742460')]:
            b=bytes.fromhex(raw)
            if read(data,a+off,len(b))[1]!=b:raise ValueError('caller tag/context binding changed')
    spec=specification()
    for o in spec['owners']:
        for site,target in o['direct_calls'].items():
            site=int(site);code=read(data,site,5)[1]
            if code[0]!=0xe8 or site+5+struct.unpack_from('<i',code,1)[0]!=target:raise ValueError('runtime direct call changed')
        for site,row in o['rip_bindings'].items():
            site=int(site);prefix=bytes.fromhex(row['prefix']);code=read(data,site,len(prefix)+4)[1]
            if code[:len(prefix)]!=prefix or site+len(code)+struct.unpack_from('<i',code,len(prefix))[0]!=row['target']:raise ValueError('runtime RIP binding changed')
    s=next(s for s in sections(data) if s['name']=='.rela.dyn')
    rels={a:(i,v) for a,i,v in struct.iter_unpack('<QQq',data[s['offset']:s['offset']+s['size']])}
    if any(rels.get(int(a))!=tuple(row) for a,row in spec['relocations'].items()):raise ValueError('runtime relocation changed')
    path=b'l1/src/utils.rs'
    if read(data,0x44ada0,len(path))[1]!=path or read(data,0x646e9b0,16)[1]!=struct.pack('<QII',len(path),28,43):raise ValueError('runtime caller source Location changed')
    _,fs,_=fde_extents(data);frames={(f['start'],f['end']):f for f in fs};owners=[]
    for o in spec['owners']:
        a,b=o['start'],o['end']
        if (a,b) not in frames:raise ValueError('runtime FDE changed')
        off,body=read(data,a,b-a)
        if hashlib.sha256(body).hexdigest()!=o['sha256']:raise ValueError('runtime instruction/dataflow changed')
        raw={}
        for kind in ['fde','cie']:
            va=frames[a,b][kind];n=struct.unpack('<I',read(data,va,4)[1])[0]+4
            raw[kind]={'va':hex(va),'bytes_hex':read(data,va,n)[1].hex()}
        owners.append({'start':hex(a),'end':hex(b),'bytes':b-a,'instructions':o['instructions'],'file_offset':hex(off),'sha256':o['sha256'],'frames':raw})
    return {'target_sha256':SHA,'spec_sha256':SPEC_SHA,'owners':owners,'parameters':p,
            'stable_nonzero_cache':'bits19 and25 ->4, else bit15 ->3, else bit10 ->2, else1; only under stable nonzero cache across repeated reads',
            'normal_return_domain':[1,2,3,4],
            'caller_flow':'normal raw marker 0x8000000000000004 path calls slot64df488, stores unchanged AL at stack+0xcb; context passed to update/finalize starts stack+0x60, so tag byte is context+0x6b',
            'cache_slot':hex(0x64dfa60),'refresh_slot':hex(0x64dfa68),
            'captured_code_executed':False,
            'limits':'One selected runtime tag relation and two initializer callers. Cache initializer, CPU/ISA bit names, stable-cache concurrency, update/finalize/hash algorithm, baseline CPU flags, all callers, Rust reconstruction and component gates remain unproved.'}


def generate(binary,output):
    data=binary.read_bytes()
    if len(data)!=105896032 or hashlib.sha256(data).hexdigest()!=SHA:raise ValueError('expected pinned node115')
    report=analyze(data);spec=specification();output.mkdir(parents=True,exist_ok=True);frame_lines=[]
    with tempfile.TemporaryDirectory() as directory:
        snapshot=Path(directory)/'node115.elf';snapshot.write_bytes(data)
        frames=subprocess.check_output(['readelf','-wf',str(snapshot)],text=True)
        for o in spec['owners']:
            a,b=o['start'],o['end'];rows=[l for l in frames.splitlines() if f'pc={a:016x}..{b:016x}' in l]
            if len(rows)!=1:raise ValueError('native runtime-tag FDE disagreement')
            frame_lines.extend(rows)
            asm=subprocess.check_output(['objdump','-d','-M','intel','--insn-width=16',f'--start-address={a:#x}',f'--stop-address={b:#x}',str(snapshot)],text=True)
            ins=decode_export(asm,a,b,read(data,a,b-a)[1]);required={int(v) for v in o['direct_calls']}|{int(v) for v in o['rip_bindings']}
            if a==0x160bee0:required|=set(BRANCHES)|{0x160bef0,0x160bf01,0x160bf13,0x160bf20}
            else:required|={a+off for off in [0xe6,0xf8,0x109]}
            if len(ins)!=o['instructions'] or not required<=set(ins):raise ValueError('native runtime-tag instruction disagreement')
            (output/f'{a:x}.objdump.txt').write_bytes(asm.replace(str(snapshot),'<authenticated-node115>').encode('utf-8'))
        raw=subprocess.check_output(['readelf','-rW',str(snapshot)],text=True)
        rows=[l for l in raw.splitlines() if any(l.startswith(f'{int(a):016x} ') for a in spec['relocations'])]
        if len(rows)!=len(spec['relocations']):raise ValueError('native runtime-tag relocation disagreement')
        (output/'selected-relocations.txt').write_bytes(('\n'.join(rows)+'\n').encode('utf-8'))
    (output/'frames.txt').write_bytes(('\n'.join(frame_lines)+'\n').encode('utf-8'))
    (output/'records.json').write_bytes((json.dumps(report,indent=2)+'\n').encode('utf-8'))
    return report


if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--binary',type=Path,default=TARGET)
    ap.add_argument('--output',type=Path,default=ROOT/'work/runtime-tag115');args=ap.parse_args()
    r=generate(args.binary,args.output);print(json.dumps({'functions':len(r['owners']),'bytes':sum(x['bytes'] for x in r['owners']),'executed':False}))
