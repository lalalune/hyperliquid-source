#!/usr/bin/env python3
"""RE-001: node115 snapshot-associated raw selectors and dispatch, static only."""
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
PACKET=ROOT/'research/work-items/RE-001-node115-snapshot-selection'
SHA='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
SPEC_SHA='683a5e3355a6f25fc5b1fa38bf412c70d47d62ec2302b7023990e0bf7730bf4a'
MAINS=[0x22b6490,0x22b6cd0,0x22b7510,0x22b7d50]
WRAPPERS=[0x273bb10,0x273bd20]
U64=(1<<64)-1


def specification():
    raw=(PACKET/'spec.json').read_bytes()
    if hashlib.sha256(raw).hexdigest()!=SPEC_SHA:raise ValueError('snapshot specification changed')
    return json.loads(raw)


def read(data,va,n):
    matches=[s for s in sections(data) if s['type']!=8 and s['address']<=va and va+n<=s['address']+s['size']]
    if len(matches)!=1:raise ValueError('expected unique file-backed mapping')
    s=matches[0];off=s['offset']+va-s['address'];return off,bytes(data[off:off+n])


def parameters(data,a):
    if a not in MAINS:raise ValueError('outside measured selector bodies')
    for site,raw in [(a+0x1f,'48f7d8'),(a+0x22,'0f'),(a+0x478,'4883f8'),(a+0x43b,'48837c2440')]:
        value=bytes.fromhex(raw)
        if read(data,site,len(value))[1]!=value:raise ValueError('selector opcode changed')
    return {'condition':read(data,a+0x23,1)[1][0],
            'threshold':struct.unpack('<b',read(data,a+0x47b,1)[1])[0]&U64,
            'mode_equal':struct.unpack('<b',read(data,a+0x440,1)[1])[0]&U64,
            'all_buffer_offset':struct.unpack('<i',read(data,a+0x35,4)[1])[0],
            'all_count_offset':struct.unpack('<i',read(data,a+0x3c,4)[1])[0],
            'all_stride':struct.unpack('<i',read(data,a+0x40,4)[1])[0],
            'diagnostic_tag':struct.unpack('<H',read(data,a+0x5f3,2)[1])[0]}


def local_route(p,word,count):
    """Abstract branch predicate for valid raw words; not an instruction emulator."""
    if not 0<=word<=U64 or not 0<=count<=U64:raise ValueError('outside raw u64 domain')
    overflow=word==1<<63  # exact 64-bit NEG overflow condition
    if p['condition']==0x81:explicit=not overflow
    elif p['condition']==0x80:explicit=overflow
    else:raise ValueError('unsupported NEG condition')
    if not explicit:return 'all-collection-route'
    return 'diagnostic-route' if count>=p['threshold'] else 'explicit-selection-route'


def analyze(data):
    spec=specification();params={}
    for index,a in enumerate(MAINS):
        p=parameters(data,a);field=0x7c8 if index in [0,2] else 0x1338
        if p!={'condition':0x81,'threshold':101,'mode_equal':1,'all_buffer_offset':field,
               'all_count_offset':field+8,'all_stride':0x510,'diagnostic_tag':0x158}:
            raise ValueError('snapshot selector relation changed')
        for off,prefix,dst in [(0x22,b'\x0f\x81',0x474),(0x47c,b'\x0f\x83',0x5da),(0x446,b'\x0f\x85',0x530)]:
            code=read(data,a+off,6)[1]
            if code[:2]!=prefix or a+off+6+struct.unpack_from('<i',code,2)[0]!=a+dst:raise ValueError('snapshot branch transfer changed')
        params[hex(a)]=p
    for a in WRAPPERS:
        for off,raw in [(0x14,'4585c0'),(0x1d,'41bc01000000'),(0x23,'48b80000000000000080'),
                        (0x2d,'48ffc0'),(0x4e,'807f1a00'),(0x8d,'4531e4'),
                        (0x90,'48b80000000000000080'),(0x9a,'48ffc0')]:
            b=bytes.fromhex(raw)
            if read(data,a+off,len(b))[1]!=b:raise ValueError('wrapper selector/normalization changed')
    s=next(s for s in sections(data) if s['name']=='.rela.dyn')
    rels={a:(i,v) for a,i,v in struct.iter_unpack('<QQq',data[s['offset']:s['offset']+s['size']])}
    for a,row in spec['relocations'].items():
        if rels.get(int(a))!=tuple(row):raise ValueError('snapshot relocation changed')
    path=b'info_server/src/save_l4_snapshots.rs'
    if read(data,0x4318ae,len(path))[1]!=path:raise ValueError('snapshot source path changed')
    for a,col in [(0x642cd18,45),(0x642cd30,80)]:
        if read(data,a+8,16)[1]!=struct.pack('<QII',len(path),51,col):raise ValueError('snapshot source Location changed')
    for o in spec['owners']:
        for site,target in o['direct_calls'].items():
            site=int(site);code=read(data,site,5)[1]
            if code[0]!=0xe8 or site+5+struct.unpack_from('<i',code,1)[0]!=target:raise ValueError('snapshot direct call changed')
        for site,r in o['rip_bindings'].items():
            site=int(site);prefix=bytes.fromhex(r['prefix']);code=read(data,site,len(prefix)+4)[1]
            if code[:len(prefix)]!=prefix or site+len(code)+struct.unpack_from('<i',code,len(prefix))[0]!=r['target']:raise ValueError('snapshot RIP binding changed')
    _,fs,_=fde_extents(data);frames={(f['start'],f['end']):f for f in fs};owners=[]
    for o in spec['owners']:
        a,b=o['start'],o['end']
        if (a,b) not in frames:raise ValueError('snapshot FDE changed')
        offset,body=read(data,a,b-a)
        if hashlib.sha256(body).hexdigest()!=o['sha256']:raise ValueError('snapshot instruction/dataflow changed')
        raw={}
        for kind in ['fde','cie']:
            va=frames[a,b][kind];n=struct.unpack('<I',read(data,va,4)[1])[0]+4
            raw[kind]={'va':hex(va),'bytes_hex':read(data,va,n)[1].hex()}
        owners.append({'start':hex(a),'end':hex(b),'bytes':b-a,'instructions':o['instructions'],
                       'file_offset':hex(offset),'sha256':o['sha256'],'frames':raw})
    return {'target_sha256':SHA,'spec_sha256':SPEC_SHA,'owners':owners,'parameters':params,
            'wrapper_special_word':hex((1<<63)+1),'main_all_word':hex(1<<63),
            'wrapper_mode':'raw incoming R8d nonzero maps to1, zero maps to0; main compares received R8 qword to1',
            'dispatch':'wrapper0 byte+0x1a nonzero->main0, zero->main2; wrapper1 nonzero->main3, zero->main1; special word uses separate collection-builder path',
            'captured_code_executed':False,
            'limits':'Raw selector/length gates and distinct measured call routes only. Concrete request enum, asset identity, collection helpers, output-format/file effects, serializer, ownership/unwind closure, all callers, Rust reconstruction and component gates remain unproved.'}


def generate(binary,output):
    data=binary.read_bytes()
    if len(data)!=105896032 or hashlib.sha256(data).hexdigest()!=SHA:raise ValueError('expected pinned node115')
    report=analyze(data);spec=specification();output.mkdir(parents=True,exist_ok=True);frame_lines=[]
    with tempfile.TemporaryDirectory() as directory:
        snapshot=Path(directory)/'node115.elf';snapshot.write_bytes(data)
        frames=subprocess.check_output(['readelf','-wf',str(snapshot)],text=True)
        for o in spec['owners']:
            a,b=o['start'],o['end'];rows=[l for l in frames.splitlines() if f'pc={a:016x}..{b:016x}' in l]
            if len(rows)!=1:raise ValueError('native snapshot FDE disagreement')
            frame_lines.extend(rows)
            asm=subprocess.check_output(['objdump','-d','-M','intel','--insn-width=16',f'--start-address={a:#x}',f'--stop-address={b:#x}',str(snapshot)],text=True)
            ins=decode_export(asm,a,b,read(data,a,b-a)[1]);required={int(v) for v in o['direct_calls']}|{int(v) for v in o['rip_bindings']}
            if a in MAINS:required|={a+v for v in [0x1f,0x22,0x43b,0x446,0x478,0x47c]}
            if len(ins)!=o['instructions'] or not required<=set(ins):raise ValueError('native snapshot instruction disagreement')
            (output/f'{a:x}.objdump.txt').write_bytes(asm.replace(str(snapshot),'<authenticated-node115>').encode('utf-8'))
        raw=subprocess.check_output(['readelf','-rW',str(snapshot)],text=True)
        rows=[l for l in raw.splitlines() if any(l.startswith(f'{int(a):016x} ') for a in spec['relocations'])]
        if len(rows)!=len(spec['relocations']):raise ValueError('native snapshot relocation disagreement')
        (output/'selected-relocations.txt').write_bytes(('\n'.join(rows)+'\n').encode('utf-8'))
    (output/'frames.txt').write_bytes(('\n'.join(frame_lines)+'\n').encode('utf-8'))
    (output/'records.json').write_bytes((json.dumps(report,indent=2)+'\n').encode('utf-8'))
    return report


if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--binary',type=Path,default=TARGET)
    ap.add_argument('--output',type=Path,default=ROOT/'work/snapshot-selection115');args=ap.parse_args()
    r=generate(args.binary,args.output);print(json.dumps({'functions':len(r['owners']),'bytes':sum(x['bytes'] for x in r['owners']),'executed':False}))
