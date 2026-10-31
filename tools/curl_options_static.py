#!/usr/bin/env python3
"""RE-012: node115 curl command-builder material and argument bindings; static only."""
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
PACKET=ROOT/'research/work-items/RE-012-node115-curl-options'
SHA='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
SPEC_SHA='bbd83f7678d32789866a8ff645304bbdca92fb614ecee58e0ebe4c5023a657bd'
BUILDERS=[0x15354f0,0x1535930,0x4e4bdb0,0x4e4c1f0]
LITERALS={0x43fecd:b'\x13 --connect-timeout \xc0\0',0x440ecb:b'\x04 -o \xc0\0',
          0x43aafa:b'\x0a/tmp/curl.\xc0\0',
          0x44a8f8:b"\x34 --header 'Content-Type: application/json' --data '@\xc0\x01'\0",
          0x4345ba:b'\x09curl -fsS\xc0\x01 \xc0\0'}


def load_spec():
    raw=(PACKET/'spec.json').read_bytes()
    if hashlib.sha256(raw).hexdigest()!=SPEC_SHA:
        raise ValueError('curl scope specification changed')
    return json.loads(raw)


def read(data,va,n):
    matches=[s for s in sections(data) if s['type']!=8 and s['address']<=va and va+n<=s['address']+s['size']]
    if len(matches)!=1:
        raise ValueError('expected one file-backed mapping')
    s=matches[0];off=s['offset']+va-s['address']
    return off,bytes(data[off:off+n])


def default_fragment(body):
    if body[0x47:0x49]!=b'\x48\xb9' or body[0x55:0x57]!=b'\x48\xb9':
        raise ValueError('curl default MOVABS opcode changed')
    tail,head=body[0x49:0x51],body[0x57:0x5f]
    if head[-1]!=tail[0]:
        raise ValueError('curl overlapping literal stores disagree')
    return head+tail[1:]


def analyze(data):
    spec=load_spec();_,fs,_=fde_extents(data);frames={(f['start'],f['end']):f for f in fs}
    sec=next(s for s in sections(data) if s['name']=='.rela.dyn')
    rels={a:(i,v) for a,i,v in struct.iter_unpack('<QQq',data[sec['offset']:sec['offset']+sec['size']])}
    for slot,row in spec['bindings'].items():
        if rels.get(int(slot,16))!=(row['info'],int(row['addend'],16)):
            raise ValueError('curl code/source/format relocation changed')
    for address,raw in spec['format_objects'].items():
        if read(data,int(address,16),len(bytes.fromhex(raw)))[1]!=bytes.fromhex(raw):
            raise ValueError('curl formatter object changed')
    for a,raw in LITERALS.items():
        if read(data,a,len(raw))[1]!=raw:
            raise ValueError('curl descriptor bytes changed')
    for slot in [0x63fd790,0x649db18]:
        pointer=rels[slot][1];path=b'base/src/curl.rs'
        if read(data,pointer,len(path))[1]!=path or read(data,slot+8,16)[1]!=struct.pack('<QII',len(path),55,13):
            raise ValueError('curl source Location changed')
    owners=[]
    for row in spec['owners']:
        start,end=int(row['start'],16),int(row['end'],16)
        if (start,end) not in frames:
            raise ValueError('curl FDE scope changed')
        off,body=read(data,start,end-start)
        if start in BUILDERS:
            if default_fragment(body)!=b' --max-time 300':
                raise ValueError('curl default option literal changed')
            sizes=[struct.unpack_from('<I',body,at)[0] for at in [0x34,0x67,0x75]]
            if sizes!=[15,15,15]:
                raise ValueError('curl default allocation/capacity/length changed')
            if body[0x2c:0x33]!=bytes.fromhex('4c8b2e4c8b7608') or body[0x79:0x7d]!=bytes.fromhex('4d85ed74'):
                raise ValueError('curl connect presence/value gate changed')
        for item in row['references']+row['transfers']:
            site,target=int(item['site'],16),int(item['target'],16);code=bytes.fromhex(item['hex'])
            if read(data,site,len(code))[1]!=code:
                raise ValueError('curl reference/call operand changed')
            displacement=3 if item in row['references'] else (2 if item['kind']=='rip' else 1)
            if site+len(code)+struct.unpack_from('<i',code,displacement)[0]!=target:
                raise ValueError('curl reference/call coordinate changed')
        if hashlib.sha256(body).hexdigest()!=row['body_sha256']:
            raise ValueError('curl instruction/argument dataflow changed')
        rawframes={}
        for kind in ['fde','cie']:
            va=frames[(start,end)][kind];n=struct.unpack('<I',read(data,va,4)[1])[0]+4
            rawframes[kind]={'va':hex(va),'bytes_hex':read(data,va,n)[1].hex()}
        owners.append({'start':row['start'],'end':row['end'],'file_offset':hex(off),'bytes':len(body),'instructions':row['instructions'],'sha256':row['body_sha256'],'frames':rawframes})
    return {'target_sha256':SHA,'spec_sha256':SPEC_SHA,'owners':owners,
            'initial_option_buffer':' --max-time 300','initial_option_bytes':15,
            'connect_presence_and_value':'input+0 nonzero; value at input+8 is passed to bound formatter',
            'other_inputs':'input+0x10: two-word final argument; input+0x20/+0x28: output argument; input+0x30: raw body selector',
            'descriptors':{hex(a):raw.hex() for a,raw in LITERALS.items()},
            'callback_pairs':[['0x15ebba0','0x1531e10'],['0x5616320','0x4e188d0']],
            'opaque_payload_helpers':['0x15053f0','0x1505080','0x50ddcc0','0x50de300'],
            'captured_code_executed':False,
            'limits':'Materialized defaults, local gates and actual format/call/data bindings only. Formatter/allocator/helper/error/unwind/IO closure, concrete Rust input types, complete returned command equivalence, runtime curl version/timeout/network behavior, escaping/security policy and production caller reachability remain unproved. No gate.'}


def generate(binary,output):
    data=binary.read_bytes()
    if len(data)!=105896032 or hashlib.sha256(data).hexdigest()!=SHA:
        raise ValueError('expected pinned node115')
    report=analyze(data);spec=load_spec();output.mkdir(parents=True,exist_ok=True);lines=[]
    with tempfile.TemporaryDirectory() as directory:
        snapshot=Path(directory)/'node115.elf';snapshot.write_bytes(data)
        native=subprocess.check_output(['readelf','-wf',str(snapshot)],text=True)
        for row in spec['owners']:
            a,b=int(row['start'],16),int(row['end'],16)
            chosen=[l for l in native.splitlines() if f'pc={a:016x}..{b:016x}' in l]
            if len(chosen)!=1:
                raise ValueError('native curl FDE disagreement')
            lines.extend(chosen)
            asm=subprocess.check_output(['objdump','-d','-M','intel','--insn-width=16',f'--start-address={a:#x}',f'--stop-address={b:#x}',str(snapshot)],text=True)
            ins=decode_export(asm,a,b,read(data,a,b-a)[1])
            required={int(i['site'],16) for i in row['references']+row['transfers']}
            if len(ins)!=row['instructions'] or not required<=set(ins):
                raise ValueError('native curl instruction denominator/boundaries changed')
            (output/f'{a:x}.objdump.txt').write_bytes(asm.replace(str(snapshot),'<authenticated-node115>').encode('utf-8'))
    (output/'frames.txt').write_bytes(('\n'.join(lines)+'\n').encode('utf-8'))
    (output/'records.json').write_bytes((json.dumps(report,indent=2)+'\n').encode('utf-8'))
    return report


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary',type=Path,default=TARGET)
    p.add_argument('--output',type=Path,default=ROOT/'work/curl-options115')
    args=p.parse_args();report=generate(args.binary,args.output)
    print(json.dumps({'functions':len(report['owners']),'bytes':sum(x['bytes'] for x in report['owners']),'executed':False}))
