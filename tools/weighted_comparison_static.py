#!/usr/bin/env python3
"""RE-001: node115 checked folds and strict 128-bit weighted comparison, static only."""
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
PACKET=ROOT/'research/work-items/RE-001-node115-weighted-comparison'
SHA='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
OWNERS={
 'context':(0x3bcad50,0x3bcae80,'86c352563c86053a02323db67fb1eb785292b37da7292f2af9b0361ff64244bb',78),
 'comparison':(0x422e280,0x422e403,'c7ab574649057fbb00d19e8c935ccaa2cff819f9a238eeb90547dc721d3acb90',107),
 'first_fold':(0x43516d0,0x4351882,'76cae3d3dab57b30583a31a68963a594443c8425665077c3860cdb509adff6f1',111),
 'next':(0x37c4430,0x37c4644,'451e2db21f3ff90c6238cf77f667b6ba8093f1ab6e2873c53991c7b3be743ca5',126)}
CALLS={0x3bcae73:0x422e280,0x422e290:0x43516d0,0x422e363:0x37c4430,
       0x43516e7:0x37c5980,0x4351727:0x37c5980,0x4351816:0x4553fd0}
U64=(1<<64)-1


def read(data,va,n):
    rows=[s for s in sections(data) if s['type']!=8 and s['address']<=va and va+n<=s['address']+s['size']]
    if len(rows)!=1:
        raise ValueError('expected one file-backed mapping')
    s=rows[0];off=s['offset']+va-s['address']
    return off,bytes(data[off:off+n])


def parameters(data):
    for site,raw in [(0x422e3d6,'48c1e9'),(0x422e3da,'4d01e4'),(0x422e3dd,'ba'),
                     (0x422e3e5,'48f7e2'),(0x422e3e8,'4939c44819d1'),(0x422e3ee,'0f')]:
        code=bytes.fromhex(raw)
        if read(data,site,len(code))[1]!=code:
            raise ValueError('wide comparison opcode changed')
    return {'left_carry_shift':read(data,0x422e3d9,1)[1][0],
            'right_factor':struct.unpack('<I',read(data,0x422e3de,4)[1])[0],
            'condition_opcode':read(data,0x422e3ef,1)[1][0],
            'required_first_status':read(data,0x422e3d0,1)[1][0],
            'fast_weight_offset':read(data,0x422e2f3,1)[1][0],
            'fast_stride':read(data,0x422e30e,1)[1][0],
            'generic_weight_offset':read(data,0x422e3ab,1)[1][0]}


def wide_relation(p,s,b):
    """Two-limb arithmetic/borrow relation, not an instruction interpreter."""
    if not 0<=s<=U64 or not 0<=b<=U64 or not 0<=p['left_carry_shift']<64:
        raise ValueError('outside static unsigned-word domain')
    left_low=(s*2)&U64;left_high=s>>p['left_carry_shift']
    product=b*p['right_factor'];right_low=product&U64;right_high=product>>64
    low_borrow=int(left_low<right_low)
    borrow=left_high<right_high+low_borrow
    if p['condition_opcode']==0x92:
        return borrow
    if p['condition_opcode']==0x93:
        return not borrow
    raise ValueError('unsupported static carry condition')


def checked_sum(values):
    """Independent unsigned sum specification for checked-add boundary controls."""
    total=0
    for value in values:
        if not 0<=value<=U64:
            raise ValueError('outside unsigned weight domain')
        if total+value>U64:
            return None
        total+=value
    return total


def analyze(data):
    p=parameters(data)
    if p!={'left_carry_shift':63,'right_factor':3,'condition_opcode':0x92,'required_first_status':1,
           'fast_weight_offset':24,'fast_stride':32,'generic_weight_offset':24}:
        raise ValueError('weighted comparison relation changed')
    # Every checked sum overflow arm reaches the observed false/tag-zero block.
    for site,opcode,target in [(0x422e2f7,b'\x0f\x82',0x422e3f3),
                               (0x435171c,b'\x0f\x82',0x435186e)]:
        code=read(data,site,6)[1]
        if code[:2]!=opcode or site+6+struct.unpack_from('<i',code,2)[0]!=target:
            raise ValueError('checked-add carry transfer changed')
    code=read(data,0x422e3b4,2)[1]
    if code[0]!=0x72 or 0x422e3b6+struct.unpack('<b',code[1:])[0]!=0x422e3f3:
        raise ValueError('generic checked-add carry transfer changed')
    for site,target in CALLS.items():
        code=read(data,site,5)[1]
        if code[0]!=0xe8 or site+5+struct.unpack_from('<i',code,1)[0]!=target:
            raise ValueError('weighted fold/context call changed')
    sec=next(s for s in sections(data) if s['name']=='.rela.dyn')
    rels={a:(i,v) for a,i,v in struct.iter_unpack('<QQq',data[sec['offset']:sec['offset']+sec['size']])}
    if rels.get(0x6475bd8)!=(8,0x449efc) or rels.get(0x64dfb50)!=((12<<32)|6,0):
        raise ValueError('weighted source/comparator relocation changed')
    path=b'base/src/quorum_policy.rs'
    if read(data,0x449efc,len(path))[1]!=path or read(data,0x6475be0,16)[1]!=struct.pack('<QII',len(path),72,9):
        raise ValueError('weighted source Location changed')
    code=read(data,0x3bcae64,7)[1]
    if code[:3]!=b'\x48\x8d\x15' or 0x3bcae6b+struct.unpack_from('<i',code,3)[0]!=0x6475bd8:
        raise ValueError('weighted source LEA changed')
    _,fs,_=fde_extents(data);frames={(f['start'],f['end']):f for f in fs};owners=[]
    for role,(a,b,sha,count) in OWNERS.items():
        if (a,b) not in frames:
            raise ValueError('weighted scope FDE changed')
        offset,body=read(data,a,b-a)
        if hashlib.sha256(body).hexdigest()!=sha:
            raise ValueError('weighted instruction/dataflow changed')
        rawframes={}
        for kind in ['fde','cie']:
            va=frames[(a,b)][kind];n=struct.unpack('<I',read(data,va,4)[1])[0]+4
            rawframes[kind]={'va':hex(va),'bytes_hex':read(data,va,n)[1].hex()}
        owners.append({'role':role,'start':hex(a),'end':hex(b),'bytes':b-a,'instructions':count,'file_offset':hex(offset),'sha256':sha,'frames':rawframes})
    return {'target_sha256':SHA,'owners':owners,'parameters':p,
            'normal_comparison':'on normal second-fold completion and first returned word==1: AL1 iff unsigned128(2*S)<unsigned128(3*B)',
            's_definition':'checked u64 sum from second stream; fast rows use+0x18 and stride0x20, generic next supplies a word pointer',
            'b_definition':'RDX of first checked-fold helper on its raw status1 path; key/collection meaning not fully recovered',
            'overflow':'second checked-add carry selects AL0; first helper checked-add carry selects raw status0, which cannot pass the final status1 gate',
            'wide_proof':'2*S=(S>>63)*2^64 + (2*S mod2^64); MUL produces both limbs of3*B. CMP low then SBB high carries the exact low borrow; SETB gives unsigned128 less-than. Both products fit66 bits; ties return0.',
            'max_left_product':2*U64,'max_right_product':3*U64,
            'direct_bindings':{hex(a):hex(v) for a,v in CALLS.items()},
            'captured_code_executed':False,
            'limits':'Checked folds/strict cross-product and source-context mapping only. Full input collections, membership/duplicates, validator/total/selected roles, Rust map/iterator ABI, unmeasured lookup/next helpers, caller reachability, protocol security and reconstruction gates remain unproved.'}


def generate(binary,output):
    data=binary.read_bytes()
    if len(data)!=105896032 or hashlib.sha256(data).hexdigest()!=SHA:
        raise ValueError('expected pinned node115')
    report=analyze(data);output.mkdir(parents=True,exist_ok=True);lines=[]
    with tempfile.TemporaryDirectory() as directory:
        snapshot=Path(directory)/'node115.elf';snapshot.write_bytes(data)
        frames=subprocess.check_output(['readelf','-wf',str(snapshot)],text=True)
        for role,(a,b,_,count) in OWNERS.items():
            rows=[l for l in frames.splitlines() if f'pc={a:016x}..{b:016x}' in l]
            if len(rows)!=1:
                raise ValueError('native weighted FDE disagreement')
            lines.extend(rows)
            asm=subprocess.check_output(['objdump','-d','-M','intel','--insn-width=16',f'--start-address={a:#x}',f'--stop-address={b:#x}',str(snapshot)],text=True)
            ins=decode_export(asm,a,b,read(data,a,b-a)[1])
            required={v for v in CALLS if a<=v<b}
            if role=='comparison':required|={0x422e2f0,0x422e2f7,0x422e3b1,0x422e3b4,0x422e3cd,0x422e3d6,0x422e3da,0x422e3dd,0x422e3e5,0x422e3e8,0x422e3eb,0x422e3ee}
            if len(ins)!=count or not required<=set(ins):
                raise ValueError('native weighted count/instruction boundary disagreement')
            (output/f'{role}.objdump.txt').write_bytes(asm.replace(str(snapshot),'<authenticated-node115>').encode('utf-8'))
        raw=subprocess.check_output(['readelf','-rW',str(snapshot)],text=True)
        selected=[l for l in raw.splitlines() if l.startswith(('0000000006475bd8 ','00000000064dfb50 '))]
        if len(selected)!=2 or 'memcmp@GLIBC_2.2.5' not in '\n'.join(selected):
            raise ValueError('native weighted source/import relocation disagreement')
        (output/'selected-relocations.txt').write_bytes(('\n'.join(selected)+'\n').encode('utf-8'))
    (output/'frames.txt').write_bytes(('\n'.join(lines)+'\n').encode('utf-8'))
    (output/'records.json').write_bytes((json.dumps(report,indent=2)+'\n').encode('utf-8'))
    return report


if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--binary',type=Path,default=TARGET)
    ap.add_argument('--output',type=Path,default=ROOT/'work/weighted-comparison115')
    args=ap.parse_args();r=generate(args.binary,args.output)
    print(json.dumps({'functions':len(r['owners']),'bytes':sum(x['bytes'] for x in r['owners']),'executed':False}))
