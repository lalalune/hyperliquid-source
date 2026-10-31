#!/usr/bin/env python3
"""RE-001: static certificates for node115 WireQty-associated scalar preparation."""
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
PACKET=ROOT/'research/work-items/RE-001-node115-wire-qty-normal-form'
SHA='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
START,END=0x41c57f0,0x41c5b83
BODY_SHA='697cfe8a1ab3360ab1777aff851cd9f4f65ba39e47eb842845d075831ac84483'
U32=(1<<32)-1
U64=(1<<64)-1
HMAX=(1<<31)-1
# Actual multiplier instruction, immediate offset, shift instruction, divisor,
# and preshift. Each site is independently confirmed as a native instruction.
HIGH=[(0x41c582c,2,0x41c5836,10,0),(0x41c58d0,3,0x41c58d7,100,0),
      (0x41c5913,3,0x41c591a,1000,0),(0x41c595f,2,0x41c5969,10000,0),
      (0x41c59a9,3,0x41c59b0,100000,5),(0x41c59f8,3,0x41c59ff,1000000,0),
      (0x41c5a3b,3,0x41c5a42,10000000,0),(0x41c5a87,3,0x41c5a8e,100000000,0)]
REM=[(0x41c588f,0x41c5896),(0x41c58db,0x41c58e2),(0x41c591e,0x41c5925),(0x41c596d,0x41c5974)]
SMALL=[(0x41c59b4,0x41c59bb,0x41c59be,21474,0xfe),
       (0x41c5a03,0x41c5a0a,0x41c5a0d,2147,0xfe),
       (0x41c5a46,0x41c5a4d,0x41c5a50,214,0x3e)]
FLAGS=[0x41c5882,0x41c58c0,0x41c5909,0x41c594f,0x41c599b,0x41c59e8,0x41c5a34,0x41c5a7a]
TEST_BRANCHES=[0x41c587d,0x41c58be,0x41c5907,0x41c594d,0x41c5999,0x41c59e6,0x41c5a32,0x41c5a78]
BINDINGS={0x64e95c8:0x5c449c0,0x64df6a0:0x1680c30,0x64df4a0:0x635de30,0x6482050:0x43e2bd}


def read(data,va,n):
    rows=[s for s in sections(data) if s['type']!=8 and s['address']<=va and va+n<=s['address']+s['size']]
    if len(rows)!=1:
        raise ValueError('expected one file-backed mapping')
    s=rows[0];off=s['offset']+va-s['address']
    return off,bytes(data[off:off+n])


def reciprocal(c,shift,d,maximum):
    """Two-endpoint proof for all n in [0,N], not a sampled input test."""
    scale=1<<shift;error=c*d-scale
    if c<=0 or error<0:
        raise ValueError('reciprocal rounds downward')
    q,r=divmod(maximum,d)
    bounds=[q*error+r*c]
    if q:
        bounds.append((q-1)*error+(d-1)*c)
    worst=max(bounds)
    if worst>=scale:
        raise ValueError('reciprocal fails declared domain')
    return {'multiplier':hex(c),'shift':shift,'divisor':d,'maximum_input':maximum,
            'error':error,'extreme_fractional_numerators':bounds,'scale':scale,
            'complete_integer_domain':True}


def parameters(data):
    high=[]
    for site,offset,shift_site,d,pre in HIGH:
        c=struct.unpack('<I',read(data,site+offset,4)[1])[0]
        shift=read(data,shift_site+3,1)[1][0]
        if pre and read(data,0x41c59a8,1)[1]!=bytes([pre]):
            raise ValueError('high-limb preshift changed')
        high.append({'multiplier':c,'shift':shift,'divisor':d,'preshift':pre})
    return {'high':high,'low_multiplier':struct.unpack('<Q',read(data,0x41c5851,8)[1])[0],
            'inverse_five':struct.unpack('<Q',read(data,0x41c5861,8)[1])[0],
            'divisibility_bound':struct.unpack('<Q',read(data,0x41c5872,8)[1])[0]}


def divisible_ten(x,inverse,bound):
    """Closed modular predicate extracted from IMUL/ROR/CMP, no CPU interpreter."""
    product=(x*inverse)&U64
    rotated=(product>>1)|((product&1)<<63)
    return rotated<=bound


def normal_form(n):
    """Independent mathematical normal form; not a recovered target implementation."""
    if not 0<=n<(1<<63):
        raise ValueError('normal-form domain is the unsigned low63 bits')
    if n==0:
        return 0,0
    coefficient,scale=n,8
    while scale and coefficient%10==0:
        coefficient//=10;scale-=1
    return coefficient,scale


def limb_relation(n,params):
    """Algebraic split-limb recurrence used only to check the preparation theorem."""
    if not 0<=n<(1<<63):
        raise ValueError('limb-relation domain is the unsigned low63 bits')
    if n==0:
        return 0,0
    high0=n>>32;low=n&U32
    highs=[high0]+[((high0>>r['preshift'])*r['multiplier'])>>r['shift'] for r in params['high']]
    for k in range(8):
        mixed=(highs[k]%10)*(1<<32)+low
        if not divisible_ten(mixed,params['inverse_five'],params['divisibility_bound']):
            return (highs[k]<<32)|low,8-k
        low=(mixed*params['low_multiplier'])>>64
    return (highs[8]<<32)|low,0


def analyze(data):
    _,fs,_=fde_extents(data);f=next((f for f in fs if (f['start'],f['end'])==(START,END)),None)
    if f is None:
        raise ValueError('WireQty preparation FDE changed')
    p=parameters(data);proofs=[]
    for row in p['high']:
        d=row['divisor']>>row['preshift'];n=HMAX>>row['preshift']
        if row['multiplier']*n>U64:
            raise ValueError('high-limb product no longer fits u64')
        proofs.append(reciprocal(row['multiplier'],row['shift'],d,n))
    proofs.append(reciprocal(p['low_multiplier'],64,10,10*(1<<32)-1))
    if (p['inverse_five']*5)&U64!=1 or p['divisibility_bound']!=U64//10:
        raise ValueError('modular divisibility certificate changed')
    for site,shift_site in REM:
        c=struct.unpack('<I',read(data,site+3,4)[1])[0];shift=read(data,shift_site+3,1)[1][0]
        proofs.append(reciprocal(c,shift,10,HMAX//10))
    for site,shift_site,mask_site,n,mask in SMALL:
        c=struct.unpack('<I',read(data,site+3,4)[1])[0];shift=read(data,shift_site+2,1)[1][0]
        proofs.append(reciprocal(c,shift,5,n))
        if read(data,mask_site+2,1)[1]!=bytes([mask]) or n*c>U32:
            raise ValueError('small-limb mask/product certificate changed')
        # Exhaustive bounded high-word subdomains, at most 21475 values.
        for h in range(n+1):
            q=(h*c)>>shift
            twice=q&(~1 if mask==0xfe else 0x3e)
            if twice*5!=10*(h//10) or not 0<=h-twice*5<10:
                raise ValueError('small-limb remainder certificate failed')
    for k,site in enumerate(FLAGS):
        code=read(data,site,5)[1]
        if code[0]!=0xbf or struct.unpack_from('<I',code,1)[0]!=(8-k)<<16:
            raise ValueError('scale-selection immediate changed')
    for site in TEST_BRANCHES:
        if read(data,site,1)[1]!=b'\x76':
            raise ValueError('divisibility JBE polarity changed')
    sec=next(s for s in sections(data) if s['name']=='.rela.dyn')
    rels={a:(i,v) for a,i,v in struct.iter_unpack('<QQq',data[sec['offset']:sec['offset']+sec['size']])}
    if any(rels.get(a)!=(8,v) for a,v in BINDINGS.items()):
        raise ValueError('WireQty code/source relocation changed')
    path=b'l1/src/wire_qty.rs'
    if read(data,0x43e2bd,len(path))[1]!=path or read(data,0x6482058,16)[1]!=struct.pack('<QII',len(path),29,48):
        raise ValueError('WireQty source Location changed')
    for a,text in [(0x7c66fd,b'called `Result::unwrap()` on an `Err` value'),(0x7c66c0,b'a Display implementation returned an error unexpectedly')]:
        if read(data,a,len(text))[1]!=text:
            raise ValueError('WireQty diagnostic changed')
    proofs=list({json.dumps(row,sort_keys=True):row for row in proofs}.values())
    off,body=read(data,START,END-START)
    if hashlib.sha256(body).hexdigest()!=BODY_SHA:
        raise ValueError('WireQty preparation instruction dataflow changed')
    rawframes={}
    for kind in ['fde','cie']:
        va=f[kind];n=struct.unpack('<I',read(data,va,4)[1])[0]+4
        rawframes[kind]={'va':hex(va),'bytes_hex':read(data,va,n)[1].hex()}
    return {'target_sha256':SHA,'start':hex(START),'end':hex(END),'bytes':END-START,'instructions':237,
            'file_offset':hex(off),'body_sha256':BODY_SHA,'frames':rawframes,
            'parameters':p,'reciprocal_certificates':proofs,
            'modular_divisibility_proof':'Odd x rotates a set bit into bit63, exceeding bound. Even x=2z gives y=(z*inv5) mod2^63; y<=floor((2^63-1)/5) iff z=5y, since 5y cannot wrap. Therefore predicate iff x is divisible by10.',
            'preparation_theorem':'For raw RSI N in[0,2^63-1], coefficient/scale abstract tuple removes at most8 trailing decimal zeros, with N=coefficient*10^(8-scale); zero maps to(0,0).',
            'prepared_words':'RSP+0x20=(scale<<16); +0x24=0; +0x28=coefficient low32; +0x2c=coefficient high32',
            'relative_bindings':{hex(a):hex(v) for a,v in BINDINGS.items()},
            'captured_code_executed':False,
            'limits':'Static scalar preparation before opaque formatter only. Original Rust input/niche representation, Decimal ABI, wire quantity units, rendered string, caller reachability, formatter/error/unwind closure and reconstruction gates are unproved. Sign-bit-set path reaches an unwrap diagnostic, not a proven negative-quantity policy.'}


def generate(binary,output):
    data=binary.read_bytes()
    if len(data)!=105896032 or hashlib.sha256(data).hexdigest()!=SHA:
        raise ValueError('expected pinned node115')
    report=analyze(data);output.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory() as directory:
        snapshot=Path(directory)/'node115.elf';snapshot.write_bytes(data)
        frames=subprocess.check_output(['readelf','-wf',str(snapshot)],text=True)
        rows=[l for l in frames.splitlines() if f'pc={START:016x}..{END:016x}' in l]
        if len(rows)!=1:
            raise ValueError('native WireQty FDE disagreement')
        asm=subprocess.check_output(['objdump','-d','-M','intel','--insn-width=16',f'--start-address={START:#x}',f'--stop-address={END:#x}',str(snapshot)],text=True)
        ins=decode_export(asm,START,END,read(data,START,END-START)[1])
        required={a for a,_,s,_,_ in HIGH}|{s for a,_,s,_,_ in HIGH}|set(FLAGS)|set(TEST_BRANCHES)|{0x41c584f,0x41c585f,0x41c5870,0x41c5a92,0x41c5a96,0x41c5a9e,0x41c5aa2,0x41c5aeb,0x41c5b4a}
        if len(ins)!=237 or not required<=set(ins):
            raise ValueError('native WireQty instruction count/boundary disagreement')
        (output/'body.objdump.txt').write_bytes(asm.replace(str(snapshot),'<authenticated-node115>').encode('utf-8'))
        (output/'frames.txt').write_bytes(('\n'.join(rows)+'\n').encode('utf-8'))
    (output/'records.json').write_bytes((json.dumps(report,indent=2)+'\n').encode('utf-8'))
    return report


if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--binary',type=Path,default=TARGET)
    ap.add_argument('--output',type=Path,default=ROOT/'work/wire-qty-normal-form115')
    args=ap.parse_args();r=generate(args.binary,args.output)
    print(json.dumps({'bytes':r['bytes'],'instructions':237,'captured_code_executed':False}))
