#!/usr/bin/env python3
"""RE-001: node94 finite binary64 to signed-nanosecond argument lowering."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

from artifacts import ROOT
from elf_index import sections
from fde_extents import eh_frame_records

SHA256='3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
START,END=0x1459ca0,0x1459df7
BODY_SHA256='3eda2460cfdfd813865399592cdad572779804d5d71ba10b4b127040f3466bd7'
MASK=(1<<64)-1


def require(value,message):
    if not value:
        raise ValueError(message)


def split_observed(ns,magic,shift,radix):
    """Widths of IMUL(high), SAR, SHR and the negative-remainder correction."""
    require(-(1<<63)<=ns<(1<<63),'Expected signed i64 nanoseconds')
    high=(ns*magic)>>64
    quotient=(high>>shift)+((high&MASK)>>63)
    remainder=ns-quotient*radix
    sign=remainder>>63
    return quotient+sign,(remainder+(sign&radix))&0xffffffff


def lower_scaled_bits(bits,constants):
    """Conditional architectural model AFTER MULSD; masked exceptions, DAZ/FTZ off.

    This does not model the input multiply, date helpers, or execute target bytes.
    """
    require(type(bits) is int and 0<=bits<=MASK,'Expected binary64 bits')
    magnitude=bits&constants['sign_mask']
    if magnitude>constants['max_finite_bits']:
        ns=0
    else:
        value=struct.unpack('<d',struct.pack('<Q',bits))[0]
        value=min(constants['upper'],max(constants['lower'],value))
        ns=(1<<63)-1 if value>constants['last_in_range'] else int(value)
    q,r=split_observed(ns,constants['magic'],constants['shift'],constants['radix'])
    return {'nanoseconds_i64':ns,'seconds_i64':q,'nanoseconds_u32':r}


def observe(data):
    secs=sections(data)

    def read(va,size):
        matches=[s for s in secs if s['type']!=8 and s['address']<=va and va+size<=s['address']+s['size']]
        require(len(matches)==1,'Expected one file-backed mapping')
        off=matches[0]['offset']+va-matches[0]['address']
        require(off+size<=len(data),'Truncated mapped bytes')
        return data[off:off+size]

    def code(va,prefix,size):
        raw=read(va,size)
        require(raw.startswith(bytes.fromhex(prefix)),f'Instruction changed at {va:#x}')
        return raw

    def rip8(va,prefix):
        raw=code(va,prefix,8)
        return va+8+struct.unpack_from('<i',raw,4)[0]

    _,frames=eh_frame_records(data,secs)
    fs=[f for f in frames if f['start']==START]
    require(len(fs)==1 and fs[0]['end']==END,'Time helper FDE changed')
    relsec=next(s for s in secs if s['name']=='.rela.dyn')
    relocs={}
    for slot,info,addend in struct.iter_unpack('<QQq',read(relsec['address'],relsec['size'])):
        if info==8:
            require(slot not in relocs,'Duplicate RELATIVE relocation')
            relocs[slot]=addend
    factor_va=rip8(0x1459cb6,'f20f5905')
    lower_va=rip8(0x1459ce3,'f20f1015')
    upper_va=rip8(0x1459cf1,'660f2e05')
    last_va=rip8(0x1459d16,'660f2e0d')
    factor=struct.unpack('<d',read(factor_va,8))[0]
    lower=struct.unpack('<d',read(lower_va,8))[0]
    upper=struct.unpack('<d',read(upper_va,8))[0]
    last=struct.unpack('<d',read(last_va,8))[0]
    require((factor,lower,upper,last)==(1e9,float(-(1<<63)),float(1<<63),float((1<<63)-1024)),
            'Scaling/clamp constants changed')
    sign_mask=struct.unpack_from('<Q',code(0x1459cc3,'48b8',10),2)[0]
    maximum=struct.unpack_from('<Q',code(0x1459cd4,'48ba',10),2)[0]
    require((sign_mask,maximum)==((1<<63)-1,0x7fefffffffffffff),'Finite classification changed')
    require(read(0x1459cd0,4)==bytes.fromhex('660f57c9'),'Zero fallback changed')
    require(read(0x1459ce1,2)==bytes.fromhex('7f2e'),'Nonfinite branch changed')
    magic=struct.unpack_from('<Q',code(0x1459d2c,'48b9',10),2)[0]
    shift=code(0x1459d43,'48c1fa',4)[3]
    radix=struct.unpack_from('<I',code(0x1459d4a,'4869c2',7),3)[0]
    radix2=struct.unpack_from('<I',code(0x1459d5e,'81e1',6),2)[0]
    require((magic,shift,radix,radix2)==(0x112e0be826d694b3,26,1000000000,1000000000),
            'Signed division/normalization constants changed')
    require(read(0x1459d54,18)==bytes.fromhex('4889f148c1f93f4801ca81e100ca9a3b01f1'),
            'Negative remainder normalization changed')
    bindings={0x576efb8:START,0x576e8a8:0x15206e0,0x576e8b0:0x151f870,0x576e468:0x157a9b0}
    require(all(relocs.get(s)==v for s,v in bindings.items()),'Time helper slot binding changed')
    location=0x566af18
    require(relocs.get(location)==0x1fd0f5,'Chrono source binding changed')
    length,line,column=struct.unpack('<QII',read(location+8,16))
    path=read(relocs[location],length).decode('utf8')
    require(path.endswith('/chrono-0.4.38/src/naive/datetime/mod.rs') and (line,column)==(1631,38),
            'Chrono source Location changed')
    require(read(0x21a01f,38)==b'`NaiveDateTime + TimeDelta` overflowed','Overflow diagnostic changed')
    require(hashlib.sha256(read(START,END-START)).hexdigest()==BODY_SHA256,'Enclosing time helper body changed')
    constants={'factor':factor,'lower':lower,'upper':upper,'last_in_range':last,
               'sign_mask':sign_mask,'max_finite_bits':maximum,'magic':magic,'shift':shift,'radix':radix}
    bits=[0,1,1<<63,(1<<63)|1,0x3ff0000000000000,0xbff0000000000000,
          0x3ff8000000000000,0xbff8000000000000,0x43dfffffffffffff,0x43e0000000000000,
          0xc3e0000000000000,0x7fefffffffffffff,0xffefffffffffffff,
          0x7ff0000000000000,0xfff0000000000000,0x7ff0000000000001,0x7ff8000000000000]
    vectors=[{'scaled_bits':hex(b),**lower_scaled_bits(b,constants)} for b in bits]
    samples={-(1<<63),(1<<63)-1,-1,0,1}
    for q in [-9223372036,-1000,-2,-1,0,1,2,1000,9223372036]:
        for r in [-1,0,1,radix-1]:
            n=q*radix+r
            if -(1<<63)<=n<(1<<63):samples.add(n)
    state=0x1459ca0
    for _ in range(16384):
        state=(state*6364136223846793005+1442695040888963407)&MASK
        samples.add(state-(1<<64) if state>>63 else state)
    mismatches=sum(split_observed(n,magic,shift,radix)!=divmod(n,radix) for n in samples)
    require(mismatches==0,'Signed split differs from independent Python divmod')
    return {'target_sha256':SHA256,'range':{'start_va':hex(START),'end_va_exclusive':hex(END),
            'bytes':END-START,'sha256':BODY_SHA256,'fde_va':hex(fs[0]['fde']),'cie_va':hex(fs[0]['cie'])},
            'prefix_end_before_call_va':'0x1459d70','constants':constants,
            'constant_vas':{'factor':hex(factor_va),'lower':hex(lower_va),'upper':hex(upper_va),'last':hex(last_va)},
            'source_location':{'slot_va':hex(location),'path':path,'line':line,'column':column},
            'relative_bindings':{hex(s):hex(v) for s,v in bindings.items()},
            'scaled_bit_vectors':vectors,'signed_split_comparison':{'samples':len(samples),'mismatches':mismatches},
            'captured_binaries_executed':False,
            'limits':'Conditional post-MULSD model only: masked exceptions, default binary64 comparisons. '
                     'No complete date arithmetic/helper closure, runtime timer meaning, Rust reconstruction '
                     'or progress gate. Split samples are not executed target calls or exhaustive coverage.'}


def build(data):
    require(hashlib.sha256(data).hexdigest()==SHA256,'Wrong node94 SHA-256')
    return observe(data)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary',type=Path,default=ROOT/'artifacts/node/94/hl-node')
    p.add_argument('--out',type=Path,default=ROOT/'work/time-delta-lowering-94.json')
    args=p.parse_args()
    record=build(args.binary.read_bytes())
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(record,indent=2)+'\n',encoding='utf8',newline='\n')
    print(json.dumps(record['signed_split_comparison']))


if __name__=='__main__':main()
