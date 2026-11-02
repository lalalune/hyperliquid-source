#!/usr/bin/env python3
"""Qualify an independently authored node94 action-delay numerical kernel.

Reads the original ELF and runs only newly authored Rust when --rust-driver is
supplied. It never loads, executes, emulates or patches captured machine code.
"""
import argparse
import fractions
import hashlib
import json
import math
import re
from pathlib import Path
import struct
import subprocess
from elf_index import sections
from fde_extents import fde_extents

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-004-action-delay-fma-rust-94'
CRATE = ROOT / 'src/node94-action-delay'
TARGET = ROOT / 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
WINDOWS = [(0x392fab0,0x392fcba),(0x565f8c0,0x565f8d1),
           (0x565fd20,0x565fd26),(0x565fd30,0x565fd37),(0x565fd40,0x565fdb1)]


def require(ok,message):
    if not ok:raise ValueError(message)


def bits(value):return struct.unpack('<Q',struct.pack('<d',value))[0]
def value(raw):return struct.unpack('<d',struct.pack('<Q',raw))[0]
def digest(data):return hashlib.sha256(data).hexdigest()


def exact_fma(x,multiplier,bias):
    """Independent rational, one-round oracle; no target or host FMA invoked."""
    if math.isnan(x):return math.nan
    if math.isinf(x):return x  # Multiplier is finite and strictly positive.
    exact = fractions.Fraction.from_float(x)*fractions.Fraction.from_float(multiplier)+fractions.Fraction.from_float(bias)
    try:return float(exact)
    except OverflowError:return math.copysign(math.inf,-1.0 if exact<0 else 1.0)


def rule(mode,action):
    # A set-form projection independently checked against the original native
    # compare tree and interval partitions, not inferred reference source.
    if mode in (0,1):kind='default20'
    elif mode==2:kind='medium12' if action==0 else 'eighth' if action in (3,4,11054,11137) else 'default20'
    else:kind='medium12' if action==5 else 'eighth' if action in (0,1,10142,10151) else 'default20'
    unsigned=action&0xffffffff
    short=kind=='default20' and (unsigned>=100000000 or ((unsigned-10000)&0xffffffff)<100000)
    return kind,short


def oracle(mode,action,input_bits):
    kind,short=rule(mode,action);x=value(input_bits)
    fused=exact_fma(x,10000.0,{'default20':-4.0,'medium12':-3.0,'eighth':-1.5}[kind])
    raw=fused/20.0 if kind=='default20' else fused/12.0 if kind=='medium12' else fused*0.125
    if math.isfinite(raw):weight=0.0 if raw<0.0 else 1.0 if raw>1.0 else raw
    else:weight=raw
    if not weight>=0.0:return ['error_weight']
    base=weight*(1.3 if kind=='default20' else 1.8)+0.76
    if not base>=0.0:return ['error_duration']
    result=base*(0.2 if short else 0.65)
    return [kind,str(int(short)),*[f'{bits(v):016x}' for v in [fused,raw,weight,base,result]]]



def native_compare_tree(mode, action):
    """Mathematical projection of the retained cmp/jcc tree, not set rules."""
    if mode < 2:
        kind='default20'
    elif mode == 2:
        if action > 11053:
            kind='eighth' if action == 11054 or action == 11137 else 'default20'
        elif ((action-3)&0xffffffff) < 2:
            kind='eighth'
        else:
            kind='medium12' if action == 0 else 'default20'
    elif action > 10141:
        kind='eighth' if action == 10142 or action == 10151 else 'default20'
    elif (action&0xffffffff) < 2:
        kind='eighth'
    else:
        kind='medium12' if action == 5 else 'default20'
    raw=action&0xffffffff
    short=kind=='default20' and (raw>=0x5f5e100 or ((raw+0xffffd8f0)&0xffffffff)<0x186a0)
    return kind,short


def dispatch_cells():
    boundaries=sorted({-(1<<31),0,1,2,3,4,5,6,10000,10142,10143,10151,10152,
                       11054,11055,11137,11138,110000,100000000,1<<31})
    rows=[]
    for low_mode,high_mode in [(0,1),(2,2),(3,255)]:
        for low,stop in zip(boundaries,boundaries[1:]):
            kind,short=rule(low_mode,low)
            for m,a in [(low_mode,stop-1),(high_mode,low),(high_mode,stop-1)]:
                require(rule(m,a)==(kind,short),'Dispatch cell crosses a native boundary')
                require(native_compare_tree(m,a)==(kind,short),'Native comparison tree differs')
            rows.append((low_mode,high_mode,low,stop-1,kind,int(short)))
    require(sum((b-a+1)*(d-c+1) for a,b,c,d,_,_ in rows)==(1<<40),'Incomplete dispatch partition')
    return rows


def corpus():
    inputs={bits(x) for x in [0.0,-0.0,1.0,-1.0,math.inf,-math.inf,math.nan,
                              math.nextafter(0.0,1.0),math.nextafter(0.0,-1.0),
                              value(0x7fefffffffffffff),-value(0x7fefffffffffffff)]}
    for point in [0.00015,0.0003,0.0004,0.0005,0.00095,0.0015,0.0024]:
        inputs.update(bits(v) for v in [math.nextafter(point,-math.inf),point,math.nextafter(point,math.inf)])
    cases=set()
    for mode,action in [(0,0),(1,10000),(2,0),(2,3),(3,5),(255,10142)]:
        cases.update((mode,action,b) for b in inputs)
    for a,b,c,d,_,_ in dispatch_cells():
        cases.update((mode,action,bits(1/1024)) for mode in (a,b) for action in (c,d))
    return sorted(cases)


def static_evidence(data):
    require(len(data)==91774280 and digest(data)==SHA256,'Expected exact node #94 size/SHA-256')
    return check_structure(data)


def check_structure(data):
    # Exposed for corrupt-input tests; the CLI always authenticates first.
    summary,fdes,_=fde_extents(data);by_start={}
    for f in fdes:
        require(f['start'] not in by_start,'Duplicate FDE start')
        by_start[f['start']]=f['end']
    secs=sections(data)
    def read(va,n):
        matching=[s for s in secs if s['type']!=8 and s['address']<=va and va+n<=s['address']+s['size']]
        require(len(matching)==1,'Unmapped VA');s=matching[0];o=s['offset']+va-s['address'];return data[o:o+n]
    windows=[]
    for start,end in WINDOWS:
        require(by_start.get(start)==end,'FDE extent changed')
        windows.append(dict(start_va=hex(start),end_va_exclusive=hex(end),bytes=end-start,sha256=digest(read(start,end-start))))
    # Two independently decoded exports must agree on every instruction start
    # and its original bytes, with no gaps or padding in the FDE windows.
    starts=set()
    for start,end in WINDOWS:
        decoded=[]
        for suffix,pattern in [('llvm',r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)'),
                               ('capstone',r'^([0-9a-f]+): ([0-9a-f]+) ')]:
            rows=[];cursor=start
            for line in (PACKET/f'{start:x}.{suffix}.txt').read_text().splitlines():
                match=re.match(pattern,line)
                if not match:continue
                va=int(match[1],16);raw=bytes.fromhex(match[2])
                require(va==cursor and read(va,len(raw))==raw,'Disassembly coverage/bytes changed')
                cursor+=len(raw);rows.append((va,raw.hex()))
            require(cursor==end,'Incomplete disassembly window')
            decoded.append(rows)
        require(decoded[0]==decoded[1],'Independent instruction boundaries differ')
        starts.update(va for va,_ in decoded[0])
    anchors={0x392fab3:'4080ff02',0x392fab7:'0f83b7000000',
             0x392fb78:'83f802',0x392fb7d:'81fb2d2b0000',0x392fb85:'8d43fd',
             0x392fb88:'83f802',0x392fb8d:'85db',0x392fb96:'81fb9d270000',
             0x392fb9e:'83fb02',0x392fba3:'83fb05',0x392fbd0:'81fb2e2b0000',
             0x392fbd8:'81fb812b0000',0x392fbe5:'81fb9e270000',0x392fbed:'81fba7270000',
             0x392fb3c:'81fb00e1f505',0x392fb42:'0f93c0',0x392fb45:'81c3f0d8ffff',
             0x392fb4b:'81fba0860100',0x392fb51:'0f92c1',
             0x565fd20:'c4e2f1a9c2c3',0x565fd30:'c4e3f96bc210c3'}
    for va,raw in anchors.items():
        require(va in starts,'Anchor is not an instruction start')
        require(read(va,len(bytes.fromhex(raw)))==bytes.fromhex(raw),'Native control anchor changed')
    # Resolve RIP operands rather than trusting nearest-symbol annotations.
    rip_operands={
        0x392fabd:(8,0x20a830),0x392fac5:(8,0x20a550),0x392facd:(6,0x576f6e0),
        0x392fad7:(8,0x20b038),0x392fb2c:(8,0x20adf0),0x392fb34:(8,0x20a250),
        0x392fb6a:(8,0x20a768),0x392fbac:(8,0x20a830),0x392fbb4:(8,0x20a380),
        0x392fbbc:(6,0x576f6e0),0x392fbc6:(8,0x20b100),0x392fbf9:(8,0x20a830),
        0x392fc01:(8,0x20a388),0x392fc09:(6,0x576f6e0),0x392fc13:(8,0x20a6d8),
        0x392fc64:(8,0x20b108),0x392fc6c:(8,0x20a250),0x392fc7e:(8,0x20a9f8),
        0x565f8c4:(7,0x57882e8)}
    for va,(size,target) in rip_operands.items():
        require(va in starts and va+size+struct.unpack('<i',read(va+size-4,4))[0]==target,
                'RIP operand changed')
    constants={0x20a830:10000.0,0x20a550:-4.0,0x20a380:-3.0,0x20a388:-1.5,
               0x20b038:20.0,0x20b100:12.0,0x20a6d8:0.125,0x20a730:1.0,
               0x20adf0:1.3,0x20b108:1.8,0x20a250:0.76,0x20a768:0.2,0x20a9f8:0.65}
    for va,x in constants.items():require(read(va,8)==struct.pack('<d',x),'Curve constant changed')
    rel=next(s for s in secs if s['name']=='.rela.dyn')
    reloc={a:(info,addend) for a,info,addend in struct.iter_unpack('<QQq',data[rel['offset']:rel['offset']+rel['size']])}
    for slot,target in [(0x5776220,0x392fab0),(0x576f6e0,0x565f8c0),(0x57882e8,0x565fd40)]:
        require(reloc.get(slot)==(8,target),'Native relative slot changed')
    # Lock current complete selected windows in addition to checking controls.
    records=json.loads((PACKET/'target-records.json').read_text(encoding='utf-8'))
    require(windows==records['windows'],'Selected target window changed')
    return dict(target_sha256=SHA256,windows=windows,constants={hex(a):f'{bits(x):016x}' for a,x in constants.items()},
                anchors={hex(a):v for a,v in anchors.items()},fde_entries=summary['fde_records'],
                qualified_fma='hardware FMA3 at 0x565fd20; RN, DAZ=0, FTZ=0, exceptions masked',
                software_fma_equivalence=False,original_abi_reconstructed=False,captured_code_executed_or_emulated=False)


def generated():
    evidence=static_evidence(TARGET.read_bytes())
    cell_rows=dispatch_cells();cells='#mode_lo\tmode_hi\taction_lo\taction_hi\tcurve\tshort\n'+''.join('\t'.join(map(str,r))+'\n' for r in cell_rows)
    cases=corpus();vectors='#id\tmode\taction\tinput_bits\texpected...\n'
    expected=[]
    for index,(mode,action,input_bits) in enumerate(cases):
        row=oracle(mode,action,input_bits)
        vectors+='\t'.join([str(index),str(mode),str(action),f'{input_bits:016x}',*row])+'\n'
        expected.append('\t'.join([str(index),*row]))
    evidence.update(dispatch_cells=len(cell_rows),dispatch_input_patterns=1<<40,corpus_cases=len(cases),
                    vectors_sha256=digest(vectors.encode()),dispatch_sha256=digest(cells.encode()),
                    progress_gate_requested=False,rust_target_equivalence=False)
    return evidence,cells,vectors,'\n'.join(expected)+'\n'


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write',action='store_true')
    parser.add_argument('--rust-driver',type=Path)
    args=parser.parse_args();evidence,cells,vectors,expected=generated()
    outputs={PACKET/'evidence.json':json.dumps(evidence,indent=2)+'\n',CRATE/'dispatch.tsv':cells,CRATE/'target-vectors.tsv':vectors}
    for path,text in outputs.items():
        if args.write:path.write_text(text,encoding='utf-8')
        else:require(path.read_text(encoding='utf-8')==text,'Retained result differs: '+str(path))
    if args.rust_driver:
        result=subprocess.run([str(args.rust_driver.resolve())],input=vectors,text=True,capture_output=True,check=True)
        require(result.stdout==expected,'Project-authored Rust corpus output differs')
        print(f"Rust corpus matched {evidence['corpus_cases']} cases at every retained stage.")
    print(f"Static evidence reproduces; {evidence['dispatch_cells']} dispatch cells cover 2**40 raw mode/action combinations.")


if __name__=='__main__':main()
