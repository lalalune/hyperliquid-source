#!/usr/bin/env python3
"""Read the two-row rank and swap path from node 94 without running it."""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import struct

from elf_index import sections, unwind_index
from fde_extents import eh_frame_records

ROOT=Path(__file__).resolve().parents[1]
BINARY=ROOT/'artifacts/node/94/hl-node'
DIGEST='3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
# Byte patterns for the compared instruction blocks. Displacements and the
# entire bodies are also retained in the output and checked independently.
ANCHORS={
 0x4dbab30:'4939f8743b483b9cd1d0020000410f97c14180d9004883c74048ffc24180f90174de410fb6f185f6744d4883e8017319eb4c',
 0x4dbac60:'4939f8743b4c3bacd1d0020000410f97c14180d9004883c74048ffc24180f90174de410fb6f185f6742d4883e801731de9c3090000',
 0x4dbabb0:'4889c148f7d9480f48c84939ce0f96c34885c00f9f4424164084ed400f94c54c89e849f7e648894424780f90442470',
 0x4dbacc5:'40326c24164020eb4889c148f7d9480f48c84939ce0f96c14885c00f9fc04584e4400f94c64030c64020ce488b44242049f7e60f90c148bffeffffffffffff7f4839f80f97c24038f30f841b',
 0x4dbb02f:'08d1488b7424784839fe0f97c208542470740f84c9488b5c24180f84d6fcffffeb134839c60f93c008c1488b5c24180f84c1fcffff41bc0200',
 0x4dbb3e0:'488b71e0488b7ae0488979e0488972e0488b71e8488b7ae8488979e8488972e8488b71f0488b7af0488979f0488972f0488b71f8488b7af8488979f8488972f8488b31488b3a4889394889324883c1284883c2d848ffc8',
}
U64=(1<<64)-1
I64_MIN=-(1<<63)
I64_MAX=(1<<63)-1
FNS={0x44885a0:(0x44886a7,'2b2913ea731ed322a65377920181959484684ef578ddadf656faada2ab8736ac'),
     0x4dba8f0:(0x4dbb6d1,'4f9dce7c2ea6a72c03438f47905d000093316db217a99510b0d65714ead0b92c')}
# Selected after checking instruction starts. Displacements are decoded from ELF.
BRANCHES=(0x44885db,0x44885e5,0x4488600,0x448862b,0x4488647,
 0x4dba927,0x4dba95e,0x4dba97e,0x4dba9ee,0x4dbaa42,0x4dbaaa4,
 0x4dbab03,0x4dbab33,0x4dbab50,0x4dbab58,0x4dbab5e,0x4dbab60,
 0x4dbab77,0x4dbab81,0x4dbabac,0x4dbac30,0x4dbac63,0x4dbac80,
 0x4dbac88,0x4dbac8e,0x4dbac90,0x4dbaca7,0x4dbacb5,0x4dbacbc,
 0x4dbad0e,0x4dbad1f,0x4dbad31,0x4dbad3b,0x4dbad41,
 0x4dbb040,0x4dbb049,0x4dbb04f,0x4dbb05e,0x4dbb06e,
 0x4dbb399,0x4dbb3a3,0x4dbb437,0x4dbb494,0x4dbb627,0x4dbb64d,0x4dbb678)
WINDOWS=(('wrapper-selection',0x44885bf,48),('wrapper-call',0x4488630,19),
 ('worker-entry',0x4dba923,52),('two-row-entry',0x4dbaa20,35),
 ('second-row-loads',0x4dbaaaf,33),('second-tree-search',0x4dbab30,50),
 ('second-tree-hit',0x4dbaba7,9),('second-row-rank',0x4dbabb0,47),
 ('first-tree-search',0x4dbac60,53),('first-tree-hit',0x4dbacb7,7),
 ('first-row-rank',0x4dbacc5,76),('equal-rank-compare',0x4dbb02f,57),
 ('swap-gate',0x4dbb397,24),('swap-five-words',0x4dbb3e0,87),
 ('finish-count',0x4dbb61f,32))


def authenticate(data):
    if hashlib.sha256(data).hexdigest()!=DIGEST:
        raise ValueError('target SHA-256 mismatch')


def resolve(data,secs,va,n):
    if va<0 or n<=0:
        raise ValueError('invalid address range')
    found=[s for s in secs if s['type']!=8 and s['flags']&2 and
           s['address']<=va and va+n<=s['address']+s['size']]
    if len(found)!=1:
        raise ValueError('no unique file-backed section')
    s=found[0];off=s['offset']+va-s['address']
    if off+n>len(data):raise ValueError('range beyond file')
    return off


def decode_branch(data,secs,va):
    off=resolve(data,secs,va,2); a,b=data[off:off+2]
    if a in range(0x70,0x80) or a==0xeb:
        length=2;delta=struct.unpack_from('<b',data,off+1)[0]
    elif a==0x0f and b in range(0x80,0x90):
        resolve(data,secs,va,6);length=6;delta=struct.unpack_from('<i',data,off+2)[0]
    elif a==0xe9:
        resolve(data,secs,va,5);length=5;delta=struct.unpack_from('<i',data,off+1)[0]
    else:raise ValueError('unexpected selected branch opcode')
    return va+length+delta,data[off:off+length].hex()


def validate_rank_anchors(body):
    base=0x4dba8f0
    for va,expected in ANCHORS.items():
        raw=bytes.fromhex(expected)
        if body[va-base:va-base+len(raw)]!=raw:
            raise ValueError('rank instruction bytes mismatch')


def record(price,asset,size,opaque,side,padding=b'\0'*7):
    if any(not 0<=x<=U64 for x in (price,asset,size,opaque)) or not 0<=side<=255 or len(padding)!=7:
        raise ValueError('invalid row fixture')
    return struct.pack('<QQQQB7s',price,asset,size,opaque,side,padding)


def fields(row,position):
    if len(row)!=40 or not I64_MIN<=position<=I64_MAX:
        raise ValueError('invalid row or signed position')
    price,asset,size,opaque,side,_=struct.unpack('<QQQQB7s',row)
    return price,asset,size,opaque,side,position


def lower_instructions(row,position,cap):
    """Static lift of neg/cmov, unsigned compare, side test and mul flags."""
    price,_,size,_,side,pos=fields(row,position)
    posbits=pos&U64
    neg=(-posbits)&U64
    # cmovs chooses the original bits if neg has its sign bit set.
    magnitude=posbits if neg & (1<<63) else neg
    small=size<=magnitude
    positive=pos>0
    side_zero=side==0
    eligible=int(small and (side_zero ^ positive))
    product=price*size
    low=product&U64
    high=product>>64
    invalid=int(high!=0 or low>cap)
    return eligible,invalid,low,high


def decision_lift(first,first_pos,second,second_pos,cap):
    """Manual lift of the selected pair comparison; True takes swap arm."""
    e1,bad1,low1,_=lower_instructions(second,second_pos,cap)
    e0,bad0,low0,_=lower_instructions(first,first_pos,cap)
    return flag_decision(e0,e1,bad0,bad1,low0,low1)


def flag_decision(e0,e1,bad0,bad1,low0,low1):
    """Lift the recorded conditional flag flow after both products."""
    if any(x not in (0,1) for x in (e0,e1,bad0,bad1)):
        raise ValueError('flags must be bits')
    if not 0<=low0<=U64 or not 0<=low1<=U64:
        raise ValueError('product low halves must be u64')
    if e1!=e0:
        return bool(e0 and not e1)
    if bad1:
        return not bad0
    return bool(not bad0 and low1<low0)


def oracle_key(row,position,cap):
    price,_,size,_,side,pos=fields(row,position)
    priority=int(size<=abs(pos) and ((side==0)!=(pos>0)))
    p=price*size
    return (priority,int(p<=cap),p if p<=cap else 0)


def independent_decision(first,first_pos,second,second_pos,cap):
    return oracle_key(first,first_pos,cap)>oracle_key(second,second_pos,cap)


def replay_pair_swap(body,first,second,swap):
    # The fixed anchor covers five load/load/store/store qword groups and
    # the loop pointer adjustments. Work only on fixture bytes.
    validate_rank_anchors(body)
    if len(first)!=40 or len(second)!=40:
        raise ValueError('pair records must be 40 bytes')
    memory=bytearray(first+second)
    if swap:
        for off in range(0,40,8):
            a=struct.unpack_from('<Q',memory,off)[0]
            b=struct.unpack_from('<Q',memory,off+40)[0]
            struct.pack_into('<Q',memory,off,b)
            struct.pack_into('<Q',memory,off+40,a)
    return bytes(memory)


def tree_lookup(node,height,key):
    """Lift the selected node scan for well-formed synthetic search trees.

    Each node has sorted unsigned keys, signed values, and children. The
    external map helper, allocation and arbitrary malformed nodes are excluded.
    """
    if not 0<=key<=U64 or not 0<=height<=255:
        raise ValueError('invalid lookup input')
    trace=[]
    if node is None:
        return False,0,'empty-root'
    while True:
        keys,values,children=node
        if (len(keys)!=len(values) or any(not 0<=k<=U64 for k in keys) or
            any(a>=b for a,b in zip(keys,keys[1:])) or
            any(not I64_MIN<=v<=I64_MAX for v in values)):
            raise ValueError('malformed lookup node')
        i=0
        while i<len(keys) and key>keys[i]:
            i+=1
        trace.append(str(i))
        if i<len(keys) and key==keys[i]:
            return True,values[i],'/'.join(trace)
        if height==0:
            return False,0,'/'.join(trace)
        if len(children)!=len(keys)+1 or children[i] is None:
            raise ValueError('malformed child slots')
        node=children[i]
        height-=1


def lookup_fixtures():
    leaf=([10,20],[-9,14],[])
    branch=([20,40],[-2,4],[
        ([10],[-1],[]),([30],[3],[]),([50],[5],[])])
    cases=[('empty',None,0,0)]
    cases.extend(('leaf',leaf,0,k) for k in (0,10,15,20,21,U64))
    cases.extend(('branch',branch,1,k) for k in (0,10,15,20,25,30,35,40,45,50,55))
    return cases


def bounded_length_case(length):
    if not 0<=length<=U64:
        raise ValueError('length outside u64')
    if length<2:
        return 'worker-returns-before-comparison'
    if length==2:
        return 'two-row-comparison'
    return 'outside-bounded-scope'


def fixtures(cap):
    # This is a boundary grid, not a statement that these rows reach the path.
    raw=((0,0,0,0),(1,1,1,0),(2,1,1,1),(1,0,0,0),
         (1,0,0,1),(1,1,-1,0),(1,1,1,1),(cap,1,1,0),
         (cap+1,1,1,0),(U64,2,-2,0),(1,1,I64_MIN,0),
         (2,1,I64_MIN,1),(1,1,I64_MAX,0),(1,1,I64_MAX,1),
         (3,2,-2,2),(4,2,-1,0),(U64,0,0,255),(0,2,-2,0))
    rows=[]
    for i,(price,size,pos,side) in enumerate(raw):
        rows.append((f'case-{i:02d}',record(price,100+i,size,0x1122334455660000+i,side,
                                               bytes([i])*7),pos))
    return rows


def tsv(path,header,rows):
    b=io.StringIO(newline='');w=csv.writer(b,delimiter='\t',lineterminator='\n')
    w.writerow(header);w.writerows(rows);path.write_text(b.getvalue(),encoding='utf-8')


def generate(data,out):
    authenticate(data);secs,index=unwind_index(data);_,fdes=eh_frame_records(data,secs)
    indexed={x['start']:x['fde'] for x in index};info=[];bodies={}
    for start,(end,digest) in sorted(FNS.items()):
        candidates=[x for x in fdes if x['start']==start and x['end']==end]
        if len(candidates)!=1 or indexed.get(start)!=candidates[0]['fde']:
            raise ValueError('FDE mismatch')
        offset=resolve(data,secs,start,end-start);body=data[offset:offset+end-start]
        if hashlib.sha256(body).hexdigest()!=digest:raise ValueError('body hash mismatch')
        bodies[start]=body
        info.append({'start_va':hex(start),'end_va':hex(end),'fde_va':hex(candidates[0]['fde']),
                     'file_offset':hex(offset),'sha256':hashlib.sha256(body).hexdigest(),
                     'body_hex':body.hex()})
    validate_rank_anchors(bodies[0x4dba8f0])
    # Verify the immediate cap and its surrounding compare sequence by raw bytes.
    cap_at=0x4dbacfd; cap_off=resolve(data,secs,cap_at,8)
    cap=struct.unpack_from('<Q',data,cap_off)[0]
    if data[cap_off-2:cap_off]!=bytes.fromhex('48bf') or cap!=(1<<63)-2:
        raise ValueError('unexpected product cap')
    call_va=0x448863e;off=resolve(data,secs,call_va,5);call_raw=data[off:off+5]
    if call_raw[0]!=0xe8 or call_va+5+struct.unpack_from('<i',call_raw,1)[0]!=0x4dba8f0:
        raise ValueError('wrapper call mismatch')
    windows=[]
    for name,addr,n in WINDOWS:
        off=resolve(data,secs,addr,n);windows.append((name,hex(addr),hex(off),data[off:off+n].hex()))
    branches=[]
    for va in BRANCHES:
        dest,raw=decode_branch(data,secs,va)
        enclosing=[(s,e) for s,(e,_) in FNS.items() if s<=va<e]
        if len(enclosing)!=1 or not enclosing[0][0]<=dest<enclosing[0][1]:
            raise ValueError('selected branch outside function extent')
        branches.append((hex(va),raw,hex(dest)))
    data_rows=[];records=fixtures(cap)
    for name0,row0,pos0 in records:
        for name1,row1,pos1 in records:
            actual=decision_lift(row0,pos0,row1,pos1,cap)
            expected=independent_decision(row0,pos0,row1,pos1,cap)
            if actual!=expected:raise ValueError('flag lift disagrees with integer oracle')
            a=lower_instructions(row0,pos0,cap);b=lower_instructions(row1,pos1,cap)
            data_rows.append((name0,name1,pos0,pos1,row0.hex(),row1.hex(),a[0],a[1],a[2],a[3],
                              b[0],b[1],b[2],b[3],int(actual),
                              replay_pair_swap(bodies[0x4dba8f0],row0,row1,actual).hex()))
    abstract=[]
    for e0 in (0,1):
        for e1 in (0,1):
            for bad0 in (0,1):
                for bad1 in (0,1):
                    for low0 in (0,1,2):
                        for low1 in (0,1,2):
                            got=flag_decision(e0,e1,bad0,bad1,low0,low1)
                            expected=(e0,1-bad0,0 if bad0 else low0)>(e1,1-bad1,0 if bad1 else low1)
                            if got!=expected:raise ValueError('flag class mismatch')
                            abstract.append((e0,e1,bad0,bad1,low0,low1,int(got)))
    lookup_rows=[]
    for name,node,height,key in lookup_fixtures():
        found,value,trace=tree_lookup(node,height,key)
        lookup_rows.append((name,height,key,int(found),value,trace))
    out.mkdir(parents=True,exist_ok=True)
    tsv(out/'lookup-cases.tsv',['tree','height','key','found','value','node_slot_trace'],lookup_rows)
    tsv(out/'flag-classes.tsv',['first_R','second_R','first_invalid','second_invalid',
        'first_low','second_low','swap'],abstract)
    tsv(out/'windows.tsv',['role','va','file_offset','bytes'],windows)
    tsv(out/'branches.tsv',['instruction_va','bytes','target_va'],branches)
    lengths=[(n,bounded_length_case(n)) for n in (0,1,2,3)]
    tsv(out/'length-cases.tsv',['length','static_path'],lengths)
    tsv(out/'pair-cases.tsv',['first_fixture','second_fixture','first_position','second_position',
        'first_bytes','second_bytes','first_eligible','first_invalid','first_product_low','first_product_high',
        'second_eligible','second_invalid','second_product_low','second_product_high','swap','result_bytes'],data_rows)
    summary={'target_sha256':DIGEST,'functions':info,'direct_call':{'site':hex(call_va),
             'target':hex(0x4dba8f0),'bytes':call_raw.hex()},'product_limit':cap,
             'selected_branches':len(branches),'instruction_windows':len(windows),
             'fixture_rows':len(records),'pair_model_cases':len(data_rows),'length_model_cases':len(lengths),
             'flag_model_classes':len(abstract),'lookup_model_cases':len(lookup_rows),
             'swap_count':sum(int(r[-2]) for r in data_rows),
             'limitations':'Static lifts and synthetic fixtures are not target execution.'}
    (out/'evidence.json').write_text(json.dumps(summary,indent=2,sort_keys=True)+'\n',encoding='utf-8')


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--out',required=True,type=Path)
    args=parser.parse_args();generate(BINARY.read_bytes(),args.out)


if __name__=='__main__':main()
