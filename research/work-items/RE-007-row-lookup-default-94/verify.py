#!/usr/bin/env python3
"""Bind the node94 row lookup, default path and conditional row+0x20 value."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
sys.path.insert(0,str(ROOT/'tools'))
from elf_index import sections
from fde_extents import eh_frame_records
from info_request_path import Elf,relative_relocs

SHA='3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
DECODE_SHA='29d11043f86dd506b89a45c29b044ab2b11c7f68bed7f7f40cc64a84ae0cb9e6'
DEFAULT=0x57862a0
STATE=0x5786300


def require(ok,reason):
    if not ok:
        raise ValueError(reason)


def frozen():
    raw=(HERE/'decode.json').read_bytes()
    require(hashlib.sha256(raw).hexdigest()==DECODE_SHA,'frozen decode changed')
    return json.loads(raw)


def rel(ins,va,offset):
    return va+len(ins)+struct.unpack_from('<i',ins,offset)[0]


def structural(data):
    elf=Elf(data)
    _,frames=eh_frame_records(data,sections(data))
    relocations=relative_relocs(elf)
    expected_slots={0x576e8b8:0x4ee3b20,0x576e470:0x157a9f0,
                    0x576e890:0x151f6f0,0x576e128:0x157b63b,
                    DEFAULT:0x3790fc0,0x56f22a0:0x37618b0,0x56f22a8:0x37608e0}
    # The poison helper's exact target is recorded below from its observed slot;
    # its implementation has no normal-path contract in this packet.
    expected_slots[0x576e868]=0x4eeb4c0
    for slot,target in expected_slots.items():
        require(relocations.get(slot)==target,'RELATIVE slot changed')
    functions,branches,calls=[],[],[]
    for f in frozen():
        start,end=int(f['start'],16),int(f['end'],16)
        rows=[r for r in frames if r['start']==start]
        require(len(rows)==1,'ambiguous FDE')
        row=rows[0]
        require(row['end']==end and row['fde']==int(f['fde'],16) and row['cie']==int(f['cie'],16),'FDE coordinates changed')
        require(row['lsda']==(None if f['lsda'] is None else int(f['lsda'],16)),'LSDA pointer changed')
        for key in ('fde','cie'):
            raw=bytes.fromhex(f[key+'_bytes'])
            require(elf.read(int(f[key],16),len(raw))==raw,key+' bytes changed')
        require(hashlib.sha256(elf.read(start,end-start)).hexdigest()==f['body_sha256'],'function bytes changed')
        at=start
        starts={int(i['va'],16) for i in f['instructions']}
        for i in f['instructions']:
            va,ins=int(i['va'],16),bytes.fromhex(i['bytes'])
            require(va==at and elf.read(va,len(ins))==ins,'decode coverage changed')
            at+=len(ins)
            mnemonic=i['asm'].split()[0]
            if mnemonic.startswith('j'):
                target=rel(ins,va,1 if ins[0]==0xe9 else 2) if ins[0] in (0xe9,0x0f) else va+2+struct.unpack('<b',ins[1:])[0]
                require(target==int(i['asm'].split()[1],16) and target in starts,'branch target changed')
                branches.append(dict(site=hex(va),kind=mnemonic,target=hex(target),bytes=ins.hex()))
            if mnemonic=='call':
                slot=None
                if ins[0]==0xe8:
                    target=rel(ins,va,1)
                    require(target==int(i['asm'].split()[1],16),'direct call target changed')
                    role='direct'
                elif ins[:2]==b'\xff\x15':
                    slot=rel(ins,va,2)
                    require(slot in expected_slots,'unrecorded call slot')
                    target=expected_slots[slot]
                    role='RELATIVE slot'
                else:
                    require(ins==b'\xff\x13' and f['role'].startswith('callback'),'unrecorded indirect call')
                    target=None
                    role='[rbx]; conditional target is constructor only when rbx is the observed default cell'
                calls.append(dict(site=hex(va),bytes=ins.hex(),slot=None if slot is None else hex(slot),
                                  target=None if target is None else hex(target),role=role))
        require(at==end,'incomplete function bytes')
        functions.append({k:v for k,v in f.items() if k!='instructions'} | dict(file_offset=hex(elf.off(start)),length=end-start,instruction_count=len(starts)))

    require(elf.read(DEFAULT,104)==bytes(96)+struct.pack('<II',3,0),'default file image changed')
    expected_vtable=struct.pack('<QQQQQ',0,8,8,0,0)
    require(elf.read(0x56f2288,40)==expected_vtable,'callback descriptor changed')
    require(elf.read(0x37618b0,92)==elf.read(0x37608e0,92),'callback normal-path prefix differs')
    anchors={0x3708c09:'4881c7f8000000e8dbcbfeff',0x3708dd0:'48837b20000f95c2',
             0x36f5869:'4d6bd278',0x36f58d4:'488d5aa0',
             0x36f58e7:'7522',0x36f5909:'74de',0x3790fd4:'0f11442430',
             0x379100f:'0f114b18'}
    for va,raw in anchors.items():
        require(elf.read(va,len(bytes.fromhex(raw))).hex()==raw,'layout/caller anchor changed')
    return dict(target_sha256=SHA,coordinates='ELF virtual addresses; explicit file offsets',
                functions=functions,branches=branches,calls=calls,
                slots=[dict(slot=hex(s),target=hex(t)) for s,t in expected_slots.items()],
                default_file_image=dict(va=hex(DEFAULT),bytes=elf.read(DEFAULT,104).hex(),
                                        note='RELATIVE relocation overlays constructor at +0; this is not a constructed runtime row'),
                descriptor=dict(va='0x56f2288',bytes=expected_vtable.hex(),size=8,alignment=8,
                                callback_slots=['0x56f22a0','0x56f22a8']),
                anchors=[dict(va=hex(v),bytes=r) for v,r in anchors.items()],
                layout=dict(entry_bytes=120,key_bytes=20,value_offset=24,value_extent=96,
                            compared_flag_offset=32,default_state_offset=96),
                counts=dict(bodies=len(functions),body_bytes=sum(f['length'] for f in functions),
                            instructions=sum(f['instruction_count'] for f in functions),
                            branches=len(branches),calls=len(calls)),
                unknowns=['External hash and generic Once/dispatch semantics, concurrency, initialization failure and lifetime/alias guarantees.',
                          'Constructor helper return meaning and unwinding/cleanup effects.',
                          'Caller aggregate/recorder mutation between lookup and the later row+0x20 test.',
                          'Economic field labels/units, complete producer invariants and full component equivalence.'],
                captured_execution=False,reconstructed_rust=False,gate_requested=False)


def select_row(count,query,control,keys,hash_word,*,state=0,control_address=0x100000):
    """Synthetic group-level model with externally supplied hash; not an emulator."""
    require(type(count) is int and 0<=count<1<<64,'count width')
    require(type(state) is int and 0<=state<1<<32,'state width')
    groups=[]
    selected=DEFAULT
    bucket=None
    if count:
        require(query is not None and len(query)>=20,'query fixture too short')
        require(type(hash_word) is int and 0<=hash_word<1<<64,'hash width')
        capacity=len(control)
        require(capacity>=16 and capacity&(capacity-1)==0,'power-of-two normal table fixture required')
        mask=capacity-1
        pos,step=hash_word&mask,0
        fingerprint=hash_word>>57
        for _ in range(capacity//16):
            lanes=[control[(pos+j)&mask] for j in range(16)]
            candidates=[j for j,c in enumerate(lanes) if c==fingerprint]
            groups.append(dict(pos=pos,candidates=candidates))
            for j in candidates:
                index=(pos+j)&mask
                require(index in keys and len(keys[index])>=20,'unset key fixture')
                if keys[index][:20]==query[:20]:
                    bucket=index
                    selected=control_address-(index+1)*120+24
                    break
            if bucket is not None or 255 in lanes:
                break
            step+=16
            pos=(pos+step)&mask
        else:
            raise ValueError('fixture lacks a normal terminating group; not a recovered native error')
    return dict(row=hex(selected),bucket=bucket,hash_called=bool(count),initializer_called=state!=0,
                groups=groups,flag_word_address=hex(selected+32),
                note='Returned row is conditional on any external initializer returning normally.')


def constructor_defined_bytes(success_word):
    """Known output bytes only; None marks uninitialized/padding bytes not proved."""
    require(type(success_word) is int and 0<success_word<1<<32,'successful helper word required')
    result=[None]*96
    for lo,hi in ((0,16),(24,48),(56,80),(84,92)):
        result[lo:hi]=[0]*(hi-lo)
    result[80:84]=struct.pack('<I',success_word)
    return result


def fixtures():
    query=bytes(range(20))
    fingerprint=0x35
    result=[]
    for name,count,state,pos,hit,decoy in (
            ('empty_ready',0,0,0,None,False),('empty_needs_initializer',0,3,0,None,False),
            ('first_group_hit',1,0,0,2,False),('hit_still_initializes',1,3,0,2,False),
            ('same_fingerprint_decoy',2,0,0,3,True),('wrapped_group_hit',1,0,31,0,False),
            ('later_group_hit',2,0,0,18,False),('missing_key',1,0,0,None,False)):
        controls=[255]*32
        keys={}
        if name=='later_group_hit':
            controls[:16]=[128]*16
        if hit is not None:
            controls[hit]=fingerprint
            keys[hit]=query+b'PAD!'
        if decoy:
            controls[1]=fingerprint
            keys[1]=query[:19]+bytes([query[19]^1])+b'xxxx'
        if name=='missing_key':
            controls[20]=fingerprint^1
            keys[20]=b'other-key-contents!!!'
        data=dict(count=count,state=state,pos=pos,hit=hit,decoy=decoy)
        out=select_row(count,None if not count else query,controls,keys,
                       None if not count else (fingerprint<<57)|pos,state=state)
        result.append(dict(name=name,input=data,output=out))
    known=constructor_defined_bytes(0x12345678)
    return dict(cases=result,constructor_example=dict(helper_word='0x12345678',defined_bytes=known,
                flag_word=0,unknown_byte_offsets=[i for i,v in enumerate(known) if v is None]),
                note='Synthetic fixtures and constructor byte contract; no target instructions executed.')


def build(data):
    require(hashlib.sha256(data).hexdigest()==SHA,'target SHA-256 mismatch')
    return structural(data)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary',type=Path,default=ROOT/'artifacts/node/94/hl-node')
    p.add_argument('--out',type=Path,required=True)
    args=p.parse_args()
    try:
        evidence=build(args.binary.read_bytes())
        args.out.mkdir(parents=True,exist_ok=True)
        for name,value in (('evidence.json',evidence),('fixtures.json',fixtures())):
            (args.out/name).write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')
    except (OSError,ValueError,KeyError,struct.error) as exc:
        print('row lookup evidence:',exc,file=sys.stderr)
        return 2
    print('PASS: 4 FDE ranges, 746 bytes, 185 instructions; 8 synthetic selection cases')
    return 0


if __name__=='__main__':
    raise SystemExit(main())
