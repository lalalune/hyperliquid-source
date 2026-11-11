#!/usr/bin/env python3
"""Authenticate static byte evidence; never run or emulate target code."""
import csv,hashlib,struct
from pathlib import Path
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from elf_index import unwind_index
from fde_extents import eh_frame_records
P=Path('research/work-items/RE-007-node115-asset-parse-fallback')
b=Path('artifacts/node/115/hl-node').read_bytes();assert hashlib.sha256(b).hexdigest()=='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
s,h=unwind_index(b);_,f=eh_frame_records(b,s);idx={(x['start'],x['fde']) for x in h};t=next(x for x in s if x['name']=='.text')
def read(a,n):
 assert t['address']<=a and a+n<=t['address']+t['size'];p=t['offset']+a-t['address'];return b[p:p+n]
bodies={0x43099f0:(0x4309be6,'2aa28d66ae5e990017a332daab2f4a28f17306dc97503f73df4912a148a864ff'),0x3c42130:(0x3c4265d,'5a3276d8bdf39750fb2494d7cb749348f8da59cd17e104e50c9142c8c5dd498b')}
ins={}
for a,(z,d) in bodies.items():
 assert any(x['start']==a and x['end']==z and (a,x['fde']) in idx for x in f);raw=read(a,z-a);assert hashlib.sha256(raw).hexdigest()==d
 seq=list(Cs(CS_ARCH_X86,CS_MODE_64).disasm(raw,a));assert sum(x.size for x in seq)==len(raw);ins.update({x.address:x for x in seq})
rows={}
with (P/'instructions.tsv').open() as fp:
 for x in csv.DictReader(fp,delimiter='\t'):
  a=int(x['va'],16);v=bytes.fromhex(x['bytes']);assert a not in rows and a in ins and ins[a].bytes==v and read(a,len(v))==v;rows[a]=v
pins={0x3c42299:'ff15c12b8a02',0x3c4229f:'0fb7442440',0x3c422a4:'3da2010000',0x4309a01:'4989d4',0x4309a04:'4989f5',0x4309a0f:'ff15abfb1d02',0x4309a15:'8b6c2430',0x4309a19:'83fd06',0x4309a1c:'7515',0x4309a1e:'f30f6f442434',0x4309a24:'f30f7f4304',0x4309a29:'66c703a201',0x4309a42:'4c89ee',0x4309a45:'4c89e2',0x4309a48:'ff15fa651d02',0x4309a4e:'807c245001',0x4309a55:'66c703b000',0x4309a65:'66480f7ec0',0x4309a6a:'48b9ffffffffffffff7f',0x4309a74:'4821c1',0x4309a77:'48ba000000000000f07f',0x4309a81:'4839d1',0x4309a84:'0f8d8f000000',0x4309a8d:'48c1ea34',0x4309a91:'48b9ffffffffffff0f00',0x4309a9e:'81e2ff070000',0x4309aa4:'7422',0x4309ab6:'81c900001000',0x4309ac0:'81c2cdfbffff',0x4309ac8:'4885c9',0x4309acb:'7452',0x4309ae1:'bacefbffff',0x4309ae8:'4885c0',0x4309aeb:'0f99c1',0x4309af8:'41b801000000',0x4309afe:'41b901000000',0x4309b04:'e857a19301',0x4309b14:'83f801',0x4309b17:'742e',0x4309b19:'66b8b000',0x4309b1f:'48c1e83f',0x4309b23:'c1e01f',0x4309b7f:'66b8a201',0x4309b83:'668903'}
def check(r):
 for a,v in pins.items():assert r[a]==bytes.fromhex(v),hex(a)
check(rows)
def target(a):return a+len(rows[a])+int.from_bytes(rows[a][-4:],'little',signed=True)
for a,v in [(0x3c42299,0x64e4e60),(0x4309a0f,0x64e95c0),(0x4309a48,0x64e0048),(0x4309a84,0x4309b19),(0x4309b04,0x5c43c60)]:assert target(a)==v
r=next(x for x in s if x['name']=='.rela.dyn');rel={a:(i,d) for a,i,d in struct.iter_unpack('<QQq',b[r['offset']:r['offset']+r['size']])}
for a,v in [(0x64e4e60,0x43099f0),(0x64e95c0,0x5c44210),(0x64e0048,0x16876b0)]:assert rel[a]==(8,v)
for bits,kind in [(0,'zero'),(1,'subnormal'),(0x3ff0000000000000,'normal'),(0xbff0000000000000,'normal'),(0x7fefffffffffffff,'normal'),(0x7ff0000000000000,'nonfinite'),(0xfff0000000000000,'nonfinite'),(0x7ff8000000000001,'nonfinite')]:
 mag=bits&0x7fffffffffffffff;exp=(bits>>52)&0x7ff;frac=bits&0xfffffffffffff
 actual='nonfinite' if mag>=0x7ff0000000000000 else ('normal' if exp else ('subnormal' if frac else 'zero'));assert actual==kind
for a in (0x4309a19,0x4309a29,0x4309a4e,0x4309a77,0x4309a84,0x4309ac0,0x4309ae1,0x4309b83):
 m=dict(rows);m[a]=m[a][:-1]+bytes([m[a][-1]^1])
 try:check(m)
 except AssertionError:pass
 else:raise AssertionError(hex(a))
print(f'{len(bodies)} FDEs, {len(rows)} instruction spans, {len(pins)} pins, 5 targets, 3 relocations, 8 bit cases and 8 controls: OK')
