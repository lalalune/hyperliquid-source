#!/usr/bin/env python3
"""Verify static #115 evidence; never execute or emulate target code."""
import csv, hashlib
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from elf_index import unwind_index
from fde_extents import eh_frame_records
P=Path('research/work-items/RE-014-node115-best-pair-readers')
b=Path('artifacts/node/115/hl-node').read_bytes()
assert hashlib.sha256(b).hexdigest()=='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
s,h=unwind_index(b);_,f=eh_frame_records(b,s);idx={(x['start'],x['fde']) for x in h}
t=next(x for x in s if x['name']=='.text')
def read(a,n):
 assert t['address']<=a and a+n<=t['address']+t['size'];p=t['offset']+a-t['address'];return b[p:p+n]
bodies={0x50eaf10:(0x50eb19a,'cf9976595d93f4b86463c73e5fbb44b9b441eb6a692f4cabd2776e70f2f59dbb'),0x22f6370:(0x22f65fa,'80a83a163908c9dd39254f54df3c87eebcf817690402ef429300e3dc186b591d'),0x58f4c70:(0x58f505e,'1bd2d143d5755a4e88644a6ef093bc9bb293e3ae0641f7a0a4e72466d5915f6e'),0x23e3b40:(0x23e3f33,'31a2d3ae36b0ffa05796754092fd5f10116e49cb4040a3928616b074b25eece4')}
starts=set();decoded={}
for a,(z,d) in bodies.items():
 assert any(x['start']==a and x['end']==z and (a,x['fde']) in idx for x in f)
 raw=read(a,z-a);assert hashlib.sha256(raw).hexdigest()==d
 ins=list(Cs(CS_ARCH_X86,CS_MODE_64).disasm(raw,a));assert sum(i.size for i in ins)==len(raw)
 for i in ins: starts.add(i.address);decoded[i.address]=i
rows={}
with (P/'instructions.tsv').open() as fp:
 for x in csv.DictReader(fp,delimiter='\t'):
  a=int(x['va'],16); raw=bytes.fromhex(x['bytes']); assert a not in rows and a in starts and decoded[a].bytes==raw and read(a,len(raw))==raw;rows[a]=raw
pins={0x50eaf23:'488b0e',0x50eaf29:'48f7d8',0x50eaf2c:'7123',0x50eaf55:'4885d2',0x50eaf58:'7428',0x50eaf8f:'48c1e707',0x50eaf93:'488d04c7',0x50eb026:'488d8888000000',0x50eb037:'4531e4',0x50eb074:'488d7c2408',0x50eb079:'e882d40400',0x50eb083:'488b00',0x50eb089:'49f7dc',0x50eb08c:'4c0f48e0',0x50eb162:'31c0',0x50eb16b:'e890d30400',0x50eb175:'488b08',0x50eb17b:'48f7d8',0x50eb17e:'480f48c1',0x50eb182:'4c8923',0x50eb185:'48894308',0x58f4cef:'498db7a8000000',0x58f4cfe:'e80d627fff',0x23e3bbf:'498db7a8000000',0x23e3bce:'e89d27f1ff'}
def check(r):
 for a,v in pins.items(): assert r[a]==bytes.fromhex(v),hex(a)
check(rows)
def dst(a):return a+len(rows[a])+int.from_bytes(rows[a][-4:],'little',signed=True)
for a,v in [(0x50eb079,0x5138500),(0x50eb16b,0x5138500),(0x22f64d9,0x2389af0),(0x22f65cb,0x2389af0),(0x58f4cfe,0x50eaf10),(0x23e3bce,0x22f6370)]:assert dst(a)==v
# The reader bodies differ only in the two direct-call displacements.
x=bytearray(read(0x50eaf10,0x28a));y=bytearray(read(0x22f6370,0x28a))
for off in (0x16a,0x25c):x[off:off+4]=y[off:off+4]=b'\0'*4
assert x==y
for a in (0x50eaf2c,0x50eaf58,0x50eb026,0x50eb08c,0x50eb185,0x58f4cfe):
 changed=dict(rows);changed[a]=changed[a][:-1]+bytes([changed[a][-1]^1])
 try:check(changed)
 except AssertionError:pass
 else:raise AssertionError('mutation accepted '+hex(a))
print(f'{len(bodies)} FDEs, {len(rows)} instruction records, {len(pins)} pins, six call targets, normalized reader comparison and six controls: OK')
