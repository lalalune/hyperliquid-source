#!/usr/bin/env python3
"""Static evidence checks only: no target execution or instruction emulation."""
import csv,hashlib,struct
from pathlib import Path
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from elf_index import unwind_index
from fde_extents import eh_frame_records
b=Path('artifacts/node/115/hl-node').read_bytes();assert hashlib.sha256(b).hexdigest()=='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
s,h=unwind_index(b);_,f=eh_frame_records(b,s);idx={(x['start'],x['fde']) for x in h}
def read(name,a,n):
 t=next(x for x in s if x['name']==name);assert t['address']<=a and a+n<=t['address']+t['size'];p=t['offset']+a-t['address'];return b[p:p+n]
bodies={0x2e1b6b0:(0x2e1da0e,'53102a5861adaaef5b17e6b0846f7a0031bd22a3b8de61a9d0442cc6a80d9cfb'),0x4eca5d0:(0x4eca82c,'8ed46d0d802b46b9527c8352615507f1b0285aaa2e8ba43848d7cdfe1d4d3305')}
starts=set()
for a,(z,d) in bodies.items():
 assert any(x['start']==a and x['end']==z and (a,x['fde']) in idx for x in f)
 raw=read('.text',a,z-a);assert hashlib.sha256(raw).hexdigest()==d
 ins=list(Cs(CS_ARCH_X86,CS_MODE_64).disasm(raw,a));assert sum(x.size for x in ins)==len(raw);starts.update(i.address for i in ins)
rows={}
with Path('research/work-items/RE-008-node115-timer-record-handoff/instructions.tsv').open() as fp:
 for x in csv.DictReader(fp,delimiter='\t'):
  a=int(x['va'],16);lo=int(x['fde_start'],16);hi=int(x['fde_end'],16);raw=bytes.fromhex(x['bytes'])
  assert a not in rows and a in starts and lo in bodies and bodies[lo][0]==hi and lo<=a<a+len(raw)<=hi and read('.text',a,len(raw))==raw
  rows[a]=raw
pins={0x2e1b6d3:'4889bc2440010000',0x2e1c73c:'488dbc2468030000',0x2e1c744:'f20f1005d4d263fd',0x2e1c74c:'ff1586c06c03',0x2e1c752:'488dbc2488030000',0x2e1c75a:'f20f1005aecc63fd',0x2e1c762:'ff1570c06c03',0x2e1cac5:'488b9c2440010000',0x2e1cb4b:'488b9c2440010000',0x2e1cd20:'0f10842468030000',0x2e1cd28:'0f108c2478030000',0x2e1cd30:'0f118424a8170000',0x2e1cd38:'0f118c24b8170000',0x2e1cd40:'0f10842488030000',0x2e1cd48:'0f108c2498030000',0x2e1cd50:'0f118424c8170000',0x2e1cd58:'0f118c24d8170000',0x2e1cf3c:'807c245000',0x2e1cf41:'7515',0x2e1cf58:'488db424200d0000',0x2e1cf60:'bad80b0000',0x2e1cf65:'4889df',0x2e1cf68:'ff159a256c03',0x4eca743:'488d0dae355d01',0x4eca755:'ff15456c6101',0x4eca75b:'bf70000000',0x4eca760:'ff151a4d6101',0x4eca7a9:'4c8933',0x4eca7ac:'44897b08',0x4eca7b0:'48894310',0x4eca7b4:'c6431800'}
def check(r):
 for a,v in pins.items():assert r[a]==bytes.fromhex(v),hex(a)
check(rows)
def target(a):
 x=rows[a];return a+len(x)+int.from_bytes(x[-4:],'little',signed=True)
for a,t in [(0x2e1c744,0x459a20),(0x2e1c74c,0x64e87d8),(0x2e1c75a,0x459410),(0x2e1c762,0x64e87d8),(0x2e1cf68,0x64df508),(0x4eca755,0x64e13a0)]:assert target(a)==t
assert 0x2e1cf41+2+int.from_bytes(rows[0x2e1cf41][1:],'little',signed=True)==0x2e1cf58
assert struct.unpack('<Q',read('.rodata',0x459a20,8))[0]==0x3fd3333333333333
assert struct.unpack('<Q',read('.rodata',0x459410,8))[0]==0x3fb9999999999999
assert 0x17a8-0xd20==0xa88 and 0x17c8-0xd20==0xaa8 and 0xaa8+0x20<=0xbd8
r=next(x for x in s if x['name']=='.rela.dyn');rel={a:(i,d) for a,i,d in struct.iter_unpack('<QQq',b[r['offset']:r['offset']+r['size']])}
assert rel[0x64e87d8]==(8,0x4eca5d0) and rel[0x64e13a0]==(8,0x5cf2150) and rel[0x64df508]==((7<<32)|6,0)
dyn=next(x for x in s if x['name']=='.dynsym');st=next(x for x in s if x['name']=='.dynstr');n=struct.unpack_from('<I',b,dyn['offset']+7*24)[0];p=st['offset']+n;assert b[p:b.index(b'\0',p)]==b'memcpy'
for a in (0x2e1c73c,0x2e1c75a,0x2e1cd30,0x2e1cd50,0x2e1cf60,0x4eca7b0):
 changed=dict(rows);changed[a]=changed[a][:-1]+bytes([changed[a][-1]^1])
 try:check(changed)
 except AssertionError:pass
 else:raise AssertionError('mutation accepted '+hex(a))
print(f'{len(bodies)} decoded FDEs, {len(rows)} spans, {len(pins)} pins, 7 edges, 3 relocations, 2 constants, 1 import and 6 corruption controls: OK')
