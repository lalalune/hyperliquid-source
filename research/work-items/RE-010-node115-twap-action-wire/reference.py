#!/usr/bin/env python3
"""Synthetic Python object packer and fixed-eight text reference."""
from pathlib import Path
import hashlib,random,struct,sys
out=Path(__file__).resolve().parents[3]/'src/node115-twap-action-wire/tests/reference-vectors.txt'
def pack(x):
 if x is None:return b'\xc0'
 if isinstance(x,bool):return b'\xc3' if x else b'\xc2'
 if isinstance(x,int):
  if x<128:return bytes([x])
  if x<256:return b'\xcc'+struct.pack('>B',x)
  if x<65536:return b'\xcd'+struct.pack('>H',x)
  if x<2**32:return b'\xce'+struct.pack('>I',x)
  return b'\xcf'+struct.pack('>Q',x)
 if isinstance(x,str):
  b=x.encode();n=len(b)
  return (bytes([0xa0+n]) if n<32 else b'\xd9'+bytes([n]) if n<256 else b'\xda'+struct.pack('>H',n))+b
 if isinstance(x,list):return bytes([0x90+len(x)])+b''.join(pack(i) for i in x)
 return bytes([0x80+len(x)])+b''.join(pack(k)+pack(v) for k,v in x.items())
def record(mode,fields):return dict(fields) if mode else [v for _,v in fields]
def decimal(n):
 s=f'{n//100000000}.{n%100000000:08d}'.rstrip('0').rstrip('.')
 return s
rows=['# mode kind asset quantity b r m t details trigger triggerbool detailstring expected'];r=random.Random(1154380)
strings=['','abc','x'*31,'y'*32,'z'*255,'é']
for i in range(6000):
 mode=i%2;kind=(i//2)%2;asset=r.choice([0,127,128,255,256,65535,65536,2**32-1]);qty=r.choice([0,1,10,10**8,10**8+1,2**63-1,r.randrange(2**63)])
 b=bool(i&4); rr=bool(i&8);m=r.choice([0,127,128,255,256,65535,65536,2**32,2**64-1]);t=bool(i&16);details=(i//32)%5
 trigger=strings[(i//160)%len(strings)]; triggerbool=bool(i&8); ds=strings[(i//960)%len(strings)]
 if kind==0:
  obj=record(mode,[('type','twapCancel'),('a',asset),('t',m)])
 else:
  nested=record(mode,[('a',asset),('b',b),('s',decimal(qty)),('r',rr),('m',m),('t',t)])
  fields=[('type','twapOrder'),('twap',nested)]
  if details:
   tr=record(mode,[('p',trigger),('a',triggerbool)]) if details&1 else None
   extra=record(mode,[('t',tr),('s',ds if details&2 else None)])
   fields.append(('details',extra))
  obj=record(mode,fields)
 rows.append(f'{mode} {kind} {asset} {qty} {int(b)} {int(rr)} {m} {int(t)} {details} {trigger.encode().hex() or "-"} {int(triggerbool)} {ds.encode().hex() or "-"} {pack(obj).hex()}')
data=('\n'.join(rows)+'\n').encode()
if '--write' in sys.argv:out.write_bytes(data)
else:
 assert out.read_bytes()==data
 print('6000 independent object-pack cases; sha256',hashlib.sha256(data).hexdigest())
