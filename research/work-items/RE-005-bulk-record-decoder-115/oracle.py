#!/usr/bin/env python3
"""Independent branch mathematics for the complete two-scalars/2048-byte record."""
from pathlib import Path
import hashlib,json,itertools
P=Path(__file__).resolve().parent;R=P.parents[2];MAX=(1<<64)-1

def input_bytes(h,n,seed,suffix):return bytes.fromhex(h)+bytes((seed+37*i)%256 for i in range(n))+bytes.fromhex(suffix)
def relation(h,n,seed,suffix,limit_text,initial):
 data=input_bytes(h,n,seed,suffix);cursor=0;charged=initial;limit=None if limit_text=='-' else int(limit_text)
 def charge(width):
  nonlocal charged
  if limit is None:return None
  if charged+width>MAX:return 'limit'
  charged+=width
  return 'limit' if charged>limit else None
 def scalar():
  nonlocal cursor
  err=charge(8)
  if err:return None,err
  count=len(data)-cursor
  if not count:return None,'short:1'
  start=cursor;marker=data[start];short=count<=8
  if short:cursor+=1
  if marker<251:cursor=start+1;return marker,None
  width={251:3,252:5,253:9}.get(marker)
  if width is None:return None,f'invalid:5:{4 if marker==254 else 12}'
  if count<width:return None,f'short:{width-count}'
  value=sum(data[start+1+i]<<(8*i) for i in range(width-1));cursor=start+width
  return value,None
 fields=[]
 for _ in range(2):
  value,err=scalar()
  if err:return f'{err}|{cursor}|{charged}|-'
  fields.append(value)
 err=charge(2048)
 if err:return f'{err}|{cursor}|{charged}|-'
 available=len(data)-cursor
 if available<2048:return f'short:{2048-available}|{cursor}|{charged}|-'
 payload=data[cursor:cursor+2048];cursor+=2048
 return f'ok:{fields[0]}:{fields[1]}|{cursor}|{charged}|{payload.hex()}'

def cases():
 seen=set()
 def unique(r):
  if r in seen:return False
  seen.add(r);return True
 enc=[bytes([0]),bytes([1]),bytes([250]),b'\xfb\xfb\x00',b'\xfb\xff\xff',b'\xfc\x00\x00\x01\x00',b'\xfc'+b'\xff'*4,b'\xfd'+b'\x00'*4+b'\x01\x00\x00\x00',b'\xfd'+b'\xff'*8,b'\xfb\x00\x00',b'\xfc\x01\x00\x00\x00',b'\xfd\x02'+b'\x00'*7]
 for a,b,n,limit in itertools.product(enc,enc,[0,1,7,8,15,2047,2048,2049],['-', '7','8','15','16','2063','2064','2065']):
  r=((a+b).hex(),n,19,'a55a',limit,0)
  if unique(r):yield r
 for h,n,limit in itertools.product(['','fb','fb01','fc010203','fd01020304050607','fe','ff','00fe','00ff','00fb','00fd010203','fb0100fe'],range(12),['-','7','8','15','16','2064']):
  r=(h,n,7,'',limit,0)
  if unique(r):yield r
 for initial,n in itertools.product([MAX,MAX-7,MAX-8,MAX-15,MAX-16,MAX-2047,MAX-2048,MAX-2063,MAX-2064,MAX-2065],[0,2048]):
  for limit in ['-',str(MAX),'0',str(initial),str(min(MAX,initial+8)),str(min(MAX,initial+16)),str(min(MAX,initial+2064))]:
   r=('0001',n,255,'cc',limit,initial)
   if unique(r):yield r
 for h,n,limit in itertools.product(['0001','fd010203040506070801'],[2046,2047,2048],['-','2063','2064']):
  r=(h,n,31,'',limit,0)
  if unique(r):yield r
 for seed,n in itertools.product(range(256),[2048,2049]):
  r=('0001',n,seed,'feff','-',0)
  if unique(r):yield r

def render():
 return ''.join('\t'.join([h or '-',str(n),str(seed),suffix or '-',limit,str(initial)])+'\t'+relation(h,n,seed,suffix,limit,initial)+'\n' for h,n,seed,suffix,limit,initial in cases()).encode()
if __name__=='__main__':
 data=render();(P/'cases.tsv').write_bytes(data);j={'case_count':len(data.splitlines()),'sha256':hashlib.sha256(data).hexdigest(),'oracle_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'new_rust_exists_at_freeze':(R/'src/node115-bulk-record-decoder').exists(),'target_sha256':'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301','basis':'Independent scalar/charge/copy relation; no captured execution or instruction emulation'};(P/'freeze.json').write_text(json.dumps(j,indent=2)+'\n');print(json.dumps(j))
