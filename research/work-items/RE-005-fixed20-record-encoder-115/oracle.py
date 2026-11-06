#!/usr/bin/env python3
"""Independent whole fixed20-prefix/four-scalar relations, no target evaluation."""
from pathlib import Path
import gzip,hashlib,json,itertools
P=Path(__file__).resolve().parent;R=P.parents[2];MAX=(1<<64)-1

def scalar(v):
 if v<251:return [bytes([v])]
 n=2 if v<65536 else 4 if v<(1<<32) else 8
 return [bytes([{2:251,4:252,8:253}[n]]),v.to_bytes(n,'little')]
def relation(op,text,prefix_hex,state,used,fail,seed):
 words=list(map(int,text.split(',')));prefix=bytes.fromhex(prefix_hex)
 if op=='s':
  count=state
  if count+20>MAX:return f'prefix|{count}'
  count+=20
  for i,v in enumerate(words):
   for event in scalar(v):
    if count+len(event)>MAX:return f'field:{i}|{count}'
    count+=len(event)
  return f'ok|{count}'
 events=[('prefix',prefix)]
 for i,v in enumerate(words):
  for j,event in enumerate(scalar(v)):events.append((f'field:{i}:{"prefix" if j==0 else "payload"}',event))
 cap=state;data=bytearray((seed+13*i)%256 for i in range(used));requests=0
 for stage,event in events:
  if len(data)+len(event)>cap:
   requests+=1
   if requests==fail:return f'{stage}|{cap}|{len(data)}|{requests}|{data.hex() or "-"}'
   cap=max(8,2*cap,len(data)+len(event))
  data.extend(event)
 return f'ok|{cap}|{len(data)}|{requests}|{data.hex() or "-"}'
def records():
 seen=set();boundaries=[0,1,250,251,65535,65536,(1<<32)-1,1<<32,MAX]
 for i,v,b in itertools.product(range(4),boundaries,[0,MAX]):
  row=[b]*4;row[i]=v;t=tuple(row)
  if t not in seen:seen.add(t);yield t
 yield (0,251,65536,MAX)
 state=0x4669786564507266
 for _ in range(128):
  row=[]
  for _ in range(4):state=(state*6364136223846793005+1442695040888963407)&MAX;row.append(state)
  yield tuple(row)
def cases():
 seen=set()
 def add(r):
  if r in seen:return False
  seen.add(r);return True
 for index,words in enumerate(records()):
  text=','.join(map(str,words));h=bytes((index+37*i)%256 for i in range(20)).hex();total=20+sum(sum(map(len,scalar(v))) for v in words)
  for initial in [0,1,*[MAX-i for i in range(61)]]:
   row=('s',text,h,initial,0,0,19)
   if add(row):yield row
  for cap,fail in itertools.product([0,1,8,19,20,21,32,40,64,total],[0,1,2,3,4]):
   for used in {0,cap}:
    row=('w',text,h,cap,used,fail,19)
    if add(row):yield row
 for seed in range(256):
  h=bytes((seed+37*i)%256 for i in range(20)).hex()
  for cap,used,fail in [(0,0,0),(0,0,1),(19,0,1),(20,0,1),(64,0,0),(8,7,1)]:
   row=('w','0,1,251,65536',h,cap,used,fail,7)
   if add(row):yield row

def render():return ''.join('\t'.join(map(str,row))+'\t'+relation(*row)+'\n' for row in cases()).encode()
if __name__=='__main__':
 d=render();(P/'cases.tsv.gz.hex').write_text(gzip.compress(d,mtime=0).hex()+'\n');j={'case_count':len(d.splitlines()),'sha256':hashlib.sha256(d).hexdigest(),'oracle_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'new_rust_exists_at_freeze':(R/'src/node115-fixed20-record-encoder').exists(),'target_sha256':'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301','basis':'Complete atomic20-prefix followed by four scalar events, checked count and real Vec-growth boundary relation. No captured execution/emulation.','storage':'lossless gzip(mtime0) hex packed before new Rust'};(P/'freeze.json').write_text(json.dumps(j,indent=2)+'\n');print(json.dumps(j))
