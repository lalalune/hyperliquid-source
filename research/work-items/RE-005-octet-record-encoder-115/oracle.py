#!/usr/bin/env python3
"""Independent whole eight-word/raw-byte record relations; no target execution."""
from pathlib import Path
import gzip,hashlib,json,itertools
P=Path(__file__).resolve().parent;R=P.parents[2];MAX=(1<<64)-1

def scalar_events(v):
 if v<251:return [bytes([v])]
 width=2 if v<65536 else 4 if v<(1<<32) else 8
 return [bytes([{2:251,4:252,8:253}[width]]),v.to_bytes(width,'little')]
def relation(op,text,trailer,state,used,fail,seed):
 words=list(map(int,text.split(',')))
 if op=='s':
  count=state
  for i,v in enumerate(words):
   for event in scalar_events(v):
    if count+len(event)>MAX:return f'field:{i}|{count}'
    count+=len(event)
  if count==MAX:return f'trailer|{count}'
  return f'ok|{count+1}'
 cap=state;data=bytearray((seed+13*i)%256 for i in range(used));requests=0
 events=[]
 for i,v in enumerate(words):
  for j,event in enumerate(scalar_events(v)):events.append((f'field:{i}:{"prefix" if j==0 else "payload"}',event))
 events.append(('trailer',bytes([trailer])))
 for stage,event in events:
  if len(data)+len(event)>cap:
   requests+=1
   if requests==fail:return f'{stage}|{cap}|{len(data)}|{requests}|{data.hex() or "-"}'
   cap=max(8,cap*2,len(data)+len(event))
  data.extend(event)
 return f'ok|{cap}|{len(data)}|{requests}|{data.hex() or "-"}'

def records():
 seen=set();boundary=[0,1,250,251,65535,65536,(1<<32)-1,1<<32,(1<<64)-1]
 for i,value,background in itertools.product(range(8),boundary,[0,MAX]):
  row=[background]*8;row[i]=value;t=tuple(row)
  if t not in seen:seen.add(t);yield t
 yield tuple([0,1,250,251,65535,65536,1<<32,MAX])
 state=0x4f72646572427974
 for _ in range(128):
  row=[]
  for i in range(8):state=(state*6364136223846793005+1442695040888963407)&MAX;row.append(state)
  yield tuple(row)

def cases():
 seen=set()
 def add(row):
  if row in seen:return False
  seen.add(row);return True
 for index,words in enumerate(records()):
  text=','.join(map(str,words));trailer=[0,1,2,255][index%4]
  total=sum(sum(map(len,scalar_events(v))) for v in words)
  for initial in [0,1,*[MAX-i for i in range(75)]]:
   row=('s',text,trailer,initial,0,0,19)
   if add(row):yield row
  caps=[0,1,8,9,16,32,64,total]
  for cap,fail in itertools.product(caps,[0,1,2,3,4,5]):
   for used in {0,cap}:
    row=('w',text,trailer,cap,used,fail,19)
    if add(row):yield row
 for trailer in range(256):
  for cap,fail in [(0,0),(8,1),(128,0)]:
   row=('w','0,1,2,3,4,5,6,7',trailer,cap,0,fail,7)
   if add(row):yield row

def render():return ''.join('\t'.join(map(str,row))+'\t'+relation(*row)+'\n' for row in cases()).encode()
if __name__=='__main__':
 d=render();(P/'cases.tsv.gz.hex').write_text(gzip.compress(d,mtime=0).hex()+'\n');j={'case_count':len(d.splitlines()),'sha256':hashlib.sha256(d).hexdigest(),'oracle_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'new_rust_exists_at_freeze':(R/'src/node115-octet-record-encoder').exists(),'target_sha256':'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301','basis':'Complete ordered eight-scalar/trailer events, scalar staged count and actual Vec-growth boundary mathematics. No captured execution/emulation.','storage':'lossless gzip(mtime0) hex, packed before new Rust'};(P/'freeze.json').write_text(json.dumps(j,indent=2)+'\n');print(json.dumps(j))
