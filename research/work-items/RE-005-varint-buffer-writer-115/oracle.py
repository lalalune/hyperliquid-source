#!/usr/bin/env python3
"""Independent value/event/growth mathematics; never executes target code."""
from pathlib import Path
import gzip,hashlib,json,itertools
P=Path(__file__).resolve().parent;R=P.parents[2]
def relation(value,cap,used,fail,seed):
 data=bytearray((seed+13*i)%256 for i in range(used));requests=0
 if value<251:prefix=value;payload=b''
 else:
  width=2 if value<65536 else 4 if value<(1<<32) else 8
  prefix={2:251,4:252,8:253}[width];payload=value.to_bytes(width,'little')
 # Each event represents one logically atomic initialized-byte append. A native
 # grow helper is required only when the event does not fit the actual capacity.
 for stage,event in [('prefix',bytes([prefix])),('payload',payload)]:
  if not event:continue
  if len(data)+len(event)>cap:
   requests+=1
   new=max(8,cap*2,len(data)+len(event))
   if requests==fail:return f'{stage}|{cap}|{len(data)}|{requests}|{data.hex() or "-"}'
   cap=new
  data.extend(event)
 return f'ok|{cap}|{len(data)}|{requests}|{data.hex() or "-"}'
def cases():
 seen=set();values=list(range(1100))+[65534,65535,65536,65537,(1<<32)-2,(1<<32)-1,1<<32,(1<<32)+1,(1<<63)-1,1<<63,(1<<64)-2,(1<<64)-1]
 for value,cap,fail in itertools.product(values,[0,1,2,3,4,5,7,8,9,16],[0,1,2,3]):
  for used in {0,cap,max(0,cap-1)}:
   row=(value,cap,used,fail,19)
   if row not in seen:seen.add(row);yield row
 state=0x72657475726e
 for i in range(512):
  state=(state*6364136223846793005+1442695040888963407)% (1<<64)
  for cap,used,fail in [(0,0,0),(0,0,1),(0,0,2),(1,0,1),(8,7,1),(16,15,1),(32,23,0),(32,32,0)]:
   row=(state,cap,used,fail,i%256)
   if row not in seen:seen.add(row);yield row

def render():return ''.join('\t'.join(map(str,row))+'\t'+relation(*row)+'\n' for row in cases()).encode()
if __name__=='__main__':
 data=render();compressed=gzip.compress(data,mtime=0);(P/'cases.tsv.gz.hex').write_text(compressed.hex()+'\n');j={'case_count':len(data.splitlines()),'sha256':hashlib.sha256(data).hexdigest(),'oracle_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'new_rust_exists_at_freeze':(R/'src/node115-varint-buffer-writer').exists(),'target_sha256':'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301','storage':'Lossless gzip(mtime0) hexadecimal text packed before Rust; hash binds original TSV bytes.','basis':'Value event relation and observed byte-vector growth max(8,2cap,len+additional); actual allocator failure snapshots adapted, no captured execution/emulation'};(P/'freeze.json').write_text(json.dumps(j,indent=2)+'\n');print(json.dumps(j))
