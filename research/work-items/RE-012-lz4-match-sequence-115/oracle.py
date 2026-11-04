#!/usr/bin/env python3
"""Mathematical staged byte events, independent of Rust scalar emission."""
from pathlib import Path
import hashlib,json,itertools
P=Path(__file__).resolve().parent;R=P.parents[2]
def events(n,seed,extra,offset):
 yield 'token', bytes([(min(n,15)<<4)|min(extra,15)]),0
 if n>=15:
  q,r=divmod(n-15,255);yield 'literal-extension',bytes([r]),q
 yield 'literals',bytes((i*17+seed)%256 for i in range(n)),0
 yield 'offset',offset.to_bytes(2,'little'),0
 if extra>=15:
  q,r=divmod(extra-15,255);yield 'match-extension',bytes([r]),q

def relation(n,seed,extra,offset,cap,used):
 sink=bytearray((i*13+seed)%256 if i<used else 0xcc for i in range(cap))
 if used>cap:return f'domain:{used}:{sink.hex() or "-"}'
 status='ok'
 for stage,payload,repeats in events(n,seed,extra,offset):
  free=cap-used
  if repeats:
   take=min(free,repeats);sink[used:used+take]=b'\xff'*take;used+=take
   if take<repeats:status=stage;break
  if len(payload)>cap-used:status=stage;break
  sink[used:used+len(payload)]=payload;used+=len(payload)
 return f'{status}:{used}:{sink.hex() or "-"}'

def cases():
 seen=set()
 def one(n,e,d,c,u,seed=19):
  row=(n,seed,e,d,c,u)
  if row in seen:return None
  seen.add(row);return row
 es=[0,1,2,14,15,16,269,270,271,524,525,526,1034,1035,1036,(1<<64)-1]
 for n,e,d,u in itertools.product(range(33),es,[0,1,0x1234,65535],[0,3]):
  lex=(n-15)//255+1 if n>=15 else 0
  prior=1+lex+n
  for free in sorted(set([0,1,2,1+lex-1,1+lex,prior-1,prior,prior+1,prior+2,prior+3,prior+6])):
   row=one(n,e,d,u+max(0,free),u)
   if row:yield row
 for n,e in itertools.product([269,270,271,524,525,526,1034,1035,1036,4096],[14,15,16,270,271,1035]):
  lex=(n-15)//255+1;prior=1+lex+n
  for u,free in itertools.product([0,7],[0,1,2,3,4,5,lex,lex+1,lex+2,prior-1,prior,prior+1,prior+2,prior+3,prior+6]):
   row=one(n,e,0x0201,u+free,u,7)
   if row:yield row
 for n,e,u,cap in itertools.product([0,14,15,16],[0,15,270],[1,8],[0,1,7]):
  row=one(n,e,255,cap,u)
  if row:yield row

def render():
 return ''.join('\t'.join(map(str,row))+'\t'+relation(*row)+'\n' for row in cases()).encode()
if __name__=='__main__':
 data=render();(P/'cases.tsv').write_bytes(data);j={'case_count':len(data.splitlines()),'sha256':hashlib.sha256(data).hexdigest(),'oracle_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'new_rust_exists_at_freeze':(R/'src/node115-lz4-match-sequence').exists(),'target_sha256':'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301','basis':'Mathematical token/literal/offset/match events from two complete FDEs, without captured execution or instruction emulation'};(P/'freeze.json').write_text(json.dumps(j,indent=2)+'\n');print(json.dumps(j))
