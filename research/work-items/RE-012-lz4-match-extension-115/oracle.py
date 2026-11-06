#!/usr/bin/env python3
"""Independent bounded common-prefix expectations, not target execution."""
from pathlib import Path
import hashlib,json,itertools
P=Path(__file__).resolve().parent;R=P.parents[2]
def relation(left,right,cursor,other):
 if len(left)<6:return f'adapter:{cursor}'
 if cursor>len(left)-6:return f'left-boundary:{cursor}'
 if other>len(right):return f'right-boundary:{cursor}'
 # Python's zip/slice relation is independent of the Rust qword/tzcnt method.
 a=left[cursor:len(left)-6];b=right[other:]
 count=next((i for i,(x,y) in enumerate(zip(a,b)) if x!=y),min(len(a),len(b)))
 return f'ok:{count}:{cursor+count}'
def cases():
 seen=set()
 def unique(row):
  if row in seen:return False
  seen.add(row);return True
 sizes=list(range(0,20))+[22,23,24,25,26,31,32,33,34,63,64,65,66,95,96]
 for n,m in itertools.product(sizes,[0,1,2,7,8,9,15,16,17,31,64,96]):
  for seed in [0,1]:
   left=bytes(((i*17+3) % 256 if seed else 0) for i in range(n));right=bytes(((i*17+3) % 256 if seed else 0) for i in range(m))
   for c,d in itertools.product([0,1,7,8,max(0,n-6),max(0,n-7),n+1],[0,1,7,8,m,m+1]):
    row=(left,right,c,d)
    if unique(row):yield row
 # Each possible differing bit in every byte near qword/tail boundaries.
 for n,c,d,index,bit in itertools.product([14,15,21,22,23,29,30,31,62],[0,1,3],[0,2],range(40),range(8)):
  left=bytes((i*31+7)%256 for i in range(n));r=bytearray(b'\xa5'*d+left[c:]+b'\xa5'*5)
  if d+index>=len(r):continue
  r[d+index]^=1<<bit
  row=(left,bytes(r),c,d)
  if unique(row):yield row
 # Same underlying buffer, which is the actual two compressor callers' case.
 for n,c,d in itertools.product([12,13,14,20,21,22,31,32,63,64,95],[0,1,4,8],[0,1,4,8]):
  for period in [1,2,4,8]:
   x=bytes(i%period for i in range(n));row=(x,x,c,d)
   if unique(row):yield row

def render():
 return ''.join(f'{a.hex() or "-"}\t{b.hex() or "-"}\t{c}\t{d}\t{relation(a,b,c,d)}\n' for a,b,c,d in cases()).encode()
if __name__=='__main__':
 data=render();(P/'cases.tsv').write_bytes(data)
 j={'cases':len(data.splitlines()),'sha256':hashlib.sha256(data).hexdigest(),'new_rust_exists_at_freeze':(R/'src/node115-lz4-match-extension').exists(),'oracle_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'target_sha256':'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301','basis':'Complete helper instructions and independent byte-prefix oracle; no captured execution/emulation'}
 (P/'freeze.json').write_text(json.dumps(j,indent=2)+'\n');print(json.dumps(j))
