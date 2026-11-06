#!/usr/bin/env python3
"""Frozen byte-copy/first-NUL relation; no captured instruction execution."""
from pathlib import Path
import hashlib,json,gzip,sys
P=Path(__file__).resolve().parent;R=P.parents[2];sys.path.insert(0,str(P));import verify

def cases():
 out=set()
 for n in list(range(80))+[127,128,129,255,256,257,383,384,385,511,512,513,1023]:
  b=bytes((i*37+11)%255+1 for i in range(n))
  for align in range(16):
   out.add((align,0,b));out.add((align,1,b))
   for zero in sorted({0,n//2,max(n-1,0),7,8,15,16,31,32}):
    if zero<n:out.add((align,0,b[:zero]+b'\0'+b[zero+1:]))
 for byte in range(256):
  for n in [0,1,2,7,8,15,16,17,31,32,33,64]:
   out.add((byte%16,0,bytes([byte])*n))
 for n in range(33):
  for first in range(n):
   for second in [first,n-1]:
    b=bytearray([255]*n);b[first]=b[second]=0;out.add((first%16,0,bytes(b)))
 return sorted(out)
def result(row):
 align,fail,b=row
 if fail:return 'allocation|0|0|1'
 pos=b.find(b'\0');cap=len(b)+1
 if pos>=0:return f'nul:{pos}:{b.hex() or "-"}|{len(b)}|{cap}|1'
 return f'ok:{(b+bytes(1)).hex()}|{len(b)+1}|{cap}|1'
def freeze():
 verify.collect(verify.TARGET.read_bytes(),True);rows=cases();raw=''.join(f'{a}\t{f}\t{b.hex() or "-"}\t{result((a,f,b))}\n' for a,f,b in rows).encode();return raw,{'cases':len(rows),'fixture_sha256':hashlib.sha256(raw).hexdigest(),'new_rust_exists':(R/'src/node115-owned-cstring').exists(),'oracle_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'scope_sha256':hashlib.sha256((P/'scope.json').read_bytes()).hexdigest(),'target_sha256':verify.SPEC['target_sha256'],'fixture_storage':'gzip(mtime0)+hex before Rust'}
if __name__=='__main__':
 raw,j=freeze();assert not j['new_rust_exists'];(P/'freeze.json').write_text(verify.dump(j));(P/'cases.tsv.gz.hex').write_text(gzip.compress(raw,mtime=0).hex()+'\n');print(verify.dump(j))
