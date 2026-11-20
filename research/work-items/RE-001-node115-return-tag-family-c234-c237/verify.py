#!/usr/bin/env python3
from pathlib import Path
import hashlib,json,re,sys
ROOT=Path(__file__).resolve().parents[3];sys.path.insert(0,str(ROOT/'tools'))
from elf_index import unwind_index
from fde_extents import eh_frame_records
TARGET='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301';P=Path(__file__).parent;R=json.loads((P/'records.json').read_text())
def main():
 d=(ROOT/'artifacts/node/115/hl-node').read_bytes();assert hashlib.sha256(d).hexdigest()==TARGET;s,h=unwind_index(d);_,f=eh_frame_records(d,s);b={(x['start'],x['end']):x for x in f};hb={x['start']:x['fde'] for x in h};q={};p=re.compile(r'^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s*)+)$')
 for l in (P/'excerpts.objdump.txt').read_text().splitlines():
  m=p.match(l)
  if m:q[int(m.group(1),16)]=bytes.fromhex(m.group(2))
 assert len(R)==4
 for r in R:
  a,z,u=(int(r[k],16) for k in ('start','end','fde'));assert b.get((a,z),{}).get('fde')==u;assert hb.get(a)==u;assert q.get(a)==b'\x53';assert q.get(a+1)==bytes.fromhex('4883ec50');assert q.get(z-1)==b'\xc3';c=[x for x,v in q.items() if a<=x<z and v[:1]==b'\xe8'];assert len(c)==1;assert c[0]+5+int.from_bytes(q[c[0]][1:5],'little',signed=True)==int(r['call_target'],16)
 assert q.get(0x4d4944f)==b'\xcc';assert q.get(0x4d49609)==b'\xcc';print('verified 4 node115 sibling FDEs, call targets, terminal returns, and boundaries')
if __name__=='__main__':main()
