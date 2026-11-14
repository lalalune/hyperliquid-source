#!/usr/bin/env python3
"""Static-only verifier for RE-067; captured code is never executed."""
from pathlib import Path
import hashlib,json,sys,re,subprocess
P=Path(__file__).resolve().parent; R=P.parents[2]; sys.path.insert(0,str(R/'tools'))
from elf_index import sections
from fde_extents import eh_frame_records
TARGET=R/'artifacts/node/115/hl-node'; SHA='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'; START=0x4d3b5c0; END=0x4d3b7b8
W={0x4d3b5c0:'4157415641545350',0x4d3b5db:'ff156f457a01',0x4d3b5ff:'49bf0000000000000080',0x4d3b609:'31c0',0x4d3b63f:'ff150b457a01',0x4d3b658:'488b4b38',0x4d3b68c:'ff15be447a01',0x4d3b6c4:'4839d1',0x4d3b6d5:'eb0a',0x4d3b720:'0fb65365',0x4d3b74b:'410fb64e66',0x4d3b77b:'410fb64664',0x4d3b780:'2a4364',0x4d3b796:'80f902',0x4d3b799:'0f95c0',0x4d3b7a3:'28c8',0x4d3b7b3:'e93bfeffff'}
def fail(m): raise ValueError(m)
def check(raw):
 if hashlib.sha256(raw).hexdigest()!=SHA: fail('wrong capture')
 ss=sections(raw)
 def read(a,n):
  x=[s for s in ss if s['type']!=8 and s['address']<=a and a+n<=s['address']+s['size']]
  if len(x)!=1: fail('VA mapping')
  s=x[0]; o=s['offset']+a-s['address']; return raw[o:o+n]
 _,fs=eh_frame_records(raw,ss)
 if len([f for f in fs if f['start']==START and f['end']==END])!=1: fail('FDE boundary')
 body=read(START,END-START); od='objdump'; txt=subprocess.check_output([od,'-d','-M','intel',f'--start-address={START:#x}',f'--stop-address={END:#x}',str(TARGET)],text=True); rows=[]
 for line in txt.splitlines():
  m=re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)',line)
  if m: rows.append((int(m[1],16),bytes.fromhex(m[2])))
 if not rows or rows[0][0]!=START or b''.join(x[1] for x in rows)!=body: fail('incomplete partition')
 for a,h in W.items():
  if read(a,len(bytes.fromhex(h)))!=bytes.fromhex(h): fail('witness '+hex(a))
 return {'target_sha256':SHA,'fde_start':hex(START),'fde_end':hex(END),'fde_bytes':END-START,'eh_frame_offset':'0xf1725c','instructions':len(rows),'witnesses':len(W),'identity_controls':2,'execution_or_emulation':False}
if __name__=='__main__':
 raw=TARGET.read_bytes(); result=check(raw)
 for bad in (raw[:-1],bytes([raw[0]^1])+raw[1:]):
  try: check(bad)
  except ValueError: pass
  else: fail('identity mutation accepted')
 print(json.dumps(result,indent=2,sort_keys=True))
