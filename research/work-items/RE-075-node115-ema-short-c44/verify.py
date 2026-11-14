#!/usr/bin/env python3
"""Static-only verifier for RE-075."""
from pathlib import Path
import hashlib,json,sys,re,subprocess
P=Path(__file__).resolve().parent;R=P.parents[2];sys.path.insert(0,str(R/'tools'))
from elf_index import sections
from fde_extents import eh_frame_records
TARGET=R/'artifacts/node/115/hl-node';SHA='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301';START=0x4d3cd70;END=0x4d3cf3a
W={0x4d3cd70:'4157415653',0x4d3cd7b:'488b7f08',0x4d3cd95:'ff15b52d7a01',0x4d3cdb6:'498b4e68',0x4d3cdc4:'488d1401',0x4d3cde0:'0f9cc2',0x4d3cdf7:'498b7e78',0x4d3ce17:'ff15332d7a01',0x4d3ce33:'498b7e70',0x4d3ce4d:'ff15fd2c7a01',0x4d3ce60:'498bbe88000000'}
def fail(m):raise ValueError(m)
def check(raw):
 if hashlib.sha256(raw).hexdigest()!=SHA:fail('wrong capture')
 ss=sections(raw)
 def read(a,n):
  x=[s for s in ss if s['type']!=8 and s['address']<=a and a+n<=s['address']+s['size']]
  if len(x)!=1:fail('VA mapping')
  s=x[0];o=s['offset']+a-s['address'];return raw[o:o+n]
 _,fs=eh_frame_records(raw,ss)
 if len([f for f in fs if f['start']==START and f['end']==END])!=1:fail('FDE boundary')
 body=read(START,END-START);txt=subprocess.check_output(['/opt/homebrew/opt/binutils/bin/objdump','-d','-M','intel',f'--start-address={START:#x}',f'--stop-address={END:#x}',str(TARGET)],text=True);rows=[]
 for line in txt.splitlines():
  m=re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)',line)
  if m:rows.append((int(m[1],16),bytes.fromhex(m[2])))
 if not rows or rows[0][0]!=START or b''.join(x[1] for x in rows)!=body:fail('incomplete partition')
 for a,h in W.items():
  if read(a,len(bytes.fromhex(h)))!=bytes.fromhex(h):fail('witness '+hex(a))
 return {'target_sha256':SHA,'fde_start':hex(START),'fde_end':hex(END),'fde_bytes':END-START,'eh_frame_offset':'0xf17568','instructions':len(rows),'witnesses':len(W),'identity_controls':2,'execution_or_emulation':False}
if __name__=='__main__':
 raw=TARGET.read_bytes();r=check(raw)
 for bad in (raw[:-1],bytes([raw[0]^1])+raw[1:]):
  try:check(bad)
  except ValueError:pass
  else:fail('identity mutation accepted')
 print(json.dumps(r,indent=2,sort_keys=True))
