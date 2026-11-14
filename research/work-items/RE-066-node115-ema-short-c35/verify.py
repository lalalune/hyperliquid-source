#!/usr/bin/env python3
"""Static-only verifier for RE-066; never executes captured code."""
from pathlib import Path
import hashlib, json, sys
P=Path(__file__).resolve().parent; R=P.parents[2]
sys.path.insert(0,str(R/'tools'))
from elf_index import sections
from fde_extents import eh_frame_records

TARGET=R/'artifacts/node/115/hl-node'
SHA='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
START,END=0x4d3b4d0,0x4d3b5b1
W={0x4d3b4d0:'4157415653',0x4d3b4db:'488b7f08',0x4d3b4df:'498b4610',0x4d3b4e3:'488b7608',0x4d3b4e7:'488b5310',0x4d3b4eb:'4989c7',0x4d3b4ee:'4929d7',0x4d3b4f1:'480f42d0',0x4d3b4f5:'ff1555467a01',0x4d3b503:'4d85ff',0x4d3b50c:'0f8597000000',0x4d3b512:'498b7e20',0x4d3b516:'498b4628',0x4d3b51a:'488b7320',0x4d3b51e:'488b5328',0x4d3b52c:'ff151e467a01',0x4d3b53a:'4d85ff',0x4d3b543:'7564',0x4d3b545:'498b7e38',0x4d3b549:'498b4640',0x4d3b54d:'488b7338',0x4d3b551:'488b5340',0x4d3b55f:'ff15eb457a01',0x4d3b56d:'4d85ff',0x4d3b576:'7531',0x4d3b578:'498b7e50',0x4d3b57c:'498b4658',0x4d3b580:'488b7350',0x4d3b584:'488b5358',0x4d3b592:'ff15b8457a01',0x4d3b5a0:'4885db',0x4d3b5a9:'28c8'}
def fail(m): raise ValueError(m)
def image(raw):
 if hashlib.sha256(raw).hexdigest()!=SHA: fail('wrong capture')
 ss=sections(raw)
 def read(a,n):
  x=[s for s in ss if s['type']!=8 and s['address']<=a<=s['address']+s['size'] and a+n<=s['address']+s['size']]
  if len(x)!=1: fail('VA mapping')
  s=x[0]; return raw[s['offset']+a-s['address']:s['offset']+a-s['address']+n]
 _,fs=eh_frame_records(raw,ss); f=[x for x in fs if x['start']==START and x['end']==END]
 if len(f)!=1: fail('FDE boundary')
 body=read(START,END-START)
 import subprocess,re
 od='objdump'
 text=subprocess.check_output([od,'-d','-M','intel',f'--start-address={START:#x}',f'--stop-address={END:#x}',str(TARGET)],text=True)
 rows=[]
 for line in text.splitlines():
  m=re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)',line)
  if m: rows.append((int(m.group(1),16),bytes.fromhex(m.group(2))))
 if not rows or rows[0][0]!=START or b''.join(x[1] for x in rows)!=body: fail('incomplete partition')
 for a,h in W.items():
  if read(a,len(bytes.fromhex(h)))!=bytes.fromhex(h): fail('witness '+hex(a))
 return {'target_sha256':SHA,'fde_start':hex(START),'fde_end':hex(END),'fde_bytes':END-START,'eh_frame_offset':'0xf17230','instructions':len(rows),'witnesses':len(W),'mutation_controls':2,'execution_or_emulation':False}
if __name__=='__main__':
 raw=TARGET.read_bytes(); r=image(raw)
 for mutated in (raw[:-1],bytes([raw[0]^1])+raw[1:]):
  try:image(mutated)
  except ValueError: pass
  else: fail('identity mutation accepted')
 print(json.dumps(r,sort_keys=True,indent=2))
