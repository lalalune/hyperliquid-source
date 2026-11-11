#!/usr/bin/env python3
"""Static branch arithmetic and bitwise identities; no captured-code evaluator."""
from pathlib import Path
import json
import verify
P=Path(__file__).resolve().parent

def derive():
 d=verify.TARGET.read_bytes();record,_=verify.collect(d)
 pins={p['meaning']:bytes.fromhex(p['raw']) for p in verify.SPEC['anchors']}
 # Only the selected grammar phrase is decoded. The complete generic formatter
 # supports more opcodes; no claim is made for those other branches.
 phrase=pins['compact-template'];assert phrase==bytes.fromhex('c0015fc000')
 assert pins['vector-space-16']==bytes([32])*16
 assert pins['vector-underscore-16']==bytes([95])*16
 assert pins['vector-space8-and-zero-high-lanes']==bytes([32])*8+bytes(8)
 assert pins['vector-underscore8-and-zero-high-lanes']==bytes([95])*8+bytes(8)
 values=[]
 for b in range(256):
  m=255 if b==32 else 0
  algebra=((~m&255)&b)|(m&95)
  direct=95 if b==32 else b
  assert algebra==direct;values.append(algebra)
 assert pins['decimal-digit-pairs']==b''.join(f'{x:02d}'.encode() for x in range(100))
 partitions=[]
 # Pure integer interval proof witnesses, not an x86 register/instruction model.
 # For any nonnegative n: q32*32 + q8*8 + q4*4 + r = n, no overlaps/gaps.
 for n in list(range(4097))+[2**k-1 for k in range(13,64)]+[2**63-1]:
  q32,r32=divmod(n,32);q8,r8=divmod(r32,8);q4,r=divmod(r8,4)
  assert q32*32+q8*8+q4*4+r==n and 0<=r<4
  assert (n&0x7fffffffffffffe0)==q32*32
  assert (n&0x7ffffffffffffff8)==q32*32+q8*8
  assert n&3==r
  if n in [0,1,3,4,7,8,15,16,31,32,33,63,64,65,2**63-1]:partitions.append({'length':n,'blocks32':q32,'blocks8':q8,'blocks4':q4,'scalar_remainder':r})
 clock=[v for v in record['bindings'] if v['slot']=='0x64e1248'];assert len(clock)==1 and clock[0]['symbol']=='clock_gettime' and clock[0]['info']&0xffffffff==6
 return {'target_sha256':record['target_sha256'],'selected_format_events':[{'argument_record_index':0,'function':'0x156d7f0','value_from':'0x1629690 output, 12 bytes'},{'literal_hex':'5f'},{'argument_record_index':1,'function':'0x1688a20','value_from':'one TLS buffered u32'}],'postprocess':'for every source byte b: 0x5f if b==0x20 else b; exact same byte count','lane_identity_values_checked':len(values),'length_partition_witnesses':partitions,'clock_symbol':clock[0],'primary_bytes':912,'context_bytes':sum(x['bytes'] for x in record['owners'] if x['role']!='primary-name-generator'),'full_function_records':len(record['owners']),'captured_execution_or_emulation':False,'limits':'No synthetic date/time rendering, RNG values, original allocator call, native panic payload, filesystem/network write, byte equivalence or source implementation.'}
if __name__=='__main__':
 import argparse
 ap=argparse.ArgumentParser();ap.add_argument('--freeze',action='store_true');a=ap.parse_args();r=derive()
 if a.freeze:(P/'derived.json').write_text(json.dumps(r,indent=2,sort_keys=True)+'\n')
 else:assert r==json.loads((P/'derived.json').read_text());print(json.dumps({'static_derived_facts':'match','lane_identity_values_checked':256,'captured_execution_or_emulation':False},indent=2))
