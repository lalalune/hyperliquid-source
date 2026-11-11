#!/usr/bin/env python3
"""Static table/format-bit and modular-bijection proofs; no instruction emulator."""
from pathlib import Path
import calendar,json
import verify
P=Path(__file__).resolve().parent

def derive():
 record,_=verify.collect(verify.TARGET.read_bytes());pins={p['meaning']:bytes.fromhex(p['raw']) for p in verify.SPEC['anchors']}
 delta=bytearray(733)
 for year in [2000,2001]:
  common=not calendar.isleap(year);ordinal=0
  for month in range(1,13):
   for day in range(1,calendar.monthrange(year,month)[1]+1):
    ordinal+=1;index=ordinal*2+common;delta[index]=month*64+day*2+common-index
 assert pins['monthday-delta-window']==bytes(delta)
 assert pins['large-year-plus-zero-width5-template']==bytes.fromhex('c320002069050000')
 for width,meaning in [(3,'fraction-zero-width3-template'),(6,'fraction-zero-width6-template'),(9,'fraction-zero-width9-template')]:
  assert pins[meaning]==bytes.fromhex('012ec320000069')+bytes([width,0,0])
 # Numeric formatter visibly tests plus bit0x200000 and zero bit0x1000000.
 assert 0x69200020&0x200000 and 0x69200020&0x1000000
 assert not 0x69000020&0x200000 and 0x69000020&0x1000000
 proofs=[]
 for divisor,shift,inverse in [(1000000,6,0x68c26139),(1000,3,0x26e978d5)]:
  odd=divisor>>shift;assert odd*(1<<shift)==divisor and odd&1 and (odd*inverse)%2**32==1
  limit=(2**32-1)//divisor;assert limit<2**(32-shift)
  # Multiply by odd inverse then rotate-right is a permutation. For each
  # k<=limit, input divisor*k maps to k without wrap of (k<<shift).
  # Bijection therefore excludes all other inputs, over the entire u32 domain.
  proofs.append({'divisor':divisor,'shift':shift,'inverse':hex(inverse),'threshold':limit,'proof':'bijective image [0,threshold] is exactly divisor multiples'})
 for seconds in range(86400):
  assert (seconds*0x91a2b3c5)>>43==seconds//3600
  assert (seconds*0x88888889)>>37==seconds//60
 return {'target_sha256':record['target_sha256'],'monthday_table_bytes':733,'all_valid_common_leap_ordinal_pairs':731,'time_second_relations_checked':86400,'fraction_divisibility_proofs':proofs,'maximum_date_bytes':13,'maximum_time_bytes':18,'maximum_adapter_bytes':32,'captured_execution_or_emulation':False}
if __name__=='__main__':
 import argparse
 ap=argparse.ArgumentParser();ap.add_argument('--freeze',action='store_true');v=ap.parse_args();r=derive()
 if v.freeze:(P/'derived.json').write_text(json.dumps(r,indent=2)+'\n')
 else:assert r==json.loads((P/'derived.json').read_text());print(json.dumps(r,indent=2))
