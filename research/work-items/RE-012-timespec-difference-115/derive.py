#!/usr/bin/env python3
from pathlib import Path
import json
import verify
P=Path(__file__).resolve().parent

def derive():
 record,_=verify.collect(verify.TARGET.read_bytes());mask=next(bytes.fromhex(p['raw']) for p in verify.SPEC['anchors'] if p['meaning']=='result-tag-xor-mask');assert mask==bytes([1])+bytes(15)
 # Canonical timestamps form [i64MIN*B, i64MAX*B+B-1]. Its width equals
 # u64MAX*B+B-1, exactly Duration's representable nonnegative interval.
 B=1000000000;lo=-2**63*B;hi=(2**63-1)*B+B-1
 assert hi-lo==(2**64-1)*B+B-1
 # For ordered timestamps with ns borrow, seconds differ by at least one;
 # normalized fractional difference lies [1,B-1], so neither underflow nor
 # an additional one-second carry reaches the native overflow failure edge.
 assert 0+B-(B-1)==1 and (B-2)+B-(B-1)==B-1
 return {'target_sha256':record['target_sha256'],'xor_flips_only_result_tag':True,'entire_normalized_timestamp_domain_fits_core_Duration':True,'native_overflow_edge':'unreachable for canonical input ns<1e9, explicitly retained rather than ignored','raw_result_fields':'qword tag0/1,+8 u64 seconds,+16 u32 nanos; not safe API ABI','captured_execution_or_emulation':False}
if __name__=='__main__':
 import argparse
 ap=argparse.ArgumentParser();ap.add_argument('--freeze',action='store_true');a=ap.parse_args();v=derive()
 if a.freeze:(P/'derived.json').write_text(json.dumps(v,indent=2)+'\n')
 else:assert v==json.loads((P/'derived.json').read_text());print(json.dumps(v,indent=2))
