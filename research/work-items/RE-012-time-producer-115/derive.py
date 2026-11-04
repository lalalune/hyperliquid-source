#!/usr/bin/env python3
"""Validate mathematical Gregorian identities against the real captured tables."""
import calendar,json,bisect
from pathlib import Path
import verify
P=Path(__file__).resolve().parent

def main():
 record,_=verify.collect(verify.TARGET.read_bytes());pins={x['meaning']:bytes.fromhex(x['raw']) for x in verify.SPEC['anchors']}
 deltas=bytes((y+3)//4-(y+99)//100+(y+399)//400 for y in range(401))
 flags=bytes((0 if calendar.isleap(y) else 8)|((calendar.weekday(y,1,1)+5)%7+1) for y in range(400))
 assert pins['400year-leap-deltas']==deltas
 assert pins['400year-packed-flags']==flags
 # Native reciprocal for positive duration seconds: C*86400 differs from
 # 2**77 by error <86400; validate all possible quotient remainders for the
 # input relation separately through the independently compiled corpus.
 C=0x1845c8a0ce512957
 assert C*86400-2**77==12928 and (2**63-1)*12928<2**77
 assert 0x396b06bd*146097-2**47==31405 and 2**31*31405<2**47
 starts=[0]
 for y in range(400):starts.append(starts[-1]+(366 if calendar.isleap(y) else 365))
 for r in range(146097):
  hi=(r*0x6719f361)>>32
  assert (((r-hi)//2+hi)>>8)==r//365
  q,t=divmod(r,365)
  if t>=deltas[q]:ordinal=t-deltas[q]+1
  else:q-=1;ordinal=t-deltas[q]+366
  expected_year=bisect.bisect_right(starts,r)-1
  assert q==expected_year and ordinal==r-starts[q]+1
 return {'target_sha256':record['target_sha256'],'leap_table_bytes':len(deltas),'flags_table_bytes':len(flags),'table_identity':'exact stdlib Gregorian tables, including negative-year cycle extension','days_per_cycle':146097,'ce_epoch_day':719163,'minimum_year':-262143,'maximum_year':262142,'captured_execution_or_emulation':False,'native_seconds_reciprocal':hex(C),'reciprocal_error_bounds':'seconds: (2^63-1)*12928<2^77; CE cycle: 2^31*31405<2^47','full_400year_remainder_relations_checked':146097}
if __name__=='__main__':
 import argparse
 a=argparse.ArgumentParser();a.add_argument('--freeze',action='store_true');v=a.parse_args();r=main()
 if v.freeze:(P/'derived.json').write_text(json.dumps(r,indent=2)+'\n')
 else:assert r==json.loads((P/'derived.json').read_text());print(json.dumps(r,indent=2))
