#!/usr/bin/env python3
import calendar,json
from pathlib import Path
import verify
P=Path(__file__).resolve().parent

def derive():
 record,_=verify.collect(verify.TARGET.read_bytes());flags=next(bytes.fromhex(p['raw']) for p in verify.SPEC['anchors'] if p['meaning']=='400-year-flags')
 expected=bytes((0 if calendar.isleap(y) else 8)|((calendar.weekday(y,1,1)+5)%7+1) for y in range(400));assert flags==expected
 for y,f in enumerate(flags):assert bool((0x406>>f)&1)==(calendar.weekday(y,1,1)==3 or (calendar.weekday(y,1,1)==2 and calendar.isleap(y)))
 assert 0x51eb851f*400-2**39==112 and 2**31*112<2**39
 return {'target_sha256':record['target_sha256'],'exact_flag_table_bytes':400,'week53_bitmap_years_checked':400,'signed_reciprocal_error_bound':'2^31*112<2^39, C*400=2^39+112','native_function_pointer_slot':'0x64e1b50','captured_execution_or_emulation':False}
if __name__=='__main__':
 import argparse
 ap=argparse.ArgumentParser();ap.add_argument('--freeze',action='store_true');a=ap.parse_args();v=derive()
 if a.freeze:(P/'derived.json').write_text(json.dumps(v,indent=2)+'\n')
 else:assert v==json.loads((P/'derived.json').read_text());print(json.dumps(v,indent=2))
