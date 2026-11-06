#!/usr/bin/env python3
"""Independent Python calendar/datetime relation, not captured execution.

Use a stdlib-calendar 400-year cumulative calendar and bisect within that cycle.
The future Rust uses a direct CE-year search over the full supported range.
"""
from pathlib import Path
import calendar,datetime,bisect,hashlib,json
P=Path(__file__).resolve().parent
MIN_YEAR=-262143;MAX_YEAR=262142
STARTS=[0]
for y in range(400):STARTS.append(STARTS[-1]+sum(calendar.monthrange(y,m)[1] for m in range(1,13)))
assert STARTS[-1]==146097

def ce(y,ordinal=1):
 # Construct CE day from independently accumulated stdlib-calendar cycle.
 q,r=divmod(y,400);return q*146097+STARTS[r]+ordinal-366

def date(day):
 q,r=divmod(day+365,146097);yi=bisect.bisect_right(STARTS,r)-1;y=q*400+yi
 if not MIN_YEAR<=y<=MAX_YEAR:return None
 ordinal=r-STARTS[yi]+1
 flags=(0 if calendar.isleap(y) else 8)|((calendar.weekday(y,1,1)+5)%7+1)
 packed=((y<<13)|(ordinal<<4)|flags)&0xffffffff
 if packed>=2**31:packed-=2**32
 return packed,y,ordinal,flags

def rows():
 # All days across one positive and one negative complete Gregorian cycle.
 for start in [ce(2000),ce(-400)]:
  for d in range(start,start+146097):yield('D',d)
 for y in [MIN_YEAR-1,MIN_YEAR,MIN_YEAR+1,-1,0,1,4,100,400,1900,1970,2000,MAX_YEAR-1,MAX_YEAR,MAX_YEAR+1]:
  for day in [ce(y)-1,ce(y),ce(y)+364,ce(y)+365,ce(y+1)-1,ce(y+1)]:yield('D',day)
 for day in [-2**31,-2**31+364,-2**31+365,2**31-366,2**31-365,2**31-1]:yield('D',day)
 for sec in [-2**63,-86401,-86400,-1,0,1,59,60,86399,86400,86401,951782400,(ce(MAX_YEAR+1)-719163)*86400-1,(ce(MAX_YEAR+1)-719163)*86400,2**63-1]:
  for ns in [0,1,999999999,1000000000,2**64-1]:yield('T',sec,ns)
 for y in [1970,1971,1999,2000,2004,2100,2400,9999]:
  for m in range(1,13):
   for d in [1,calendar.monthrange(y,m)[1]]:
    value=datetime.datetime(y,m,d,23,59,59,tzinfo=datetime.timezone.utc);sec=int((value-datetime.datetime(1970,1,1,tzinfo=datetime.timezone.utc)).total_seconds())
    for ns in [0,123456789,999999999]:yield('T',sec,ns)

def result(row):
 if row[0]=='D':
  v=date(row[1]);return 'N' if v is None else 'D '+' '.join(map(str,v))
 _,seconds,nanos=row
 if nanos>=1000000000:return 'nanos'
 if seconds<0:return 'before'
 days,within=divmod(seconds,86400);v=date(days+719163)
 if v is None:return 'range'
 if seconds<=253402300799:
  actual=datetime.datetime(1970,1,1,tzinfo=datetime.timezone.utc)+datetime.timedelta(seconds=seconds)
  assert actual.year==v[1] and actual.timetuple().tm_yday==v[2]
  assert within==actual.hour*3600+actual.minute*60+actual.second
 return 'T '+' '.join(map(str,(*v,within,nanos)))

def freeze():
 ih=hashlib.sha256();eh=hashlib.sha256();count=0
 for r in rows():
  a=(' '.join(map(str,r))+'\n').encode();z=(result(r)+'\n').encode();ih.update(a);eh.update(z);count+=1
 return {'cases':count,'input_sha256':ih.hexdigest(),'expected_sha256':eh.hexdigest(),'oracle_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'stdlib_calendar_cycle_days':STARTS[-1]}
if __name__=='__main__':print(json.dumps(freeze(),indent=2))
