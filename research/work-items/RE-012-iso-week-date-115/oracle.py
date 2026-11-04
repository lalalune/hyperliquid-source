#!/usr/bin/env python3
"""Independent stdlib ISO calendar, extended by exact Gregorian 400-year cycles."""
from pathlib import Path
import datetime,calendar,hashlib,json
MIN=-262143;MAX=262142

def rows():
 for y in list(range(2000,2400))+list(range(-400,0))+[-2**31,-2**31+1,MIN-1,MIN,MIN+1,MAX-1,MAX,MAX+1,2**31-2,2**31-1]:
  for w in list(range(55))+[2**32-1]:
   for day in range(7):yield(y,w,day)

def result(r):
 year,week,weekday=r;q,small=divmod(year-2000,400)
 try:d=datetime.date.fromisocalendar(2000+small,week,weekday+1)
 except ValueError:return 'N'
 actual=d.year+400*q
 if not -2**31<=actual<2**31:return 'overflow'
 if not MIN<=actual<=MAX:return 'N'
 ordinal=d.timetuple().tm_yday
 flags=(0 if calendar.isleap(actual) else 8)|((calendar.weekday(actual,1,1)+5)%7+1)
 packed=((actual<<13)|(ordinal<<4)|flags)&0xffffffff
 if packed>=2**31:packed-=2**32
 return f'D {packed} {actual} {ordinal} {flags}'

def freeze():
 ih=hashlib.sha256();eh=hashlib.sha256();count=0
 for r in rows():
  a=(' '.join(map(str,r))+'\n').encode();z=(result(r)+'\n').encode();ih.update(a);eh.update(z);count+=1
 return {'cases':count,'input_sha256':ih.hexdigest(),'expected_sha256':eh.hexdigest(),'oracle_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
if __name__=='__main__':print(json.dumps(freeze(),indent=2))
