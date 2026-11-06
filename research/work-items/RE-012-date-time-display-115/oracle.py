#!/usr/bin/env python3
"""Independent stdlib calendar/datetime and declarative decimal formatting.

Only successful display text and explicit safe-API domain rejection; native
writer calls/errors are not simulated. No captured execution or OS calls.
"""
from pathlib import Path
import calendar,datetime,hashlib,json
MIN=-262143;MAX=262142

def date(y,o):
 if not MIN<=y<=MAX or o<1 or o>365+calendar.isleap(y):return None
 month=1;day=o
 while day>calendar.monthrange(y,month)[1]:day-=calendar.monthrange(y,month)[1];month+=1
 year=f'{y:04d}' if 0<=y<=9999 else f'{y:+05d}'
 text=f'{year}-{month:02d}-{day:02d}'
 if 1<=y<=9999:assert text==datetime.date(y,month,day).isoformat()
 return text

def time(s,n):
 if not 0<=s<86400 or not 0<=n<2000000000 or (n>=1000000000 and s%60!=59):return None
 hour,remain=divmod(s,3600);minute,second=divmod(remain,60);leap,n=divmod(n,1000000000);second+=leap
 text=f'{hour:02d}:{minute:02d}:{second:02d}'
 if n:
  width=3 if n%1000000==0 else 6 if n%1000==0 else 9
  text+='.'+f'{n//(10**(9-width)):0{width}d}'
 return text

def rows():
 for y in range(400):
  for o in range(1,367):yield('D',y,o)
 for y in [MIN-1,MIN,MIN+1,-10000,-400,-100,-4,-1,9999,10000,10001,MAX-1,MAX,MAX+1]:
  for o in range(0,368):yield('D',y,o)
 for s in range(86400):
  for n in [0,123456789]:yield('T',s,n)
 for s in [0,1,58,59,60,3599,3600,86399,86400,2**32-1]:
  for n in [1,999,1000,999999,1000000,100000000,999000000,999999999,1000000000,1000000001,1001000000,1999999999,2000000000,2**32-1]:yield('T',s,n)
 for y in [MIN,-10000,-1,0,1,9999,10000,MAX]:
  for o in [1,59,60,365,366]:
   for s in [0,59,86399]:
    for n in [0,100000000,123456000,999999999,1000000000,1999999999]:yield('X',y,o,s,n)

def result(r):
 if r[0]=='D':v=date(*r[1:])
 elif r[0]=='T':v=time(*r[1:])
 else:
  d=date(r[1],r[2]);t=time(r[3],r[4]);v=None if d is None or t is None else d+' '+t
 return 'N' if v is None else 'O '+v

def freeze():
 ih=hashlib.sha256();eh=hashlib.sha256();count=0
 for r in rows():
  a=(' '.join(map(str,r))+'\n').encode();z=(result(r)+'\n').encode();ih.update(a);eh.update(z);count+=1
 return {'cases':count,'input_sha256':ih.hexdigest(),'expected_sha256':eh.hexdigest(),'oracle_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
if __name__=='__main__':print(json.dumps(freeze(),indent=2))
