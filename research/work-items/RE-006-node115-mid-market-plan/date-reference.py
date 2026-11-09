#!/usr/bin/env python3
"""Independent Python calendar fixtures for selected valid dates."""
import datetime,hashlib,json,random,sys
from pathlib import Path
rng=random.Random(1153916);lines=['# year ordinal seconds nanos expected_millis'];epoch=datetime.date(1970,1,1).toordinal()
for _ in range(2500):
 year=rng.randrange(1,10000);leap=year%4==0 and (year%100!=0 or year%400==0);ordinal=rng.randrange(1,367 if leap else 366);seconds=rng.randrange(86400);nanos=rng.randrange(1000000000)
 day=datetime.date(year,1,1).toordinal()+ordinal-1;result=max(0,((day-epoch)*86400+seconds)*1000+nanos//1000000)
 lines.append(f'{year} {ordinal} {seconds} {nanos} {result}')
text='\n'.join(lines)+'\n';root=Path(__file__).resolve().parents[3];fixture=root/'src/node115-mid-market-plan/tests/date-vectors.txt'
if '--write' in sys.argv:fixture.write_text(text)
else:assert fixture.read_text()==text
print(json.dumps({'cases':2500,'fixture_sha256':hashlib.sha256(text.encode()).hexdigest(),'reference':'Python proleptic Gregorian date; not target execution'},indent=2))
