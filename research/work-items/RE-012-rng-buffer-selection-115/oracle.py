#!/usr/bin/env python3
"""Closed branch relation for policy fields, with explicit external boundary inputs.

No target code, instruction evaluator, OS RNG, clock, TLS or real refill call.
The supplied seed/refill arrays are arbitrary contract fixtures, not RNG output.
"""
from pathlib import Path
import hashlib,json,datetime
P=Path(__file__).resolve().parent
U=2**64;S=2**63

def rows():
 epochs=[(0,0),(1,0),(0,1),(0,U-1),(U-1,0),(S,0),(0,S),(S+1,1),(1,S+1),(U-1,S-1),(S-1,U-1)]
 rems=[-S,-257,-256,-1,0,1,255,256,257,S-1]
 bases=[-S,-S+1,-S+255,-S+256,-1,0,255,256,S-1]
 for cursor in [0,1,62,63,64,65,U-1]:
  for remaining in rems:
   for base in bases:
    for old,now in epochs:
     for success in [0,1]:yield(cursor,remaining,base,old,now,success,73)
 for cursor in range(67):
  for seed in [0,1,127,255]:yield(cursor,256,65536,0,0,seed&1,seed)

def result(row):
 cursor,rem,base,old,now,success,seed=row
 key=bytes(i^seed for i in range(48))
 def state():return ','.join([str(cursor),str(rem),str(base),str(old),key.hex()])
 def firstword():return ((seed*0x9e3779b1)+cursor)&0xffffffff
 if cursor<64:
  v=firstword();cursor+=1;return 'word='+str(v)+' final='+state()
 # Pure relation: sign bit of modular subtraction, deliberately NOT i64 >=.
 same_epoch_half=((old-now)%U)<S
 if rem>0 and same_epoch_half:
  rem-=256;prefix='refill='+state()
 else:
  prefix='entropy='+state()
  if success:key=bytes((i+seed)&255 for i in range(32))+bytes(16)
  old=now
  next_remaining=base-256
  if next_remaining < -S:return prefix+' overflow='+state()
  rem=next_remaining;prefix+=' refill='+state()
 # Explicit arbitrary external refill result. This is a caller boundary value;
 # the Rust kernel must never construct this or assert it is random.
 key=bytes((i*3+seed+1)&255 for i in range(48));cursor=1
 return prefix+' word='+str(seed^0xa5a5a5a5)+' final='+state()

def freeze():
 ih=hashlib.sha256();eh=hashlib.sha256();count=0
 for r in rows():
  a=(' '.join(map(str,r))+'\n').encode();z=(result(r)+'\n').encode();ih.update(a);eh.update(z);count+=1
 return {'cases':count,'input_sha256':ih.hexdigest(),'expected_sha256':eh.hexdigest(),'oracle_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
if __name__=='__main__':print(json.dumps(freeze(),indent=2))
