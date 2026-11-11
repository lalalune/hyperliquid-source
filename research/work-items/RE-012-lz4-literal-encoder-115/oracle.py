#!/usr/bin/env python3
"""Independent sequence specification from #115 static branches, not an emulator.

First form the abstract token/extension/literal event sequence; then interpret
capacity at each atomic event. This differs from the production scalar encoder.
All native panic boundaries are represented by logical status names.
"""
from pathlib import Path
import hashlib,json
P=Path(__file__).resolve().parent;ROOT=P.parents[2]
def cases():
 # Every short length and capacities surrounding header/append boundaries;
 # four different nonempty prefixes/source anchors/payload patterns.
 for n in range(0,1100):
  h=1+(0 if n<15 else 1+(n-15)//255)
  for initial,anchor,seed in [(0,0,0),(3,5,73),(7,1,255)]:
   for spare in sorted({0,1,max(0,h-1),h,h+n-1 if n else h,h+n,h+n+1}):
    if spare>=0:yield (n+anchor,anchor,n+anchor,initial+spare,initial,seed)
 for n in [1289,1290,1291,4094,4095,4096,65534,65535,65536,131071]:
  h=1+1+(n-15)//255
  for spare in [0,1,2,3,4,5,h-1,h,h+n-1,h+n,h+n+1]:
   yield (n+9,9,n+9,11+spare,11,29)
 # All positions with available suffix ignored and explicit safe-API domain errors.
 for size in range(9):
  for anchor in range(size+3):
   for end in range(size+3):yield(size,anchor,end,17,2,91)
 yield(4,0,4,2,3,7)
def result(row):
 size,anchor,end,cap,initial,seed=row;buf=bytearray([165])*cap
 # Safe caller checks are outside the captured function's unchecked pointer ABI.
 if initial>cap or end>size:return 'domain '+str(initial)+' '+buf.hex()
 if anchor>end:return 'anchor '+str(initial)+' '+buf.hex()
 n=end-anchor
 token=bytes([min(n,15)*16]);extensions=b''
 if n>=15:
  q,r=divmod(n-15,255);extensions=bytes([255])*q+bytes([r])
 literals=bytes(((i*37+seed)&255) for i in range(anchor,end))
 events=[('token',token)]+[('extension',bytes([b])) for b in extensions]+[('literals',literals)]
 used=initial
 for label,payload in events:
  if len(payload)>cap-used:return label+' '+str(used)+' '+buf.hex()
  buf[used:used+len(payload)]=payload;used+=len(payload)
 return 'ok '+str(used)+' '+buf.hex()
def generate():
 ih=hashlib.sha256();eh=hashlib.sha256();count=0
 for row in cases():
  a=(' '.join(map(str,row))+'\n').encode();z=(result(row)+'\n').encode();ih.update(a);eh.update(z);count+=1
 return {'cases':count,'input_sha256':ih.hexdigest(),'expected_sha256':eh.hexdigest(),'oracle_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
if __name__=='__main__':print(json.dumps(generate(),indent=2))
