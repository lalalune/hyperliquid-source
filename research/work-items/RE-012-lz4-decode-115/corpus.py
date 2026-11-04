"""Frozen pre-Rust corpus. Construction witnesses do not call the decoder model."""
import hashlib,json,random,struct
from pathlib import Path
P=Path(__file__).resolve().parent

def hx(b):return b.hex() or '-'
def outcome(b,limit):
 # Abstract logical-byte equations derived from the listed #115 branches.
 if len(b)<4:return 'E header'
 cap=struct.unpack('<I',b[:4])[0]
 if cap>limit:return 'E limit'
 block=b[4:];n=len(block);ip=0;out=bytearray()
 if not n:return 'E input'
 while ip<n:
  t=block[ip];ip+=1;lit=t>>4
  if lit==15:
   total=0
   while True:
    if ip==n:return 'E input'
    x=block[ip];ip+=1;total+=x
    if total>0xffffffff:return 'P extension'
    if x!=255:break
   lit+=total
  if ip+lit>n:return 'E literal'
  if len(out)+lit>cap:return 'E output'
  out+=block[ip:ip+lit];ip+=lit
  if ip==n:return 'O '+hx(out)
  if ip+2>n:return 'E input'
  distance=int.from_bytes(block[ip:ip+2],'little');ip+=2
  if distance==0:return 'E zero'
  length=(t&15)+4
  if length==19:
   total=0
   while True:
    if ip==n:return 'E input'
    x=block[ip];ip+=1;total+=x
    if total>0xffffffff:return 'P extension'
    if x!=255:break
   length+=total
  if len(out)+length>cap:return 'E output'
  if distance>len(out):return 'E history'
  # Periodic mathematical expansion, separate from Rust's append loop.
  period=bytes(out[-distance:]);out+=(period*((length+distance-1)//distance))[:length]
 return 'E input' # A completed match still requires a following terminal token.

def extension(n):return bytes([255])*(n//255)+bytes([n%255])
def sequence(literals,distance=None,length=None,terminal_low=0):
 l=len(literals);m=terminal_low if distance is None else min(length-4,15)
 b=bytes([(min(l,15)<<4)|m])
 if l>=15:b+=extension(l-15)
 b+=literals
 if distance is not None:
  b+=distance.to_bytes(2,'little')
  if length>=19:b+=extension(length-19)
 return b

def cases():
 # tuple(category, size-prefixed bytes, limit, independently constructed expectation or None)
 rng=random.Random(115477)
 for n in range(4):yield 'short',bytes(range(n)),0,'E header'
 for c in [0,1,255,256,0xffffffff]:
  for lim in [0,max(0,c-1),c,0xffffffffffffffff]:
   if c>lim:yield 'limit',struct.pack('<I',c),lim,'E limit'
   elif c<=256:yield 'empty-block',struct.pack('<I',c),lim,'E input'
 for l in [0,1,2,3,4,14,15,16,17,18,19,31,32,33,34,35,254,255,269,270,271,524,525,1024]:
  literal=bytes(rng.randrange(256) for _ in range(l))
  for low in range(16):
   block=sequence(literal,terminal_low=low)
   for cap in sorted({max(0,l-1),l,l+1,l+35}):
    want='O '+hx(literal) if cap>=l else 'E output'
    yield 'terminal-literals',struct.pack('<I',cap)+block,cap,want
 lengths=[4,5,7,14,18,19,20,31,32,33,34,63,64,65,273,274,275,529]
 for distance in [1,2,3,4,7,8,15,16,17,18,19,31,32,33,64,255,256]:
  seed=bytes(rng.randrange(256) for _ in range(distance))
  for length in lengths:
   for tail in [b'',b'!',bytes(range(20))]:
    expected=seed+(seed*((length+distance-1)//distance))[:length]+tail
    block=sequence(seed,distance,length)+sequence(tail)
    for extra in [0,1,34,35,128]:
     cap=len(expected)+extra
     yield 'constructed-backref',struct.pack('<I',cap)+block,cap,'O '+hx(expected)
 # Multi-sequence history witnesses with distances crossing earlier match boundaries.
 for _ in range(1200):
  expected=bytearray();block=bytearray()
  for j in range(rng.randrange(1,7)):
   lit=bytes(rng.randrange(256) for _ in range(rng.randrange(1,30)));expected+=lit
   distance=rng.randrange(1,min(65535,len(expected))+1);length=rng.choice(lengths)
   period=bytes(expected[-distance:]);expected+=(period*((length+distance-1)//distance))[:length]
   block+=sequence(lit,distance,length)
  tail=bytes(rng.randrange(256) for _ in range(rng.randrange(20)));expected+=tail;block+=sequence(tail)
  cap=len(expected)+rng.choice([0,1,34,35,100])
  yield 'constructed-multisequence',struct.pack('<I',cap)+block,cap,'O '+hx(expected)
 # Every token, selected cut points, capacity thresholds and offset classes.
 for token in range(256):
  for dist in [0,1,2,15,16,17,255,256,65535]:
   raw=bytes([token])+bytes(range(15))+dist.to_bytes(2,'little')+bytes(range(30))
   for cut in [1,2,3,15,16,17,18,19,len(raw)]:
    for cap in [0,1,16,34,35,64,256]:yield 'malformed-grid',struct.pack('<I',cap)+raw[:cut],cap,None
 for _ in range(6000):
  raw=bytes(rng.randrange(256) for _ in range(rng.randrange(1,90)));cap=rng.choice([0,1,16,34,35,64,128,512])
  yield 'seeded-malformed',struct.pack('<I',cap)+raw,cap,None
 # Target u32 extension accumulator overflows after 16,843,009 bytes of 255.
 # This compact recipe is retained; only generated ignored-work files hold expanded bytes.
 yield 'literal-u32-overflow',struct.pack('<I',32)+b'\xf0'+b'\xff'*16843010,32,'P extension'
 yield 'match-u32-overflow',struct.pack('<I',32)+b'\x1fA\x01\x00'+b'\xff'*16843010,32,'P extension'

def freeze(out):
 out.mkdir(parents=True,exist_ok=False);assert not (P.parents[2]/'src/node115-lz4-decode/lib.rs').exists()
 h=hashlib.sha256();e=hashlib.sha256();counts={};n=0;witnesses=0
 with (out/'input.txt').open('w') as fi,(out/'expected.txt').open('w') as fe:
  for category,b,limit,want in cases():
   got=outcome(b,limit)
   if want is not None:
    if got!=want:raise ValueError((category,got,want))
    witnesses+=1
   a=f'{limit} {hx(b)}\n';z=got+'\n';fi.write(a);fe.write(z);h.update(a.encode());e.update(z.encode());n+=1;counts[category]=counts.get(category,0)+1
 return {'cases':n,'construction_or_boundary_witnesses':witnesses,'input_sha256':h.hexdigest(),'expected_sha256':e.hexdigest(),'categories':counts,'corpus_script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'frozen_before_rust':True,'target_execution':False}
if __name__=='__main__':
 import sys
 r=freeze(Path(sys.argv[1]));(P/'frozen.json').write_text(json.dumps(r,indent=2,sort_keys=True)+'\n');print(json.dumps(r))
