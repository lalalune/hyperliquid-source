#!/usr/bin/env python3
"""Static scalar equations for complete ClientBlocksError, never code emulation."""
from pathlib import Path
import hashlib,json,itertools,sys
P=Path(__file__).resolve().parent;R=P.parents[2];sys.path.insert(0,str(P));import verify
U=(1<<64)-1

def relation(src,mode,count,limit):
 pos=0
 def scalar(bits):
  nonlocal pos,count
  charge=bits//8
  if mode:
   if count>U-charge:return 'e2',None
   count+=charge
   if count>limit:return 'e2',None
  remain=len(src)-pos
  if not remain:return 'e0:1',None
  start=pos;tag=src[pos];slow=remain<=charge
  if slow:pos+=1
  if tag<251:pos=start+1;return None,tag
  width={251:3,252:5,253:9}.get(tag)
  if width is None or width>charge+1:return 'e3:'+str((3 if slow else 2) if bits==64 else 2)+':'+str({253:3,254:4,255:12}[tag]),None
  if remain<width:return 'e0:'+str(width-remain),None
  pos=start+width;return None,int.from_bytes(src[start+1:pos],'little')
 err,index=scalar(32)
 if err:result=err
 elif index>6:result='variant:'+str(index)
 elif index in (1,5,6):
  err,a=scalar(64)
  if not err:err,b=scalar(64)
  result=err if err else f'ok:{index}:{a}:{b}'
 else:result=f'ok:{index}'
 return f'{result}|{pos}|{count}'

def cases():
 out=set();vals=[0,1,250,251,65535,65536,(1<<32)-1,1<<32,U]
 def enc(v,w):return bytes([251 if w==2 else 252 if w==4 else 253])+v.to_bytes(w,'little')
 bodies=[b'',b'\x00',b'\x01\x02']
 for a,b in itertools.product(vals,repeat=2):
  aa=bytes([a]) if a<251 else enc(a,2 if a<=65535 else 4 if a<(1<<32) else 8)
  bb=bytes([b]) if b<251 else enc(b,2 if b<=65535 else 4 if b<(1<<32) else 8)
  bodies.append(aa+bb)
 bodies += [bytes([m])+bytes(n) for m in range(251,256) for n in range(18)]
 for i in range(9):
  for tag in [bytes([i]),enc(i,2),enc(i,4)]:
   for body in bodies:
    full=tag+body
    for n in range(len(full)+1):out.add((0,0,0,full[:n]))
    for suffix in [b'',b'\xff'*10]:
     for c in [0,1,U-20,U-12,U-4,U]:
      for lim in [0,3,4,11,12,19,20,U]:out.add((1,c,lim,full+suffix))
 for tag in range(256):
  for n in [0,1,3,4,8,9,18]:out.add((0,0,0,bytes([tag])+bytes(n)))
 return sorted(out)
def freeze():
 verify.collect(verify.TARGET.read_bytes(),True);rows=cases();raw=''.join(f'{m}\t{c}\t{l}\t{b.hex() or "-"}\t{relation(b,m,c,l)}\n' for m,c,l,b in rows).encode();return raw,{'cases':len(rows),'fixture_sha256':hashlib.sha256(raw).hexdigest(),'new_rust_exists':(R/'src/node115-client-blocks-error').exists(),'oracle_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'scope_sha256':hashlib.sha256((P/'scope.json').read_bytes()).hexdigest(),'target_sha256':verify.SPEC['target_sha256']}
if __name__=='__main__':
 raw,meta=freeze();assert not meta['new_rust_exists'];(P/'cases.tsv').write_bytes(raw);(P/'freeze.json').write_text(verify.dump(meta));print(verify.dump(meta))
