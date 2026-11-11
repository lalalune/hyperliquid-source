#!/usr/bin/env python3
"""Independent static wire/scalar/budget relation, never captured execution."""
from pathlib import Path
import hashlib,json,itertools,sys
P=Path(__file__).resolve().parent;R=P.parents[2];sys.path.insert(0,str(P));import verify
U=(1<<64)-1

def relation(src,limited,count,limit):
 pos=0
 def finish(s):return f'{s}|{pos}|{count}'
 def charge(n):
  nonlocal count
  if not limited:return None
  if count>U-n:return 'limit'
  count+=n
  return 'limit' if count>limit else None
 def scalar(bits,field=None):
  nonlocal pos
  err=charge(bits//8)
  if err:return err,None
  left=len(src)-pos
  if not left:return 'end:1',None
  start=pos;marker=src[pos];slow=left<=bits//8
  if slow:pos+=1
  if marker<251:pos=start+1;return None,marker
  w={251:3,252:5,253:9}.get(marker)
  if w is None or w>bits//8+1:
   expected=field if field is not None else 2 if bits==32 or not slow else 3
   return f'invalid:{expected}:'+str({253:3,254:4,255:12}[marker]),None
  if left<w:return f'end:{w-left}',None
  pos=start+w;return None,int.from_bytes(src[start+1:pos],'little')
 err,n=scalar(64)
 if err:return finish(err)
 if limited:
  if n>U//24:return finish('limit')
  err=charge(n*24)
  if err:return finish(err)
 values=[]
 for _ in range(n):
  if limited:
   if count<24:return finish('refund')
   count-=24
  err,tag=scalar(32)
  if err:return finish(err)
  if tag:return finish(f'variant:{tag}')
  remaining=len(src)-pos
  if remaining<4:return finish(f'end:{4-remaining}')
  fixed=src[pos:pos+4].hex();pos+=4
  err=charge(1)
  if err:return finish(err)
  if pos==len(src):return finish('end:1')
  flag=src[pos];pos+=1
  if flag>1:return finish('bool')
  err,v=scalar(64,5)
  if err:return finish(err)
  values.append(f'{fixed}:{flag}:{v}')
 return finish('ok:'+','.join(values))

def cases():
 out=set()
 def enc(v,w=0):
  if not w:w=0 if v<251 else 2 if v<65536 else 4 if v<2**32 else 8
  return bytes([v]) if w==0 else bytes([{2:251,4:252,8:253}[w]])+v.to_bytes(w,'little')
 def elem(t=0,flag=0,v=1):return enc(t)+bytes([1,2,3,4])+bytes([flag])+enc(v)
 payloads=[b'',b'\x00',b'\x01',b'\x02']
 for n in range(5):
  for flag in [0,1,2,255]:
   for v in [0,250,251,65535,65536,2**32-1,2**32,U]:payloads.append(enc(n)+elem(0,flag,v)*n)
 for t in [1,2,250,251,65535,65536]:payloads.append(b'\x01'+elem(t))
 for marker in range(251,256):
  for k in range(12):payloads.extend([bytes([marker])+bytes(k),b'\x01\x00'+bytes(4)+b'\x00'+bytes([marker])+bytes(k)])
 for full in payloads:
  for k in range(len(full)+1):out.add((0,0,0,full[:k]))
  for used in [0,1,23,24,U-32,U-8,U]:
   for limit in [0,7,8,12,13,20,21,31,32,33,34,47,48,59,60,100,U]:out.add((1,used,limit,full))
 for n in [0,1,43689,43690,43691,U//24,U//24+1,U]:
  for used in [0,U-8,U]:
   for lim in [0,8,32,U]:out.add((1,used,lim,enc(n)))
 # Nonminimal count and inner discriminant encodings; suffix bytes retained.
 for w in [2,4,8]:
  for n in [0,1,2]:
   out.add((0,0,0,enc(n,w)+elem()*n+b'\xff\x99'))
 for w in [2,4]:out.add((0,0,0,b'\x01'+enc(0,w)+bytes(4)+b'\x01\x00'))
 return sorted(out)
def freeze():
 verify.collect(verify.TARGET.read_bytes(),True);rows=cases();raw=''.join(f'{m}\t{c}\t{l}\t{b.hex() or "-"}\t{relation(b,m,c,l)}\n' for m,c,l,b in rows).encode();return raw,{'cases':len(rows),'fixture_sha256':hashlib.sha256(raw).hexdigest(),'new_rust_exists':(R/'src/node115-gossip-address-vector').exists(),'oracle_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'scope_sha256':hashlib.sha256((P/'scope.json').read_bytes()).hexdigest(),'target_sha256':verify.SPEC['target_sha256']}
if __name__=='__main__':
 raw,meta=freeze();assert not meta['new_rust_exists'];(P/'cases.tsv').write_bytes(raw);(P/'freeze.json').write_text(verify.dump(meta));print(verify.dump(meta))
