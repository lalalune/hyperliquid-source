#!/usr/bin/env python3
"""Independent integer/threshold oracle; no Rust import or instruction interpretation."""
import argparse,gzip,hashlib,json,random
from collections import Counter
from datetime import datetime,timezone
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
Q=1<<384; WORD=1<<64
TARGET_SHA='3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
def sha(b):return hashlib.sha256(b).hexdigest()
def tag(n,c):return n%2+2*int(n>=(c+1)//2)
def digits(n):return [(n//WORD**i)%WORD for i in range(6)]
def union(n):return sum(2**b for b in range(64) if any((n//2**(64*i+b))%2 for i in range(6)))
def single(a,c):
 d=digits((2*a-c)%Q)
 return [tag(a,c),d[4],d[5],a%2,d[0],d[1],d[2],d[3]]
def pair(low,high,c):
 d=digits((2*low-c)%Q)
 first=low if low else high;last=high if high else low
 result=first%2+2*int(last>=(c+1)//2)
 return [result,d[4],d[5],tag(high,c),union(low),d[1],d[2],d[3]]
def mapped(image,base,address,width):
 if base+len(image)>WORD or address<base or address-base+width>len(image):return None
 return address-base
def evaluate(row):
 mode=row[1]
 if mode=='S':value=single(int(row[2],16),int(row[3],16))
 elif mode=='P':value=pair(int(row[2],16),int(row[3],16),int(row[4],16))
 else:
  base,at,correction=(int(v,16) for v in row[2:5]);image=bytes.fromhex(row[5]) if row[5]!='-' else b'';width=48 if mode=='F' else 96
  a=mapped(image,base,at,width);c=mapped(image,base,correction,48)
  if a is None or c is None:return [row[0],'E','-']
  cv=int.from_bytes(image[c:c+48],'little');low=int.from_bytes(image[a:a+48],'little')
  value=single(low,cv) if mode=='F' else pair(low,int.from_bytes(image[a+48:a+96],'little'),cv)
 return [row[0],'V'+''.join(f':{v:016x}' for v in value),'-']
def generate():
 rng=random.Random(0x56573a0);rows=[];coverage=Counter()
 def add(mode,*values,label=None):
  row=[f'case-{len(rows):05d}',mode,*values];row+=['-']*(7-len(row));rows.append(row);coverage[mode]+=1
  if label:coverage[label]+=1
 def s(a,c,label=None):add('S',f'{a:096x}',f'{c:096x}',label=label)
 def p(a,b,c,label=None):add('P',f'{a:096x}',f'{b:096x}',f'{c:096x}',label=label)
 special=[0,1,2,3,4,WORD-1,WORD,WORD+1,Q//2-1,Q//2,Q//2+1,Q-3,Q-2,Q-1]
 for a in special:
  for c in special:s(a,c,'directed')
 for bit in range(384):
  for c in [max(0,(1<<bit)-1),1<<bit,min(Q-1,(1<<bit)+1)]:
   threshold=(c+1)//2
   for a in sorted({0,Q-1,max(0,threshold-1),threshold,min(Q-1,threshold+1)}):s(a,c,'threshold-bit')
 for _ in range(1600):s(rng.randrange(Q),rng.randrange(Q),'random')
 for c in special:
  t=(c+1)//2;v=sorted({0,1,2,max(0,t-1),t,min(Q-1,t+1),Q//2,Q-1})
  for a in v:
   for b in v:p(a,b,c,'zero-select-boundary')
 for bit in range(384):
  a=1<<bit;c=rng.randrange(Q)
  p(a,0,c,'low-only');p(0,a,c,'high-only');p(a,Q-1-a,c,'both-nonzero')
 for _ in range(2000):p(rng.randrange(Q),rng.randrange(Q),rng.randrange(Q),'random')
 for mode in ['F','G']:
  width=48 if mode=='F' else 96
  placements=[(0,0),(0,1),(1,0),(32,32),(32,40),(32,33),(33,32),(32,79),(79,32),(32,80),(80,32),(32,127),(127,32),(0,208),(256-width,0),(1,208)]
  for _ in range(900):placements.append((rng.randrange(257-width),rng.randrange(209)))
  for i,(a,c) in enumerate(placements):
   image=bytes(rng.randrange(256) for _ in range(256));base=[0,0x1000,WORD-256][i%3]
   add(mode,f'{base:016x}',f'{base+a:016x}',f'{base+c:016x}',image.hex(),label='alias' if a<c+48 and c<a+width else 'disjoint')
  for i in range(90):
   length=rng.randrange(0,130);image=bytes(rng.randrange(256) for _ in range(length));base=[0,0x1000,min(WORD-1,WORD-length)][i%3]
   a=base+max(0,length-width+1);c=base
   if a>=WORD:a=WORD-1
   add(mode,f'{base:016x}',f'{a:016x}',f'{c:016x}',image.hex() or '-',label='range-refusal')
  for zero in [bytes(256),bytes(96)+bytes([255])*160]:
   add(mode,'0000000000001000','0000000000001000','0000000000001100',zero.hex(),label='mandatory-correction-refusal')
  if mode=='G':
   add(mode,'0000000000001000','0000000000000fd0','0000000000001060',(bytes([255])*128).hex(),label='mandatory-low-refusal')
  for i in range(30):
   image=bytes(rng.randrange(256) for _ in range(256));base=WORD-255
   add(mode,f'{base:016x}',f'{base:016x}',f'{base:016x}',image.hex(),label='image-wrap')
 return rows,dict(sorted(coverage.items()))
def freeze():
 source=ROOT/'src/node94-classification384-family'
 if source.exists():raise ValueError('freeze requires absent Rust source')
 rows,coverage=generate();inputs=('\n'.join('\t'.join(r) for r in rows)+'\n').encode();expected=('\n'.join('\t'.join(evaluate(r)) for r in rows)+'\n').encode()
 out=HERE/'fixtures';out.mkdir(exist_ok=True)
 for name,b in [('inputs.tsv',inputs),('expected.tsv',expected)]: (out/(name+'.gz')).write_bytes(gzip.compress(b,compresslevel=9,mtime=0))
 record={'target_sha256':TARGET_SHA,'frozen_at_utc':datetime.now(timezone.utc).isoformat(),'rust_source_absent':True,'cases':len(rows),'coverage':coverage,'sha256':{'inputs.tsv':sha(inputs),'expected.tsv':sha(expected),'inputs.tsv.gz':sha((out/'inputs.tsv.gz').read_bytes()),'expected.tsv.gz':sha((out/'expected.tsv.gz').read_bytes()),'oracle.py':sha(Path(__file__).read_bytes())}}
 (out/'freeze.json').write_text(json.dumps(record,sort_keys=True,indent=2)+'\n');print(json.dumps(record,indent=2));return record
def check():
 record=json.loads((HERE/'fixtures/freeze.json').read_text());inputs=gzip.decompress((HERE/'fixtures/inputs.tsv.gz').read_bytes());expected=gzip.decompress((HERE/'fixtures/expected.tsv.gz').read_bytes());rows=[line.split('\t') for line in inputs.decode().splitlines()]
 pairs={'inputs.tsv':inputs,'expected.tsv':expected,'inputs.tsv.gz':(HERE/'fixtures/inputs.tsv.gz').read_bytes(),'expected.tsv.gz':(HERE/'fixtures/expected.tsv.gz').read_bytes(),'oracle.py':Path(__file__).read_bytes()}
 if any(sha(value)!=record['sha256'][name] for name,value in pairs.items()):raise ValueError('freeze hash')
 actual=('\n'.join('\t'.join(evaluate(r)) for r in rows)+'\n').encode()
 if actual!=expected or len(rows)!=record['cases']:raise ValueError('independent expectation replay')
 return record,inputs,expected
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--freeze',action='store_true');a=p.parse_args()
 if a.freeze:freeze()
 else:print('PASS frozen oracle',check()[0]['cases'])
