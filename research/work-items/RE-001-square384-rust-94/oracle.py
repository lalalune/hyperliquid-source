#!/usr/bin/env python3
"""Independent whole-integer square/cross-polynomial oracle, frozen before Rust."""
import argparse,gzip,hashlib,itertools,json,random
from collections import Counter
from datetime import datetime,timezone
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
B=1<<64;Q=B**6;MASK=B-1
SHA='3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
def digest(raw):return hashlib.sha256(raw).hexdigest()
def digits(value,n):return [(value//B**i)%B for i in range(n)]
def square(a):
 v=digits(a,6);s=a*a;w=digits(s,12)
 cross=sum(v[i]*v[j]*B**(i+j) for i in range(6) for j in range(i+1,6))
 partial=sum(v[i]*v[j]*B**(i+j) for i in range(3) for j in range(i+1,6))
 def carry(k):
  modulus=B**(2*k);diagonal=sum(v[i]**2*B**(2*i) for i in range(k))
  return (2*(cross%modulus)+diagonal)//modulus
 q4,q6,q8,q10=(carry(k) for k in [2,3,4,5])
 r8=(v[3]*v[4]+(partial//B**7)%B)//B
 regs=[w[10],w[9],w[8],w[11],2*((cross//B**10)%B)%B,v[5],r8,
       v[2]**2%B+q4,w[2],v[3]**2%B+q6,v[4]**2%B+q8,q10,w[6],w[7]]
 if not all(0<=x<B for x in regs):raise ValueError('raw register range theorem')
 return regs,w

def offset(image,base,address,width):
 if base+len(image)>B or address<base or address-base+width>len(image):return None
 return address-base

def evaluate(row):
 if row[1]=='V':r,w=square(int(row[2],16));after='-'
 else:
  base,src,dst=(int(x,16) for x in row[2:5]);image=bytearray.fromhex(row[5]) if row[5]!='-' else bytearray()
  i=offset(image,base,src,48);o=offset(image,base,dst,96)
  if i is None or o is None:return [row[0],'E',image.hex() or '-']
  a=int.from_bytes(image[i:i+48],'little');r,w=square(a);image[o:o+96]=(a*a).to_bytes(96,'little');after=image.hex()
 return [row[0],'V'+''.join(f':{x:016x}' for x in r+w),after]

def generate():
 rng=random.Random(0x565b800);rows=[];coverage=Counter()
 def add(mode,*args,label):
  row=[f'case-{len(rows):05d}',mode,*args];row+=['-']*(7-len(row));rows.append(row);coverage[mode]+=1;coverage[label]+=1
 def value(words,label):add('V',f'{sum(x*B**i for i,x in enumerate(words)):096x}',label=label)
 for words in itertools.product(range(4),repeat=6):value(words,'small-exhaustive')
 for words in itertools.product([0,MASK],repeat=6):value(words,'zero-max-patterns')
 for i in range(6):
  for bit in range(64):
   for x in sorted({max(0,(1<<bit)-1),1<<bit,min(MASK,(1<<bit)+1)}):
    words=[0]*6;words[i]=x;value(words,'single-limb-boundaries')
 for i in range(6):
  for j in range(i+1,6):
   for x,y in itertools.product([1,2,3,MASK,MASK-1,1<<63,(1<<63)-1],repeat=2):
    words=[0]*6;words[i]=x;words[j]=y;value(words,'cross-product-boundaries')
 for _ in range(2400):value([rng.randrange(B) for _ in range(6)],'random')
 placements=[(0,0),(0,1),(1,0),(32,32),(32,33),(33,32),(32,79),(79,32),(32,80),(80,32),(0,160),(208,0),(208,160)]
 for _ in range(1000):placements.append((rng.randrange(209),rng.randrange(161)))
 for i,(src,dst) in enumerate(placements):
  image=bytes(rng.randrange(256) for _ in range(256));base=[0,0x1000,B-256][i%3]
  add('I',f'{base:016x}',f'{base+src:016x}',f'{base+dst:016x}',image.hex(),label='alias' if src<dst+96 and dst<src+48 else 'disjoint')
 for n in [0,1,47,48,95,96,127,128,255]:
  for src,dst in [(0,0),(0,max(0,n-95)),(max(0,n-47),0),(1,1)]:
   for base in [0,0x1000,min(MASK,B-n)]:
    image=bytes(rng.randrange(256) for _ in range(n));src=min(MASK,base+src);dst=min(MASK,base+dst)
    add('I',f'{base:016x}',f'{src:016x}',f'{dst:016x}',image.hex() or '-',label='range-boundaries')
 for _ in range(24):
  image=bytes(rng.randrange(256) for _ in range(256));base=B-255
  add('I',f'{base:016x}',f'{base:016x}',f'{base:016x}',image.hex(),label='image-wrap')
 return rows,dict(sorted(coverage.items()))

def freeze():
 if (ROOT/'src/node94-square384').exists():raise ValueError('Rust source must be absent')
 rows,coverage=generate();inputs=('\n'.join('\t'.join(r) for r in rows)+'\n').encode();expected=('\n'.join('\t'.join(evaluate(r)) for r in rows)+'\n').encode();out=HERE/'fixtures';out.mkdir(exist_ok=True)
 for name,data in [('inputs.tsv',inputs),('expected.tsv',expected)]: (out/(name+'.gz')).write_bytes(gzip.compress(data,compresslevel=9,mtime=0))
 record={'target_sha256':SHA,'frozen_at_utc':datetime.now(timezone.utc).isoformat(),'rust_source_absent':True,'cases':len(rows),'coverage':coverage,'sha256':{'oracle.py':digest(Path(__file__).read_bytes()),'inputs.tsv':digest(inputs),'expected.tsv':digest(expected),'inputs.tsv.gz':digest((out/'inputs.tsv.gz').read_bytes()),'expected.tsv.gz':digest((out/'expected.tsv.gz').read_bytes())}}
 (out/'freeze.json').write_text(json.dumps(record,sort_keys=True,indent=2)+'\n');print(json.dumps(record,indent=2))

def check():
 record=json.loads((HERE/'fixtures/freeze.json').read_text());inputs=gzip.decompress((HERE/'fixtures/inputs.tsv.gz').read_bytes());expected=gzip.decompress((HERE/'fixtures/expected.tsv.gz').read_bytes());rows=[line.split('\t') for line in inputs.decode().splitlines()]
 values={'oracle.py':Path(__file__).read_bytes(),'inputs.tsv':inputs,'expected.tsv':expected,'inputs.tsv.gz':(HERE/'fixtures/inputs.tsv.gz').read_bytes(),'expected.tsv.gz':(HERE/'fixtures/expected.tsv.gz').read_bytes()}
 if any(digest(raw)!=record['sha256'][name] for name,raw in values.items()):raise ValueError('frozen hash drift')
 if len(rows)!=record['cases'] or ('\n'.join('\t'.join(evaluate(r)) for r in rows)+'\n').encode()!=expected:raise ValueError('expectation replay')
 return record,inputs,expected
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--freeze',action='store_true');args=p.parse_args()
 if args.freeze:freeze()
 else:print('PASS frozen oracle',check()[0]['cases'])
