#!/usr/bin/env python3
"""Independent arbitrary-precision signed-nanosecond relation; no OS execution."""
from pathlib import Path
import itertools,random,hashlib,json
B=1000000000

def rows():
 seconds=[-2**63,-2**63+1,-2**32,-86400,-2,-1,0,1,2,86400,2**32,2**63-2,2**63-1]
 nanos=[0,1,2,499999999,500000000,999999998,999999999]
 for a,b,n,m in itertools.product(seconds,seconds,nanos,nanos):yield(a,n,b,m)
 for a,b,n,m in itertools.product(range(-12,13),range(-12,13),range(4),range(4)):yield(a,n,b,m)
 rng=random.Random(0x1155c84210)
 for _ in range(25000):yield(rng.randrange(-2**63,2**63),rng.randrange(B),rng.randrange(-2**63,2**63),rng.randrange(B))
 for a,b,n,m in itertools.product([-2**63,0,2**63-1],[-2**63,0,2**63-1],[0,B-1,B,2**32-1],[0,B-1,B,2**32-1]):yield(a,n,b,m)

def result(r):
 a,n,b,m=r
 if n>=B or m>=B:return 'domain'
 delta=(a*B+n)-(b*B+m);s,ns=divmod(abs(delta),B);assert s<=2**64-1
 return ('O' if delta>=0 else 'E')+f' {s} {ns}'

def freeze():
 ih=hashlib.sha256();eh=hashlib.sha256();count=0
 for r in rows():
  a=(' '.join(map(str,r))+'\n').encode();z=(result(r)+'\n').encode();ih.update(a);eh.update(z);count+=1
 return {'cases':count,'input_sha256':ih.hexdigest(),'expected_sha256':eh.hexdigest(),'oracle_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
if __name__=='__main__':print(json.dumps(freeze(),indent=2))
