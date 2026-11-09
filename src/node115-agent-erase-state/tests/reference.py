"""Independent list/dict reference. Does not load or execute captured code."""
from pathlib import Path
import random, hashlib
r=random.Random(1153914)
def hx(b):return b.hex() or '-'
def pack_a(a):
 return '|'.join(k.hex()+'='+(';'.join(','.join([hx(n),v.hex(),o.hex()]) for n,v,o in rows) or '-') for k,rows in sorted(a.items())) or '-'
def pack_f(f):
 return '|'.join(k.hex()+'='+(';'.join(','.join([v.hex(),str(d),str(s),str(n)]) for v,d,s,n in sorted(rows)) or '-') for k,rows in sorted(f.items())) or '-'
keys=[bytes([0]*19+[i]) for i in range(8)]+[bytes([255]*20)]
names=[b'',b'a',b'aa',b'a\0',b'\0',b'agent','é'.encode(),'é'.encode()]
out=[];counts={92:0,418:0}
for scenario in range(100):
 a={};f={}
 for step in range(40):
  owner=r.choice(keys);name=r.choice(names)
  if step%3==0:
   a[owner]=[(r.choice(names),r.choice(keys),r.randbytes(12)) for _ in range(r.randrange(9))]
   if a[owner] and step%2==0:name=a[owner][r.randrange(len(a[owner]))][0]
  if step%7==0:f[owner]=[(r.choice(keys),700000,20,7),(r.choice(keys),700001,40,9)]
  d=r.choice([-95746129,-1,0,1,730120,95745398,95745399,r.randint(-95746129,95745399)])
  s=r.choice([0,53,54,58,59,86393,86394,86399,r.randrange(86400)])
  n=r.choice([0,1,999999999,r.randrange(1_000_000_000)])
  if s%60==59 and r.randrange(2):n+=1_000_000_000
  beforea,beforef=pack_a(a),pack_f(f)
  rows=a.setdefault(owner,[]);ix=next((i for i,x in enumerate(rows) if x[0]==name),None)
  if ix is None:status=92
  else:
   _,agent,_=rows[ix];a[owner]=rows[:ix]+rows[ix+1:]
   # Nanosecond leap extension is consumed before ordinary six-second addition.
   carry,sec=divmod(s+6,86400);day=d+carry;ns=n%1_000_000_000
   if day>95745399:day,sec,ns=95745399,86399,999999999
   f[owner]=[(agent,day,sec,ns)];status=418
  counts[status]+=1
  out.append('\t'.join([owner.hex(),hx(name),str(d),str(s),str(n),beforea,beforef,str(status),pack_a(a),pack_f(f)]))
p=Path(__file__).with_name('cases.tsv');p.write_text('\n'.join(out)+'\n')
print(len(out),counts,hashlib.sha256(p.read_bytes()).hexdigest())
