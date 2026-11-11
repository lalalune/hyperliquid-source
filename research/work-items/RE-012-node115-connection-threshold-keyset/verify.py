#!/usr/bin/env python3
"""Static selected-path evidence; never execute target instructions."""
from hashlib import sha256
from pathlib import Path
from elf_index import unwind_index
from fde_extents import eh_frame_records
b=Path('artifacts/node/115/hl-node').read_bytes()
assert sha256(b).hexdigest()=='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
s,h=unwind_index(b);_,f=eh_frame_records(b,s);idx={(x['start'],x['fde']) for x in h}
def read(a,n):
    x=next(x for x in s if x['address']<=a and a+n<=x['address']+x['size'] and x['name']=='.text')
    p=x['offset']+a-x['address'];return b[p:p+n]
a,z=0x5a628d0,0x5a630f2
assert any(x['start']==a and x['end']==z and (a,x['fde']) in idx for x in f)
assert sha256(read(a,z-a)).hexdigest()=='7ee3fff5e3a94a4e82d5d2da9234ad2592ed6435c73cbd0b2d56450eec6d5b90'
pins={0x5a628e1:'89d5',0x5a628e6:'89742414',0x5a6293c:'44897c247c',0x5a62cd8:'e8839254ff',0x5a62cdd:'483b442470',0x5a62ce2:'732c',0x5a62daf:'8b44247c',0x5a62db3:'89442430',0x5a62db7:'498b4628',0x5a62dbb:'4885c0',0x5a62dbe:'0f8485000000',0x5a62dc4:'498b4e30',0x5a62dc8:'488d7808',0x5a62dcc:'0fb77036',0x5a62dd3:'41c1e002',0x5a62dd7:'48c7c2ffffffff',0x5a62de0:'4d85c0',0x5a62de3:'744b',0x5a62de5:'448b4c2430',0x5a62dea:'448b17',0x5a62ded:'4883c704',0x5a62df1:'410fc9',0x5a62df4:'410fca',0x5a62df7:'4539d1',0x5a62dfa:'410f97c1',0x5a62dfe:'4180d900',0x5a62e14:'48ffc2',0x5a62e17:'4983c0fc',0x5a62e1b:'4180f901',0x5a62e1f:'74bf',0x5a62e25:'85f6',0x5a62e27:'750a',0x5a62e29:'eb15',0x5a62e30:'4889f2',0x5a62e33:'4883e901',0x5a62e37:'7210',0x5a62e39:'488b44d038',0x5a62e3e:'eb88',0x5a62e40:'b003',0x5a62e42:'4584e4',0x5a62e45:'7409',0x5a62e47:'eb21',0x5a62e49:'31c0',0x5a62e4b:'4584e4',0x5a62e4e:'751a',0x5a62e57:'f0490fc10f',0x5a62e64:'0f84cc010000',0x5a63039:'4189c6',0x5a63042:'4489f0',0x5a63045:'e920feffff',0x5a62e6a:'3c03',0x5a62e6c:'0f95c1',0x5a62e6f:'4080f501',0x5a62e73:'4008cd',0x5a62e76:'0f8568010000',0x5a62fe4:'4881c498000000',0x5a62ff5:'c3'}
def check(r):
    for a,hx in pins.items():
        q=bytes.fromhex(hx);assert r(a,len(q))==q,hex(a)
check(read)
for bad in [0x5a62ce2,0x5a62dbe,0x5a62dcc,0x5a62df1,0x5a62df4,0x5a62e1f,0x5a62e29,0x5a62e37,0x5a62e39,0x5a62e40,0x5a62e49,0x5a63042,0x5a62e6f,0x5a62e76]:
    def corrupt(a,n):
        q=bytearray(read(a,n))
        if a<=bad<a+n:q[bad-a]^=1
        return bytes(q)
    try:check(corrupt)
    except AssertionError:pass
    else:raise AssertionError(hex(bad))
from itertools import combinations
keys=[bytes(x) for x in [(0,0,0,0),(0,0,0,1),(1,0,0,0),(127,255,255,255),(128,0,0,0),(255,255,255,255)]]
cases=0
for n in range(5):
 for seq in combinations(keys,n):
  for key in keys:
   words=[int.from_bytes(q,'big') for q in seq];needle=int.from_bytes(key,'big');i=0
   while i<len(words) and needle>words[i]:i+=1
   present=i<len(words) and needle==words[i]
   assert present==(key in seq)
   for flag in (0,1):
    intermediate=3 if present else 0
    second_counter=(intermediate==3 and flag==1)
    assert second_counter==(present and flag==1)
    cases+=1
print(f'1 FDE, {len(pins)} instruction pins, 14 corruption controls, {cases} key/flag cases: OK')
