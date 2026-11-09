#!/usr/bin/env python3
"""Verify target-bound static instructions and unsigned-key arithmetic."""
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
a,z=0x4fac470,0x4fac699
assert any(x['start']==a and x['end']==z and (a,x['fde']) in idx for x in f)
assert sha256(read(a,z-a)).hexdigest()=='6b4154b37863f247d5dbfc7880d6b689e25e7ae40b4c468bbb9554855b8aaf17'
pins={0x4fac47a:'89f5',0x4fac47f:'8974240c',0x4fac483:'488b32',0x4fac48e:'f00fb04e10',0x4fac493:'0f8511010000',0x4fac4c0:'e84b3be9ff',0x4fac4c9:'f00fb00b',0x4fac4cd:'0f85f0000000',0x4fac4d3:'4d8b36',0x4fac4da:'b908000000',0x4fac4e1:'f0490fb14e10',0x4fac4e7:'0f85e6000000',0x4fac4ed:'4d8b7e18',0x4fac4f4:'48f7d8',0x4fac4f7:'0f81f4000000',0x4fac4fd:'498b4620',0x4fac501:'4885c0',0x4fac504:'0f8423010000',0x4fac50a:'498b4e28',0x4fac50e:'4c8d80b8000000',0x4fac515:'0fb7b8e6000000',0x4fac51c:'488d70f0',0x4fac523:'41c1e102',0x4fac527:'48c7c2ffffffff',0x4fac530:'4d85c9',0x4fac533:'745b',0x4fac535:'448b54240c',0x4fac53a:'458b18',0x4fac53d:'4983c004',0x4fac541:'410fca',0x4fac544:'410fcb',0x4fac547:'4539da',0x4fac54a:'410f97c2',0x4fac54e:'4180da00',0x4fac564:'4883c610',0x4fac568:'48ffc2',0x4fac56b:'4983c1fc',0x4fac56f:'4180fa01',0x4fac573:'74bb',0x4fac579:'85ff',0x4fac57b:'0f84a8000000',0x4fac590:'4889fa',0x4fac593:'4883e901',0x4fac597:'0f8290000000',0x4fac59d:'488b84d0e8000000',0x4fac5a5:'e964ffffff',0x4fac629:'c6460801',0x4fac62d:'31c9',0x4fac62f:'b808000000',0x4fac634:'f0480fb10b',0x4fac639:'750b'}
def check(r):
    for a,hx in pins.items():
        q=bytes.fromhex(hx);assert r(a,len(q))==q,hex(a)
    a=0x4fac4c0;q=r(a,5);assert a+5+int.from_bytes(q[1:],'little',signed=True)==0x4e40010
check(read)
for bad in [0x4fac4c0,0x4fac4e1,0x4fac4f7,0x4fac504,0x4fac515,0x4fac541,0x4fac544,0x4fac564,0x4fac57b,0x4fac597,0x4fac59d,0x4fac629]:
    def corrupt(a,n):
        q=bytearray(read(a,n))
        if a<=bad<a+n:q[bad-a]^=1
        return bytes(q)
    try:check(corrupt)
    except AssertionError:pass
    else:raise AssertionError(hex(bad))
from itertools import combinations
samples=[bytes(x) for x in [(0,0,0,0),(0,0,0,1),(1,0,0,0),(127,255,255,255),(128,0,0,0),(255,255,255,255)]]
cases=0
for count in range(5):
    for keys in combinations(samples,count):
        for key in samples:
            words=[int.from_bytes(x,'little') for x in keys]
            input_word=int.from_bytes(key,'little')
            swapped=lambda v:int.from_bytes(v.to_bytes(4,'little'),'big')
            i=0
            while i<len(words) and swapped(input_word)>swapped(words[i]):i+=1
            found=i<len(words) and swapped(input_word)==swapped(words[i])
            assert found==(key in keys)
            if found:assert 16*i+8 < 16*len(keys)
            cases+=1
print(f'1 FDE, {len(pins)} instruction pins, 12 corruption controls, {cases} ordered-key cases: OK')
