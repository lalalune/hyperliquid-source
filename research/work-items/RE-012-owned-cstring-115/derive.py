#!/usr/bin/env python3
"""Pure integer identities for the authenticated native zero-scan constants."""
from pathlib import Path
import sys,json
P=Path(__file__).resolve().parent;sys.path.insert(0,str(P));import verify
D=verify.TARGET.read_bytes();record,_=verify.collect(D,True)
ss=verify.sections(D)
def read(data,a,n):
 sec=next(x for x in ss if x['type']!=8 and x['address']<=a and a+n<=x['address']+x['size']);off=sec['offset']+a-sec['address'];return data[off:off+n]
pins=[(0x141e9ee,bytes.fromhex('8080808080808080')),(0x141e9f8,bytes.fromhex('0001010101010101'))]
def check(data):return all(read(data,a,len(v))==v for a,v in pins)
assert check(D)
for a,v in pins:
 sec=next(x for x in ss if x['type']!=8 and x['address']<=a<a+len(v)<=x['address']+x['size']);off=sec['offset']+a-sec['address']
 for i in range(len(v)):
  bad=bytearray(D);bad[off+i]^=1;assert not check(bad)

C=0x0101010101010100;H=0x8080808080808080;M=(1<<64)-1
# With no zero byte, the initial C.low=0 produces borrow1. Every subsequent
# nonzero byte propagates borrow1; either x has highbit1 or (-x mod256) does.
# At the first zero byte (whether byte0 or a later byte with borrow1), both
# operands' high bits are zero. Thus the equality holds iff no byte is zero.
def predicate(b):
 x=int.from_bytes(b,'little');return ((((C-x)&M)|x)&H)==H
count=0
for lane in range(7):
 for a in range(256):
  for b in range(256):
   v=bytearray([0xa5]*8);v[lane]=a;v[lane+1]=b;assert predicate(v)==(0 not in v);count+=1
for v in range(256):
 b=bytes([v])*8;assert predicate(b)==(v!=0);count+=1
for n in range(16,1025):
 for source_mod8 in range(8):
  head=(-source_mod8)&7;assert 0<=head<=7<n
  whole=(n-head)//16;tail=n-head-16*whole;assert 0<=tail<16 and head+16*whole+tail==n
print(json.dumps({'target_sha256':verify.SPEC['target_sha256'],'word_relations':count,'additional_actual_constant_byte_controls':16,'alignment_length_pairs':1009*8,'all_word_domain_argument':'first-zero/borrow-chain proof, not exhaustive2^64 enumeration','captured_execution_or_emulation':False},indent=2))
