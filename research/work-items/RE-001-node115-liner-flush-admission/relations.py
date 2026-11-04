#!/usr/bin/env python3
"""Operand-derived local relations; no target execution or instruction emulation."""
import argparse
import itertools
import struct
import verify

def u(im,a,n=1):
    return int.from_bytes(im.get(a,n),'little')

def changed_relation(data,va,new,fn):
    image=verify.Image(data)
    altered=bytearray(data);altered[image.off(va)]=new
    before,after=fn(data),fn(altered)
    verify.require(before!=after,'surviving relation counterfactual')
    return {'va':hex(va),'new_byte':new,'original':verify.json.loads(verify.encoded(before)),'mutated':verify.json.loads(verify.encoded(after))}

def operands(data):
 im=verify.Image(data)
 return {'subnormal_limit':u(im,0x14c47fe,8),'abs_mask':u(im,0x14c480e,8),'bias':u(im,0x14c4822,8),'shift':u(im,0x14c4830),'threshold':u(im,0x14c4833,4),'parse_error':u(im,0x14c47e6),'default_bits':u(im,0x459718,8)}
def admitted(bits,o):
 m=(1<<64)-1;a=bits&o['abs_mask']
 return ((bits-1)&m)<o['subnormal_limit'] or a==0 or (((a+o['bias'])&m)>>o['shift']<o['threshold'] and bits>>63==0)
def project(query,parse,bits,o):
 if query:return ['default',o['default_bits']]
 if parse==o['parse_error']:return ['parse-failure']
 return ['value',bits] if admitted(bits,o) else ['range-failure']
def evaluate(data):
 o=operands(data);cases=[];count=0
 for sign,exp,mant in itertools.product(range(2),range(2048),[0,1,2,(1<<51)-1,1<<51,(1<<52)-2,(1<<52)-1]):
  bits=sign<<63|exp<<52|mant;actual=admitted(bits,o);expected=(exp!=2047 and (sign==0 or exp==0 and mant==0))
  verify.require(actual==expected,'finite nonnegative boundary');count+=1
 for bits in [0,1,1<<52,(1023<<52),0x7fefffffffffffff,0x7ff0000000000000,0x7ff8000000000001,1<<63,0x8000000000000001,0xfff0000000000000]:
  cases.append({'bits':hex(bits),'admitted':admitted(bits,o)})
 for q,p in itertools.product(range(256),range(2)):
  r=project(q,p,0,o);verify.require(r==(['default',0x404e000000000000] if q else ['parse-failure'] if p else ['value',0]),'default/parse precedence')
 controls=[changed_relation(data,0x14c47e6,2,lambda d:project(0,1,0,operands(d))),changed_relation(data,0x14c4833,254,lambda d:admitted(0x7fefffffffffffff,operands(d))),changed_relation(data,0x45971e,0x50,lambda d:project(1,0,0,operands(d)))]
 return {'native_operands':o,'binary64_boundary_cases':count,'query_parse_cases':512,'examples':cases,'counterfactuals':controls,'limits':'Every exponent and sign with seven mantissa boundaries; not exhaustive64-bit enumeration. Parser and query outcomes supplied. No parsing grammar, units or target execution claim.'}
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--write',action='store_true');args=p.parse_args()
    data=verify.TARGET.read_bytes();verify.require(verify.sha(data)==verify.DIGEST,'wrong target')
    result=verify.encoded(evaluate(data))
    if args.write:(verify.PACKET/'relations.json').write_text(result)
    else:verify.require((verify.PACKET/'relations.json').read_text()==result,'relations drift')
    print('PASS: native operand relations and counterfactuals')
