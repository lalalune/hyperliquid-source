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
 return {'loopback':u(im,0x2af8e14,4),'bit_test_opcode':u(im,0x2af8ebd),'first_budget':u(im,0x2af8f3e,4),'other_budget':u(im,0x2af8fd3,4),'decode_budget':u(im,0x2af8cf9,4)}
def project(ip,presence,expected,special,limiter_al,o):
 check=(presence&int(ip==expected)) if o['bit_test_opcode']==0x84 else (presence|int(ip==expected))
 allowed=ip==o['loopback'] or bool(check)
 return (allowed,o['first_budget'] if special else o['other_budget'],allowed and limiter_al==0)
def evaluate(data):
 o=operands(data);verify.require(o=={'loopback':0x100007f,'bit_test_opcode':0x84,'first_budget':10000,'other_budget':1000000,'decode_budget':0xa7d8c0},'listener operands');n=0
 for ip,p,e,c,a in itertools.product([0,0x100007f,0x200007f,0xffffffff],[0,1,2,3,255],[0,0x100007f,0x200007f,0xffffffff],[0,1],[0,1,2,255]):
  yes=ip==0x100007f or (p&1 and ip==e)
  verify.require(project(ip,p,e,c,a,o)==(bool(yes),10000 if c else 1000000,bool(yes and a==0)),'listener admission');n+=1
 controls=[changed_relation(data,0x2af8e14,0x7e,lambda d:project(0x100007f,0,0,0,0,operands(d))),changed_relation(data,0x2af8ebd,0x08,lambda d:project(1,2,0,0,0,operands(d))),changed_relation(data,0x2af8f3e,0x11,lambda d:project(0x100007f,0,0,1,0,operands(d)))]
 return {'native_operands':o,'projection_cases':n,'counterfactuals':controls,'limits':'Four-byte stored address, lookup packed low byte/expected DWORD and limiter result are supplied. Local policy alone establishes neither authentication nor runtime rate units. Raw decoder classes are not assigned wire names. No network or target execution.'}
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--write',action='store_true');args=p.parse_args()
    data=verify.TARGET.read_bytes();verify.require(verify.sha(data)==verify.DIGEST,'wrong target')
    result=verify.encoded(evaluate(data))
    if args.write:(verify.PACKET/'relations.json').write_text(result)
    else:verify.require((verify.PACKET/'relations.json').read_text()==result,'relations drift')
    print('PASS: native operand relations and counterfactuals')
