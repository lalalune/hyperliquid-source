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
 return {'first_pending':u(im,0x29699cd),'second_pending':u(im,0x29699f5),'first_state':u(im,0x29699d8),'second_state':u(im,0x2969a04),'query_trigger':u(im,0x2969ba2),'first_absence':u(im,0x2969b71),'outer_error':u(im,0x2969a81,4),'default_output':u(im,0x2969c24,4)}
def project(first,second_pending,second_absent,o):
 if first==o['first_pending']:return ('pending',o['first_state'])
 if first in (3,o['first_absence']):return ('short-circuit',o['outer_error'])
 if first!=o['query_trigger']:return ('default',o['default_output'])
 if second_pending:return ('pending',o['second_state'])
 return ('default',o['default_output']) if second_absent else ('second-result',None)
def evaluate(data):
 o=operands(data);verify.require(o=={'first_pending':4,'second_pending':2,'first_state':3,'second_state':4,'query_trigger':1,'first_absence':2,'outer_error':3,'default_output':2},'conditional query operands');n=0
 for a,b,c in itertools.product(range(5),[0,1],[0,1]):
  want=('pending',3) if a==4 else ('short-circuit',3) if a in (2,3) else ('default',2) if a==0 else ('pending',4) if b else ('default',2) if c else ('second-result',None)
  verify.require(project(a,b,c,o)==want,'conditional query routing');n+=1
 controls=[changed_relation(data,0x2969ba2,0,lambda d:project(1,1,0,operands(d))),changed_relation(data,0x29699d8,4,lambda d:project(4,0,0,operands(d))),changed_relation(data,0x2969c24,1,lambda d:project(0,0,0,operands(d)))]
 return {'native_operands':o,'projection_cases':n,'counterfactuals':controls,'limits':'Valid first result tags0..4 and separate second pending/absence classifications supplied. The second pending discriminator resides at result+0x40; absence is a different first-word tag2 after readiness. Payload field mapping, helper query meaning and all cancellation/destructor semantics remain unclosed. No target execution.'}
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--write',action='store_true');args=p.parse_args()
    data=verify.TARGET.read_bytes();verify.require(verify.sha(data)==verify.DIGEST,'wrong target')
    result=verify.encoded(evaluate(data))
    if args.write:(verify.PACKET/'relations.json').write_text(result)
    else:verify.require((verify.PACKET/'relations.json').read_text()==result,'relations drift')
    print('PASS: native operand relations and counterfactuals')
