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



MAX=(1<<64)-1
def operands(data):
 im=verify.Image(data)
 return {'first_period':struct.unpack('<d',im.get(0x1509d1a,8))[0],'second_period':struct.unpack('<d',im.get(0x1509d31,8))[0],'first_branch':u(im,0x1509d8b),'second_branch':u(im,0x1509da1),'step':u(im,0x150a085)}
def project(first,second,count,o):
 if bool(first)==(o['first_branch']==0x75):return ('proceed-first',count,None)
 if bool(second)==(o['second_branch']==0x84):return ('proceed-second',0,count)
 nxt=min(count+1,MAX) if o['step']==0xc1 else (count-1)&MAX
 return ('suppressed',nxt,None)
def evaluate(data):
 o=operands(data);verify.require(o=={'first_period':300.,'second_period':1.,'first_branch':0x75,'second_branch':0x84,'step':0xc1},'repeat operands');n=0
 for a,b,c in itertools.product([0,1,2,255],[0,1,2,255],[0,1,MAX-1,MAX]):
  want=('proceed-first',c,None) if a else ('proceed-second',0,c) if b else ('suppressed',min(c+1,MAX),None)
  verify.require(project(a,b,c,o)==want,'repeat counter routing');n+=1
 controls=[changed_relation(data,0x1509d8b,0x74,lambda d:project(1,0,10,operands(d))),changed_relation(data,0x1509da1,0x85,lambda d:project(0,1,10,operands(d))),changed_relation(data,0x150a085,0xc9,lambda d:project(0,0,10,operands(d)))]
 return {'native_operands':o,'projection_cases':n,'counterfactuals':controls,'limits':'The period helper result low bytes are inputs. No elapsed-time units, clock execution, lock semantics or full critical-message reporting behavior is inferred. The first nonzero result skips the second predicate and retains the existing count.'}
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--write',action='store_true');args=p.parse_args()
    data=verify.TARGET.read_bytes();verify.require(verify.sha(data)==verify.DIGEST,'wrong target')
    result=verify.encoded(evaluate(data))
    if args.write:(verify.PACKET/'relations.json').write_text(result)
    else:verify.require((verify.PACKET/'relations.json').read_text()==result,'relations drift')
    print('PASS: native operand relations and counterfactuals')
