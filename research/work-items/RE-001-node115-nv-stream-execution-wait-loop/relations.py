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
 return {'warning':struct.unpack('<d',im.get(0x5a89968,8))[0],'sleep':struct.unpack('<d',im.get(0x5a89d75,8))[0],'closed_mask':u(im,0x5a89adc),'ordinary':u(im,0x5a89b27),'closed':u(im,0x5a89f03),'pending':u(im,0x5a8a033),'sleep_branch':u(im,0x5a89da0)}
def project(flags,tag,empty,sleep_pending,o):
 if flags&o['closed_mask']:return ('closed',o['closed'])
 if tag!=o['ordinary']:return ('error',tag)
 if empty:return ('complete',o['ordinary'])
 pending=bool(sleep_pending) if o['sleep_branch']==0x85 else not sleep_pending
 return ('retain-pending',o['pending']) if pending else ('retain-repoll',None)
def evaluate(data):
 o=operands(data);verify.require(o=={'warning':60.,'sleep':.01,'closed_mask':1,'ordinary':0x44,'closed':0x39,'pending':0x45,'sleep_branch':0x85},'wait operands');n=0
 for flag,tag,empty,pending in itertools.product(range(256),[0,1,0x39,0x44],[0,1],[0,1,255]):
  want=('closed',0x39) if flag&1 else ('error',tag) if tag!=0x44 else ('complete',0x44) if empty else ('retain-pending',0x45) if pending else ('retain-repoll',None)
  verify.require(project(flag,tag,empty,pending,o)==want,'wait precedence');n+=1
 controls=[changed_relation(data,0x5a89adc,2,lambda d:project(1,0x44,1,0,operands(d))),changed_relation(data,0x5a89da0,0x84,lambda d:project(0,0x44,0,1,operands(d))),changed_relation(data,0x5a89d75,0x7a,lambda d:operands(d)['sleep'])]
 return {'native_operands':o,'projection_cases':n,'counterfactuals':controls,'limits':'Projection begins inside the retained-buffer loop. Valid descriptor, supplied helper outputs and normally returning cleanup are premises. Warning and sleep inputs are binary64 numbers, not established elapsed units. Buffer transition, timer/executor progress and actual waiting are not simulated.'}
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--write',action='store_true');args=p.parse_args()
    data=verify.TARGET.read_bytes();verify.require(verify.sha(data)==verify.DIGEST,'wrong target')
    result=verify.encoded(evaluate(data))
    if args.write:(verify.PACKET/'relations.json').write_text(result)
    else:verify.require((verify.PACKET/'relations.json').read_text()==result,'relations drift')
    print('PASS: native operand relations and counterfactuals')
