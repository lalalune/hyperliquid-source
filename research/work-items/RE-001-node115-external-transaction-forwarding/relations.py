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
 return {'local_tag':u(im,0x5a7dcfb,8),'encoding_adjustment':int.from_bytes(im.get(0x5a7df90,1),'little',signed=True),'closed_mask':u(im,0x5a7e081),'pending_state':u(im,0x5a7e1ad),'complete_state':u(im,0x5a7e1e5),'reset_state':u(im,0x5a7e127)}
def project(pending,payload,counter,o):
 if pending:return {'state':o['pending_state'],'trace':['pending']}
 if not payload:return {'state':o['complete_state'],'trace':['terminal cleanup']}
 tag=o['local_tag'];wire=(tag+o['encoding_adjustment'])&((1<<64)-1)
 trace=['encode envelope tag '+hex(wire),'remote forwarding']
 if counter&o['closed_mask']:trace+=['drop local tagged value']
 else:trace+=['enqueue local tag '+hex(tag)]
 trace+=['reset nested state '+str(o['reset_state']),'repoll']
 return {'state':None,'trace':trace}
def evaluate(data):
 o=operands(data);verify.require(o=={'local_tag':(1<<63)+1,'encoding_adjustment':-1,'closed_mask':1,'pending_state':3,'complete_state':1,'reset_state':0},'forward operands');count=0;examples=[]
 for pending,payload,counter in itertools.product([0,1],[0,1,4096],range(256)):
  r=project(pending,payload,counter,o);count+=1
  if pending:verify.require(r['state']==3 and r['trace']==['pending'],'pending precedence')
  elif not payload:verify.require(r['state']==1 and r['trace']==['terminal cleanup'],'closed input')
  else:
   verify.require(r['trace'][:2]==['encode envelope tag 0x8000000000000000','remote forwarding'],'encode before remote')
   verify.require(('drop local tagged value' in r['trace'])==bool(counter&1),'local closure');verify.require(r['trace'][-1]=='repoll','closure does not stop worker')
  if counter<3:examples.append({'pending':pending,'payload':payload,'counter':counter,**r})
 controls=[changed_relation(data,0x5a7df90,0,lambda d:project(0,1,0,operands(d))),changed_relation(data,0x5a7e081,2,lambda d:project(0,1,1,operands(d))),changed_relation(data,0x5a7e1e5,2,lambda d:project(0,0,0,operands(d)))]
 return {'native_operands':o,'projection_cases':count,'examples':examples,'counterfactuals':controls,'limits':'Receive pending/payload supplied at continuation boundary; closure counter below overflow sentinel and normal-return helpers. Remote/local are call routes, not delivery guarantees. No wire bytes/schema, queue concurrency, input polling or captured-code execution recovered.'}
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--write',action='store_true');args=p.parse_args()
    data=verify.TARGET.read_bytes();verify.require(verify.sha(data)==verify.DIGEST,'wrong target')
    result=verify.encoded(evaluate(data))
    if args.write:(verify.PACKET/'relations.json').write_text(result)
    else:verify.require((verify.PACKET/'relations.json').read_text()==result,'relations drift')
    print('PASS: native operand relations and counterfactuals')
