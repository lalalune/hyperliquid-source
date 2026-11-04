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
 return {'size_limit':u(im,0x4faf1db,4),'last_old_length':u(im,0x4faf222,4),'height_branch':u(im,0x4faf0e5)}
def project(height,requested,old_count,total,cost,o):
 successor=min(height+1,MAX)
 stop=successor<=requested if o['height_branch']==0x77 else successor<requested
 if stop and old_count:return ('height',old_count,total)
 total=min(total+cost,MAX)
 if total>o['size_limit']:return ('size',old_count,total)
 return ('rows' if old_count>o['last_old_length'] else 'next',old_count+1,total)
def evaluate(data):
 o=operands(data);verify.require(o=={'size_limit':20000000,'last_old_length':298,'height_branch':0x77},'batch operands');n=0
 for h,r,c,t,k in itertools.product([0,1,MAX-1,MAX],[0,1,2,MAX],[0,1,298,299],[0,19999999,20000000,MAX],[0,1,2,20000000,MAX]):
  got=project(h,r,c,t,k,o)
  if c and min(h+1,MAX)<=r:want=('height',c,t)
  elif min(t+k,MAX)>20000000:want=('size',c,min(t+k,MAX))
  else:want=('rows' if c>=299 else 'next',c+1,min(t+k,MAX))
  verify.require(got==want,'batch stop ordering');n+=1
 controls=[changed_relation(data,0x4faf1db,1,lambda d:project(0,0,0,20000000,1,operands(d))),changed_relation(data,0x4faf222,0x2b,lambda d:project(0,0,299,0,0,operands(d))),changed_relation(data,0x4faf0e5,0x73,lambda d:project(0,1,1,0,0,operands(d)))]
 return {'native_operands':o,'projection_cases':n,'counterfactuals':controls,'limits':'Safe batch descriptors and normally returning helpers; cost and height supplied at observed call boundaries. The size helper is not proved to count encoded bytes. Tests do not run or emulate the capture. Missing-materialization and missing-next result handling are retained in native obligations, not invented helper implementations.'}
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--write',action='store_true');args=p.parse_args()
    data=verify.TARGET.read_bytes();verify.require(verify.sha(data)==verify.DIGEST,'wrong target')
    result=verify.encoded(evaluate(data))
    if args.write:(verify.PACKET/'relations.json').write_text(result)
    else:verify.require((verify.PACKET/'relations.json').read_text()==result,'relations drift')
    print('PASS: native operand relations and counterfactuals')
