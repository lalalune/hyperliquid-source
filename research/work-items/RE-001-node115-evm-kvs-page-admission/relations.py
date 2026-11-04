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
 return {'overhead':u(im,0x2b206b2),'warning':u(im,0x2b206dc,4),'row_limit':u(im,0x2b207a6,4),'page_limit':u(im,0x2b207b6,4),'resume_branch':u(im,0x2b20303)}
def project(k,v,total,o):
 charge=min(min(k+o['overhead'],MAX)+v,MAX)
 if charge>o['row_limit']:return ('error-clear',charge>o['warning'],charge)
 if total+charge>o['page_limit']:return ('stop-retain-prefix',charge>o['warning'],charge)
 return ('append',charge>o['warning'],charge)
def evaluate(data):
 o=operands(data);verify.require(o=={'overhead':32,'warning':1000000,'row_limit':2000000,'page_limit':2000000,'resume_branch':0x84},'KVS page operands');n=0
 for k,v,t in itertools.product([0,1,999967,999968,1999967,1999968,1999969,MAX],[0,1,2,MAX],[0,1,1999999,2000000]):
  c=min(k+32+v,MAX);want=('error-clear' if c>2000000 else 'stop-retain-prefix' if t+c>2000000 else 'append',c>1000000,c)
  verify.require(project(k,v,t,o)==want,'page row admission');n+=1
 controls=[changed_relation(data,0x2b206b2,31,lambda d:project(1999969,0,0,operands(d))),changed_relation(data,0x2b206dc,0x41,lambda d:project(999969,0,0,operands(d))),changed_relation(data,0x2b207b6,0x81,lambda d:project(1999968,0,1,operands(d)))]
 return {'native_operands':o,'projection_cases':n,'counterfactuals':controls,'limits':'Supplied iterator result lengths, valid descriptors and cumulative accepted total at most2000000. The32-byte overhead is an internal charge, not proved wire size. Iterator and scheduler implementations are not simulated. Native obligations retain exact resume-row match and disposal ordering.'}
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--write',action='store_true');args=p.parse_args()
    data=verify.TARGET.read_bytes();verify.require(verify.sha(data)==verify.DIGEST,'wrong target')
    result=verify.encoded(evaluate(data))
    if args.write:(verify.PACKET/'relations.json').write_text(result)
    else:verify.require((verify.PACKET/'relations.json').read_text()==result,'relations drift')
    print('PASS: native operand relations and counterfactuals')
