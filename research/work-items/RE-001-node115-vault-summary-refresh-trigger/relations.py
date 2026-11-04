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
 return {'comparison_branch':u(im,0x29694b8),'count_pending_state':u(im,0x2969402),'compute_pending_state':u(im,0x2969562),'cutoff':u(im,0x29696cb,4)}
def project(count,cached,timestamp,o):
 same=count==cached
 recompute=not same if o['comparison_branch']==0x84 else same
 return (['compute','update','query'] if recompute else ['query'],max(max(timestamp,0)-o['cutoff'],0))
def evaluate(data):
 o=operands(data);verify.require(o=={'comparison_branch':0x84,'count_pending_state':3,'compute_pending_state':4,'cutoff':7200000},'vault refresh operands');n=0
 for count,cached,t in itertools.product([0,1,2,(1<<64)-1],[0,1,2,(1<<64)-1],[0,1,2,(1<<63)-1]):
  a=project(count,cached,t,o);verify.require(a==(['query'] if count==cached else ['compute','update','query'],max(t-7200000,0)),'refresh equality');n+=1
 for t in [-1,0,1,7199999,7200000,7200001,(1<<63)-1]:
  verify.require(project(1,1,t,o)[1]==max(t-7200000,0),'cutoff boundary');n+=1
 controls=[changed_relation(data,0x29694b8,0x85,lambda d:project(1,1,0,operands(d))),changed_relation(data,0x29696cb,1,lambda d:project(0,0,7200001,operands(d))),changed_relation(data,0x2969562,3,lambda d:(operands(d)['count_pending_state'],operands(d)['compute_pending_state']))]
 return {'native_operands':o,'projection_cases':n,'counterfactuals':controls,'limits':'Count and calendar-derived signed timestamp supplied at the measured boundary; calendar conversion and cache helpers remain opaque. Equal length is the only refresh comparison here, not proof of cache content equality. Pending states retain their respective boxed future. No target execution.'}
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--write',action='store_true');args=p.parse_args()
    data=verify.TARGET.read_bytes();verify.require(verify.sha(data)==verify.DIGEST,'wrong target')
    result=verify.encoded(evaluate(data))
    if args.write:(verify.PACKET/'relations.json').write_text(result)
    else:verify.require((verify.PACKET/'relations.json').read_text()==result,'relations drift')
    print('PASS: native operand relations and counterfactuals')
