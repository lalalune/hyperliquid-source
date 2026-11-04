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
 return {'sequence_offset':u(im,0x5a7d75c,4),'step_opcode':u(im,0x5a7d7c8),'selection_opcode':u(im,0x5a7d7d2),'second_time_parameter':u(im,0x5a7d8f7,4)}
def project(value,o):
 candidate=(value+(1 if o['step_opcode']==0xc0 else -1))&MAX
 use=candidate!=0 if o['selection_opcode']==0x45 else candidate==0
 return {'post_call_value':value,'field_offset':o['sequence_offset'],'next_value':candidate if use else MAX,'order':['register','store sequence','first channel','second channel','rearm']}
def evaluate(data):
 o=operands(data);verify.require(o=={'sequence_offset':0xc8,'step_opcode':0xc0,'selection_opcode':0x45,'second_time_parameter':70000000},'sequence operands');n=0
 for value in [0,1,2,MAX-2,MAX-1,MAX]:
  r=project(value,o);verify.require(r['next_value']==min(value+1,MAX),'saturating sequence');verify.require(r['post_call_value']==value,'value read after registration');n+=1
 controls=[changed_relation(data,0x5a7d7c8,0xc8,lambda d:project(10,operands(d))),changed_relation(data,0x5a7d7d2,0x44,lambda d:project(10,operands(d))),changed_relation(data,0x5a7d75c,0xc0,lambda d:project(10,operands(d)))]
 return {'native_operands':o,'projection_cases':n,'counterfactuals':controls,'limits':'Accepted input and normally returning digest/registration helpers are premises. Saturation means multiple items can pass the same maximum sequence to registration; no uniqueness guarantee is inferred. Both output queues may be closed independently after the sequence store. Native call order is retained in obligations, not simulated concurrency.'}
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--write',action='store_true');args=p.parse_args()
    data=verify.TARGET.read_bytes();verify.require(verify.sha(data)==verify.DIGEST,'wrong target')
    result=verify.encoded(evaluate(data))
    if args.write:(verify.PACKET/'relations.json').write_text(result)
    else:verify.require((verify.PACKET/'relations.json').read_text()==result,'relations drift')
    print('PASS: native operand relations and counterfactuals')
