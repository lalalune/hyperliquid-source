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
 return {'pending_tag':u(im,0x5a64707),'pending_state':u(im,0x5a6470e),'error_skip_opcode':u(im,0x5a6479b),'format_error_opcode':u(im,0x5a6480b),'complete_state':u(im,0x5a6488b),'nested_parameter_bits':u(im,0x5a646cb,8)}
def project(status,error,format_error,capacity,o):
 if status==o['pending_tag']:return {'state':o['pending_state'],'trace':['retain pending send']}
 trace=['nested cleanup']+(['release encoded buffer'] if capacity else [])
 report=bool(error) if o['error_skip_opcode']==0x84 else not error
 if report:
  trace+=['lock','format error']
  if bool(format_error)==(o['format_error_opcode']==0x85):return {'state':None,'trace':trace+['fatal format']}
  trace+=['report rejection failure','unlock','drop error']
 return {'state':o['complete_state'],'trace':trace+['owner cleanup','secondary cleanup','release reference']}
def evaluate(data):
 o=operands(data);verify.require(o=={'pending_tag':1,'pending_state':3,'error_skip_opcode':0x84,'format_error_opcode':0x85,'complete_state':1,'nested_parameter_bits':0x404e000000000000},'send operands');examples=[]
 for status,error,fmt,cap in itertools.product(range(2),[0,1,4096],range(256),[0,8]):
  r=project(status,error,fmt,cap,o)
  if status:verify.require(r=={'state':3,'trace':['retain pending send']},'pending retention')
  elif error and fmt:verify.require(r['trace'][-1]=='fatal format' and r['state'] is None,'format failure before reporting')
  else:verify.require(r['state']==1 and ('report rejection failure' in r['trace'])==bool(error),'terminal reporting')
  if fmt in (0,1) and cap==8:examples.append({'status':status,'error':error,'format_error':fmt,**r})
 controls=[changed_relation(data,0x5a64707,2,lambda d:project(1,0,0,8,operands(d))),changed_relation(data,0x5a6479b,0x85,lambda d:project(0,0,0,8,operands(d))),changed_relation(data,0x5a6480b,0x84,lambda d:project(0,1,0,8,operands(d)))]
 return {'native_operands':o,'projection_cases':3072,'examples':examples,'counterfactuals':controls,'limits':'Valid status0/1, initial/resumed state and well-formed owned inputs. Normal returning cleanup/lock/report helpers. No network send, admission policy, clock units or complete exception-safety proof.'}
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--write',action='store_true');args=p.parse_args()
    data=verify.TARGET.read_bytes();verify.require(verify.sha(data)==verify.DIGEST,'wrong target')
    result=verify.encoded(evaluate(data))
    if args.write:(verify.PACKET/'relations.json').write_text(result)
    else:verify.require((verify.PACKET/'relations.json').read_text()==result,'relations drift')
    print('PASS: native operand relations and counterfactuals')
