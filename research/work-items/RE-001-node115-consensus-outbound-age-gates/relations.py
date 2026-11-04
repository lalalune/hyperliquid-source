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


import math
def operands(data):
 im=verify.Image(data)
 return {'age':struct.unpack('<d',im.get(0x4593d0,8))[0],'backoff':struct.unpack('<d',im.get(0x458eb0,8))[0],'connect':struct.unpack('<d',im.get(0x5a7fbf5,8))[0],'send':struct.unpack('<d',im.get(0x5a7fdf5,8))[0]}
def special(x):return math.isnan(x) or x==math.inf
def project(age,backoff,has_failure,disconnected,recheck,older_than_connection,o):
 if not special(age) and age>o['age']:return ('drop-age',False,False)
 connect=disconnected and not(has_failure and (special(backoff) or backoff<o['backoff']))
 # State after a normally completed connect is supplied independently below.
 value=0. if special(recheck) else recheck
 send=not disconnected and not(value>o['age']) and not older_than_connection
 return ('continue',connect,send)
def evaluate(data):
 o=operands(data);verify.require(o=={'age':5.,'backoff':2.,'connect':2.,'send':20.},'network timing operands');n=0
 vals=[-math.inf,-1.,0.,1.999999,2.,4.999999,5.,5.000001,math.inf,math.nan]
 for age,b,failed,disconnected,recheck,old in itertools.product(vals,vals,[0,1],[0,1],vals,[0,1]):
  got=project(age,b,failed,disconnected,recheck,old,o)
  if math.isfinite(age) and age>5:want=('drop-age',False,False)
  elif age==-math.inf or age<=5 or special(age):
   retry=bool(disconnected and (not failed or (not special(b) and b>=2)))
   send=bool(not disconnected and (special(recheck) or recheck<=5) and not old)
   want=('continue',retry,send)
  verify.require(got==want,'outbound gates');n+=1
 controls=[changed_relation(data,0x4593d0+6,0x10,lambda d:project(4.5,0,0,0,0,0,operands(d))),changed_relation(data,0x458eb0+6,0xf0,lambda d:project(0,2.5,1,1,0,0,operands(d))),changed_relation(data,0x5a7fdf5+6,0x24,lambda d:operands(d)['send'])]
 return {'native_operands':o,'projection_cases':n,'counterfactuals':controls,'limits':'Converted binary64 differences and valid connection state are supplied. Connect outcome is deliberately not simulated: send is evaluated with an independently supplied post-connect state. Unordered comparisons and positive infinity retain their actual special treatment. TCP/clock semantics, units, progress and delivery are not established.'}
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--write',action='store_true');args=p.parse_args()
    data=verify.TARGET.read_bytes();verify.require(verify.sha(data)==verify.DIGEST,'wrong target')
    result=verify.encoded(evaluate(data))
    if args.write:(verify.PACKET/'relations.json').write_text(result)
    else:verify.require((verify.PACKET/'relations.json').read_text()==result,'relations drift')
    print('PASS: native operand relations and counterfactuals')
