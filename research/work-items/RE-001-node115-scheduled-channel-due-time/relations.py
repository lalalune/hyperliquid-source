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
 return {'signed_compare':u(im,0x5a7143b),'last_branch':u(im,0x5a71458),'borrow_unit':u(im,0x5a7148c,4),'scale':struct.unpack('<d',im.get(0x458d50,8))[0],'pending_state':u(im,0x5a71534),'state_reset':u(im,0x5a714ce)}
def project(due,now,seconds,nanos,pending,o):
 if due[0]!=now[0]:
  earlier=due[0]<now[0] if o['signed_compare']==0x9c else (due[0]&0xffffffff)<(now[0]&0xffffffff)
 elif due[1]!=now[1]:earlier=due[1]<now[1]
 else:earlier=due[2]<now[2] if o['last_branch']==0x73 else due[2]<=now[2]
 if earlier:delay=0.
 else:
  if seconds<0 and nanos>0:seconds+=1;nanos+=o['borrow_unit']-(1<<32)
  raw=float(seconds)+float(nanos)/o['scale']
  delay=0. if math.isnan(raw) or raw<=0. or raw==math.inf else raw
 return (not earlier,delay,'pending-'+str(o['pending_state']) if pending else 'next-send',o['state_reset'])
def evaluate(data):
 o=operands(data);verify.require(o=={'signed_compare':0x9c,'last_branch':0x73,'borrow_unit':0xc4653600,'scale':1e9,'pending_state':4,'state_reset':0},'scheduled operands');n=0
 dates=[(-(1<<31),0,0),(-1,0,0),(0,0,0),(0,0,1),(0,0xffffffff,0),(1,0,0),((1<<31)-1,0xffffffff,0xffffffff)]
 for due,now,s,ns,pending in itertools.product(dates,dates,[-(1<<63),-2,-1,0,1,2,(1<<63)-1],[-(1<<31),-1,0,1,999999999,(1<<31)-1],[0,1]):
  got=project(due,now,s,ns,pending,o);want_call=due>=now
  if want_call:
   sec=s+int(s<0 and ns>0);nano=ns-1000000000*int(s<0 and ns>0)
   delay=max(0.,float(sec)+float(nano)/1000000000.)
  else:delay=0.
  verify.require(got==(want_call,delay,'pending-4' if pending else 'next-send',0),'due-time projection');n+=1
 controls=[changed_relation(data,0x5a7143b,0x92,lambda d:project((-1,0,0),(0,0,0),1,0,0,operands(d))),changed_relation(data,0x5a71458,0x77,lambda d:project((0,0,0),(0,0,0),1,0,0,operands(d))),changed_relation(data,0x5a71534,3,lambda d:project((0,0,1),(0,0,0),1,0,1,operands(d)))]
 return {'native_operands':o,'projection_cases':n,'counterfactuals':controls,'limits':'The three-word comparison uses signed first DWORD and unsigned tie-break words. Calendar difference output is supplied as i64/i32, not assumed to agree with arbitrary date triples. Projection covers only caller arithmetic; no captured instructions, timers, queue, scheduling or delivery are executed. All valid finite integer helper outputs yield finite binary64 conversion; the infinity/unordered guard is recorded native context.'}
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--write',action='store_true');args=p.parse_args()
    data=verify.TARGET.read_bytes();verify.require(verify.sha(data)==verify.DIGEST,'wrong target')
    result=verify.encoded(evaluate(data))
    if args.write:(verify.PACKET/'relations.json').write_text(result)
    else:verify.require((verify.PACKET/'relations.json').read_text()==result,'relations drift')
    print('PASS: native operand relations and counterfactuals')
