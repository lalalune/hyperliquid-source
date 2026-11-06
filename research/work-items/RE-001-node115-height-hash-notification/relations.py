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
 return {'freeze_tag':u(im,0x5a6c906),'past_branch':u(im,0x5a6c911),'outer_skip':u(im,0x5a6c94f),'last_equal_branch':u(im,0x5a6cac2),'sentinel_branch':u(im,0x5a6c960)}
def project(freeze_tag,target,height,period,outer,has_last,last_key,o):
 if freeze_tag==o['freeze_tag']:
  bad=target<height if o['past_branch']==0x82 else target<=height
  if bad:return 'freeze-panic'
  if target==height:return 'skip-freeze'
 if period==0:return 'division-trap'
 if height%period:return 'skip-cadence'
 if outer==o['outer_skip']:return 'skip-outer'
 if not has_last:return 'skip-empty'
 equal=last_key==height if o['last_equal_branch']==0x85 else last_key!=height
 return 'channel-handoff' if equal else 'skip-last-key'
def ring_slot(start,length,capacity):
 x=start+length-1
 verify.require(0<=start<capacity and 0<length<=capacity and x<=MAX,'valid ring premise')
 return x-(capacity if x>=capacity else 0)
def evaluate(data):
 o=operands(data);verify.require(o=={'freeze_tag':1,'past_branch':0x82,'outer_skip':2,'last_equal_branch':0x85,'sentinel_branch':0x81},'notifier operands');n=0
 for flag,target,height,period,outer,present,key in itertools.product([0,1,2],[0,1,2,MAX],[0,1,2,MAX],[0,1,2,3,MAX],[0,1,2,3],[0,1],[0,1,2,MAX]):
  want='freeze-panic' if flag==1 and target<height else 'skip-freeze' if flag==1 and target==height else 'division-trap' if not period else 'skip-cadence' if height%period else 'skip-outer' if outer==2 else 'skip-empty' if not present else 'channel-handoff' if key==height else 'skip-last-key'
  verify.require(project(flag,target,height,period,outer,present,key,o)==want,'notification precedence');n+=1
 for cap in range(1,33):
  for start,length in itertools.product(range(cap),range(1,cap+1)):
   verify.require(ring_slot(start,length,cap)==(start+length-1)%cap,'last circular entry');n+=1
 controls=[changed_relation(data,0x5a6c911,0x86,lambda d:project(1,2,2,1,0,1,2,operands(d))),changed_relation(data,0x5a6c94f,1,lambda d:project(0,0,2,1,2,1,2,operands(d))),changed_relation(data,0x5a6cac2,0x84,lambda d:project(0,0,2,1,0,1,1,operands(d)))]
 return {'native_operands':o,'projection_cases':n,'counterfactuals':controls,'limits':'Nonzero cadence required for normal DIV; zero is recorded as native trap possibility, not reachable configuration proof. Valid tree/ring and no-overflow ring descriptors assumed. Last-key lookup and exact40-byte handoff are bound in native obligations; no channel delivery, scheduling, snapshot or consensus finality claim.'}
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--write',action='store_true');args=p.parse_args()
    data=verify.TARGET.read_bytes();verify.require(verify.sha(data)==verify.DIGEST,'wrong target')
    result=verify.encoded(evaluate(data))
    if args.write:(verify.PACKET/'relations.json').write_text(result)
    else:verify.require((verify.PACKET/'relations.json').read_text()==result,'relations drift')
    print('PASS: native operand relations and counterfactuals')
