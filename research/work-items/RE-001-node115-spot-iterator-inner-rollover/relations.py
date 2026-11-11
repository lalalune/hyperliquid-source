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
 return {'empty':u(im,0x22b3d67),'outer_stride':u(im,0x22b3db5),'index_branch':u(im,0x22b3dcf),'metadata_shift':u(im,0x22b3de2),'fallback_offset':u(im,0x22b3ea4,4),'replace_tag':u(im,0x22b3e5f,4)}
def project(first,active,indices,bound,later,o):
 events=['poll-current'];advanced=0
 if first!=o['empty']:return (events,advanced,'current')
 for index,result in zip(indices,later) if active else []:
  advanced+=o['outer_stride'];events.append('advance')
  rejected=index>=bound if o['index_branch']==0x83 else index>bound
  if rejected:return (events,advanced,'index-panic')
  events.extend(['convert@'+str(index<<o['metadata_shift']),'drop-old','install-'+str(o['replace_tag']),'poll-current'])
  if result!=o['empty']:return(events,advanced,'current')
 events.append('poll-fallback@'+str(o['fallback_offset']))
 return (events,advanced,'fallback')
def evaluate(data):
 o=operands(data);verify.require(o=={'empty':0,'outer_stride':16,'index_branch':0x83,'metadata_shift':5,'fallback_offset':344,'replace_tag':2},'rollover operands');n=0
 for first,active,indices,bound,later in itertools.product([0,1,255],[0,1],[[],[0],[1],[0,1],[0,MAX]],[0,1,2,MAX],itertools.product([0,1],repeat=2)):
  # A separate event oracle states the source-level sequence, not instruction execution.
  events=['poll-current'];advanced=0;route='current'
  if first==0:
   route='fallback'
   for index,result in zip(indices,later) if active else []:
    advanced+=16;events.append('advance')
    if index>=bound:route='index-panic';break
    events.extend(['convert@'+str(index*32),'drop-old','install-2','poll-current'])
    if result:route='current';break
   if route=='fallback':events.append('poll-fallback@344')
  verify.require(project(first,active,indices,bound,later,o)==(events,advanced,route),'rollover ordering');n+=1
 controls=[changed_relation(data,0x22b3db5,8,lambda d:project(0,1,[0],1,[1],operands(d))),changed_relation(data,0x22b3dcf,0x87,lambda d:project(0,1,[1],1,[1],operands(d))),changed_relation(data,0x22b3ea4,0x50,lambda d:project(0,0,[],0,[],operands(d)))]
 return {'native_operands':o,'projection_cases':n,'counterfactuals':controls,'limits':'Valid aligned descriptors and normally returning opaque poll/converter/drop boundaries. Supplied result tags describe observations at calls; this is not an implementation of those helpers. The cursor advances even before a bounds failure. Unwind publication retained in the export, not simulated.'}
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--write',action='store_true');args=p.parse_args()
    data=verify.TARGET.read_bytes();verify.require(verify.sha(data)==verify.DIGEST,'wrong target')
    result=verify.encoded(evaluate(data))
    if args.write:(verify.PACKET/'relations.json').write_text(result)
    else:verify.require((verify.PACKET/'relations.json').read_text()==result,'relations drift')
    print('PASS: native operand relations and counterfactuals')
