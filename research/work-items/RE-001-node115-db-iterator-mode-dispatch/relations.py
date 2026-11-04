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
 return {'mode_one':u(im,0x2a0daa8),'reverse_byte':u(im,0x2a0dad2),'slots':[u(im,a) for a in [0x5d3482c,0x5d3483c,0x5d3486c,0x5d348bc]],'direction_offset':u(im,0x2a0dafe),'initial_flag':u(im,0x2a0db02)}
def project(mode,direction,o):
 index=0 if mode==0 else 1 if mode==o['mode_one'] else 3 if direction==o['reverse_byte'] else 2
 return {'virtual_slot':o['slots'][index],'takes_key':index>=2,'stored_direction':int(index in (1,3)),'initial_flag':o['initial_flag']}
def evaluate(data):
 o=operands(data);verify.require(o=={'mode_one':1,'reverse_byte':1,'slots':[24,32,40,48],'direction_offset':64,'initial_flag':0},'mode operands');examples=[]
 for mode,d in itertools.product(range(3),range(256)):
  r=project(mode,d,o);i=0 if mode==0 else 1 if mode==1 else 3 if d==1 else 2
  verify.require(r=={'virtual_slot':[24,32,40,48][i],'takes_key':mode==2,'stored_direction':int(i in (1,3)),'initial_flag':0},'mode dispatch')
  if d in (0,1,2,255):examples.append({'mode':mode,'direction':d,**r})
 controls=[changed_relation(data,0x2a0daa8,2,lambda d:project(1,0,operands(d))),changed_relation(data,0x2a0dad2,2,lambda d:project(2,1,operands(d))),changed_relation(data,0x5d348bc,0x28,lambda d:project(2,1,operands(d)))]
 return {'native_operands':o,'projection_cases':768,'examples':examples,'counterfactuals':controls,'limits':'Mode0/1/2 supplied; all direction bytes are machine controls, not a claim of valid source enum domain. Virtual targets opaque; no key ordering or live database behavior inferred.'}
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--write',action='store_true');args=p.parse_args()
    data=verify.TARGET.read_bytes();verify.require(verify.sha(data)==verify.DIGEST,'wrong target')
    result=verify.encoded(evaluate(data))
    if args.write:(verify.PACKET/'relations.json').write_text(result)
    else:verify.require((verify.PACKET/'relations.json').read_text()==result,'relations drift')
    print('PASS: native operand relations and counterfactuals')
