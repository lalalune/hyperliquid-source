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



MIN=1<<63
def operands(data):
 im=verify.Image(data)
 return {'sentinel':u(im,0x2e1ae25,8),'down_threshold':u(im,0x2e1ae36),'down_compare':u(im,0x2e1ae38),'up_last':u(im,0x2e1b02d),'lookup_branch':u(im,0x2e1b024)}
def project(marker,count,lookup,o):
 down=count<o['down_threshold'] if o['down_compare']==0x92 else count<=o['down_threshold']
 if marker==o['sentinel']:return 'downsize' if down else 'retain-A'
 lookup_yes=bool(lookup) if o['lookup_branch']==0x74 else not lookup
 return 'upsize' if lookup_yes and count>o['up_last'] else 'retain-B'
def evaluate(data):
 o=operands(data);verify.require(o=={'sentinel':MIN,'down_threshold':32,'down_compare':0x92,'up_last':63,'lookup_branch':0x74},'registry thresholds');n=0
 for marker,count,lookup in itertools.product([0,1,MIN,MIN+1],[0,1,30,31,32,33,62,63,64,65,(1<<64)-1],[0,1,2,(1<<64)-1]):
  want=('downsize' if count<32 else 'retain-A') if marker==MIN else ('upsize' if lookup and count>=64 else 'retain-B')
  verify.require(project(marker,count,lookup,o)==want,'registry hysteresis');n+=1
 controls=[changed_relation(data,0x2e1ae36,31,lambda d:project(MIN,31,1,operands(d))),changed_relation(data,0x2e1b02d,64,lambda d:project(0,64,1,operands(d))),changed_relation(data,0x2e1b024,0x75,lambda d:project(0,64,0,operands(d)))]
 return {'native_operands':o,'projection_cases':n,'counterfactuals':controls,'limits':'Each test starts at one native representation decision with supplied valid descriptor/count and lookup status. Converter-produced counts are not assumed unchanged, so the two decisions are not spuriously composed. A/B names are representation markers, not proved public container types. Full add_tx admission and helper algorithms remain opaque.'}
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--write',action='store_true');args=p.parse_args()
    data=verify.TARGET.read_bytes();verify.require(verify.sha(data)==verify.DIGEST,'wrong target')
    result=verify.encoded(evaluate(data))
    if args.write:(verify.PACKET/'relations.json').write_text(result)
    else:verify.require((verify.PACKET/'relations.json').read_text()==result,'relations drift')
    print('PASS: native operand relations and counterfactuals')
