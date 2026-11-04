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
 return {'targets':[0x6012b4+x for x in struct.unpack('<6i',im.get(0x6012b4,24))],'join_pending':u(im,0x2a1937f),'reader_pending':u(im,0x2a0c09e),'outer_pending':u(im,0x2a0c0a4,4),'no_read_tag':u(im,0x2a0c267,4),'error_tag':u(im,0x2a0c15e,4),'error_code':u(im,0x2a0c178)}
def project(selector,captured,explicit,o):
 target=o['targets'][selector]
 if target==0x2a0c265:return ('no-read',o['no_read_tag'])
 if target==0x2a0bfb5:return ('read',0)
 if target==0x2a0c006:return ('read',explicit)
 verify.require(target==0x2a0bfb7,'unknown selector edge');return ('read',captured)
def evaluate(data):
 o=operands(data);verify.require(o=={'targets':[0x2a0bfb7]*3+[0x2a0bfb5,0x2a0c265,0x2a0c006],'join_pending':4,'reader_pending':3,'outer_pending':4,'no_read_tag':2,'error_tag':3,'error_code':0x27},'block selector operands');n=0
 for s,c,e in itertools.product(range(6),[0,1,2,(1<<64)-1],[0,1,2,(1<<64)-1]):
  want=('no-read',2) if s==4 else ('read',0 if s==3 else e if s==5 else c)
  verify.require(project(s,c,e,o)==want,'height lowering');n+=1
 controls=[changed_relation(data,0x6012b4,1,lambda d:operands(d)['targets'][0]),changed_relation(data,0x2a0c267,3,lambda d:project(4,0,0,operands(d))),changed_relation(data,0x2a0c0a4,3,lambda d:operands(d)['outer_pending'])]
 return {'native_operands':o,'projection_cases':n,'counterfactuals':controls,'limits':'Valid raw selector0..5, captured height and explicit qword supplied; public enum variant names are unresolved. Relative table edges authenticated separately. Nested pending4->3->4 and error3->2->3/0x27 are tag translations, not scheduler or disk behavior. Other output payload bytes are not asserted initialized for absent/error variants.'}
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--write',action='store_true');args=p.parse_args()
    data=verify.TARGET.read_bytes();verify.require(verify.sha(data)==verify.DIGEST,'wrong target')
    result=verify.encoded(evaluate(data))
    if args.write:(verify.PACKET/'relations.json').write_text(result)
    else:verify.require((verify.PACKET/'relations.json').read_text()==result,'relations drift')
    print('PASS: native operand relations and counterfactuals')
