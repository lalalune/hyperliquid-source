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
 return {'miss_tag':u(im,0x2969f21),'minimum_count':u(im,0x296a23b),'expiry_parameter':u(im,0x296a147,4),'last_compare':u(im,0x296a244),'retain_branch':u(im,0x296a288)}
def project(tag,count,expiry,now,same_date,same_class,o):
 if tag==o['miss_tag']:return ('refresh',0)
 future=expiry>now if o['last_compare']==0x87 else expiry>=now
 if count>=o['minimum_count'] and future:return ('reuse',count)
 same=same_class if o['retain_branch']==0x44 else not same_class
 return ('refresh',count if same_date and same else 0)
def evaluate(data):
 o=operands(data);verify.require(o=={'miss_tag':5,'minimum_count':61,'expiry_parameter':120,'last_compare':0x87,'retain_branch':0x44},'role operands');n=0
 # Valid raw role tags are supplied; dates are triples after the opaque conversion.
 dates=[(-1,0,0),(0,0,0),(0,0,1),(0,1,0),(1,0,0)]
 for tag,count,exp,now,day,cl in itertools.product(range(6),[0,1,60,61,62,(1<<64)-1],dates,dates,[False,True],[False,True]):
  got=project(tag,count,exp,now,day,cl,o)
  want=('refresh',0) if tag==5 else ('reuse',count) if count>60 and exp>now else ('refresh',count if day and cl else 0)
  verify.require(got==want,'role freshness');n+=1
 controls=[changed_relation(data,0x296a23b,60,lambda d:project(0,60,(1,0,0),(0,0,0),False,False,operands(d))),changed_relation(data,0x296a244,0x83,lambda d:project(0,61,(0,0,0),(0,0,0),False,False,operands(d))),changed_relation(data,0x296a288,0x45,lambda d:project(0,12,(0,0,0),(0,0,1),True,True,operands(d)))]
 return {'native_operands':o,'projection_cases':n,'counterfactuals':controls,'limits':'Expiry triple is the post-conversion value, including the observed fallback triple. Signed first dword and unsigned tie-break dwords are represented by valid triples. Calendar conversion, 120 parameter units, classification helper and cache selection/update are not reconstructed. No target execution.'}
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--write',action='store_true');args=p.parse_args()
    data=verify.TARGET.read_bytes();verify.require(verify.sha(data)==verify.DIGEST,'wrong target')
    result=verify.encoded(evaluate(data))
    if args.write:(verify.PACKET/'relations.json').write_text(result)
    else:verify.require((verify.PACKET/'relations.json').read_text()==result,'relations drift')
    print('PASS: native operand relations and counterfactuals')
