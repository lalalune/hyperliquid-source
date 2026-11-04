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
 return {'multiplier':u(im,0x5a70676,8),'rotate':u(im,0x5a70686),'bound':u(im,0x5a70689,8),'owner_tag':u(im,0x5a706af),'request_tag':u(im,0x5a706b4),'report_minimum':u(im,0x5a70aa5)}
def project(counter,owner,request,result,o):
 x=counter*o['multiplier']&MAX;r=o['rotate'];rot=((x>>r)|(x<<(64-r)))&MAX
 admitted=rot<=o['bound'] and owner==o['owner_tag'] and request==o['request_tag']
 return (admitted,admitted and result>=o['report_minimum'])
def evaluate(data):
 o=operands(data);verify.require(o=={'multiplier':0xd288ce703afb7e91,'rotate':4,'bound':0x68db8bac710cb,'owner_tag':3,'request_tag':0,'report_minimum':2},'firewall cadence operands')
 verify.require((o['multiplier']*625)&MAX==1 and o['bound']==MAX//10000,'modular inverse proof constants')
 # 625 is odd; multiplication is bijective mod2^64. Rotation places the
 # required four low zero bits at the top. Accepted rotated values0..floor(MAX/10000)
 # map bijectively back to counter=10000*q, proving the predicate over all u64.
 values=[0,1,9999,10000,10001,MAX-1,MAX,MAX//10000*10000]
 state=0x123456789abcdef
 for _ in range(256):state=(state*6364136223846793005+1)&MAX;values.extend([state,(state//10000)*10000])
 n=0
 for c,a,b,z in itertools.product(values,[0,2,3,4,255],[0,1,255],[0,1,2,3,MAX]):
  yes=c%10000==0 and a==3 and b==0;verify.require(project(c,a,b,z,o)==(yes,yes and z>=2),'cadence conjunction');n+=1
 controls=[changed_relation(data,0x5a70686,3,lambda d:project(MAX//10000*10000,3,0,2,operands(d))),changed_relation(data,0x5a706af,2,lambda d:project(10000,3,0,2,operands(d))),changed_relation(data,0x5a70aa5,3,lambda d:project(10000,3,0,2,operands(d)))]
 return {'native_operands':o,'projection_cases':n,'counterfactuals':controls,'limits':'Counter is raw owner+0x28; its epoch/unit and update site are unclosed. The final scalar is supplied from the collection helper result. No set-operation semantics or firewall/network execution is claimed.'}
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--write',action='store_true');args=p.parse_args()
    data=verify.TARGET.read_bytes();verify.require(verify.sha(data)==verify.DIGEST,'wrong target')
    result=verify.encoded(evaluate(data))
    if args.write:(verify.PACKET/'relations.json').write_text(result)
    else:verify.require((verify.PACKET/'relations.json').read_text()==result,'relations drift')
    print('PASS: native operand relations and counterfactuals')
