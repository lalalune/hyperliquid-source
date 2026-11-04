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
 return {'bypass_tag':u(im,0x5a6cfcc),'query_skip_branch':u(im,0x5a6d03a),'optional_mask':u(im,0x5a6d05d),'ip_shift':u(im,0x5a6d067),'allocation':u(im,0x5a6d0d4,4)}
def project(tag,query,packed,o):
 queried=tag!=o['bypass_tag']
 skip=bool(query) if o['query_skip_branch']==0x74 else not query
 if queried and skip:return(queried,'consume-no-worker',None)
 if not packed&o['optional_mask']:return(queried,'missing-ip-fatal',None)
 return(queried,'launch',(packed>>o['ip_shift'])&0xffffffff)
def evaluate(data):
 o=operands(data);verify.require(o=={'bypass_tag':1,'query_skip_branch':0x74,'optional_mask':1,'ip_shift':8,'allocation':288},'launch operands');n=0
 for tag,q,flag,ip in itertools.product([0,1,2,255],range(256),[0,1,2,3,254,255],[0,1,0x7f000001,0xffffffff]):
  packed=(0xabcdef<<40)|(ip<<8)|flag
  want=(tag!=1,'consume-no-worker',None) if tag!=1 and q else (tag!=1,'launch',ip) if flag&1 else (tag!=1,'missing-ip-fatal',None)
  verify.require(project(tag,q,packed,o)==want,'launch precedence');n+=1
 controls=[changed_relation(data,0x5a6cfcc,0,lambda d:project(1,1,0,operands(d))),changed_relation(data,0x5a6d05d,2,lambda d:project(1,0,1,operands(d))),changed_relation(data,0x5a6d067,16,lambda d:project(1,0,0x1234567801,operands(d)))]
 return {'native_operands':o,'projection_cases':n,'counterfactuals':controls,'limits':'is_main_signer is the observed operation label, not recovered query implementation. The packed address is a raw DWORD; no host/network-order label or public enum names. Spawn allocation/request is established, not successful worker execution or runtime effect. Other copied bytes include inactive payload and are not claimed initialized.'}
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--write',action='store_true');args=p.parse_args()
    data=verify.TARGET.read_bytes();verify.require(verify.sha(data)==verify.DIGEST,'wrong target')
    result=verify.encoded(evaluate(data))
    if args.write:(verify.PACKET/'relations.json').write_text(result)
    else:verify.require((verify.PACKET/'relations.json').read_text()==result,'relations drift')
    print('PASS: native operand relations and counterfactuals')
