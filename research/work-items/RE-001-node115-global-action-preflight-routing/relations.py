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
 return {'chain_table':u(im,0x54ccf38),'lookup_xor':u(im,0x54ccf9c),'resolver_success':u(im,0x54ccfc7,2),'base':u(im,0x54cd009),'special':[u(im,a) for a in [0x54cd020,0x54cd02a,0x54cd128]],'conditional':u(im,0x54cd11e),'conditional_byte':u(im,0x54cd219),'handler_done':u(im,0x54cd10a,4),'rejection':u(im,0x54cd207,2),'fallback_success':u(im,0x54cd2a6,2)}
def project(chain,table_present,lookup_tag,resolver_tag,action,flag,handler_tag,fallback_tag,o):
 table='A' if chain==o['chain_table'] else 'B';allow=(lookup_tag^o['lookup_xor']) if table_present else 0
 if resolver_tag!=o['resolver_success'] and not allow:return {'table':table,'route':'reject','output':o['rejection']}
 delta=action-o['base'];special=delta in o['special'] or delta==o['conditional'] and flag==o['conditional_byte']
 result=['accepted',0] if handler_tag==o['handler_done'] else ['accepted',1] if fallback_tag==o['fallback_success'] else ['forward fallback error']
 return {'table':table,'route':'special' if special else 'ordinary','output':result,'resolver_payload_present':resolver_tag==o['resolver_success']}
def evaluate(data):
 o=operands(data);verify.require(o=={'chain_table':3,'lookup_xor':1,'resolver_success':418,'base':20,'special':[10,31,84],'conditional':73,'conditional_byte':1,'handler_done':134,'rejection':149,'fallback_success':418},'preflight operands');count=0;examples=[]
 for present,lookup,resolver,action,flag in itertools.product([0,1],[0,1],[0,418],range(256),[0,1,2,255]):
  r=project(3,present,lookup,resolver,action,flag,134,0,o);allow=resolver==418 or present and lookup==0
  expected='reject' if not allow else 'special' if action in (30,51,104) or action==93 and flag==1 else 'ordinary'
  verify.require(r['route']==expected,'admission and routing');count+=1
 for chain,handler,fall in itertools.product(range(256),[0,134,255],[0,418]):
  r=project(chain,0,1,418,30,0,handler,fall,o);verify.require(r['table']==('A' if chain==3 else 'B'),'chain table')
  verify.require(r['output']==(['accepted',0] if handler==134 else ['accepted',1] if fall==418 else ['forward fallback error']),'result continuation')
 for a in [0,19,20,29,30,31,51,92,93,94,104,255]:examples.append({'action':a,'flag0':project(3,0,1,418,a,0,134,0,o),'flag1':project(3,0,1,418,a,1,134,0,o)})
 controls=[changed_relation(data,0x54ccf9c,0,lambda d:project(3,1,0,0,30,0,134,0,operands(d))),changed_relation(data,0x54cd219,2,lambda d:project(3,0,1,418,93,1,134,0,operands(d))),changed_relation(data,0x54cd10a,135,lambda d:project(3,0,1,418,30,0,134,0,operands(d)))]
 return {'native_operands':o,'admission_route_cases':count,'chain_result_cases':1536,'examples':examples,'counterfactuals':controls,'limits':'Raw selector0..255 as machine controls, not a valid source enum claim. Table and resolver outcomes supplied; opaque dispatchers and fallback effects not executed. No authentication policy or action-name assignment.'}
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--write',action='store_true');args=p.parse_args()
    data=verify.TARGET.read_bytes();verify.require(verify.sha(data)==verify.DIGEST,'wrong target')
    result=verify.encoded(evaluate(data))
    if args.write:(verify.PACKET/'relations.json').write_text(result)
    else:verify.require((verify.PACKET/'relations.json').read_text()==result,'relations drift')
    print('PASS: native operand relations and counterfactuals')
