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
 return {'row_tag':u(im,0x294d75c),'row_stride':u(im,0x294d754),'mean_modrm':u(im,0x294d7c7),'max_condition':u(im,0x294d81c),'limit':u(im,0x294d829,8),'limit_compare':u(im,0x294d835)}
def project(a,b,lower,qty,o):
 if not a or not b:return('missing-quote',None)
 mean=((a&b)+((a^b)>>1 if o['mean_modrm']==0xe8 else ((a^b)<<1)&MAX))&MAX
 if not mean:return('missing-quote',None)
 price=(lower if lower>mean else mean) if o['max_condition']==0x47 else (lower if lower<mean else mean)
 product=price*qty;low=product&MAX
 over=low>o['limit'] if o['limit_compare']==0x97 else low>=o['limit']
 return ('product-error',None) if product>MAX or over else ('value',low)
def evaluate(data):
 o=operands(data);verify.require(o=={'row_tag':1,'row_stride':72,'mean_modrm':0xe8,'max_condition':0x47,'limit':(1<<63)-2,'limit_compare':0x97},'quote operands');n=0
 values=[0,1,2,3,(1<<32)-1,1<<32,(1<<63)-2,(1<<63)-1,1<<63,MAX]
 for a,b,lo,qty in itertools.product(values,values,[0,1,3,(1<<63)-2,MAX],[0,1,2,3,MAX]):
  product=max((a+b)//2,lo)*qty
  want=('missing-quote',None) if not a or not b else ('value',product) if product<=(1<<63)-2 else ('product-error',None)
  verify.require(project(a,b,lo,qty,o)==want,'midpoint and exact product');n+=1
 controls=[changed_relation(data,0x294d7c7,0xe0,lambda d:project(1,7,0,1,operands(d))),changed_relation(data,0x294d81c,0x42,lambda d:project(2,4,7,1,operands(d))),changed_relation(data,0x294d835,0x93,lambda d:project((1<<63)-2,(1<<63)-2,0,1,operands(d)))]
 return {'native_operands':o,'projection_cases':n,'counterfactuals':controls,'limits':'Nonzero quote pair comes from opaque helper0x22f6860. The new contract is the iterator consumer, not that helper or the older market-order builder. Economic types/units unknown. Raw tags and failure payload bytes are qualified separately in README. No original code execution or emulation.'}
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--write',action='store_true');args=p.parse_args()
    data=verify.TARGET.read_bytes();verify.require(verify.sha(data)==verify.DIGEST,'wrong target')
    result=verify.encoded(evaluate(data))
    if args.write:(verify.PACKET/'relations.json').write_text(result)
    else:verify.require((verify.PACKET/'relations.json').read_text()==result,'relations drift')
    print('PASS: native operand relations and counterfactuals')
