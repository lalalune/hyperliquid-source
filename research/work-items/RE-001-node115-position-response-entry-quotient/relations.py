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
 return {'zero_size_tag':u(im,0x2c7fdc0,4),'decimal_bound':u(im,0x2c800aa),'exponent_base':u(im,0x2c800b2,4),'divisors':list(struct.unpack('<7d',im.get(0x5ed748,56)))}
def project(size,entry,dec,o):
 if size==0:return (o['zero_size_tag'],None)
 if entry==0 or entry<abs(size):return (0,None)
 if dec>=o['decimal_bound']:return ('fatal-decimal',None)
 q=entry//abs(size)
 return (1,float(q)/o['divisors'][o['exponent_base']-dec])
def evaluate(data):
 o=operands(data);verify.require(o['zero_size_tag']==2 and o['decimal_bound']==7 and o['exponent_base']==6,'position operands');verify.require(o['divisors']==[10.**i for i in range(7)],'decimal table');n=0
 for s,e,dec in itertools.product([-(1<<63),-10,-3,-1,0,1,3,10,(1<<63)-1],[0,1,2,3,9,10,11,(1<<63)-1],range(8)):
  want=(2,None) if s==0 else (0,None) if e<abs(s) else ('fatal-decimal',None) if dec>=7 else (1,float(e//abs(s))/(10**(6-dec)))
  verify.require(project(s,e,dec,o)==want,'integer quotient before decimal scaling');n+=1
 controls=[changed_relation(data,0x2c7fdc0,1,lambda d:project(0,10,1,operands(d))),changed_relation(data,0x2c800aa,6,lambda d:project(3,10,6,operands(d))),changed_relation(data,0x2c800b2,5,lambda d:project(3,10,3,operands(d)))]
 return {'native_operands':o,'projection_cases':n,'counterfactuals':controls,'limits':'Valid selected asset row, nonnegative signed entry value, valid size and normally returning helpers are supplied. Relations reconstruct the optional quotient only, not financial valuation or all output fields. Default host binary64 conversion is used for the local formula; no target execution.'}
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--write',action='store_true');args=p.parse_args()
    data=verify.TARGET.read_bytes();verify.require(verify.sha(data)==verify.DIGEST,'wrong target')
    result=verify.encoded(evaluate(data))
    if args.write:(verify.PACKET/'relations.json').write_text(result)
    else:verify.require((verify.PACKET/'relations.json').read_text()==result,'relations drift')
    print('PASS: native operand relations and counterfactuals')
