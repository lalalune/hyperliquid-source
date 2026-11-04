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
 return {'prefix':(im.get(0x46dbd2e,8)+im.get(0x46dbd40,4)).decode('ascii'),'max_digit':u(im,0x46dbdd2),'divisor_magic':u(im,0x46dbf8c,8),'divisor_shift':u(im,0x46dbf9d),'other_side':u(im,0x46dbfb3),'side_stride':u(im,0x46dbfbc,4),'result_offset':u(im,0x46dc07c),'metadata_error':u(im,0x46dc06c)}
def project(s,lookup_ok,metadata_tag,o):
 if not s.startswith(o['prefix']):return None
 suffix=s[len(o['prefix']):]
 if not suffix or any(ord(x)-48<0 or ord(x)-48>o['max_digit'] for x in suffix):return None
 value=int(suffix)
 if value>(1<<64)-1 or str(value)!=suffix:return None
 quotient=((value*o['divisor_magic'])>>64)>>o['divisor_shift'];side=value-10*quotient
 if side not in (0,o['other_side']) or not lookup_ok or metadata_tag==o['metadata_error']:return None
 return {'query':quotient,'result_field_offset':o['result_offset']+(o['side_stride'] if side else 0)}
def evaluate(data):
 o=operands(data);verify.require(o=={'prefix':'outcomeToken','max_digit':9,'divisor_magic':0xcccccccccccccccd,'divisor_shift':3,'other_side':1,'side_stride':32,'result_offset':24,'metadata_error':1},'symbol operands');cases=[];count=0
 values=list(range(1000))+[10**k+d for k in range(1,19) for d in (-1,0,1)]+[(1<<64)-1-d for d in range(32)]
 for value,lookup,tag in itertools.product(values,[False,True],[0,1]):
  s='outcomeToken'+str(value);r=project(s,lookup,tag,o);q,side=divmod(value,10)
  expected={'query':q,'result_field_offset':24+side*32} if side in (0,1) and lookup and tag==0 else None
  verify.require(r==expected,'quotient side metadata');count+=1
 for suffix in ['', '+0','+1','00','01','-0','-1',' 1','1 ','1.0','1e1','١','18446744073709551616','1\x00']:
  verify.require(project('outcomeToken'+suffix,True,0,o) is None,'noncanonical suffix')
 for value in [0,1,2,10,11,12,100,101,(1<<64)-6]:cases.append({'suffix':str(value),'result':project('outcomeToken'+str(value),True,0,o)})
 controls=[changed_relation(data,0x46dbfb3,2,lambda d:project('outcomeToken1',True,0,operands(d))),changed_relation(data,0x46dbfbc,0x40,lambda d:project('outcomeToken1',True,0,operands(d))),changed_relation(data,0x46dc06c,0,lambda d:project('outcomeToken0',True,0,operands(d)))]
 return {'native_operands':o,'projection_cases':count,'rejected_noncanonical_examples':14,'examples':cases,'counterfactuals':controls,'limits':'Unqualified outcomeToken path only; qualified-name parsing is retained context. Metadata lookup supplied symbolically, no original type names or concrete token IDs inferred. Decimal formatting relation checked against the visible canonical byte comparison, not emulated.'}
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--write',action='store_true');args=p.parse_args()
    data=verify.TARGET.read_bytes();verify.require(verify.sha(data)==verify.DIGEST,'wrong target')
    result=verify.encoded(evaluate(data))
    if args.write:(verify.PACKET/'relations.json').write_text(result)
    else:verify.require((verify.PACKET/'relations.json').read_text()==result,'relations drift')
    print('PASS: native operand relations and counterfactuals')
