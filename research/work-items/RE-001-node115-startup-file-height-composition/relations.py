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
 return {'suffix':im.get(0x459e84,4).decode('ascii'),'minimum_suffix_length':u(im,0x595b749),'plus':u(im,0x595bab9),'max_digit':u(im,0x595baec),'helper_error_mask':u(im,0x595bba6),'carry_select':[u(im,0x595bbb5),u(im,0x595bbb9)]}
def parse(s,o):
 if s.startswith(chr(o['plus'])):s=s[1:]
 if not s or any(not 0<=ord(x)-48<=o['max_digit'] for x in s):return None
 value=int(s);return value if value<(1<<64) else None
def project(s,count,status,o):
 base=parse(s,o)
 if base is None:return ['parse-error']
 if status&o['helper_error_mask']:return ['helper-error',count]
 total=base+count;carry=total>>64
 # Two identical CMOVAE sites in the image; either can restore the sum.
 selected=(1<<64)-1
 for opcode in o['carry_select']:
  if (not carry) if opcode==0x43 else bool(carry):selected=total&((1<<64)-1)
 return ['value',selected]
def choose(strings,o):
 return next((s for s in strings if len(s)<o['minimum_suffix_length'] or not s.endswith(o['suffix'])),None)
def evaluate(data):
 o=operands(data);verify.require(o=={'suffix':'.lz4','minimum_suffix_length':4,'plus':43,'max_digit':9,'helper_error_mask':1,'carry_select':[0x43,0x43]},'startup operands');count=0
 vals=[0,1,9,10,(1<<63)-1,1<<63,(1<<64)-2,(1<<64)-1]
 for base,extra,status,prefix in itertools.product(vals,vals,range(256),['','+','00']):
  s=prefix+str(base);r=project(s,extra,status,o);expected=['helper-error',extra] if status&1 else ['value',min(base+extra,(1<<64)-1)]
  verify.require(r==expected,'saturating composition');count+=1
 for s in ['', '+','-','-0','1.0',' 1','1 ','18446744073709551616']:
  verify.require(parse(s,o) is None,'decimal rejection')
 selections=[]
 for xs in [[],['1.lz4'],['1.lz4','2'],['x.LZ4','2'],['.lz4',''],['2','3']]:
  selections.append({'supplied_iteration':xs,'selected':choose(xs,o)})
 controls=[changed_relation(data,0x459e84,ord('!'),lambda d:choose(['1.lz4','2'],operands(d))),changed_relation(data,0x595baec,8,lambda d:project('9',0,0,operands(d))),changed_relation(data,0x595bba6,2,lambda d:project('1',2,1,operands(d)))]
 return {'native_operands':o,'composition_cases':count,'selection_examples':selections,'counterfactuals':controls,'limits':'Valid unsigned helper count and decimal slice already supplied by opaque path extraction. No directory-order assertion, filesystem access, wc invocation or target execution. Last-entry tree selection assumes valid native tree; ordering semantics unclosed.'}
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--write',action='store_true');args=p.parse_args()
    data=verify.TARGET.read_bytes();verify.require(verify.sha(data)==verify.DIGEST,'wrong target')
    result=verify.encoded(evaluate(data))
    if args.write:(verify.PACKET/'relations.json').write_text(result)
    else:verify.require((verify.PACKET/'relations.json').read_text()==result,'relations drift')
    print('PASS: native operand relations and counterfactuals')
