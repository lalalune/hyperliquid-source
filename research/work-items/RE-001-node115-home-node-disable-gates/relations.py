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
    return {'va':hex(va),'new_byte':new,'original':before,'mutated':after}

def operands(data):
    im=verify.Image(data)
    return {'optional_skip_value':u(im,0x4facb35),'resolver_tag':u(im,0x4facc1e,2),
            'equal_mask':u(im,0x4facc4c,4),'key_bytes':4,'identity_bytes':20}

def route(member,optional_tag,candidates,identity,op):
    if member:return ['four-byte membership',0]
    if optional_tag==op['optional_skip_value']:return ['return',0]
    calls=0
    for tag,value in candidates:
        calls+=1
        if tag==op['resolver_tag'] and value==identity:return ['twenty-byte identity',calls]
    return ['return',calls]

def evaluate(data):
    op=operands(data)
    verify.require(op=={'optional_skip_value':1,'resolver_tag':418,'equal_mask':65535,'key_bytes':4,'identity_bytes':20},'disable operands')
    identity=bytes(range(20));other=identity[:-1]+b'\xff';count=0
    for member,tag in itertools.product((False,True),range(256)):
        for results in [[],[(418,other)],[(417,identity),(418,identity)],[(418,identity),(418,other)]]:
            r=route(member,tag,results,identity,op)
            expected='four-byte membership' if member else 'return' if tag==1 else 'twenty-byte identity' if any(t==418 and x==identity for t,x in results) else 'return'
            verify.require(r[0]==expected,'gate precedence');count+=1
    byte_cases=0
    for index in range(20):
        for replacement in range(256):
            b=bytearray(identity);b[index]=replacement
            # PCMPEQB of sixteen lanes, and MOVD zeroes upper twelve lanes for each tail.
            lanes=[int(identity[j]==b[j]) & (int(identity[j+16]==b[j+16]) if j<4 else 1) for j in range(16)]
            mask=sum(x<<j for j,x in enumerate(lanes))
            verify.require((mask==op['equal_mask'])==(identity==b),'twenty-byte SIMD equality');byte_cases+=1
    keys=[bytes.fromhex(x) for x in ['00000000','00000001','00000100','01000000','7fffffff','80000000','ffffffff']]
    for a,b in itertools.product(keys,repeat=2):verify.require((int.from_bytes(a,'big')<int.from_bytes(b,'big'))==(a<b),'four-byte bswap order')
    controls=[changed_relation(data,0x4facb35,0,lambda d:route(False,1,[(418,identity)],identity,operands(d))),
              changed_relation(data,0x4facc1e,0xa3,lambda d:route(False,0,[(418,identity)],identity,operands(d))),
              changed_relation(data,0x4facc4c,0xfe,lambda d:65535==operands(d)['equal_mask'])]
    return {'native_operands':op,'gate_cases':count,'simd_byte_cases':byte_cases,'key_order_cases':len(keys)**2,'counterfactuals':controls,
            'limits':'Membership outcome and resolver results are supplied boundary facts. Byte ordering and twenty-byte comparison are local algebra, not execution. Tree/iterator validity, resolver meaning, formatted diagnostic helper effects and process termination are unproved.'}

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--write',action='store_true');args=p.parse_args()
    data=verify.TARGET.read_bytes();verify.require(verify.sha(data)==verify.DIGEST,'wrong target')
    result=verify.encoded(evaluate(data))
    if args.write:(verify.PACKET/'relations.json').write_text(result)
    else:verify.require((verify.PACKET/'relations.json').read_text()==result,'relations drift')
    print('PASS: native operand relations and counterfactuals')
