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

import math

def operands(data):
    im=verify.Image(data)
    return {'abs_mask':u(im,0x5a79593,8),'finite_limit':u(im,0x5a795a0,8),
            'admit':u(im,0x5a795b2),'skip_branch':u(im,0x5a795de),
            'delay_bits':u(im,0x5a7969b,8),'commit':u(im,0x5a7968b,4)}

def project(bits,flag,threshold,closed,op):
    finite=(bits&op['abs_mask'])<op['finite_limit']
    if (int(finite)&flag)!=op['admit']:return (False,False,False)
    value=struct.unpack('<d',bits.to_bytes(8,'little'))[0]
    skip=math.isnan(threshold) or math.isnan(value) or threshold<value
    if op['skip_branch']==0x86:skip=skip or threshold==value
    elif op['skip_branch']!=0x82:raise ValueError('unsupported branch')
    return (False,False,False) if skip else (True,not closed,bool(op['commit']))

def evaluate(data):
    op=operands(data)
    verify.require(op=={'abs_mask':(1<<63)-1,'finite_limit':0x7ff0000000000000,'admit':1,'skip_branch':0x86,'delay_bits':0x4014000000000000,'commit':1},'override operands')
    bits=[0,1,0x8000000000000000,0x8000000000000001,0x3fe0000000000000,0x3ff0000000000000,0xbff0000000000000,0x7fefffffffffffff,0xffefffffffffffff,0x7ff0000000000000,0xfff0000000000000,0x7ff8000000000000,0xfff8000000000001]
    cases=0
    for raw,flag,threshold,closed in itertools.product(bits,range(256),[-math.inf,-1.,-0.,0.5,1.,math.inf,math.nan],[False,True]):
        value=struct.unpack('<d',raw.to_bytes(8,'little'))[0]
        admitted=math.isfinite(value) and bool(flag&1) and value<threshold
        verify.require(project(raw,flag,threshold,closed,op)==(admitted,admitted and not closed,admitted),'finite strict decrease');cases+=1
    controls=[changed_relation(data,0x5a795b2,0,lambda d:project(0,0,1.,False,operands(d))),
              changed_relation(data,0x5a795de,0x82,lambda d:project(0,1,0.,False,operands(d))),
              changed_relation(data,0x5a7968b,0,lambda d:project(0,1,1.,True,operands(d)))]
    return {'native_operands':op,'projection_cases':cases,'counterfactuals':controls,
            'limits':'Safe live state, supplied query result and threshold, normally returning helpers. Default table index validity, queue internals and scheduling are not modeled. Closed delivery still commits an accepted new threshold. No target execution or emulation.'}
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--write',action='store_true');args=p.parse_args()
    data=verify.TARGET.read_bytes();verify.require(verify.sha(data)==verify.DIGEST,'wrong target')
    result=verify.encoded(evaluate(data))
    if args.write:(verify.PACKET/'relations.json').write_text(result)
    else:verify.require((verify.PACKET/'relations.json').read_text()==result,'relations drift')
    print('PASS: native operand relations and counterfactuals')
