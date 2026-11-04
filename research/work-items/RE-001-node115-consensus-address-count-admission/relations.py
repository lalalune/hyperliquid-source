#!/usr/bin/env python3
"""Check the address/count admission projection against native operands."""
import argparse
import itertools
import json
import verify
MAX=(1<<64)-1

def operands(data):
    image=verify.Image(data)
    read=lambda a,n=1:int.from_bytes(image.get(a,n),'little')
    return {'loopback_word':read(0x29f7437,4),'count_limit':read(0x29f7447),
            'variant_mask':read(0x29f738e),'saturation_condition':read(0x29f74ff)}

def projected(variant,projected_address,count,o):
    reject=count>=o['count_limit'] and bool((int(projected_address!=o['loopback_word'])|variant)&o['variant_mask'])
    if reject:return {'admitted':False,'count':count,'events':['unlock','cleanup']}
    incremented=(count+1)&MAX
    selected=(incremented!=0) if o['saturation_condition']==0x45 else (incremented==0)
    result=incremented if selected else MAX
    return {'admitted':True,'count':result,'events':['store_count','unlock','spawn']}

def evaluate(data):
    o=operands(data)
    verify.require(o=={'loopback_word':0x0100007f,'count_limit':2,'variant_mask':1,'saturation_condition':0x45},'native admission operands')
    admission_cases=0
    for variant,address,count in itertools.product(range(256),(0,0x0100007f,0x0200007f,0x0100007e,0xffffffff),(0,1,2,3,MAX-1,MAX)):
        actual=projected(variant,address,count,o)
        exempt=(variant%2==0 and address==0x0100007f)
        accepted=(count<2 or exempt)
        verify.require(actual['admitted']==accepted,'independent admission predicate')
        verify.require(actual['count']==(min(MAX,count+1) if accepted else count),'count store relation')
        verify.require(actual['events']==(['store_count','unlock','spawn'] if accepted else ['unlock','cleanup']),'store-before-handoff')
        admission_cases+=1
    saturation_cases=0
    for count in list(range(1025))+[MAX-2,MAX-1,MAX]:
        actual=projected(0,0x0100007f,count,o)
        verify.require(actual['count']==min(MAX,count+1),'saturating increment boundary')
        saturation_cases+=1
    counterfactuals=[]
    for va,byte,args in [(0x29f7447,3,(0,0,2)),(0x29f7437,0x7e,(0,0x0100007f,2)),(0x29f74ff,0x44,(0,0x0100007f,MAX))]:
        changed=bytearray(data);changed[verify.Image(data).off(va)]=byte
        before=projected(*args,o);after=projected(*args,operands(changed))
        verify.require(before!=after,'counterfactual survived')
        counterfactuals.append({'va':hex(va),'byte':byte,'inputs':args,'before':before,'after':after})
    return json.loads(verify.encoded({'native_operands':o,'admission_cases':admission_cases,'saturation_cases':saturation_cases,
        'counterfactuals':counterfactuals,'limits':'The count pointer is supplied by opaque entry helpers, and the address word is the worker’s projected word after variant processing. Key equality, global per-IP limits, lifecycle decrements, lock correctness, allocation failures and actual task execution are not proved. No captured instructions are executed or emulated.'}))

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--write',action='store_true');args=parser.parse_args()
    data=verify.TARGET.read_bytes();verify.require(verify.sha(data)==verify.DIGEST,'wrong target')
    result=verify.encoded(evaluate(data))
    if args.write:(verify.PACKET/'relations.json').write_text(result)
    else:verify.require((verify.PACKET/'relations.json').read_text()==result,'relations drift')
    print('PASS: address/count admission and three operand counterfactuals')
