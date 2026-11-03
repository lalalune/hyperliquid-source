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
    return {'bound':u(im,0x2cde1fc,4),'pending':u(im,0x2cde256),
            'first_mask':u(im,0x2cde3b9),'payload_bytes':u(im,0x2cde3ab,4),
            'no_enabled':u(im,0x2cde3f3,4),'pending_result':u(im,0x2cde3fc,4),
            'shift':u(im,0x5ce2120)}

def choose(seed,mask,results,op):
    polled=[]
    for step in range(3):
        index=(seed+step)%3
        if mask & (1<<index):continue
        polled.append(index)
        if results[index]!=op['pending']:
            bit=op['first_mask'] if index==0 else 1<<index
            return {'tag':index,'mask':mask|bit,'polled':polled,'copy':op['payload_bytes']}
    return {'tag':op['pending_result'] if polled else op['no_enabled'],'mask':mask,'polled':polled,'copy':0}

def evaluate(data):
    op=operands(data)
    verify.require(op=={'bound':3,'pending':2,'first_mask':1,'payload_bytes':184,'no_enabled':3,'pending_result':4,'shift':32},'selector operands')
    count=0
    for seed in range(3):
        for mask in range(256):
            for results in itertools.product(range(4),repeat=3):
                order=[(seed+j)%3 for j in range(3) if not mask&(1<<((seed+j)%3))]
                ready=next((j for j in order if results[j]!=2),None)
                prefix=order if ready is None else order[:order.index(ready)+1]
                expected={'tag':(4 if order else 3) if ready is None else ready,
                          'mask':mask if ready is None else mask|(1<<ready),
                          'polled':prefix,'copy':0 if ready is None else 184}
                verify.require(choose(seed,mask,results,op)==expected,'ordered choice');count+=1
    seeds=[]
    for word in [0,1,0x55555555,0x55555556,0xaaaaaaaa,0xaaaaaaab,0xffffffff]:
        value=(word*op['bound'])>>op['shift'];verify.require(0<=value<3,'seed range')
        seeds.append({'word':hex(word),'seed':value})
    controls=[changed_relation(data,0x2cde256,3,lambda d:choose(0,0,(2,0,0),operands(d))),
              changed_relation(data,0x2cde3b9,2,lambda d:choose(0,0,(0,2,2),operands(d))),
              changed_relation(data,0x2cde1fc,2,lambda d:(0xffffffff*operands(d)['bound'])>>operands(d)['shift'])]
    return {'native_operands':op,'choice_cases':count,'seed_boundaries':seeds,'counterfactuals':controls,
            'proof':'The seed helper forms a u32 sum x, then returns (x*3)>>32. For 0<=x<2^32 this is 0,1,2. Therefore seed+2 cannot overflow, all three residues are visited once, and the seed==-2 trap is unreachable on this normal helper-return path.',
            'limits':'Valid descriptor/mask and normally returning queue helpers. Pending=2 is the selected helper output word only. No queue payload interpretation, original Rust ABI, entropy/uniformity/fairness or runtime progress claim.'}

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--write',action='store_true');args=p.parse_args()
    data=verify.TARGET.read_bytes();verify.require(verify.sha(data)==verify.DIGEST,'wrong target')
    result=verify.encoded(evaluate(data))
    if args.write:(verify.PACKET/'relations.json').write_text(result)
    else:verify.require((verify.PACKET/'relations.json').read_text()==result,'relations drift')
    print('PASS: native operand relations and counterfactuals')
