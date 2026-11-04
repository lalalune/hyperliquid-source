#!/usr/bin/env python3
"""Check bounded attempt selection from native operands, without target execution."""
import argparse
import itertools
import json
import math
import struct
import verify
U64_MAX=(1<<64)-1

def read(data,va,size=1,signed=False):
    return int.from_bytes(verify.Image(data).get(va,size),'little',signed=signed)

def operands(data):
    image=verify.Image(data)
    return {'coefficients':[None,struct.unpack('<d',image.get(0x2bb535e,8))[0],struct.unpack('<d',image.get(0x2bb537c,8))[0]],
            'attempt_count':read(data,0x2bb59f5),'retry_subtract':-read(data,0x2bb59e4,1,True),
            'retry_unsigned_threshold':read(data,0x2bb59e8,1,True)&U64_MAX,
            'unresolved_tag':read(data,0x2bb67f1),'normalized_tag':read(data,0x2bb67f9,4),
            'normalized_error':read(data,0x2bb67f6)}

def quantity(base,coefficient):
    if coefficient is None:return base
    if not 0.0<=coefficient<=1.0:return 'coefficient error'
    product=float(base)*coefficient
    if not math.isfinite(product):product=0.0
    return min(U64_MAX,max(0,int(min(float(1<<64),max(0.0,product)))))

def projected(mode,provided,helper_bases,tags,o):
    attempts=[]
    for index in range(o['attempt_count']):
        helper_called=(mode&255)==0
        base=helper_bases[index] if helper_called else provided
        value=quantity(base,o['coefficients'][index])
        tag=tags[index]
        attempts.append({'index':index,'helper_called':helper_called,'base':base,'quantity':value,'tag':tag})
        retry=((tag-o['retry_subtract'])&U64_MAX)>=o['retry_unsigned_threshold']
        if mode!=0 or not retry:break
    last=attempts[-1]['tag']
    return {'attempts':attempts,'final_tag':o['normalized_tag'] if last==o['unresolved_tag'] else last,
            'final_error':o['normalized_error'] if last==o['unresolved_tag'] else 'latest payload'}

def evaluate(data):
    o=operands(data)
    verify.require(o=={'coefficients':[None,0.99,0.9],'attempt_count':3,'retry_subtract':5,
                      'retry_unsigned_threshold':U64_MAX-1,'unresolved_tag':4,'normalized_tag':3,'normalized_error':5},'native attempt operands')
    retry_cases=0
    for tag in list(range(256))+[U64_MAX-1,U64_MAX]:
        actual=((tag-o['retry_subtract'])&U64_MAX)>=o['retry_unsigned_threshold']
        verify.require(actual==(tag in (3,4)),'exact unsigned retry set');retry_cases+=1
    selection_cases=0
    for mode in (0,1,255,256,1<<63):
        for tags in itertools.product((0,1,2,3,4,5,U64_MAX),repeat=3):
            actual=projected(mode,12345,[10000,20000,30000],tags,o)
            count=1
            if mode==0:
                while count<3 and tags[count-1] in (3,4):count+=1
            verify.require(len(actual['attempts'])==count,'independent bounded stop index')
            verify.require(actual['attempts'][-1]['tag']==tags[count-1],'latest rather than best result')
            for i,a in enumerate(actual['attempts']):
                verify.require(a['helper_called']==((mode&255)==0),'byte-wide helper selector')
                verify.require(a['base']==([10000,20000,30000][i] if (mode&255)==0 else 12345),'fresh source each attempt')
            selection_cases+=1
    examples=[]
    for mode,tags in [(0,[3,3,0]),(0,[4,4,4]),(0,[0,3,3]),(1,[3,3,0]),(256,[3,3,0])]:
        examples.append({'mode':mode,'tags':tags,'result':projected(mode,12345,[10000,20000,30000],tags,o)})
    verify.require([x['quantity'] for x in examples[0]['result']['attempts']]==[10000,19800,27000],'noncompounded percentages')
    quantity_cases=0
    for base,coefficient,expected in [(0,None,0),(1000,None,1000),(1000,0.99,990),(1000,0.9,900),(1,0.99,0),(U64_MAX,None,U64_MAX)]:
        verify.require(quantity(base,coefficient)==expected,'quantity boundary');quantity_cases+=1
    controls=[]
    for va,byte,args in [(0x2bb5365,0x3e,(0,0,[10000,20000,30000],[3,3,0])),
                         (0x2bb59f5,2,(0,0,[10000,20000,30000],[3,3,0])),
                         (0x2bb59e4,0xfa,(0,0,[10000,20000,30000],[3,3,0]))]:
        changed=bytearray(data);changed[verify.Image(data).off(va)]=byte
        original=projected(*args,o);altered=projected(*args,operands(changed))
        verify.require(original!=altered,'counterfactual survived')
        controls.append({'va':hex(va),'byte':byte,'inputs':args,'original':original,'mutated':altered})
    return json.loads(verify.encoded({'native_operands':o,'retry_cases':retry_cases,'selection_cases':selection_cases,
        'quantity_cases':quantity_cases,'examples':examples,'counterfactuals':controls,
        'limits':'Each inner attempt result and opaque helper base is supplied explicitly. This checks selection and quantity preparation, not inner-accounting equivalence, rollback, helper purity, or liquidation effects. Python binary64 uses round-to-nearest/ties-to-even; captured-code execution/emulation is not performed. Noncanonical mode words are distinguished because the native helper selector is one byte while the retry stop selector is a full qword.'}))

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--write',action='store_true');args=parser.parse_args()
    data=verify.TARGET.read_bytes();verify.require(verify.sha(data)==verify.DIGEST,'wrong target')
    result=verify.encoded(evaluate(data))
    if args.write:(verify.PACKET/'relations.json').write_text(result)
    else:verify.require((verify.PACKET/'relations.json').read_text()==result,'relations drift')
    print('PASS: three-attempt selection and three operand counterfactuals')
