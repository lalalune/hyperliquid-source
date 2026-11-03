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
    return {'parse_error_branch':u(im,0x5a396f8),'seconds':u(im,0x5a39722,4),
            'eintr':u(im,0x5a39776),'clock_id':u(im,0x5a3975e,4),'flags_zero':im.get(0x5a39762,2).hex()}

def cycle(parse_result,sleep_results,op):
    error=bool(parse_result) if op['parse_error_branch']==0x85 else not bool(parse_result)
    events=['observe','parse']
    if error:return events+['parse failure']
    events+=['publish',f"sleep({op['seconds']},0)"]
    for status,residual in sleep_results:
        if status==0:return events+['next observation']
        if status!=op['eintr']:return events+['sleep failure']
        if residual==(0,0):return events+['next observation']
        events.append('retry residual '+str(residual))
    return events+['sleep boundary pending input']

def evaluate(data):
    op=operands(data)
    verify.require(op=={'parse_error_branch':0x85,'seconds':5,'eintr':4,'clock_id':1,'flags_zero':'31f6'},'publisher operands')
    cases=[]
    for parse in [0,1,2,(1<<64)-1]:
        for seq in [[],[(0,(0,0))],[(4,(3,10)),(0,(0,0))],[(4,(0,0))],[(22,(0,0))],[(4,(3,0)),(4,(1,5)),(0,(0,0))]]:
            actual=cycle(parse,seq,op)
            verify.require(actual[:2]==['observe','parse'],'observation prefix')
            if parse:verify.require(actual==['observe','parse','parse failure'],'no publication on parse error')
            else:verify.require(actual[2:4]==['publish','sleep(5,0)'],'immediate publication then relative sleep')
            cases.append({'parse_result':parse,'sleep_results':verify.json.loads(verify.encoded(seq)),'events':actual})
    verify.require(cycle(0,[(4,(3,10)),(0,(0,0))],op)[4:]==['retry residual (3, 10)','next observation'],'EINTR retry')
    verify.require(cycle(0,[(22,(0,0))],op)[-1]=='sleep failure','non-EINTR failure')
    controls=[changed_relation(data,0x5a39722,6,lambda d:cycle(0,[],operands(d))),
              changed_relation(data,0x5a39776,5,lambda d:cycle(0,[(4,(3,10))],operands(d))),
              changed_relation(data,0x5a396f8,0x84,lambda d:cycle(0,[],operands(d)))]
    return {'native_operands':op,'cases':cases,'counterfactuals':controls,'limits':'Conditional normal returns and valid timespec residuals. Models one bounded iteration and supplied OS results; no target execution, clock measurement, snapshot meaning or publication delivery guarantee.'}
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--write',action='store_true');args=p.parse_args()
    data=verify.TARGET.read_bytes();verify.require(verify.sha(data)==verify.DIGEST,'wrong target')
    result=verify.encoded(evaluate(data))
    if args.write:(verify.PACKET/'relations.json').write_text(result)
    else:verify.require((verify.PACKET/'relations.json').read_text()==result,'relations drift')
    print('PASS: native operand relations and counterfactuals')
