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
    return {'base_marker':u(im,0x2b79eb8,8),'pending_delta':u(im,0x2b79ec9),
            'pending_output':u(im,0x2b79ed2),'decode_success':u(im,0x2b79f79),
            'free_skip':u(im,0x2b79f8c)}

def project(capacity_or_tag,second,length,decoded_tag,op):
    if capacity_or_tag==op['base_marker']+op['pending_delta']:return {'tag':op['pending_output'],'state':3,'decode':False,'convert_error':False,'free_buffer':False,'word8':None}
    if capacity_or_tag==op['base_marker']:return {'tag':1,'state':1,'decode':False,'convert_error':False,'free_buffer':False,'word8':second}
    success=decoded_tag==op['decode_success']
    return {'tag':0 if success else 1,'state':1,'decode':True,'convert_error':not success,'free_buffer':bool(capacity_or_tag),'word8':length if success else 'converted error'}

def evaluate(data):
    op=operands(data);verify.require(op=={'base_marker':1<<63,'pending_delta':1,'pending_output':2,'decode_success':18,'free_skip':0x74},'typed reader operands')
    cases=[]
    for cap,tag,length in itertools.product([0,1,16,1<<63,(1<<63)+1],range(256),[0,1,4096]):
        actual=project(cap,99,length,tag,op)
        if cap==(1<<63)+1:verify.require(actual=={'tag':2,'state':3,'decode':False,'convert_error':False,'free_buffer':False,'word8':None},'pending precedence')
        elif cap==1<<63:verify.require(actual['word8']==99 and not actual['decode'] and not actual['free_buffer'],'transport error')
        else:
            verify.require(actual['tag']==(0 if tag==18 else 1),'decode tag')
            verify.require(actual['free_buffer']==bool(cap),'buffer release')
            verify.require(actual['word8']==(length if tag==18 else 'converted error'),'length preservation')
        if tag in (0,18,255) and length==4096:cases.append({'input_first_word':cap,'decoder_tag':tag,**actual})
    controls=[changed_relation(data,0x2b79ec9,2,lambda d:project((1<<63)+1,99,7,18,operands(d))),
              changed_relation(data,0x2b79ed2,3,lambda d:project((1<<63)+1,99,7,18,operands(d))),
              changed_relation(data,0x2b79f79,19,lambda d:project(8,99,7,18,operands(d)))]
    return {'native_operands':op,'projection_cases':3840,'examples':cases,'counterfactuals':controls,'limits':'Valid initial/resumed state and well-formed lower-reader outputs; decoded error helper supplied as a symbolic result. Only success defines output bytes1/2 as copied decoder bytes. Other output padding is not asserted. No framing implementation, target execution or emulation.'}
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--write',action='store_true');args=p.parse_args()
    data=verify.TARGET.read_bytes();verify.require(verify.sha(data)==verify.DIGEST,'wrong target')
    result=verify.encoded(evaluate(data))
    if args.write:(verify.PACKET/'relations.json').write_text(result)
    else:verify.require((verify.PACKET/'relations.json').read_text()==result,'relations drift')
    print('PASS: native operand relations and counterfactuals')
