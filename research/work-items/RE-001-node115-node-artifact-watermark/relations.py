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
    return {'query_error':u(im,0x4e4cc19),'watermark_skip':u(im,0x4e4ccd2),
            'load_error':u(im,0x4e4cd50),'parse_error_branch':u(im,0x4e4cecf),
            'commit_offset':u(im,0x4e4d234)}

def project(old,new,query_tag,load_tag,parse_result,op):
    events=['query'];stored=old
    if query_tag==op['query_error']:return {'events':events+['query error','delay'],'watermark':stored}
    skip=old>=new if op['watermark_skip']==0x83 else old>new
    if skip:return {'events':events+['delay'],'watermark':stored}
    events+=['load']
    if load_tag==op['load_error']:return {'events':events+['load error','delay'],'watermark':stored}
    events+=['parse']
    error=bool(parse_result) if op['parse_error_branch']==0x85 else not bool(parse_result)
    if error:return {'events':events+['parse failure'],'watermark':stored}
    events+=['cleanup','commit watermark','update callback','delay'];stored=new
    return {'events':events,'watermark':stored}

def evaluate(data):
    op=operands(data);verify.require(op=={'query_error':1,'watermark_skip':0x83,'load_error':2,'parse_error_branch':0x85,'commit_offset':8},'artifact operands')
    cases=0;examples=[]
    for old,new,query,load,parse in itertools.product([0,1,2,(1<<63)-1,1<<63,(1<<64)-1],[0,1,2,(1<<63)-1,1<<63,(1<<64)-1],range(3),range(4),[0,1,2]):
        actual=project(old,new,query,load,parse,op)
        committed=query!=1 and new>old and load!=2 and parse==0
        verify.require(actual['watermark']==(new if committed else old),'watermark preservation')
        verify.require(('update callback' in actual['events'])==committed,'callback admission')
        if committed:verify.require(actual['events'].index('commit watermark')<actual['events'].index('update callback'),'commit precedes callback')
        cases+=1
        if old==0 and new==1 and query in [0,1] and load in [0,2] and parse in [0,1]:examples.append({'old':old,'new':new,'query':query,'load':load,'parse':parse,**actual})
    controls=[changed_relation(data,0x4e4cc19,2,lambda d:project(0,1,1,0,0,operands(d))),
              changed_relation(data,0x4e4ccd2,0x87,lambda d:project(1,1,0,0,0,operands(d))),
              changed_relation(data,0x4e4cd50,3,lambda d:project(0,1,0,2,0,operands(d)))]
    return {'native_operands':op,'projection_cases':cases,'examples':examples,'counterfactuals':controls,'limits':'Raw helper tags are supplied boundaries. Normally returning cleanup/initialization is assumed; the watermark store is before callback entry, with no success flag inspected. Artifact I/O and application semantics are not executed or inferred.'}
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--write',action='store_true');args=p.parse_args()
    data=verify.TARGET.read_bytes();verify.require(verify.sha(data)==verify.DIGEST,'wrong target')
    result=verify.encoded(evaluate(data))
    if args.write:(verify.PACKET/'relations.json').write_text(result)
    else:verify.require((verify.PACKET/'relations.json').read_text()==result,'relations drift')
    print('PASS: native operand relations and counterfactuals')
