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
    return {'row_shift':u(im,0x37bf14f),'output_shift':u(im,0x37bf157),
            'pointer_offset':u(im,0x37bf174),'length_offset':u(im,0x37bf179),
            'failure_branch':u(im,0x37bf189),'output_step':u(im,0x37bf19c)}

def project(tags,initial,op):
    completed=0;copies=[]
    for i,tag in enumerate(tags):
        # Signed zero minus MIN is the unique overflowing qword subtraction.
        success=tag==(1<<63)
        if op['failure_branch']!=0x71:success=not success
        if not success:return {'published_count':initial+completed,'copied_indices':copies,'failed_row':i,'exit':'unwind-prefix'}
        copies.append([i*(1<<op['row_shift'])+op['pointer_offset'],(initial<<op['output_shift'])+i*op['output_step']]);completed+=1
    return {'published_count':initial+completed,'copied_indices':copies,'failed_row':None,'exit':'ordinary'}

def evaluate(data):
    op=operands(data)
    verify.require(op=={'row_shift':6,'output_shift':4,'pointer_offset':48,'length_offset':56,'failure_branch':0x71,'output_step':16},'DB collector operands')
    cases=[]
    for size,initial in itertools.product(range(9),[0,1,7]):
        for failure in range(size+1):
            tags=[1<<63]*size
            if failure<size:tags[failure]=3
            actual=project(tags,initial,op)
            verify.require(actual['published_count']==initial+failure,'successful prefix count')
            verify.require(actual['copied_indices']==[[64*i+48,16*(initial+i)] for i in range(failure)],'row/copy strides')
            cases.append({'size':size,'initial':initial,'first_failure':failure if failure<size else None,**actual})
    for tag in [0,1,(1<<63)-1,(1<<63)+1,(1<<64)-1]:verify.require(project([tag],4,op)['published_count']==4,'only MIN accepted')
    controls=[changed_relation(data,0x37bf189,0x70,lambda d:project([1<<63],0,operands(d))),
              changed_relation(data,0x37bf174,40,lambda d:project([1<<63],0,operands(d))),
              changed_relation(data,0x37bf19c,8,lambda d:project([1<<63,1<<63],0,operands(d)))]
    return {'native_operands':op,'cases':cases,'counterfactuals':controls,'limits':'Aligned 64-byte input rows, safe preallocated output, valid converter output and count arithmetic without overflow. Converter and allocator internals are not re-recovered; unwind statement is limited to the visible landing pad reached after normal rejected-buffer cleanup.'}
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--write',action='store_true');args=p.parse_args()
    data=verify.TARGET.read_bytes();verify.require(verify.sha(data)==verify.DIGEST,'wrong target')
    result=verify.encoded(evaluate(data))
    if args.write:(verify.PACKET/'relations.json').write_text(result)
    else:verify.require((verify.PACKET/'relations.json').read_text()==result,'relations drift')
    print('PASS: native operand relations and counterfactuals')
