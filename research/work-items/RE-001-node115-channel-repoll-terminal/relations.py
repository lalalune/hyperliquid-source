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
    return {'queue_ready':u(im,0x2ced7b6),'counter_step':u(im,0x2ced7eb),
            'closed_value':u(im,0x2ced80c),'terminal_below':u(im,0x2ced819),
            'slot_mask':u(im,0x2ccf38d),'terminal_shift':u(im,0x2ccf3a4),
            'pending_state':u(im,0x2ced886)}

def receive(first,second,closed,count,enabled,budget,op):
    if enabled and budget==0:return {'kind':'pending','calls':0,'register':False,'count':count,'budget':budget}
    calls=1;registered=False;tag,payload=first
    if tag!=op['queue_ready']:
        registered=True;calls=2;tag,payload=second
    if tag==op['queue_ready']:
        if payload:
            return {'kind':'underflow' if count<op['counter_step'] else 'item','calls':calls,'register':registered,'count':(count-op['counter_step'])%(1<<64),'budget':budget-int(enabled)}
        kind='terminal'
    else:kind='terminal' if closed==op['closed_value'] and count<op['terminal_below'] else 'pending'
    return {'kind':kind,'calls':calls,'register':registered,'count':count,'budget':budget-int(enabled and kind!='pending')}

def queue(bitmap,index,payload,op):
    bit=(bitmap>>(index&31))&1
    if bit:return [1,payload,(index+1)%(1<<64)]
    return [(bitmap>>op['terminal_shift'])&1,0,index]

def evaluate(data):
    op=operands(data)
    verify.require(op=={'queue_ready':1,'counter_step':2,'closed_value':1,'terminal_below':2,'slot_mask':31,'terminal_shift':33,'pending_state':3},'channel operands')
    cases=0
    for first,second in itertools.product([(0,0),(1,0),(1,8),(2,16)],repeat=2):
        for closed,count,enabled,budget in itertools.product(range(3),range(5),(False,True),(0,1,255)):
            r=receive(first,second,closed,count,enabled,budget,op)
            if enabled and budget==0:expected='pending';calls=0
            else:
                tag,payload=first if first[0]==1 else second;calls=1 if first[0]==1 else 2
                expected=('item' if count>=2 else 'underflow') if tag==1 and payload else ('terminal' if tag==1 or closed==1 and count<2 else 'pending')
            verify.require(r['kind']==expected and r['calls']==calls,'receive projection')
            if expected=='pending':verify.require(r['budget']==budget,'pending restores budget')
            cases+=1
    queue_cases=0
    for index,bit,terminal,payload in itertools.product(range(96),(0,1),(0,1),(0,8)):
        bitmap=(bit<<(index%32))|(terminal<<33)
        verify.require(queue(bitmap,index,payload,op)==([1,payload,index+1] if bit else [terminal,0,index]),'queue bit projection');queue_cases+=1
    controls=[changed_relation(data,0x2ced819,1,lambda d:receive((0,0),(0,0),1,1,False,8,operands(d))),
              changed_relation(data,0x2ced7eb,3,lambda d:receive((1,8),(0,0),0,4,False,8,operands(d))),
              changed_relation(data,0x2ccf3a4,32,lambda d:queue(1<<33,0,8,operands(d)))]
    return {'native_operands':op,'receive_cases':cases,'queue_bit_cases':queue_cases,'counterfactuals':controls,
            'limits':'Current-block matched index and valid state/queue memory; payload/registration/scheduler helpers normally return. This is a local return projection, not a concurrency, wakeup-liveness or ownership proof. No target execution/emulation.'}

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--write',action='store_true');args=p.parse_args()
    data=verify.TARGET.read_bytes();verify.require(verify.sha(data)==verify.DIGEST,'wrong target')
    result=verify.encoded(evaluate(data))
    if args.write:(verify.PACKET/'relations.json').write_text(result)
    else:verify.require((verify.PACKET/'relations.json').read_text()==result,'relations drift')
    print('PASS: native operand relations and counterfactuals')
