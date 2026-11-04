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
    return {'initial_marker':u(im,0x5a61e5e,8),'equal_skip_opcode':u(im,0x5a61f2b),
            'delay_bits':u(im,0x5a620fe,8),'pending_state':u(im,0x5a62138)}

def decision(marker,equal,op):
    compare=marker!=op['initial_marker']
    skip=bool(equal) if op['equal_skip_opcode']==0x84 else not bool(equal)
    # Native JE jumps to report on false; a nonzero comparison skips the report.
    report=not compare or not skip
    return {'compare':compare,'report':report,'replace_cached_snapshot':report,'delay_bits':hex(op['delay_bits'])}

def evaluate(data):
    op=operands(data)
    verify.require(op=={'initial_marker':(1<<63)+1,'equal_skip_opcode':0x84,'delay_bits':0x403e000000000000,'pending_state':3},'peer report operands')
    cases=[]
    for marker,equal in itertools.product([0,1,1<<63,(1<<63)+1,(1<<64)-1],range(256)):
        got=decision(marker,equal,op);verify.require(got['report']==(marker==(1<<63)+1 or equal==0),'report gate');cases.append(got)
    controls=[changed_relation(data,0x5a61e5e,2,lambda d:decision((1<<63)+1,1,operands(d))),
              changed_relation(data,0x5a61f2b,0x85,lambda d:decision(0,0,operands(d))),
              changed_relation(data,0x5a62104,0x3f,lambda d:decision(0,0,operands(d)))]
    return {'native_operands':op,'report_cases':len(cases),'counterfactuals':controls,
            'initial_transition':'Write absent marker and arm 30.0 before the first snapshot call; ready waits observe, compare unless absent, conditionally report and replace, then rearm. Pending wait returns AL=1 with state+0xc8=3.',
            'limits':'The comparator is a supplied low-byte result; its first guard rejects unequal +0x18 lengths, later element semantics remain opaque. Snapshot/callback/cleanup normally return. No logging-delivery, equality correctness, original Rust type, time-unit or scheduling-progress claim.'}

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--write',action='store_true');args=p.parse_args()
    data=verify.TARGET.read_bytes();verify.require(verify.sha(data)==verify.DIGEST,'wrong target')
    result=verify.encoded(evaluate(data))
    if args.write:(verify.PACKET/'relations.json').write_text(result)
    else:verify.require((verify.PACKET/'relations.json').read_text()==result,'relations drift')
    print('PASS: native operand relations and counterfactuals')
