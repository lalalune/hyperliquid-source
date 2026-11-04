#!/usr/bin/env python3
"""Finite-width NEG identities, not a target/allocator/callback evaluator."""
import json
mask=(1<<64)-1
values=[0,1,15,1<<60,(1<<63)-1,1<<63,(1<<63)+1,mask]
rows=[]
for n in values:
    neg=(-n)&mask
    # Independent integer definitions of the x86 two's-complement conditions.
    of=(n==1<<63); cf=(n!=0)
    assert (n==0)==(neg==0)
    rows.append(dict(raw=hex(n),neg=hex(neg),overflow=of,borrow=cf,shifted_modulo=hex((n*16)&mask)))
print(json.dumps(dict(claim='NEG zero/overflow predicates and modulo scalar sizing only',rows=rows,target_executed=False,target_emulated=False),indent=2))
