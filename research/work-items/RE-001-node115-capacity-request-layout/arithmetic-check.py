#!/usr/bin/env python3
"""Sizing-gate algebra, not allocator calls or captured instruction execution."""
import hashlib
import json
import verify

MASK=(1<<64)-1
LIMIT=0x7ffffffffffffff8


def accepted(n,shift=4):
    return (n>>60)==0 and ((n<<shift)&MASK)<=LIMIT


def main():
    data=(verify.ROOT/'artifacts/node/115/hl-node').read_bytes()
    verify.require(len(data)==105896032 and hashlib.sha256(data).hexdigest()==verify.SHA,'node115 identity')
    elf=verify.Elf(data)
    shift=elf.read(0x5c8b903,1)[0]
    highshift=elf.read(0x5c8b907,1)[0]
    limit=int.from_bytes(elf.read(0x5c8b90d,8),'little')
    verify.require((shift,highshift,limit)==(4,60,LIMIT),'authenticated sizing operands')
    bound=LIMIT//16
    verify.require(bound==(1<<59)-1,'closed gate bound')
    values=sorted(set([0,1,2,3,4,15,16,17,bound-1,bound,bound+1,(1<<60)-1,1<<60,(1<<63)-1,1<<63,MASK-1,MASK]))
    rows=[]
    for n in values:
        gate=accepted(n)
        verify.require(gate==(n<=bound),'gate relation')
        rows.append(dict(count=str(n),shifted_size=str((n<<4)&MASK),high_bits_nonzero=bool(n>>60),gate_accepted=gate))
    # One local immediate counterfactual and its size witness; opaque allocation
    # APIs are neither modeled nor invoked.
    changed=shift^1
    verify.require(((1<<changed)&MASK)!=16,'shift counterfactual witness')
    print(json.dumps(dict(target_sha256=verify.SHA,accepted_count_upper_inclusive=str(bound),
        proof='For count>=2^60 the high-bits gate rejects. Below it, 16*count does not wrap and <=2^63-8 iff count<=2^59-1.',
        witnesses=rows,counterfactual=dict(immediate_va='0x5c8b903',original_shift=shift,changed_shift=changed,count=1,original_size=16,changed_size=(1<<changed)&MASK),
        captured_binary_executed=False,allocators_executed=False,limits='Sizing algebra only; null/non-null allocator behavior and source error types are not simulated'),indent=2))


if __name__=='__main__':main()
