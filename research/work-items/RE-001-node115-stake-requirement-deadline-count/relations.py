#!/usr/bin/env python3
"""Check native-operand relations; do not execute or emulate the target."""
import argparse
import itertools
import json
import verify

def read(data, va, size=1):
    return int.from_bytes(verify.Image(data).get(va, size), 'little')

def mutated(data, va, byte):
    result = bytearray(data)
    result[verify.Image(data).off(va)] = byte
    return result

def signed(x):return x-(1<<32) if x>>31 else x

def operands(data):
    return {'zero_flag':read(data,0x2c59079),'offset_seconds':read(data,0x2c591a7,4),
            'last_condition':read(data,0x2c59284),'first_condition':read(data,0x2c59296),
            'fallback':[read(data,0x4679d0+4*i,4) for i in range(3)],
            'count_target':0x60aeec+int.from_bytes(verify.Image(data).get(0x60aef0,4),'little',signed=True)}

def projected(flag,timestamp_present,current,deadline,o):
    if flag is not None and flag==o['zero_flag']:return 1
    if not timestamp_present:return 1
    deadline=o['fallback'] if deadline is None else deadline
    a,b,c=current; x,y,z=deadline
    last=c<=z if o['last_condition']==0x96 else c<z
    middle=last if b==y else b<y
    first=signed(a)<=signed(x) if o['first_condition']==0x9e else a<=x
    return int(middle if a==x else first)

def independent(flag,present,current,deadline,fallback):
    if flag==0 or not present:return 1
    end=fallback if deadline is None else deadline
    return int((signed(current[0]),current[1],current[2]) <= (signed(end[0]),end[1],end[2]))

def evaluate_raw(data):
    o=operands(data)
    verify.require(o=={'zero_flag':0,'offset_seconds':15811200,'last_condition':0x96,
                      'first_condition':0x9e,'fallback':[0x7fffd6de,86399,999999999],
                      'count_target':0x2c58e0f},'native deadline-count operands')
    verify.require(o['offset_seconds']==183*24*60*60,'183-day offset relation')
    triples=[(a,b,c) for a,b,c in itertools.product([0,1,0x7fffd6de,0x7fffffff,0x80000000,0xffffffff],[0,1,86399,0xffffffff],[0,1,999999999,0xffffffff])]
    cases=0
    for flag,present,current,deadline in itertools.product([None,0,1,255],[False,True],triples,[None,(0,0,0),(1,86399,999999999),(0xffffffff,1,1)]):
        verify.require(projected(flag,present,current,deadline,o)==independent(flag,present,current,deadline,o['fallback']),'mixed signed/unsigned inclusive comparison')
        cases+=1
    # Summation is mathematical until it crosses u64; native ADD/JB panics there.
    sums=[]
    for initial,flags in [(0,[0,1,1]),((1<<64)-2,[1,0,1]),((1<<64)-1,[1])]:
        total=initial+sum(flags)
        sums.append({'initial':initial,'contributions':flags,'result':total if total<(1<<64) else 'overflow'})
    controls=[]
    for va,byte,args in [(0x2c59079,1,(0,True,(2,0,0),(1,0,0))),
                         (0x2c59284,0x92,(1,True,(1,1,1),(1,1,1))),
                         (0x2c59296,0x96,(1,True,(0xffffffff,0,0),(1,0,0)))]:
        before=projected(*args,o);after=projected(*args,operands(mutated(data,va,byte)))
        verify.require(before!=after,'counterfactual survived')
        controls.append({'va':hex(va),'byte':byte,'inputs':args,'original':before,'mutated':after})
    return {'native_operands':o,'predicate_cases':cases,'sum_boundaries':sums,
            'counterfactuals':controls,
            'limits':'The relation supplies the helper-derived deadline as an explicit input and does not implement or prove date conversion, calendar units, leap handling or iterator selection. Invalid conversion uses the exact static fallback triple. Valid raw selector is 1; other selectors and malformed selector bytes are outside this policy. This is static algebra, not captured-code execution or emulation.'}

def evaluate(data):
    return json.loads(verify.encoded(evaluate_raw(data)))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true')
    args = parser.parse_args()
    data = verify.TARGET.read_bytes()
    verify.require(verify.sha(data) == verify.DIGEST, 'wrong target')
    result = verify.encoded(evaluate(data))
    if args.write:
        (verify.PACKET / 'relations.json').write_text(result)
    else:
        verify.require((verify.PACKET / 'relations.json').read_text() == result, 'relations drift')
    print('PASS: native operand relations and three counterfactuals')
