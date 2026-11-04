#!/usr/bin/env python3
"""Validate operand-bound four-way value relations without captured-code execution."""
import argparse
import json
import math
import struct
from fractions import Fraction
import verify
I64_MAX = (1 << 63) - 1
I64_MIN = -(1 << 63)
U64_MAX = (1 << 64) - 1

def read(data, va, size=1):
    return int.from_bytes(verify.Image(data).get(va, size), 'little')

def operands(data):
    image = verify.Image(data)
    return {'magnitude_offset': read(data, 0x42035b4, 4), 'growth_offset': read(data, 0x420361e, 4),
            'crossing_offset': read(data, 0x42037a1, 4), 'crossing_cap': read(data, 0x42037c5, 8),
            'ratio_opcode': read(data, 0x420369c),
            'clamp_low': struct.unpack('<d', image.get(0x459808, 8))[0],
            'clamp_high': struct.unpack('<d', image.get(0x459360, 8))[0],
            'cast_upper_threshold': struct.unpack('<d', image.get(0x458e50, 8))[0]}

def projected(old, side, previous, fields, o):
    magnitude = fields[o['magnitude_offset']]
    if magnitude > I64_MAX:
        return {'path': 'magnitude panic'}
    delta = -magnitude if side else magnitude
    new = min(I64_MAX, max(I64_MIN, old + delta))
    saturated = new != old + delta
    if new == 0:
        return {'path': 'zero', 'new': new, 'value': 0, 'size_saturated': saturated}
    if (old > 0 and new > 0) or (old < 0 and new < 0):
        if (old > 0 and not side) or (old < 0 and side):
            value = min(U64_MAX, previous + fields[o['growth_offset']])
            path = 'growth'
        else:
            if previous > I64_MAX:
                return {'path': 'reduction input panic', 'new': new, 'size_saturated': saturated}
            ratio = float(new) / float(old) if o['ratio_opcode'] == 0x5e else float(new) * float(old)
            value = float(previous) * ratio
            if not math.isfinite(value):
                value = 0.0
            value = min(o['clamp_high'], max(o['clamp_low'], value))
            value = I64_MAX if value > o['cast_upper_threshold'] else int(value)
            value = max(0, value)
            path = 'reduction'
    else:
        value = fields[o['crossing_offset']] * abs(new)
        if value > o['crossing_cap']:
            return {'path': 'crossing product panic', 'new': new, 'size_saturated': saturated}
        path = 'crossing or opening'
    return {'path': path, 'new': new, 'value': value, 'size_saturated': saturated}

def evaluate(data):
    o = operands(data)
    verify.require(o == {'magnitude_offset': 0x250, 'growth_offset': 0x258, 'crossing_offset': 0x248,
                         'crossing_cap': I64_MAX - 1, 'ratio_opcode': 0x5e,
                         'clamp_low': float(I64_MIN), 'clamp_high': float(1 << 63),
                         'cast_upper_threshold': float.fromhex('0x1.fffffffffffffp+62')}, 'native transition operands')
    # Independent exact expectations use small integer/rational inputs, then explicit limits.
    cases = [
        (10, 0, 100, 5, 7, 30, 'growth', 15, 130),
        (-10, 1, 100, 5, 7, 30, 'growth', -15, 130),
        (10, 1, 100, 5, 7, 30, 'reduction', 5, 50),
        (-10, 0, 100, 5, 7, 30, 'reduction', -5, 50),
        (10, 1, 100, 10, 7, 30, 'zero', 0, 0),
        (-10, 0, 100, 10, 7, 30, 'zero', 0, 0),
        (10, 1, 100, 15, 7, 30, 'crossing or opening', -5, 35),
        (-10, 0, 100, 15, 7, 30, 'crossing or opening', 5, 35),
        (0, 0, 100, 5, 7, 30, 'crossing or opening', 5, 35),
        (0, 255, 100, 5, 7, 30, 'crossing or opening', -5, 35),
        (0, 0, 100, 0, 7, 30, 'zero', 0, 0),
        (I64_MAX, 0, U64_MAX, 1, 1, 1, 'growth', I64_MAX, U64_MAX),
        (I64_MIN, 1, 100, 1, 1, 1, 'growth', I64_MIN, 101),
        (0, 0, 100, I64_MAX - 1, 1, 1, 'crossing or opening', I64_MAX - 1, I64_MAX - 1),
        (0, 0, 100, I64_MAX, 0, 1, 'crossing or opening', I64_MAX, 0),
        (10, 1, U64_MAX, 0, 1, 1, 'reduction input panic', 10, None),
        (0, 0, 0, I64_MAX, 1, 0, 'crossing product panic', I64_MAX, None),
        (1, 1, 0, 2, U64_MAX, 0, 'crossing product panic', -1, None),
        (0, 0, 0, I64_MAX + 1, 0, 0, 'magnitude panic', None, None),
    ]
    examples=[]
    for old, side, previous, mag, price, increment, path, new, value in cases:
        fields={0x248:price,0x250:mag,0x258:increment}
        result=projected(old, side, previous, fields, o)
        verify.require(result['path']==path and result.get('new')==new and result.get('value')==value, 'four-way boundary expectation')
        examples.append({'old':old,'side':side,'previous':previous,'fields':fields,'result':result})
    rational_cases=0
    # Dyadic ratios are exact in binary64, allowing a separate Fraction oracle.
    for sign in (-1,1):
        for old_abs in (2,4,8,16,32,64):
            for mag in range(1,old_abs):
                for previous in (0,1,3,100,1024):
                    expected=int(Fraction(previous*(old_abs-mag),old_abs))
                    actual=projected(sign*old_abs, sign>0, previous, {0x248:999,0x250:mag,0x258:999}, o)
                    verify.require(actual['path']=='reduction' and actual['value']==expected, 'exact dyadic reduction')
                    rational_cases+=1
    controls=[]
    witnesses=[(0x420361e,0x48,(10,0,100,{0x248:7,0x250:5,0x258:30})),
               (0x42037a1,0x58,(0,0,100,{0x248:7,0x250:5,0x258:30})),
               (0x42037c5,0xff,(0,0,0,{0x248:1,0x250:I64_MAX,0x258:0})),
               (0x420369c,0x59,(10,1,100,{0x248:7,0x250:5,0x258:30}))]
    for va,byte,args in witnesses:
        changed=bytearray(data);changed[verify.Image(data).off(va)]=byte
        original=projected(*args,o); altered=projected(*args,operands(changed))
        verify.require(original!=altered,'counterfactual survived')
        controls.append({'va':hex(va),'byte':byte,'inputs':args,'original':original,'mutated':altered})
    return json.loads(verify.encoded({'native_operands':o,'branch_boundary_cases':len(cases),'exact_rational_cases':rational_cases,
        'examples':examples,'counterfactuals':controls,
        'limits':'The relation accepts the old signed size supplied through bundle[0], a raw side byte and three raw input qwords. Native field units and caller invariants are not inferred. Python binary64 calculations assume round-to-nearest, ties-to-even; exact dyadic cases have an independent Fraction oracle. Other rounding modes, invalid memory, log/panic side effects, lookup insertion and downstream size mutation are not modeled. This is arithmetic evidence, not target execution or runtime equivalence.'}))

if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--write',action='store_true');args=parser.parse_args()
    data=verify.TARGET.read_bytes();verify.require(verify.sha(data)==verify.DIGEST,'wrong target')
    result=verify.encoded(evaluate(data))
    if args.write:(verify.PACKET/'relations.json').write_text(result)
    else:verify.require((verify.PACKET/'relations.json').read_text()==result,'relations drift')
    print('PASS: four-way native value relations and four operand counterfactuals')
