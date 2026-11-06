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

def operands(data):
    return {'length_offset':read(data,0x5b56a28),'header_success':read(data,0x5b569d9),
            'payload_arithmetic':read(data,0x5b56a42),
            'small_threshold':read(data,0x5822854,4),'medium_threshold':read(data,0x5822879,4),
            'large_shift':read(data,0x58228a8), 'last_prefix_offset':read(data,0x5968170)}

def width(value,o):
    if value<o['small_threshold']:return 1
    if value<o['medium_threshold']:return 3
    if value>>o['large_shift']==0:return 5
    return 9

def projected(header,rows,o):
    total=header
    if o['header_success']!=8:return ('ordinary-header-result',total)
    additions=[width(len(rows),o)]
    for row in rows:
        length=row[o['length_offset']]
        additions.extend([width(length,o),length if o['payload_arithmetic']==3 else -length])
    for add in additions:
        if not 0<=total+add<(1<<64):return ('overflow',)
        total+=add
    return ('success',total)

def independent_width(value):
    # Byte lengths of a separately expressed marker-plus-payload representation.
    if value in range(251):return 1
    return 1+next(n for n in (2,4,8) if value < 256**n)

def evaluate_raw(data):
    o=operands(data)
    verify.require(o=={'length_offset':32,'header_success':8,'payload_arithmetic':3,
                      'small_threshold':251,'medium_threshold':65536,'large_shift':32,
                      'last_prefix_offset':56},'native batch-cost operands')
    lengths=[0,1,250,251,65535,65536,(1<<32)-1,1<<32,(1<<64)-1]
    cases=0
    for count in range(4):
        for items in itertools.product(lengths,repeat=count):
            for header in [0,9,72,1024,(1<<64)-1]:
                rows=[{32:x,24:0} for x in items]
                total=header+independent_width(count)+sum(independent_width(x)+x for x in items)
                expected=('success',total) if total<(1<<64) else ('overflow',)
                verify.require(projected(header,rows,o)==expected,'count plus framed lengths')
                cases+=1
    prefix_cases=0
    for words in itertools.product(lengths[:6],repeat=3):
        fields=list(words)+[0]*5
        verify.require(1+sum(width(x,o) for x in fields)==1+sum(independent_width(x) for x in fields),'fixed header prefix')
        prefix_cases+=1
    controls=[]
    for va,byte in [(0x5b56a28,24),(0x5b569d9,0),(0x5b56a42,0x2b)]:
        args=(40,[{32:251,24:2}])
        original=projected(*args,o);changed=projected(*args,operands(mutated(data,va,byte)))
        verify.require(original!=changed,'counterfactual survived')
        controls.append({'va':hex(va),'byte':byte,'original':original,'mutated':changed})
    return {'native_operands':o,'framing_cases':cases,'fixed_prefix_cases':prefix_cases,
            'examples':[{'header_H':40,'lengths':xs,'result':projected(40,[{32:x,24:0} for x in xs],o)} for xs in [[],[0],[250],[251],[0,0],[1,250]]],
            'counterfactuals':controls,
            'limits':'Header H is the counter after successful 0x5829040; its nested 0x5966e40 contribution is opaque. Formula assumes successful helper returns, valid metadata and no u64 overflow. Payload contents are not accessed by the selected loop. Overflow is nonreturning and may occur after partial prefix increments; this model reports the outcome, not exact panic-state counters. It does not execute the target or prove a whole wire serialization format.'}

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
