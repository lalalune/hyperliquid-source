#!/usr/bin/env python3
"""Check the raw two-set mempool admission contract against native operands."""
import argparse,itertools,json
import verify
MASK32=(1<<32)-1

def operands(data):
    im=verify.Image(data)
    read=lambda a,n=1:int.from_bytes(im.get(a,n),'little')
    return {'bypass_tag':read(0x57bc00c,4),'adjustment':read(0x57bc1e4,4),
            'underflow_value':read(0x57bc1c2,4),'pair_start':(-int.from_bytes(im.get(0x57bc1ef,1),'little',signed=True)),
            'pair_width':read(0x57bc1f3),'special_adjusted':read(0x57bc1f9),'special_subtype':read(0x57bc200),
            'reject':read(0x57bc21b),'success':read(0x57bc239)}

def secondary_action(action,o):
    tag,argument,subtype=action
    adjusted=tag-o['adjustment'] if tag>=o['adjustment'] else o['underflow_value']
    return ((adjusted-o['pair_start'])&MASK32)<o['pair_width'] or (adjusted==o['special_adjusted'] and subtype==o['special_subtype'])

def projected(flag,configured,actions,primary,secondary,o):
    if flag==0 and actions and all((tag&MASK32)==o['bypass_tag'] and argument==configured for tag,argument,subtype in actions):
        return (o['success'],'bypass')
    if primary:return (o['success'],'primary')
    if secondary and actions and all(secondary_action(a,o) for a in actions):return(o['success'],'secondary')
    return(o['reject'],'reject')

def evaluate(data):
    o=operands(data)
    verify.require(o=={'bypass_tag':220,'adjustment':134,'underflow_value':20,'pair_start':86,'pair_width':2,'special_adjusted':60,'special_subtype':2,'reject':38,'success':46},'native selector operands')
    # This independent predicate explicitly preserves the native 32-bit LEA on
    # the two-tag range and the full-width comparison on the subtype arm.
    def expected_action(a):
        tag,arg,sub=a
        return (tag>=134 and (tag& MASK32) in (220,221)) or (tag==194 and sub==2)
    selector_cases=0
    for tag,subtype in itertools.product(list(range(512))+[(1<<32)+194,(1<<32)+220,(1<<32)+221,(1<<64)-1],range(256)):
        verify.require(secondary_action((tag,0,subtype),o)==expected_action((tag,0,subtype)),'independent raw selector predicate')
        selector_cases+=1
    variants=[(220,7,0),(220,8,0),(221,7,0),(194,7,2),(194,7,1),(0,7,0),((1<<32)+220,7,0),((1<<32)+194,7,2)]
    sequences=[[]]+[[x] for x in variants]+[list(x) for x in itertools.product(variants,repeat=2)]
    decisions=0
    for flag,primary,secondary,actions in itertools.product([0,1,2,255],[False,True],[False,True],sequences):
        actual=projected(flag,7,actions,primary,secondary,o)
        bypass=flag==0 and len(actions)>0 and all((tag&MASK32)==220 and arg==7 for tag,arg,sub in actions)
        expected=(46,'bypass') if bypass else (46,'primary') if primary else (46,'secondary') if secondary and actions and all(expected_action(a) for a in actions) else (38,'reject')
        verify.require(actual==expected,'admission precedence and nonempty policy')
        decisions+=1
    mutants=[]
    for va,byte,args in [(0x57bc00c,221,(0,7,[(220,7,0)],False,False)),(0x57bc1f3,1,(1,7,[(221,7,0)],False,True)),(0x57bc200,3,(1,7,[(194,7,2)],False,True))]:
        changed=bytearray(data);changed[verify.Image(data).off(va)]=byte
        before=projected(*args,o);after=projected(*args,operands(changed))
        verify.require(before!=after,'counterfactual survived')
        mutants.append({'va':hex(va),'byte':byte,'inputs':args,'before':before,'after':after})
    return json.loads(verify.encoded({'native_operands':o,'selector_cases':selector_cases,'decision_cases':decisions,'counterfactuals':mutants,
      'limits':'This is a raw predicate over valid supplied vector extents and abstract membership outcomes. Noncanonical tag examples distinguish instruction widths; they do not broaden any source enum or prove constructible transactions. Generic B-tree mechanics, set population, trust or system authority, cryptographic checks and full mempool acceptance are unresolved. No captured code is executed or emulated.'}))
if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--write',action='store_true');args=parser.parse_args()
    data=verify.TARGET.read_bytes();verify.require(verify.sha(data)==verify.DIGEST,'wrong target')
    result=verify.encoded(evaluate(data))
    if args.write:(verify.PACKET/'relations.json').write_text(result)
    else:verify.require((verify.PACKET/'relations.json').read_text()==result,'relations drift')
    print('PASS: two-set admission, exact raw selectors and three operand counterfactuals')
