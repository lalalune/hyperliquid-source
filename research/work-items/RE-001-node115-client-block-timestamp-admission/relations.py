#!/usr/bin/env python3
"""Timestamp admission formulas and ordered scalar-boundary effects from native operands."""
import argparse,itertools,random
import capstone
import verify
U64=(1<<64)-1;U32=(1<<32)-1

def operands(data):
    im=verify.Image(data);cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);cs.detail=True
    ins=lambda a:next(cs.disasm(im.get(a,15),a));imm=lambda a:ins(a).operands[-1].imm
    return {'division_magic':imm(0x4ece8f7),'division_shift':imm(0x4ece913),'seconds_per_day':imm(0x4ece91a),
      'ce_epoch':imm(0x4ece964),'nanos_max':imm(0x4ece978),'leap_threshold':imm(0x4ece984),
      'second_magic':imm(0x4ece98d)&U32,'second_bias':imm(0x4ece994)&U32,'second_rotate':imm(0x4ece99a),'second_bound':imm(0x4ece99d),
      'nanos_max_branch':ins(0x4ece97e).mnemonic,'leap_reject_branch':ins(0x4ece9a8).mnemonic,
      'success_tag':imm(0x4ece9b8),'invalid_tag':imm(0x4eceaa0),'seconds_claim':imm(0x4ece8a5),'nanos_claim':imm(0x5821164),
      'scalar_success':imm(0x4ece8d1),'seconds_little_endian':ins(0x4ece8c0).mnemonic=='xor',
      'date_branch':ins(0x4ece972).mnemonic}

def split_seconds(seconds,o):
    hi=(seconds*o['division_magic'])>>64
    q=(hi>>o['division_shift'])+((hi&U64)>>63)
    remainder=seconds-q*o['seconds_per_day']
    return q-(remainder<0),remainder+(o['seconds_per_day'] if remainder<0 else 0)

def admit(seconds,nanos,date_word,o):
    days,sod=split_seconds(seconds,o);ce=days+o['ce_epoch']
    if not -(1<<31)<=ce<1<<31:return (o['invalid_tag'],None)
    if (date_word==0)==(o['date_branch']=='je'):return (o['invalid_tag'],None)
    too_many=nanos>o['nanos_max'] if o['nanos_max_branch']=='ja' else nanos>=o['nanos_max']
    x=(sod*o['second_magic']+o['second_bias'])&U32;r=o['second_rotate'];rot=((x>>r)|(x<<(32-r)))&U32
    bad_second=rot>=o['second_bound'];bad=bad_second and nanos>=o['leap_threshold']
    if o['leap_reject_branch']!='jne':bad=not bad
    if too_many or bad:return (o['invalid_tag'],None)
    return (o['success_tag'],(date_word,sod,nanos))

def reference(seconds,nanos,date_word):
    day,sod=divmod(seconds,86400)
    valid=(-(1<<31)<=day+719163<1<<31 and date_word!=0 and nanos<2_000_000_000 and (nanos<1_000_000_000 or sod%60==59))
    return (18,(date_word,sod,nanos)) if valid else (17,None)

def boundary_flow(mode,limit,claimed,seconds_status,seconds_consumed,nanos_status,nanos_consumed,o):
    cursor=0;calls=[]
    if mode:
        if claimed>U64-o['seconds_claim']:return (2,claimed,cursor,calls)
        claimed+=o['seconds_claim']
        if claimed>limit:return (2,claimed,cursor,calls)
    calls.append('seconds');cursor+=seconds_consumed
    if seconds_status!=o['scalar_success']:return (seconds_status,claimed,cursor,calls)
    if mode:
        if claimed>U64-o['nanos_claim']:return (2,claimed,cursor,calls)
        claimed+=o['nanos_claim']
        if claimed>limit:return (2,claimed,cursor,calls)
    calls.append('nanos');cursor+=nanos_consumed
    if nanos_status!=o['scalar_success']:return (nanos_status,claimed,cursor,calls)
    calls.append('admission');return (18,claimed,cursor,calls)

def evaluate(data):
    o=operands(data)
    verify.require((o['seconds_per_day'],o['ce_epoch'],o['nanos_max'],o['leap_threshold'])==(86400,719163,1999999999,1000000000),'timestamp units and bounds')
    verify.require(o['success_tag']==o['scalar_success']==18 and o['invalid_tag']==17,'result markers')
    verify.require((o['seconds_claim'],o['nanos_claim'])==(8,4) and o['seconds_little_endian'],'scalar call budget/endianness')
    verify.require(o['date_branch']=='je' and o['nanos_max_branch']=='ja' and o['leap_reject_branch']=='jne','admission branch polarity')
    rng=random.Random(82);seconds=[-(1<<63),(1<<63)-1,-86401,-86400,-86399,-61,-60,-59,-1,0,1,58,59,60,86399,86400,86401]
    seconds += [rng.randrange(-(1<<63),1<<63) for _ in range(8192)]
    for sec in seconds:verify.require(split_seconds(sec,o)==divmod(sec,86400),'negative epoch floor division')
    nanos=[0,999999999,1000000000,1000000001,1999999999,2000000000,U32]
    admission_cases=0
    for sec,nano in itertools.product(range(-43200,43200),nanos):
        verify.require(admit(sec,nano,0x1234,o)==reference(sec,nano,0x1234),'all seconds-of-day leap admission');admission_cases+=1
    for sec,nano,date in itertools.product(seconds,nanos,[0,0x1234]):
        verify.require(admit(sec,nano,date,o)==reference(sec,nano,date),'calendar boundary and scalar extremes');admission_cases+=1
    boundary_cases=0
    for mode,limit,claimed,ss,ns in itertools.product([0,1],[0,7,8,11,12,100,U64],[0,1,7,U64-11,U64-7,U64],[0,2,3,17,18],[0,2,3,17,18]):
        status,used,cursor,calls=boundary_flow(mode,limit,claimed,ss,3,ns,5,o)
        # Independent stage table: claim8, read seconds, claim4, read nanos.
        expected_used=claimed;expected_cursor=0;expected_calls=[];expected_status=18
        for name,charge,result,consumed in [('seconds',8,ss,3),('nanos',4,ns,5)]:
            if mode and expected_used+charge>U64:expected_status=2;break
            if mode:
                expected_used+=charge
                if expected_used>limit:expected_status=2;break
            expected_calls.append(name);expected_cursor+=consumed
            if result!=18:expected_status=result;break
        else:expected_calls.append('admission')
        verify.require((status,used,cursor,calls)==(expected_status,expected_used,expected_cursor,expected_calls),'first-error budget and cursor effect');boundary_cases+=1
    mutations=[]
    for va,value,case in [(0x4ece97e,0x83,(59,1999999999,1)),(0x4ece9a8,0x84,(0,1000000000,1)),(0x4ece972,0x85,(0,0,0)),(0x4ece91d,0x81,(-86400,0,1))]:
        changed=bytearray(data);changed[verify.Image(data).off(va)]=value
        before=admit(*case,o);after=admit(*case,operands(changed))
        verify.require(before!=after,'native operand counterfactual survived');mutations.append({'va':hex(va),'new_byte':value,'input':list(case),'before':before,'after':after})
    # JSON-native representation is necessary for reproducible recorded comparison.
    import json
    return json.loads(json.dumps({'native_operands':o,'division_cases':len(seconds),'admission_cases':admission_cases,'boundary_cases':boundary_cases,
      'counterfactuals':mutations,'limits':'Gregorian date helper is a prior-proven boundary whose raw zero/nonzero return is injected; this packet does not claim its complete arithmetic. Scalar helper statuses/consumption are boundary values, not reconstructed malformed-varint internals. Successful native descriptors and budget modes0/1 only; no captured code execution.'}))
if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--write',action='store_true');args=parser.parse_args()
    data=verify.TARGET.read_bytes();verify.require(verify.sha(data)==verify.DIGEST,'wrong target');text=verify.encoded(evaluate(data))
    if args.write:(verify.PACKET/'relations.json').write_text(text)
    else:verify.require((verify.PACKET/'relations.json').read_text()==text,'relations drift')
    print('PASS: timestamp admission and ordered boundary effects')
