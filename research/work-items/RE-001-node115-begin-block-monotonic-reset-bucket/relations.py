#!/usr/bin/env python3
"""Check monotonic bucket inputs/ordering, without executing the captured node."""
import argparse
import datetime
import json
import verify

def read(data, va, size=1, signed=False):
    return int.from_bytes(verify.Image(data).get(va,size),'little',signed=signed)

def operands(data):
    return {'stride':read(data,0x2be6009,4),'sentinel':read(data,0x2be60c4,8),
            'divisor_displacement':read(data,0x2be617d,4,True),'stored_displacement':read(data,0x2be6195,4,True),
            'flag_condition':read(data,0x2be6057),'seconds_per_day':read(data,0x2be6150,4),
            'milliseconds_per_second':read(data,0x2be616c,4),'nano_magic':read(data,0x2be6161,4),
            'nano_shift':read(data,0x2be6168),'epoch_day_offset':read(data,0x2be6147,4,True),
            'guard_enabled_value':read(data,0x4229ff6)}

def scalar(year, ordinal, seconds, nanos, o):
    # Algebraic calendar relation, not an instruction emulator. Date validity is a premise.
    prior=year-1
    days=365*prior+prior//4-prior//100+prior//400+ordinal+o['epoch_day_offset']
    submilliseconds=(nanos*o['nano_magic'])>>o['nano_shift']
    return max(0,(days*o['seconds_per_day']+seconds)*o['milliseconds_per_second']+submilliseconds)

def projected(sentinel, milliseconds, fields, o):
    if sentinel!=o['sentinel']:
        return {'path':'skip','events':[]}
    divisor=fields[o['divisor_displacement']]
    old=fields[o['stored_displacement']]
    if divisor==0:
        return {'path':'zero-divisor exception','events':['division exception before store or guard']}
    quotient=milliseconds//divisor
    advance=quotient>old
    flag=advance if o['flag_condition']==0x97 else quotient>=old
    return {'path':'eligible','division_bits':32 if (milliseconds|divisor)<(1<<32) else 64,
            'quotient':quotient,'stored':max(old,quotient),'flag':flag,
            'events':(['store quotient'] if advance else [])+['call guard'],
            'guard_enters':int(flag)==o['guard_enabled_value']}

def evaluate(data):
    o=operands(data)
    verify.require(o=={'stride':0x510,'sentinel':1<<63,'divisor_displacement':-0x130,'stored_displacement':-0x128,
                      'flag_condition':0x97,'seconds_per_day':86400,'milliseconds_per_second':1000,
                      'nano_magic':0x431bde83,'nano_shift':50,'epoch_day_offset':-719163,'guard_enabled_value':1},'native bucket operands')
    verify.require(verify.Image(data).get(0x453d80,16)==b'reset_recent_ois','bounded guard name')
    calendar_cases=0
    epoch=datetime.datetime(1970,1,1)
    for year in (1,4,100,400,1600,1900,1969,1970,1971,2000,2100,2400,9999):
        for ordinal in (1,59,60,61,365):
            for seconds in (0,1,86399):
                for nanos in (0,999999,1000000,999999999):
                    instant=datetime.datetime(year,1,1)+datetime.timedelta(days=ordinal-1,seconds=seconds)
                    delta=instant-epoch
                    expected=max(0,(delta.days*86400+delta.seconds)*1000+nanos//1000000)
                    verify.require(scalar(year,ordinal,seconds,nanos,o)==expected,'independent datetime scalar')
                    calendar_cases+=1
    nanosecond_cases=0
    for quotient in range(4295):
        for offset in (-1,0,1):
            n=quotient*1000000+offset
            if 0<=n<(1<<32):
                verify.require((n*o['nano_magic'])>>o['nano_shift']==n//1000000,'nanosecond conversion boundary')
                nanosecond_cases+=1
    cases=0;examples=[]
    for sentinel in (0,(1<<63)-1,1<<63,(1<<63)+1):
        for milliseconds in (0,1,999,1000,(1<<32)-1,1<<32,(1<<63)-1):
            for divisor in (0,1,1000,(1<<32)-1,1<<32,(1<<64)-1):
                for old in (0,1,1000,(1<<64)-1):
                    result=projected(sentinel,milliseconds,{-0x130:divisor,-0x128:old},o)
                    if sentinel==(1<<63) and divisor:
                        quotient,remainder=divmod(milliseconds,divisor)
                        verify.require(quotient*divisor+remainder==milliseconds and 0<=remainder<divisor,'division identity')
                        verify.require(result['stored']>=old and result['stored']>=quotient,'monotonic floor')
                        verify.require(result['flag']==(result['stored']!=old),'flag equals storage change')
                        verify.require(result['guard_enters']==result['flag'],'guard entry relation')
                        verify.require(result['events'][-1]=='call guard','store precedes handoff')
                    cases+=1
                    if sentinel==(1<<63) and divisor in (0,1000) and old in (0,1) and milliseconds in (0,999,1000,1<<32):
                        examples.append({'milliseconds':milliseconds,'divisor':divisor,'old':old,'result':result})
    controls=[]
    for va,byte,args in [(0x2be60c4,1,(1<<63,1000,{-0x130:1000,-0x128:0})),
                         (0x2be617d,0xd8,(1<<63,1000,{-0x130:1000,-0x128:2})),
                         (0x2be6057,0x93,(1<<63,1000,{-0x130:1000,-0x128:1}))]:
        changed=bytearray(data);changed[verify.Image(data).off(va)]=byte
        original=projected(*args,o);altered=projected(*args,operands(changed))
        verify.require(original!=altered,'counterfactual survived')
        controls.append({'va':hex(va),'byte':byte,'inputs':args,'original':original,'mutated':altered})
    return json.loads(verify.encoded({'native_operands':o,'calendar_cases':calendar_cases,'nanosecond_boundary_cases':nanosecond_cases,
        'bucket_cases':cases,'examples':examples,'counterfactuals':controls,
        'limits':'The Gregorian algebra is context, checked on valid positive-year inputs with datetime; arbitrary invalid packed dates are not modeled. Milliseconds and field words are explicit inputs to the new bucket relation. Zero-divisor behavior is a static DIV instruction consequence; no exception is induced by running captured code. The guard entry test is checked, but its time check, callback completion, vector contents, threading and financial meaning remain unresolved or credited context.'}))

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--write',action='store_true');args=parser.parse_args()
    data=verify.TARGET.read_bytes();verify.require(verify.sha(data)==verify.DIGEST,'wrong target')
    result=verify.encoded(evaluate(data))
    if args.write:(verify.PACKET/'relations.json').write_text(result)
    else:verify.require((verify.PACKET/'relations.json').read_text()==result,'relations drift')
    print('PASS: monotonic bucket relation and three operand counterfactuals')
