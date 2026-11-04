#!/usr/bin/env python3
"""Check mempool collision authorization using bound native operands."""
import argparse,itertools,json
import verify
MAX=(1<<64)-1
SENTINEL=(1<<63)+1

def operands(data):
    im=verify.Image(data)
    read=lambda a,n=1:int.from_bytes(im.get(a,n),'little')
    return {'saturation_condition':read(0x2e1da6c),'floor_reject':read(0x2e1e1c0),
            'hash_mask':read(0x2e1eb56,4),'conflict_tag':read(0x2e1ec61)}

def scalar(value,o):
    incremented=(value+1)&MAX
    use_increment=(incremented!=0) if o['saturation_condition']==0x45 else (incremented==0)
    return incremented if use_increment else MAX

def projected(value,floor,ordered_rows,index_hash,incoming_hash,remove_found,o):
    h=scalar(value,o)
    if h<floor:return ('below-floor',None,[])
    old=next((key for key,v in ordered_rows if scalar(v,o)==h),None)
    if old is None:return ('continue',None,[])
    floor_reject=(h<=floor) if o['floor_reject']==0x86 else (h<floor)
    equality_mask=0 if index_hash is None else sum((1<<i) for i in range(16) if index_hash[i]==incoming_hash[i] and index_hash[i+16]==incoming_hash[i+16])
    if floor_reject or index_hash is None or equality_mask!=o['hash_mask']:
        return ('conflict',old,[])
    events=['request_remove_old']
    if remove_found:events+=['displaced_event']
    return ('continue_after_displacement',old,events+['resume_registration'])

def evaluate(data):
    o=operands(data)
    verify.require(o=={'saturation_condition':0x45,'floor_reject':0x86,'hash_mask':65535,'conflict_tag':16},'native policy operands')
    saturation_cases=0
    for x in list(range(1025))+[MAX-2,MAX-1,MAX]:
        verify.require(scalar(x,o)==min(MAX,x+1),'saturated comparison scalar')
        saturation_cases+=1
    incoming=bytes(range(32));different=bytes([255])+incoming[1:]
    cases=0
    for value,floor,index_hash,remove_found in itertools.product([0,1,2,3,MAX-1,MAX],[0,1,2,3,MAX-1,MAX],[None,incoming,different],[False,True]):
        h=min(MAX,value+1)
        for rows in [[],[('first',value)],[('first',value),('second',value)],[('other',0),('match',value)]]:
            actual=projected(value,floor,rows,index_hash,incoming,remove_found,o)
            key=next((k for k,v in rows if min(MAX,v+1)==h),None)
            if h<floor:expected=('below-floor',None,[])
            elif key is None:expected=('continue',None,[])
            elif h<=floor or index_hash!=incoming:expected=('conflict',key,[])
            else:expected=('continue_after_displacement',key,['request_remove_old']+(['displaced_event'] if remove_found else [])+['resume_registration'])
            verify.require(actual==expected,'independent collision decision')
            cases+=1
    hash_cases=0
    for i in range(32):
        changed=bytearray(incoming);changed[i]^=1
        verify.require(projected(1,0,[('old',1)],bytes(changed),incoming,True,o)[0]=='conflict','all hash bytes matter')
        hash_cases+=1
    mutations=[]
    for va,byte,args in [(0x2e1da6c,0x44,(1,0,[],None,incoming,True)),(0x2e1e1c0,0x82,(1,2,[('old',1)],incoming,incoming,True)),(0x2e1eb57,0x7f,(1,0,[('old',1)],incoming,incoming,True))]:
        changed=bytearray(data);changed[verify.Image(data).off(va)]=byte
        before=projected(*args,o);after=projected(*args,operands(changed))
        if va==0x2e1da6c:before=scalar(1,o);after=scalar(1,operands(changed))
        verify.require(before!=after,'counterfactual survived')
        mutations.append({'va':hex(va),'byte':byte,'before':before,'after':after})
    return json.loads(verify.encoded({'native_operands':o,'saturation_cases':saturation_cases,'decision_cases':cases,'single_byte_hash_mismatches':hash_cases,'counterfactuals':mutations,
      'limits':'Ordered rows and index lookup results are abstract supplied outcomes, not emulated native collections. The first equal scalar row is selected in the native iteration order; no canonical sort order is asserted. Missing removal results skip the event yet still resume registration. Height names, map repair, source of index authorization, full transaction admission and atomicity remain unresolved.'}))
if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--write',action='store_true');args=parser.parse_args()
    data=verify.TARGET.read_bytes();verify.require(verify.sha(data)==verify.DIGEST,'wrong target')
    result=verify.encoded(evaluate(data))
    if args.write:(verify.PACKET/'relations.json').write_text(result)
    else:verify.require((verify.PACKET/'relations.json').read_text()==result,'relations drift')
    print('PASS: collision authorization, first-match selection and three operand counterfactuals')
