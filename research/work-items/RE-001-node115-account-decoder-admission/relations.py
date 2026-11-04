#!/usr/bin/env python3
"""Check native account field/arity decisions with opaque value-helper premises."""
import argparse
import itertools
import json
import verify

def read(data,va,size=1,signed=False):
    return int.from_bytes(verify.Image(data).get(va,size),'little',signed=signed)

def operands(data):
    image=verify.Image(data)
    return {'short_keys':[chr(read(data,a)) for a in (0x3263248,0x326325a,0x3263251)],
            'balance_long':(image.get(0x32634bc,4)+image.get(0x32634c6,4)[1:]).decode('ascii'),
            'nonce_long':(image.get(0x32634d7,4)+bytes([read(data,0x32634e3)])).decode('ascii'),
            'code_hash_long':(image.get(0x32634f1,8)+bytes([read(data,0x3263503)])).decode('ascii'),
            'balance_duplicate_value':read(data,0x3262e6c),'sequence_limit':-read(data,0x3264104,1,True),
            'default_code_hash':image.get(0x4585a0,32).hex()}

def defaults(o):return {'balance':'00'*32,'nonce':0,'code_hash':o['default_code_hash']}

def map_relation(entries,o):
    names=['balance','nonce','code_hash'];aliases={}
    for name,short,long in zip(names,o['short_keys'],[o['balance_long'],o['nonce_long'],o['code_hash_long']]):
        aliases[short]=name;aliases[long]=name
    result=defaults(o);seen=set();events=[]
    for key,value,helper_ok in entries:
        name=aliases.get(key)
        if name is None:
            events.append('skip unknown value')
            if not helper_ok:return {'error':'skip helper failure','events':events}
            continue
        duplicate=int(name in seen)==o['balance_duplicate_value'] if name=='balance' else name in seen
        if duplicate:return {'error':'duplicate '+name,'events':events}
        events.append('decode '+name)
        if not helper_ok:return {'error':'value helper failure','events':events}
        result[name]=value;seen.add(name)
    return {'value':result,'events':events}

def sequence_relation(values,o):
    result=defaults(o);names=['balance','nonce','code_hash']
    for name,value in zip(names,values):result[name]=value
    return {'error':'declared extra element','decoded_fields':3} if len(values)>o['sequence_limit'] else {'value':result,'decoded_fields':min(3,len(values))}

def evaluate(data):
    o=operands(data)
    empty_hash='c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470'
    verify.require(o=={'short_keys':['b','n','c'],'balance_long':'balance','nonce_long':'nonce','code_hash_long':'code_hash',
                      'balance_duplicate_value':1,'sequence_limit':3,'default_code_hash':empty_hash},'native field operands')
    values={'balance':'01'*32,'nonce':7,'code_hash':'02'*32}
    map_cases=0;examples=[]
    for keys in itertools.product(('b','balance'),('n','nonce'),('c','code_hash')):
        entries=[(k,v,True) for k,v in zip(keys,values.values())]
        for ordered in itertools.permutations(entries):
            result=map_relation(ordered,o)
            verify.require(result['value']==values,'field order and aliases')
            map_cases+=1
    duplicate_cases=0
    for field,keys in zip(values,[('b','balance'),('n','nonce'),('c','code_hash')]):
        for first,second in itertools.product(keys,repeat=2):
            result=map_relation([(first,values[field],True),(second,None,False)],o)
            verify.require(result['error']=='duplicate '+field and result['events']==['decode '+field],'duplicate before value helper')
            duplicate_cases+=1
    omission_cases=0
    for flags in itertools.product((False,True),repeat=3):
        entries=[(key,values[name],True) for key,name,present in zip(('b','n','c'),values,flags) if present]
        expected=defaults(o);expected.update({name:values[name] for name,present in zip(values,flags) if present})
        verify.require(map_relation(entries,o)['value']==expected,'map omission defaults');omission_cases+=1
    for entries in [[],[('extra',None,True)],[('extra',None,False)],[('b','01'*32,True),('extra',None,True),('nonce',7,True)],
                    [('b','01'*32,True),('balance',None,False)]]:
        examples.append({'entries':entries,'result':map_relation(entries,o)})
    sequence_cases=0
    for count in range(16):
        raw_values=list(values.values())+['unread extra']*max(0,count-3)
        result=sequence_relation(raw_values[:count],o)
        verify.require(('error' in result)==(count>3),'sequence arity')
        verify.require(result['decoded_fields']==min(count,3),'extra element not decoded')
        sequence_cases+=1
    controls=[]
    for va,byte,kind,arg in [(0x3263251,ord('d'),'map',[('c','02'*32,True)]),
                             (0x3262e6c,0,'map',[('b','01'*32,True)]),
                             (0x4585a0,0xc4,'map',[]),
                             (0x3264104,0xfc,'sequence',list(values.values())+['unread extra'])]:
        changed=bytearray(data);changed[verify.Image(data).off(va)]=byte
        function=map_relation if kind=='map' else sequence_relation
        original=function(arg,o);altered=function(arg,operands(changed))
        verify.require(original!=altered,'counterfactual survived')
        controls.append({'va':hex(va),'byte':byte,'kind':kind,'input':arg,'original':original,'mutated':altered})
    return json.loads(verify.encoded({'native_operands':o,'map_order_alias_cases':map_cases,'duplicate_cases':duplicate_cases,
        'omission_cases':omission_cases,'sequence_arity_cases':sequence_cases,'examples':examples,'counterfactuals':controls,
        'limits':'Inputs here are already identified string keys and already decoded field values, with explicit success/failure supplied for opaque value and skip helpers. This is a native-operand admission projection, not a complete MessagePack parser, target execution, emulation, or wire-equivalence test. Fixed map/array control flow and the wrapper absence of a remaining-byte check are established by the retained native bodies. Alternative marker families and accepted balance/hash/nonce value encodings remain unresolved.'}))

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--write',action='store_true');args=parser.parse_args()
    data=verify.TARGET.read_bytes();verify.require(verify.sha(data)==verify.DIGEST,'wrong target')
    result=verify.encoded(evaluate(data))
    if args.write:(verify.PACKET/'relations.json').write_text(result)
    else:verify.require((verify.PACKET/'relations.json').read_text()==result,'relations drift')
    print('PASS: account admission relations and four operand counterfactuals')
