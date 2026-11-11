#!/usr/bin/env python3
"""Decoded Content schema and first-error policy; not a byte-stream decoder."""
import argparse,itertools,json,struct
import capstone
import verify

def operands(data):
    im=verify.Image(data);cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);cs.detail=True
    ins=lambda a:next(cs.disasm(im.get(a,15),a));imm=lambda a:ins(a).operands[-1].imm
    return {'sequence_tag':imm(0x2058c59),'map_tag':imm(0x2058c71),'sequence_length':imm(0x20596ca),
      'numeric_gas_index':imm(0x2058f44),'duplicate_gas_branch':ins(0x20591e9).mnemonic,
      'option_none_tag':imm(0x200caf3),'option_some_tag':imm(0x200caf8),'option_unit_tag':imm(0x200cafd),
      'map_option_unseen':imm(0x20591e0),'map_default_compare':imm(0x20594ac),
      'keys':[im.get(0x5ff4c5,6).decode(),im.get(0x5ff4cb,2).decode(),im.get(0x5fed04,6).decode()],
      'key_dispatch':[hex(0x5dd138+x) for x in struct.unpack('<15i',im.get(0x5dd138,60))]}

def field(key,o):
    tag,value=key
    if tag in [1,4]:
        if value==0:return 0
        if value==1:return 1
        if value==o['numeric_gas_index']:return 2
        raise ValueError('invalid field index')
    if tag in [12,13,14,15]:
        raw=value if isinstance(value,bytes) else value.encode()
        for i,k in enumerate(o['keys']):
            if raw==k.encode():return i
        raise ValueError('unknown field')
    raise ValueError('invalid key type')

def integer(content):
    tag,value=content
    if tag not in range(1,9) or value<0:raise ValueError('invalid unsigned integer')
    return value

def value_for(index,content,o):
    tag,value=content
    if index==0:return integer(value if tag==19 else content)
    if index==1:
        for _ in range(2):
            if tag!=19:break
            tag,value=value
        # Valid owned/borrowed string Content; byte-to-UTF8 helpers remain a boundary.
        if tag not in [12,13]:raise ValueError('invalid string')
        return value
    if tag in [o['option_none_tag'],o['option_unit_tag']]:return None
    if tag==o['option_some_tag']:
        tag,value=value
        if tag==19:tag,value=value
    elif tag==19:tag,value=value
    return integer((tag,value))

def admit(kind,items,o):
    calls=[];values={};gas_state=o['map_option_unseen']
    try:
        if kind==o['sequence_tag']:
            for i in range(3):
                if i>=len(items):return {'error':'invalid length','length':i,'calls':calls}
                calls.append(o['keys'][i]);values[i]=value_for(i,items[i],o)
            if len(items)!=o['sequence_length']:return {'error':'invalid length','length':len(items),'calls':calls}
        elif kind==o['map_tag']:
            for key,value in items:
                i=field(key,o)
                dup=(i in values)
                if i==2:dup=(gas_state!=o['map_option_unseen']) if o['duplicate_gas_branch']=='jne' else (gas_state==o['map_option_unseen'])
                if dup:return {'error':'duplicate '+o['keys'][i],'calls':calls}
                calls.append(o['keys'][i]);values[i]=value_for(i,value,o)
                if i==2:gas_state=int(values[i] is not None)
            for i in [0,1]:
                if i not in values:return {'error':'missing '+o['keys'][i],'calls':calls}
            if 2 not in values:values[2]=None
        else:return {'error':'invalid struct type','calls':calls}
    except ValueError as e:return {'error':str(e),'calls':calls}
    return {'value':[values[0],values[1],values[2]],'calls':calls}

def reference_map(entries,o):
    # Independent field-occurrence scan, with an explicit first invalid position.
    present=[];values={};events=[]
    for key,val in entries:
        try:i=field(key,o)
        except ValueError as e:return {'error':str(e),'calls':events}
        if i in present:return {'error':'duplicate '+o['keys'][i],'calls':events}
        present.append(i);events.append(o['keys'][i])
        try:values[i]=value_for(i,val,o)
        except ValueError as e:return {'error':str(e),'calls':events}
    if 0 not in present:return {'error':'missing slotId','calls':events}
    if 1 not in present:return {'error':'missing ip','calls':events}
    return {'value':[values[0],values[1],values.get(2)],'calls':events}

def evaluate(data):
    o=operands(data)
    verify.require((o['sequence_tag'],o['map_tag'],o['sequence_length'])==(20,21,3),'container contract')
    verify.require(o['keys']==['slotId','ip','maxGas'] and o['numeric_gas_index']==2,'exact fields')
    verify.require((o['option_none_tag'],o['option_some_tag'],o['option_unit_tag'])==(16,17,18),'option tags')
    verify.require(o['duplicate_gas_branch']=='jne' and o['map_option_unseen']==o['map_default_compare']==2,'unseen versus explicit None')
    # Jump table establishes only u8/u64 numeric field identifiers, not every integer tag.
    verify.require(o['key_dispatch']==[hex(x) for x in [0x2058e4d,0x2059255,0x2059255,0x2058f31,0x2059255,0x2059255,0x2059255,0x2059255,0x2059255,0x2059255,0x2059255,0x2058f58,0x2058e98,0x2058ef8,0x2058ee9]],'key dispatch')
    keys=[(tag,value) for tag in [1,4] for value in range(5)]
    keys += [(tag,value) for tag in [12,13,14,15] for value in ['slotId','ip','maxGas','slotid','maxgas','ipx','']]
    key_cases=0
    for key in keys:
        tag,val=key;expected=val if tag in [1,4] and val<3 else ({'slotId':0,'ip':1,'maxGas':2}.get(val) if tag in [12,13,14,15] else None)
        try:actual=field(key,o)
        except ValueError:actual=None
        verify.require(actual==expected,'field alias/unknown');key_cases+=1
    for tag in [0,2,3,5,6,7,8,9,10,11,16,17,18,19,20,21]:
        try:field((tag,0),o);raise AssertionError('unexpected key type')
        except ValueError:pass
        key_cases+=1
    good=[(4,7),(13,'127.0.0.1'),(16,None)];bad=(0,False)
    seq_cases=0
    for size in range(7):
        for mask in range(8):
            seq=[(bad if mask&(1<<i) else good[i]) for i in range(min(size,3))]+[(4,999)]*max(0,size-3)
            expected_calls=[];expected=None
            for i in range(3):
                if size<=i:expected={'error':'invalid length','length':i,'calls':expected_calls};break
                expected_calls.append(o['keys'][i])
                if mask&(1<<i):expected={'error':'invalid string' if i==1 else 'invalid unsigned integer','calls':expected_calls};break
            if expected is None:expected={'error':'invalid length','length':size,'calls':expected_calls} if size!=3 else {'value':[7,'127.0.0.1',None],'calls':expected_calls}
            verify.require(admit(20,seq,o)==expected,'sequence first error versus arity');seq_cases+=1
    map_cases=0
    for size in range(6):
        for order in itertools.product(range(4),repeat=size):
            for invalid in [-1,*range(size)]:
                entries=[((13,(['slotId','ip','maxGas','unknown'][i])),bad if j==invalid else (good[i] if i<3 else bad)) for j,i in enumerate(order)]
                verify.require(admit(21,entries,o)==reference_map(entries,o),'map seen-state/error order');map_cases+=1
    option_cases=0
    for val in [(16,None),(18,None),(17,(4,0)),(4,(1<<64)-1),(5,-1),(19,(4,7)),(17,(19,(4,8)))]:
        result=admit(20,[*good[:2],val],o)
        expected={16:None,18:None}
        if val[0]==5:verify.require(result.get('error')=='invalid unsigned integer','negative option')
        else:verify.require('value' in result,'valid option content')
        option_cases+=1
    mutants=[];im=verify.Image(data)
    base_map=[((13,'slotId'),good[0]),((13,'ip'),good[1]),((13,'maxGas'),good[2])]
    for va,new,kind,items,label in [(0x20596cd,2,20,good,'exact arity'),(0x2058f47,3,21,[((4,0),good[0]),((4,1),good[1]),((4,2),good[2])],'numeric gas index'),(0x200caf5,15,20,good,'explicit None'),(0x20591ea,0x84,21,base_map,'option duplicate state')]:
        changed=bytearray(data);changed[im.off(va)]=new;before=admit(kind,items,o);after=admit(kind,items,operands(changed))
        verify.require(before!=after,'mutated operand survived');mutants.append({'va':hex(va),'new_byte':new,'meaning':label,'before':before,'after':after})
    return {'native_operands':o,'key_cases':key_cases,'sequence_cases':seq_cases,'map_cases':map_cases,'option_cases':option_cases,'counterfactuals':mutants,
      'limits':'Valid decoded Content layout; scalar/string/option helpers are context. Semantic relations use valid owned/borrowed string values and explicit invalid-type cases; byte-string UTF8 validation, allocation, error text construction and direct wire cursor are outside the claim. No captured execution/emulation.'}

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--write',action='store_true');args=parser.parse_args()
    data=verify.TARGET.read_bytes();verify.require(verify.sha(data)==verify.DIGEST,'wrong target');text=verify.encoded(evaluate(data))
    if args.write:(verify.PACKET/'relations.json').write_text(text)
    else:verify.require((verify.PACKET/'relations.json').read_text()==text,'relations drift')
    print('PASS: GossipPriorityBid Content admission')
