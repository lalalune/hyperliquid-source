#!/usr/bin/env python3
"""Recover TWAP result shapes from bound native call/field operands."""
import argparse,itertools,struct
import capstone
import verify

def operands(data):
    im=verify.Image(data);cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);cs.detail=True
    ins=lambda a:next(cs.disasm(im.get(a,15),a));imm=lambda a:ins(a).operands[-1].imm
    literal=lambda a,n:im.get(a,n).decode()
    return {'create_niche':imm(0x5183a54)&((1<<64)-1),'cancel_niche':imm(0x5184264)&((1<<64)-1),
      'create_branch':ins(0x5183adb).mnemonic,'cancel_branch':ins(0x51842e7).mnemonic,
      'mode_offset':ins(0x5183a5e).operands[0].mem.disp,'id_offset':ins(0x5183bda).operands[-1].mem.disp,
      'error_pointer_offset':ins(0x5183b84).operands[-1].mem.disp,'error_length_offset':ins(0x5183b88).operands[-1].mem.disp,
      'status':literal(0x91f283,6),'running':literal(0x91f270,7),'error':literal(0x91f277,5),'success':literal(0x91f27c,7),'twapId':literal(0x91e477,6),
      'success_helper':imm(0x51842f8),'id_helper':imm(0x5183be6),'error_helper':imm(0x518434e),
      'string_helper':0x57cf860,'unsigned_helper':0x57d00b0,'helper_success':imm(0x5183b94)}

def projection(action,mode,raw,id_value,message,o):
    success=(raw==o[action+'_niche'])
    if o[action+'_branch']!='jne':success=not success
    if not success:value={o['error']:message}
    elif action=='cancel':
        value=o['success'] if o['success_helper']==o['string_helper'] else {o['success']:None}
    else:value={o['running']:({o['twapId']:id_value} if mode else [id_value])}
    return {o['status']:value} if mode else [value]

def operations(action,mode,success,o):
    result=[('map' if mode else 'array',1)]
    if mode:result.append(('string',o['status']))
    if not success:result += [('map',1),('string',o['error']),('string','MESSAGE')]
    elif action=='cancel':result.append(('string',o['success']))
    else:
        result += [('map',1),('string',o['running']),('map' if mode else 'array',1)]
        if mode:result.append(('string',o['twapId']))
        result.append(('unsigned','ID'))
    return result

def evaluate(data):
    o=operands(data)
    verify.require(o['create_niche']==o['cancel_niche']==1<<63,'successful niche')
    verify.require(o['create_branch']==o['cancel_branch']=='jne','niche branch polarity')
    verify.require((o['mode_offset'],o['id_offset'],o['error_pointer_offset'],o['error_length_offset'])==(11,8,8,16),'field descriptors')
    verify.require(o['success_helper']==o['error_helper']==o['string_helper'] and o['id_helper']==o['unsigned_helper'],'value type helpers')
    verify.require(o['helper_success']==2,'primitive success marker')
    ids=[0,1,127,128,255,256,65535,65536,(1<<32)-1,1<<32,(1<<63)-1,1<<63,(1<<64)-1]
    errors=['','x','bad order','quote " slash \u005c','\u0000','\u2603','a'*32,'a'*256]
    cases=0;fixtures=[]
    for action,mode,success,id_value,message in itertools.product(['create','cancel'],[0,1],[0,1],ids,errors):
        raw=(1<<63) if success else len(message.encode())
        actual=projection(action,mode,raw,id_value,message,o)
        value=({'running':({'twapId':id_value} if mode else [id_value])} if action=='create' else 'success') if success else {'error':message}
        expected={'status':value} if mode else [value]
        verify.require(actual==expected,'TWAP result shape');cases+=1
        if id_value==0 and message=='':fixtures.append(actual)
    failure_cases=0
    # A successful primitive is 2; any other helper status reaches an error exit.
    for action,mode,success in itertools.product(['create','cancel'],[0,1],[0,1]):
        calls=operations(action,mode,success,o)
        for stop in range(len(calls)):
            for error in [0,1,3,(1<<64)-1]:
                visited=[]
                for index,operation in enumerate(calls):
                    visited.append(operation)
                    if (error if index==stop else 2)!=o['helper_success']:break
                verify.require(visited==calls[:stop+1],'first helper failure stops ordered output');failure_cases+=1
    mutations=[]
    for va,new in [(0x5183adb,0x74),(0x51842e7,0x74),(0x91f27c,ord('S')),(0x91e477,ord('T'))]:
        changed=bytearray(data);changed[verify.Image(data).off(va)]=new
        before=[projection(a,1,1<<63,7,'error',o) for a in ['create','cancel']]
        after=[projection(a,1,1<<63,7,'error',operands(changed)) for a in ['create','cancel']]
        verify.require(before!=after,'native counterfactual survived');mutations.append({'va':hex(va),'new_byte':new,'different':True})
    return {'native_operands':o,'projection_cases':cases,'failure_order_cases':failure_cases,'fixtures':fixtures,'counterfactuals':mutations,
      'limits':'Valid descriptors, UTF-8 strings and serializer modes0/1 only. Helper errors are boundary values; generic encoder internals, allocation behavior, native execution and TWAP business lifecycle are not reconstructed.'}
if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--write',action='store_true');args=parser.parse_args()
    data=verify.TARGET.read_bytes();verify.require(verify.sha(data)==verify.DIGEST,'wrong target');text=verify.encoded(evaluate(data))
    if args.write:(verify.PACKET/'relations.json').write_text(text)
    else:verify.require((verify.PACKET/'relations.json').read_text()==text,'relations drift')
    print('PASS: TWAP result shape and operand counterfactuals')
