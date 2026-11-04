#!/usr/bin/env python3
"""Operand-derived local relations; no target execution or instruction emulation."""
import argparse
import itertools
import struct
import verify

def u(im,a,n=1):
    return int.from_bytes(im.get(a,n),'little')

def changed_relation(data,va,new,fn):
    image=verify.Image(data)
    altered=bytearray(data);altered[image.off(va)]=new
    before,after=fn(data),fn(altered)
    verify.require(before!=after,'surviving relation counterfactual')
    return {'va':hex(va),'new_byte':new,'original':verify.json.loads(verify.encoded(before)),'mutated':verify.json.loads(verify.encoded(after))}

def operands(data):
    im=verify.Image(data)
    return {'identity_mask':u(im,0x5a7c5cd,4),'self_branch':u(im,0x5a7c5d1),
            'kind_word':u(im,0x5a7c518,8),'copy_bytes':u(im,0x5a7c580,4),
            'envelope_bytes':u(im,0x5a7c645,4),'closed_bit':u(im,0x5a7c691)}

def route(own,destination,closed,op):
    mask=sum(int(own[i]==destination[i] and (i>=4 or own[16+i]==destination[16+i]))<<i for i in range(16))
    equal=mask==op['identity_mask']
    local=equal if op['self_branch']==0x74 else not equal
    return {'local_attempt':local,'local_enqueue':local and not closed,'remote_call':not local,'copied_message_bytes':op['copy_bytes'],'allocated_envelope_bytes':op['envelope_bytes'] if local else 0}

def kind(raw,op):
    index=(raw&255) if raw&(1<<63) else 2
    return (op['kind_word']>>((index*8)&63))&255

def evaluate(data):
    op=operands(data)
    verify.require(op=={'identity_mask':65535,'self_branch':0x74,'kind_word':0x7060403020501,'copy_bytes':0x178,'envelope_bytes':0x190,'closed_bit':1},'delivery operands')
    own=bytes(range(20));cases=0
    for pos,value,closed in itertools.product(range(20),range(256),[False,True]):
        dst=bytearray(own);dst[pos]=value;local=own==dst
        expected={'local_attempt':local,'local_enqueue':local and not closed,'remote_call':not local,'copied_message_bytes':376,'allocated_envelope_bytes':400 if local else 0}
        verify.require(route(own,dst,closed,op)==expected,'identity route');cases+=1
    labels=[kind((1<<63)+i,op) for i in range(256)]
    verify.require(labels==[1,5,2,3,4,6,7,0]*32,'formatted kind projection')
    verify.require(all(kind(x,op)==2 for x in [0,1,7,(1<<63)-1]),'nonnegative kind')
    other=bytes([99])+own[1:]
    controls=[changed_relation(data,0x5a7c5cd,0xfe,lambda d:route(own,other,False,operands(d))),
              changed_relation(data,0x5a7c5d1,0x75,lambda d:route(own,own,True,operands(d))),
              changed_relation(data,0x5a7c518,2,lambda d:kind(1<<63,operands(d)))]
    return {'native_operands':op,'identity_cases':cases,'machine_kind_bytes':labels,'counterfactuals':controls,
            'broadcast_normal_return_routes':[{'closed':False,'local_enqueue':True,'remote_call':True},{'closed':True,'local_enqueue':False,'remote_call':True}],
            'limits':'Identity byte projection and label arithmetic only; raw kind values outside the source enum are machine-level controls, not valid source inputs. Broadcast ordering comes from bound call/branch spans, not a network simulation. Encoding, allocation, queue synchronization and transport delivery are opaque.'}
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--write',action='store_true');args=p.parse_args()
    data=verify.TARGET.read_bytes();verify.require(verify.sha(data)==verify.DIGEST,'wrong target')
    result=verify.encoded(evaluate(data))
    if args.write:(verify.PACKET/'relations.json').write_text(result)
    else:verify.require((verify.PACKET/'relations.json').read_text()==result,'relations drift')
    print('PASS: native operand relations and counterfactuals')
