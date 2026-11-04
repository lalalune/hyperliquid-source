#!/usr/bin/env python3
"""Operand-derived relations for the system-row RPC address projection."""
import argparse,itertools,struct
import verify
import capstone

def operands(data):
    im=verify.Image(data);cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);cs.detail=True
    instruction=lambda va:next(cs.disasm(im.get(va,15),va))
    imm=lambda va:instruction(va).operands[-1].imm
    displacement=lambda va:instruction(va).operands[-1].mem.disp
    table=0x5ea758
    return {'explicit_mask':imm(0x232e2bc),'presence_tag':imm(0x232e293),
      'row_stride':imm(0x232e0f0),'projection_stride':imm(0x232e5ff),
      'row_flag_offset':displacement(0x232e1c0)-0x4a0,
      'row_address_offset':displacement(0x232e38e)-0x10,
      'selected_field_base':instruction(0x232e2f1).operands[0].mem.disp,'selected_field_shift':imm(0x232e2ee),
      'fallback':im.get(0x450f20,16)+int(imm(0x232e3ca)).to_bytes(4,'little'),
      'stop':im.get(0x4507f0,16),'context':im.get(0x5eb259,19),
      'dispatch':[table+struct.unpack('<i',im.get(table+4*j,4))[0] for j in range(5)]}

def choose(kind,word1,present,flag,supplied,fields,callback,o):
    # This is a new bounded relation over decoded fields, not instruction execution.
    if flag&o['explicit_mask']:return supplied,'supplied',None
    if kind<3 and present!=o['presence_tag']:return bytes(20),'zero',None
    field=o['selected_field_base']+((kind!=0 or word1!=0)<<o['selected_field_shift'])
    if fields.get(field,0)==0:return o['fallback'],'repeated',field
    return callback,'callback',field

def evaluate(data):
    o=operands(data)
    verify.require(o=={'explicit_mask':1,'presence_tag':1,'row_stride':288,'projection_stride':560,
      'row_flag_offset':264,'row_address_offset':265,'selected_field_base':48,'selected_field_shift':4,
      'fallback':bytes([34])*20,'stop':bytes([5])+bytes(15),'context':b'system_txs_by_block',
      'dispatch':[0x232e21f,0x232e268,0x232e256,0x232e239,0x232e231]},'native operand contract')
    supplied=bytes(range(20));callback=bytes(range(20,40));decisions=0
    for kind,word1,present,flag,f0,f1 in itertools.product(range(5),[0,1,(1<<64)-1],[0,1,2,255],range(256),[0,1],[0,1]):
        fields={0x30:f0,0x40:f1};actual=choose(kind,word1,present,flag,supplied,fields,callback,o)
        field=0x30 if kind==0 and word1==0 else 0x40
        expected=(supplied,'supplied',None) if flag%2 else (bytes(20),'zero',None) if kind<3 and present!=1 else (bytes([34])*20,'repeated',field) if fields[field]==0 else (callback,'callback',field)
        verify.require(actual==expected,'address precedence relation');decisions+=1
    # The stop sentinel is a 16-byte pair (5,0); equal first qword alone is insufficient.
    stop_cases=0
    for a,b in itertools.product([0,1,4,5,6,(1<<64)-1],repeat=2):
        raw=a.to_bytes(8,'little')+b.to_bytes(8,'little')
        verify.require((raw==o['stop'])==(a==5 and b==0),'full-width row terminator');stop_cases+=1
    mutants=[]
    for va,value,args in [
      (0x232e2bf,2,(0,0,0,1,supplied,{0x30:0,0x40:0},callback)),
      (0x232e3ce,0x23,(4,1,0,0,supplied,{0x30:0,0x40:0},callback)),
      (0x232e2f0,3,(4,1,0,0,supplied,{0x30:0,0x40:1,0x38:0},callback))]:
        changed=bytearray(data);changed[verify.Image(data).off(va)]=value
        before=choose(*args,o);after=choose(*args,operands(changed));verify.require(before!=after,'counterfactual survived')
        mutants.append({'va':hex(va),'new_byte':value,'before':[before[0].hex(),*before[1:]],'after':[after[0].hex(),*after[1:]]})
    return {'native_operands':{k:v.hex() if isinstance(v,bytes) else v for k,v in o.items()},'decision_cases':decisions,'stop_cases':stop_cases,'counterfactuals':mutants,
      'limits':'Valid decoded kinds0..4 and valid row/vector extents are assumed. Relations do not decode transactions, execute the capture, prove callback effects or establish full RPC equivalence.'}
if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--write',action='store_true');args=parser.parse_args()
    data=verify.TARGET.read_bytes();verify.require(verify.sha(data)==verify.DIGEST,'wrong target')
    text=verify.encoded(evaluate(data))
    if args.write:(verify.PACKET/'relations.json').write_text(text)
    else:verify.require((verify.PACKET/'relations.json').read_text()==text,'relations drift')
    print('PASS: system RPC projection relations and operand counterfactuals')
