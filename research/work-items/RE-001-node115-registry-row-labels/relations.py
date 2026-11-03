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
    return {'va':hex(va),'new_byte':new,'original':before,'mutated':after}

def operands(data):
    im=verify.Image(data)
    return {'magic':[u(im,a,8) for a in (0x22b5a27,0x22b5c50,0x22b5ece)],
            'shift':[u(im,a) for a in (0x22b5a38,0x22b5c5e,0x22b5edf)],
            'divisor':[u(im,a,4) for a in (0x22b5a4c,0x22b5c72,0x22b5eef)],
            'namespace_offset':[u(im,a) for a in (0x22b5a46,0x22b5c6c,0x22b5ee9)],
            'bounds_branch':[u(im,a) for a in (0x22b5a57,0x22b5c7d,0x22b5efa)],
            'row_shift':[u(im,a) for a in (0x22b5a60,0x22b5c86,0x22b5f03)]}

def project(identifier,descriptor,labels,op,site=0):
    quotient=((identifier*op['magic'][site])>>64)>>op['shift'][site]
    remainder=(identifier-quotient*op['divisor'][site])%(1<<64)
    namespace=descriptor.get(op['namespace_offset'][site],-1)
    below=remainder<len(labels)
    in_range=below if op['bounds_branch'][site]==0x73 else not below
    valid=quotient==namespace and in_range
    # Safe projection stops at the metadata access for counterfactual out-of-range rows.
    if valid and remainder>=len(labels):return {'invalid_access':remainder}
    label=labels[remainder] if valid else b''
    return {'label_hex':label.hex(),'capacity':len(label),'length':len(label),
            'pointer':'owned copy' if label else 1,'value_helper_called':True,'end_marker':False}

def evaluate(data):
    op=operands(data)
    for name,expected in [('magic',0x346dc5d63886594b),('shift',11),('divisor',10000),('namespace_offset',80),('bounds_branch',0x73),('row_shift',5)]:
        verify.require(op[name]==[expected]*3,'projection operand agreement: '+name)
    ids=set([0,1,9999,10000,10001,19999,20000,(1<<64)-1])
    for q in [0,1,2,9999,10000,(1<<32)-1,((1<<64)-1)//10000]:
        for delta in [-1,0,1,9998,9999,10000]:
            x=q*10000+delta
            if 0<=x<1<<64:ids.add(x)
    cases=0
    for identifier,namespace,labels in itertools.product(sorted(ids),[0,1,2,(1<<32)-1], [[],[b''],[b'A'],[b'X',b'',b'YZ']]):
        quotient=((identifier*op['magic'][0])>>64)>>op['shift'][0]
        verify.require(quotient==identifier//10000,'division boundary')
        index=identifier%10000
        selected=labels[index] if identifier//10000==namespace and index<len(labels) else b''
        expected={'label_hex':selected.hex(),'capacity':len(selected),'length':len(selected),'pointer':'owned copy' if selected else 1,'value_helper_called':True,'end_marker':False}
        for site in range(3):verify.require(project(identifier,{80:namespace},labels,op,site)==expected,'label fallback');cases+=1
    controls=[changed_relation(data,0x22b5a4c,0x11,lambda d:project(10001,{80:1},[b'A',b'B'],operands(d))),
              changed_relation(data,0x22b5a46,0x51,lambda d:project(1,{80:0,81:1},[b'A',b'B'],operands(d))),
              changed_relation(data,0x22b5a57,0x72,lambda d:project(1,{80:0},[b'A',b'B'],operands(d)))]
    return {'native_operands':op,'identifier_boundaries':len(ids),'projection_cases':cases,'counterfactuals':controls,
            'output_layout':{'bytes':96,'capacity':0,'pointer':8,'length':16,'opaque_helper_output':[24,96],'end_first_word':'0x8000000000000000'},
            'limits':'Only observed valid iterator rows, safe descriptors and normally returning helper/allocation paths. Selected division boundaries cross-check the multiply-high formula; this test count is not exhaustive u64 enumeration. Generic tree/ring iteration, value-helper semantics, final sorting/deduplication and map type are unproved. No target execution or emulation.'}

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--write',action='store_true');args=p.parse_args()
    data=verify.TARGET.read_bytes();verify.require(verify.sha(data)==verify.DIGEST,'wrong target')
    result=verify.encoded(evaluate(data))
    if args.write:(verify.PACKET/'relations.json').write_text(result)
    else:verify.require((verify.PACKET/'relations.json').read_text()==result,'relations drift')
    print('PASS: native operand relations and counterfactuals')
