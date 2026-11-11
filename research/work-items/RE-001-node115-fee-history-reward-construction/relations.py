#!/usr/bin/env python3
"""Operand-bound fee-history equations, without captured execution or emulation."""
import argparse,json,random,struct
import capstone
import verify
MASK=(1<<64)-1

def operands(data):
    im=verify.Image(data);cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);cs.detail=True
    ins=lambda a:next(cs.disasm(im.get(a,15),a))
    imm=lambda a:ins(a).operands[-1].imm
    disp=lambda a:next(op.mem.disp for op in ins(a).operands if op.type==capstone.x86.X86_OP_MEM)
    return {'tx_stride':imm(0x2355665),'loop_tx_stride':imm(0x2355783),
      'receipt_stride':imm(0x235577f),'cumulative_offset':disp(0x235564e),
      'prior_offset':disp(0x2355658),'base_pointer_offset':disp(0x2355675),
      'first_cap_offset':disp(0x2355696),'later_cap_offset':disp(0x23557c8),
      'nonzero_shift':imm(0x2355693),'later_nonzero_shift':imm(0x23557c5),
      'first_threshold':imm(0x23556bc),'later_threshold':imm(0x23557f6),
      'first_tip_offset':disp(0x23556c6),'later_tip_offset':disp(0x2355800),
      'output_stride':imm(0x235577b),'output_gas_offset':disp(0x2355703),
      'floor_branch':ins(0x23556b3).mnemonic,'later_floor_branch':ins(0x23557ed).mnemonic,
      'threshold_branch':ins(0x23556c4).mnemonic,'later_threshold_branch':ins(0x23557fe).mnemonic,
      'first_min':ins(0x23556d7).mnemonic,'later_min':ins(0x2355811).mnemonic,
      'first_gas_underflow':ins(0x235565c).mnemonic,'later_gas_underflow':ins(0x23557a5).mnemonic,
      'zip_select':ins(0x2a20da5).mnemonic,'empty_branch':ins(0x2355631).mnemonic,
      'initial_index':imm(0x2a20dd1),'initial_previous':imm(0x2a20df5),
      'empty_descriptor':[imm(0x2355853),imm(0x235585a),imm(0x2355862)]}

def below(a,b):
    # Independent limb comparator for the instruction-derived relation.
    alo,ahi=a&MASK,a>>64;blo,bhi=b&MASK,b>>64
    return ahi<bhi or (ahi==bhi and alo<blo)

def branch(name,is_below):
    if name=='jb':return is_below
    if name=='jae':return not is_below
    raise ValueError('unsupported conditional: '+name)

def read128(raw,offset):
    lo,hi=struct.unpack_from('<QQ',raw,offset);return lo|(hi<<64)

def projected_fee(row,base,o,later=False):
    prefix=read128(row,0);capoff=o['later_cap_offset' if later else 'first_cap_offset']
    shift=o['later_nonzero_shift' if later else 'nonzero_shift']
    cap=read128(row,capoff+((1 if prefix else 0)<<shift))
    if branch(o['later_floor_branch' if later else 'floor_branch'],below(cap,base)):return 0
    low=(cap&MASK)-base;borrow=low<0
    high=((cap>>64)-int(borrow))&MASK
    difference=(low&MASK)|(high<<64)
    threshold=o['later_threshold' if later else 'first_threshold']
    if branch(o['later_threshold_branch' if later else 'threshold_branch'],below(prefix,threshold)):return difference
    priority=read128(row,o['later_tip_offset' if later else 'first_tip_offset'])
    select=o['later_min' if later else 'first_min']
    verify.require(select in ['cmovb','cmovae'],'unsigned minimum conditional')
    take=below(priority,difference)
    if select=='cmovae':take=not take
    return priority if take else difference

def tx(prefix,zero_cap,other_cap,priority):
    raw=bytearray(336)
    for offset,value in [(0,prefix),(64,zero_cap),(80,other_cap),(96,priority)]:
        struct.pack_into('<QQ',raw,offset,value&MASK,value>>64)
    return raw

def oracle_fee(prefix,a,b,tip,base):
    difference=max((a if prefix==0 else b)-base,0)
    return min(difference,tip) if prefix>=2 else difference

def construct(transactions,cumulative,base,o,start=0,previous=0):
    end=min(len(transactions),len(cumulative))
    if start>=end:return []
    rawtx=b''.join(transactions);rawreceipts=bytearray(len(cumulative)*40)
    for i,value in enumerate(cumulative):struct.pack_into('<Q',rawreceipts,i*40+24,value)
    rows=[];prev=previous
    for i in range(start,end):
        current=struct.unpack_from('<Q',rawreceipts,i*o['receipt_stride']+o['cumulative_offset'])[0]
        verify.require(o['later_gas_underflow' if i>start else 'first_gas_underflow']=='jb','checked gas branch')
        if current<prev:raise ArithmeticError('cumulative gas underflow')
        item=rawtx[i*o['tx_stride']:i*o['tx_stride']+336]
        rows.append([projected_fee(item,base,o,i>start),current-prev]);prev=current
    return rows

def evaluate(data):
    o=operands(data)
    expected={'tx_stride':336,'loop_tx_stride':336,'receipt_stride':40,'cumulative_offset':24,
      'prior_offset':56,'base_pointer_offset':48,'first_cap_offset':64,'later_cap_offset':64,
      'nonzero_shift':4,'later_nonzero_shift':4,'first_threshold':2,'later_threshold':2,
      'first_tip_offset':96,'later_tip_offset':96,'output_stride':32,'output_gas_offset':16,
      'floor_branch':'jb','later_floor_branch':'jb','threshold_branch':'jb','later_threshold_branch':'jb',
      'first_min':'cmovb','later_min':'cmovb','first_gas_underflow':'jb','later_gas_underflow':'jb',
      'zip_select':'cmovb','empty_branch':'jbe','initial_index':0,'initial_previous':0,'empty_descriptor':[0,16,0]}
    verify.require(o==expected,'native operand contract')
    rng=random.Random(11588);cases=[]
    bounds=[0,1,2,3,MASK-1,MASK,MASK+1,(1<<127)-1,1<<127,(1<<128)-1]
    for prefix in bounds:
        for cap in bounds:
            for base in [0,1,MASK-1,MASK]:
                for tip in [0,1,MASK,1<<64,(1<<128)-1]:
                    cases.append((prefix,cap,(cap+1)&((1<<128)-1),tip,base))
    for _ in range(5000):cases.append((rng.getrandbits(128),rng.getrandbits(128),rng.getrandbits(128),rng.getrandbits(128),rng.getrandbits(64)))
    for prefix,a,b,tip,base in cases:
        row=tx(prefix,a,b,tip);expected_fee=oracle_fee(prefix,a,b,tip,base)
        for later in [False,True]:verify.require(projected_fee(row,base,o,later)==expected_fee,'128-bit reward against integer oracle')
    vector_cases=0;underflow_cases=0
    for nt in range(9):
        for nr in range(9):
            items=[tx(i%4,100+i,101+i,7+i) for i in range(nt)];cum=[i*i for i in range(nr)]
            for start in range(min(nt,nr)+2):
                prev=cum[start-1] if start and start<=len(cum) else 0
                expected_rows=[[oracle_fee(i%4,100+i,101+i,7+i,100),cum[i]-(prev if i==start else cum[i-1])] for i in range(start,min(nt,nr))]
                verify.require(construct(items,cum,100,o,start,prev)==expected_rows,'zip truncation, start and ordered gas differences');vector_cases+=1
    for nt,nr,cum,prior in [(1,1,[0],1),(2,2,[9,8],0),(4,3,[5,7,6],0),(1,1,[MASK-1],MASK)]:
        try:construct([tx(2,0,10,3)]*nt,cum,2,o,previous=prior)
        except ArithmeticError:underflow_cases+=1
        else:raise ValueError('gas underflow survived')
    # A decreasing tail beyond the zipped prefix is not consumed.
    verify.require(construct([tx(2,0,10,3)],[5,4],2,o)==[[3,5]],'unpaired bad receipt ignored')
    verify.require(construct([tx(0,MASK,0,0)],[MASK],0,o)==[[MASK,MASK]],'maximum gas without overflow')
    vector_cases+=2
    mutants=[];im=verify.Image(data)
    def change(va,new,label,projection):
        modified=bytearray(data);modified[im.off(va)]=new
        before=projection(o);after=projection(operands(modified))
        verify.require(before!=after,'counterfactual survived: '+label)
        mutants.append({'va':hex(va),'replacement':new,'meaning':label,'before':before,'after':after})
    change(0x235569a,0x50,'zero-prefix cap reads a different field',lambda x:projected_fee(tx(0,10,70,3),2,x))
    change(0x23556bf,3,'prefix two no longer caps the difference',lambda x:projected_fee(tx(2,0,100,3),2,x))
    change(0x23556b3,0x73,'cap-below-base branch reverses',lambda x:projected_fee(tx(0,10,0,0),2,x))
    change(0x2355652,0x10,'receipt reads another qword',lambda x:construct([tx(2,0,10,3)],[5],2,x))
    return {'native_operands':o,'fee_cases':len(cases)*2,'vector_cases':vector_cases,'underflow_cases':underflow_cases,
      'counterfactuals':mutants,'limits':'Raw field/prefix relation on valid storage, not proof that every synthetic prefix is a reachable enum variant. No target execution/emulation, allocator/panic-runtime equivalence, receipt log cloning, percentile selection, fee units or exact source provenance.'}

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--write',action='store_true');args=parser.parse_args()
    data=verify.TARGET.read_bytes();verify.require(verify.sha(data)==verify.DIGEST,'wrong target');text=verify.encoded(evaluate(data))
    if args.write:(verify.PACKET/'relations.json').write_text(text)
    else:verify.require((verify.PACKET/'relations.json').read_text()==text,'relations drift')
    print('PASS: fee-history reward construction relations')
