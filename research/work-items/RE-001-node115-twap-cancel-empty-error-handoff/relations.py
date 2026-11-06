#!/usr/bin/env python3
"""Static path certificates for a conditional error continuation; no emulation."""
import argparse,json
import capstone
import verify

PATHS={
 'perp_removal_after_store':[(0x2d2c9c8,0x2d2ca55),(0x2d2ca55,0x2d2ca5c),(0x2d2cacc,0x2d2cae9),(0x2d2cc60,0x2d2cce9),(0x2d2cdee,0x2d2ce03)],
 'spot_removal_after_store':[(a+0x940,b+0x940) for a,b in [(0x2d2c9c8,0x2d2ca55),(0x2d2ca55,0x2d2ca5c),(0x2d2cacc,0x2d2cae9),(0x2d2cc60,0x2d2cce9),(0x2d2cdee,0x2d2ce03)]],
 'perp_core_error':[(0x2c2f13e,0x2c2f1b2),(0x2c2f4c7,0x2c2f4ef),(0x2c2f627,0x2c2f68f)],
 'spot_core_error':[(0x2c2f215,0x2c2f289),(0x2c2f607,0x2c2f627),(0x2c2f627,0x2c2f68f)],
 'perp_empty_handoff':[(0x2419810,0x2419889),(0x241a128,0x241a144)],
 'spot_empty_handoff':[(0x241a3c0,0x241a42c),(0x241af23,0x241af3f)],
 'perp_empty_drop':[(0x2822f50,0x2822f86),(0x2822f9a,0x2822fa3),(0x2822fbe,0x2822fc8)],
 'spot_empty_drop':[(0x2824790,0x28247c6),(0x28247da,0x28247e3),(0x28247fe,0x2824808)],
 'direct_wrapper_after_core':[(0x2a2fbe7,0x2a2fc8e),(0x2a2fcf0,0x2a2fd02)],
 'api_wrapper_after_core':[(0x2c0a86d,0x2c0a91b),(0x2c0aa96,0x2c0aaa8)],
}
EXPECTED_CALLS={'perp_core_error':[0x2419810],'spot_core_error':[0x241a3c0],
 'perp_empty_handoff':[0x2822f50],'spot_empty_handoff':[0x2824790]}

def decoded(data):
    im=verify.Image(data);cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);cs.detail=True
    return im,cs,lambda a:next(cs.disasm(im.get(a,15),a))

def fields(data):
    im,cs,ins=decoded(data)
    imm=lambda a:ins(a).operands[-1].imm
    disp=lambda a:next(x.mem.disp for x in ins(a).operands if x.type==capstone.x86.X86_OP_MEM)
    return {'perp_count_offset':disp(0x2d2c9cb),'spot_count_offset':disp(0x2d2d30b),
      'perp_removed_tag':imm(0x2d2ca4f),'spot_removed_tag':imm(0x2d2d38f),
      'perp_error':imm(0x2d2ccd6),'spot_error':imm(0x2d2d616),
      'perp_error_variant':imm(0x2d2ccdd),'spot_error_variant':imm(0x2d2d61d),
      'perp_initial_vector':[imm(0x2c2f0b0),imm(0x2c2f0b8),imm(0x2c2f0c1)],
      'spot_initial_vector':[imm(0x2c2f1c3),imm(0x2c2f1cb),imm(0x2c2f1d4)],
      'perp_empty_branch':ins(0x2419883).mnemonic,'spot_empty_branch':ins(0x241a426).mnemonic,
      'direct_outer_tag':imm(0x2a2fc42),'api_outer_tag':imm(0x2c0a8c8)}

def path_records(data):
    im,cs,ins=decoded(data);answer={}
    for name,blocks in PATHS.items():
        calls=[];writes=[];edges=[];count=0
        for index,(a,b) in enumerate(blocks):
            rows=list(cs.disasm(im.get(a,b-a),a))
            verify.require(rows and rows[-1].address+rows[-1].size==b,'path instruction boundary')
            for i in rows:
                count+=1
                if i.mnemonic=='call':
                    verify.require(i.operands[0].type==capstone.x86.X86_OP_IMM,'selected path indirect call')
                    calls.append(i.operands[0].imm)
                # Explicit native memory destinations; pushes/calls use the stack.
                for op in i.operands:
                    if op.type==capstone.x86.X86_OP_MEM and op.access&capstone.CS_AC_WRITE:
                        writes.append({'va':hex(i.address),'base':i.reg_name(op.mem.base),'offset':op.mem.disp,'width':op.size})
            last=rows[-1]
            if index+1<len(blocks):
                next_address=blocks[index+1][0]
                if last.mnemonic.startswith('j'):
                    target=last.operands[0].imm
                    verify.require(next_address==target or (last.mnemonic!='jmp' and next_address==b),'selected path edge')
                    edges.append({'va':hex(last.address),'condition':last.mnemonic,'taken':next_address==target,'next':hex(next_address)})
                else:verify.require(next_address==b,'nonbranch discontinuity')
            else:verify.require(last.mnemonic=='ret','selected normal return')
        verify.require(calls==EXPECTED_CALLS.get(name,[]),'selected call closure: '+name)
        allowed={'rsp'}
        if 'removal' in name:allowed|={'r13','r15'}
        elif 'core_error' in name or 'wrapper' in name:allowed|={'rbx'}
        elif 'handoff' in name:allowed|={'rdi'}
        verify.require(all(x['base'] in allowed for x in writes),'unexpected write base on '+name)
        if 'removal' in name:
            state_writes=[x for x in writes if x['base']=='r13']
            verify.require(len(state_writes)==1 and state_writes[0]['offset']==24 and state_writes[0]['width']==8,'only selected state count store')
        answer[name]={'blocks':[[hex(a),hex(b)] for a,b in blocks],'instructions':count,'calls':[hex(x) for x in calls],'memory_writes':writes,'edges':edges}
    return answer

def consequence(o,route,initial_count):
    # Abstract boundary relation, not a run of native instructions. The path
    # certificate supplies the no-restoration premise after the observed store.
    assert initial_count>0
    count_offset=o[route+'_count_offset'];after={24:initial_count}
    after[count_offset]=initial_count-1
    empty=o[route+'_initial_vector']==[0,8,0]
    no_records=empty and o[route+'_empty_branch']=='je'
    return {'count_at24':after[24],'internal_error':o[route+'_error'],
      'record_processing_skipped':no_records,'outer_tag':o['direct_outer_tag']}

def evaluate(data):
    o=fields(data)
    verify.require(o=={'perp_count_offset':24,'spot_count_offset':24,'perp_removed_tag':2,'spot_removed_tag':2,
      'perp_error':212,'spot_error':212,'perp_error_variant':1,'spot_error_variant':1,
      'perp_initial_vector':[0,8,0],'spot_initial_vector':[0,8,0],
      'perp_empty_branch':'je','spot_empty_branch':'je','direct_outer_tag':5,'api_outer_tag':5},'joined error operands')
    paths=path_records(data)
    # Validate the predicates that choose the retained paths. The compact
    # representation premise makes the conversion conjunction false regardless
    # of count; no unknown helper lies after the selected store on this path.
    im,cs,ins=decoded(data)
    for delta in [0,0x940]:
        for a,m in [(0x2d2ca53,'jne'),(0x2d2cae3,'jne'),(0x2d2ccd4,'jne')]:verify.require(ins(a+delta).mnemonic==m,'selected removal predicate')
    for a in [0x2c2f143,0x2c2f21a]:verify.require(ins(a).mnemonic=='jne','error result reaches handoff without append')
    for a in [0x2822f84,0x2822fa1,0x28247c4,0x28247e1]:verify.require(ins(a).mnemonic=='je','empty zero-capacity drop predicates')
    cases=[]
    for route in ['perp','spot']:
        for n in [1,2,31,32,(1<<64)-1]:
            actual=consequence(o,route,n)
            verify.require(actual=={'count_at24':n-1,'internal_error':212,'record_processing_skipped':True,'outer_tag':5},'conditional boundary relation')
            cases.append({'route':route,'before':n,'after':actual})
    mutants=[]
    def change(va,new,label):
        modified=bytearray(data);modified[im.off(va)]=new
        before=consequence(o,'perp',3);after=consequence(fields(modified),'perp',3)
        verify.require(before!=after,'counterfactual survived: '+label)
        mutants.append({'va':hex(va),'replacement':new,'meaning':label,'before':before,'after':after})
    change(0x2d2c9ce,16,'decrement lands in another state field')
    change(0x2d2ccdb,0xd5,'different internal error number')
    change(0x2419884,0x85,'empty handoff branch polarity changes')
    change(0x2a2fc44,15,'different outer wrapper variant')
    return {'native_fields':o,'selected_paths':paths,'boundary_cases':len(cases),'cases':cases,'counterfactuals':mutants,
      'premises':['Selected compact count store was reached and returns normally from earlier shifting helpers.','Removed row tag is two; compact representation excludes conversion branch.','Call outputs and scratch vectors use the observed distinct stack locations; valid native ABI/storage.'],
      'limits':'No target execution/emulation, proof that the selected tag combination is externally reachable, complete removal/movement equivalence, global alias or outer rollback/commit/persistence claim.'}

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--write',action='store_true');args=parser.parse_args()
    data=verify.TARGET.read_bytes();verify.require(verify.sha(data)==verify.DIGEST,'wrong target');text=verify.encoded(evaluate(data))
    if args.write:(verify.PACKET/'relations.json').write_text(text)
    else:verify.require((verify.PACKET/'relations.json').read_text()==text,'relations drift')
    print('PASS: joined TWAP empty error path certificates')
