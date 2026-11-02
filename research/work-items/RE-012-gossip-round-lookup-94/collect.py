#!/usr/bin/env python3
"""Digest-bound static lookup layout and local AL-use evidence. Never runs target."""
import hashlib
import json
from pathlib import Path
import platform
import re
import struct
import subprocess
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT/'tools'))
from elf_index import sections, unwind_index
from fde_extents import eh_frame_records

DIGEST='3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
BASE='e5c9b6436876b2a4a39daef813171f9879317699'
START,END=0x4743490,0x4744152
LLVM='/Library/Developer/CommandLineTools/usr/bin/'
PINS={
 'root':(0x47436a4,'498b8770380000'),
 'query_word':(0x47436b9,'498b8f88380000'),
 'depth_word':(0x47436c0,'498b9778380000'),
 'node_count':(0x47436c7,'0fb7b81a020000'),
 'count_times40':(0x47436ce,'8d34fd000000004c8d0cb6'),
 'key_compare':(0x47436f5,'483b4cf010'),
 'unsigned_compare_map':(0x47436fa,'410f97c24180da00'),
 'value_stride':(0x4743702,'4983c02848ffc6'),
 'search_continue':(0x4743709,'4180fa0174e1'),
 'descend':(0x4743723,'4883ea017222488b84f020020000eb94'),
 'matched_first_word':(0x4743733,'4a8b4c0038'),
 'matched_zero_test':(0x4743738,'4885c97439'),
 'matched_payload':(0x474373d,'f3420f6f440040b801000000eb31'),
 'missing_tag':(0x474374b,'66c74424109700'),
 'missing_word0_zero':(0x4743752,'48c78424e001000000000000'),
 'missing_word2_zero':(0x474375e,'48c78424f001000000000000'),
 'matched_zero':(0x4743776,'660fefc031c0'),
 'candidate_handoff':(0x47437f3,'488dbc24e0010000488db42420010000'),
 'call_result_rcx_load':(0x4743808,'488b8c24e0010000'),
 'call_flags_kill':(0x4743810,'4885c9'),
 'callee_saved_store':(0x4743813,'4c89a42488000000'),
 'local_result_branch':(0x474381b,'743d'),
 'nonnull_rdx_load':(0x474381d,'488b9424e8010000'),
 'nonnull_rax_kill':(0x4743825,'488b8424f0010000'),
 'zero_path_rcx_kill':(0x474385a,'31c9'),
 'zero_path_rax_kill':(0x474385c,'31c0'),
}
CALLS={0x474376f:0x3379490,0x47437d6:0x3bb3c40,
       0x4743803:0x49a58f0,0x4743886:0x49478b0}


def need(ok,message):
    if not ok:raise ValueError(message)


def main():
    data=(ROOT/'artifacts/node/94/hl-node').read_bytes()
    need(len(data)==91774280 and hashlib.sha256(data).hexdigest()==DIGEST,'target identity')
    secs=sections(data)
    def offset(va,n):
        matches=[s for s in secs if s['type']!=8 and s['address']<=va and va+n<=s['address']+s['size']]
        need(len(matches)==1,'unique address mapping')
        return matches[0]['offset']+va-matches[0]['address']
    def raw(va,n):
        o=offset(va,n);return data[o:o+n]
    def validate(reader):
        for name,(va,hx) in PINS.items():
            need(reader(va,len(bytes.fromhex(hx))).hex()==hx,name)
        for va,target in CALLS.items():
            bs=reader(va,5)
            need(bs[0]==0xe8 and va+5+struct.unpack('<i',bs[1:])[0]==target,'call '+hex(va))
    validate(raw)
    cies,fdes=eh_frame_records(data,secs)
    fs=[f for f in fdes if f['start']==START]
    need(len(fs)==1 and fs[0]['end']==END,'owner FDE')
    f=fs[0];_,index=unwind_index(data)
    ii=[i for i in index if i['start']==START]
    need(len(ii)==1 and ii[0]['fde']==f['fde'],'owner unwind index')
    cmd=[LLVM+'llvm-objdump','-d','--x86-asm-syntax=intel','--start-address='+hex(START),
         '--stop-address='+hex(END),'artifacts/node/94/hl-node']
    text=subprocess.check_output(cmd,cwd=str(ROOT),text=True)
    rows=[];cursor=START
    for line in text.splitlines():
        m=re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)(.*)$',line)
        if m:
            va,bs=int(m[1],16),bytes.fromhex(m[2]);asm=m[3].strip()
            need(va==cursor and raw(va,len(bs))==bs and '<unknown>' not in asm,'contiguous LLVM bytes')
            rows.append((va,bs,asm));cursor+=len(bs)
    need(cursor==END,'exact LLVM end')
    by_va={va:(bs,asm) for va,bs,asm in rows}
    need(all(va in by_va for va,_ in PINS.values()) and all(va in by_va for va in CALLS),'anchor instruction boundary')
    frame=next(s for s in secs if s['name']=='.eh_frame')
    dcmd=[LLVM+'llvm-dwarfdump','--eh-frame='+hex(f['fde']-frame['address']),'artifacts/node/94/hl-node']
    dwarf=subprocess.check_output(dcmd,cwd=str(ROOT),text=True)
    need('pc=04743490...04744152' in dwarf,'independent LLVM FDE')
    selected_edges=[]
    for va,bs,asm in rows:
        if not 0x47436a4<=va<0x4743896:continue
        target=None
        if len(bs)==2 and (0x70<=bs[0]<=0x7f or bs[0]==0xeb):
            target=va+2+struct.unpack('<b',bs[1:])[0]
        elif len(bs)==5 and bs[0]==0xe9:
            target=va+5+struct.unpack('<i',bs[1:])[0]
        elif len(bs)==6 and bs[0]==0x0f and 0x80<=bs[1]<=0x8f:
            target=va+6+struct.unpack('<i',bs[2:])[0]
        if target is not None:
            need(target in by_va,'selected direct branch boundary')
            selected_edges.append({'site':hex(va),'target':hex(target),'raw_hex':bs.hex(),'LLVM':asm})

    # Two local continuations, not execution/simulation of target instructions.
    # Their exact supported bytes are above; branch target is decoded below.
    branch=by_va[0x474381b][0]
    need(branch[0]==0x74 and 0x474381b+2+struct.unpack('<b',branch[1:])[0]==0x474385a,'local branch destination')
    paths=[['0x4743808','0x4743810','0x4743813','0x474381b','0x474381d','0x4743825'],
           ['0x4743808','0x4743810','0x4743813','0x474381b','0x474385a','0x474385c']]
    # Check fallthrough adjacency within each supported corridor. The sole
    # conditional skips only to the alternative zero path, handled explicitly.
    for path in paths:
        for left,right in zip(path,path[1:]):
            a,b=int(left,16),int(right,16)
            need(a in by_va and b in by_va,'local path boundary')
            need(a==0x474381b or a+len(by_va[a][0])==b,'local path fallthrough')
    controls=[]
    mutations=[('query-offset',0x47436bc),('node-count-offset',0x47436ca),
               ('unsigned-comparison',0x47436fc),('value-stride',0x4743705),
               ('child-offset',0x474372f),('match-field-offset',0x4743737),
               ('payload-offset',0x4743743),('missing-initializer',0x4743769),
               ('comparison-call-target',0x4743804),('flags-kill-operand',0x4743812),
               ('local-result-edge',0x474381c),('nonnull-result-kill',0x4743828),
               ('zero-result-kill',0x474385d)]
    for name,at in mutations:
        def changed(va,n):
            bs=bytearray(raw(va,n))
            if va<=at<va+n:bs[at-va]^=1
            return bytes(bs)
        try:validate(changed)
        except ValueError as error:
            controls.append({'name':name,'mutated_va':hex(at),'rejected':True,'failed_obligation':str(error)})
        else:raise ValueError('unrejected mutation '+name)
    def metadata_record(va):
        n=struct.unpack('<I',raw(va,4))[0]+4
        return {'va':hex(va),'file_offset':hex(offset(va,n)),'raw_hex':raw(va,n).hex()}
    interpreted=[(0x47436a4,0x4743896)]
    records={'task':'RE-012','component':'node-runtime','source_base':BASE,
             'target_sha256':DIGEST,'target_size':len(data),
             'reference_gitlink':'999556f6e0a474b8312db96ec3149e1c44e97c23',
             'coordinates':'linked ELF VA; ends exclusive; section-resolved file offsets',
             'owner':{**{k:hex(v) if isinstance(v,int) else v for k,v in f.items()},
                      'bytes':END-START,'LLVM_instruction_rows':len(rows),
                      'code_sha256':hashlib.sha256(raw(START,END-START)).hexdigest(),
                      'FDE_record':metadata_record(f['fde']),'CIE_record':metadata_record(f['cie'])},
             'interpreted_windows':[{'start':hex(a),'end':hex(b),'file_offset':hex(offset(a,b-a)),
                 'bytes':b-a,'instruction_rows':sum(a<=v<b for v,_,_ in rows),'raw_hex':raw(a,b-a).hex()}
                 for a,b in interpreted],
             'direct_boundaries':[{'site':hex(va),'target':hex(t),'raw_hex':raw(va,5).hex(),
                  'callee_FDE':{k:hex(v) if isinstance(v,int) else v for k,v in
                        next(ff for ff in fdes if ff['start']==t).items()}}
                    for va,t in CALLS.items()],
             'pins':{name:{'va':hex(va),'file_offset':hex(offset(va,len(bytes.fromhex(hx)))),'raw_hex':hx}
                     for name,(va,hx) in PINS.items()},
             'local_AL_liveness':{'normal_call_successor':'0x4743808','paths_until_full_RAX_definition':paths,
                                  'first_EFLAGS_overwrite':'0x4743810',
                                  'limits':'local ordinary-return corridor only; no global purity or ignored-effects claim'},
             'selected_direct_branch_edges':selected_edges,
             'negative_controls':controls,'Python':platform.python_version(),
             'platform':platform.system()+' '+platform.machine(),
             'LLVM_version':subprocess.check_output([LLVM+'llvm-objdump','--version'],text=True).splitlines()[0],
             'parser_sha256':{p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest()
                              for p in ('tools/elf_index.py','tools/fde_extents.py')},
             'limits':['No captured instruction evaluation or target execution','No source type/round interpretation established',
                       'Opaque callees and alias effects are not closed','Existing seed/helper work is context, not new coverage',
                       'No Rust, identity comparison, node completion or acceptance gate claim']}
    (HERE/'4743490.llvm.txt').write_text(' '.join(cmd)+'\n'+text.rstrip('\n')+'\n')
    (HERE/'4743490.fde.llvm.txt').write_text(' '.join(dcmd)+'\n'+dwarf.rstrip('\n')+'\n')
    (HERE/'records.json').write_text(json.dumps(records,indent=2)+'\n')
    print('PASS: digest/FDE/index/LLVM owner; 26 anchors; four direct boundaries; two local AL-kill corridors; 13 rejected corruptions')


if __name__=='__main__':main()
