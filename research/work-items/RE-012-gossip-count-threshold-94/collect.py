#!/usr/bin/env python3
"""Static node94 count/threshold guards; never execute or emulate target code."""
import hashlib
import json
from pathlib import Path
import platform
import re
import struct
import subprocess
import sys

sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
sys.path.insert(0,str(ROOT/'tools'))
from elf_index import sections,unwind_index
from fde_extents import eh_frame_records

DIGEST='3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
START,END=0x4743490,0x4744152
LLVM='/Library/Developer/CommandLineTools/usr/bin/'
PINS={
 'input_word_load':(0x47434aa,'488b423048898424b0010000'),
 'post_lookup_word_reload':(0x47438d0,'488b9c24b0010000'),
 'collector_arguments':(0x474394b,'4c8da42470010000488db424480200004c89e7'),
 'count_compare':(0x4743963,'48399c2480010000'),
 'word_save':(0x474396b,'48899c24c0010000'),
 'count_mismatch_edge':(0x4743973,'0f857b020000'),
 'threshold_load':(0x4743979,'488b842410010000'),
 'high_word_extract':(0x4743981,'4889c148c1e93f'),
 'double_low':(0x4743988,'4801c0'),
 'triple_low':(0x474398b,'488d145b'),
 'low_compare':(0x474398f,'4839d0'),
 'high_borrow':(0x4743992,'4883d900'),
 'threshold_edge':(0x4743996,'0f83b6020000'),
 'less_than_successor_load':(0x474399c,'4d8b7628'),
 'diagnostic_location':(0x4743c38,'488d0d41b0fe00'),
 'diagnostic_call':(0x4743c4c,'ff1526ad0201'),
 'numeric_tag':(0x4743c52,'48b83800000000000080'),
 'tag_pointer_reload':(0x4743c5c,'4c8ba42488000000'),
 'tag_store':(0x4743c64,'49890424'),
}


def need(ok,message):
    if not ok:raise ValueError(message)


def main():
    data=(ROOT/'artifacts/node/94/hl-node').read_bytes()
    need(len(data)==91774280 and hashlib.sha256(data).hexdigest()==DIGEST,'target identity')
    ss=sections(data)
    def off(va,n):
        ss1=[s for s in ss if s['type']!=8 and s['address']<=va and va+n<=s['address']+s['size']]
        need(len(ss1)==1,'unique VA map')
        return ss1[0]['offset']+va-ss1[0]['address']
    def raw(va,n):
        o=off(va,n);return data[o:o+n]
    def validate(read):
        for name,(va,hx) in PINS.items():
            need(read(va,len(bytes.fromhex(hx))).hex()==hx,name)
        bs=read(0x474395e,5)
        need(bs[0]==0xe8 and 0x4743963+struct.unpack('<i',bs[1:])[0]==0x47c0ec0,'collector direct boundary')
    validate(raw)
    cies,fdes=eh_frame_records(data,ss)
    ff=[f for f in fdes if f['start']==START]
    need(len(ff)==1 and ff[0]['end']==END,'owner FDE')
    f=ff[0];_,idx=unwind_index(data)
    ii=[i for i in idx if i['start']==START]
    need(len(ii)==1 and ii[0]['fde']==f['fde'],'unwind index')
    cmd=[LLVM+'llvm-objdump','-d','--x86-asm-syntax=intel','--start-address='+hex(START),
         '--stop-address='+hex(END),'artifacts/node/94/hl-node']
    out=subprocess.check_output(cmd,cwd=str(ROOT),text=True)
    rows=[];cursor=START
    for line in out.splitlines():
        m=re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)(.*)$',line)
        if m:
            va,bs=int(m[1],16),bytes.fromhex(m[2]);text=m[3].strip()
            need(va==cursor and raw(va,len(bs))==bs and '<unknown>' not in text,'LLVM contiguous bytes')
            rows.append((va,bs,text));cursor+=len(bs)
    need(cursor==END,'LLVM exact end')
    boundaries={v for v,_,_ in rows}
    need(all(v in boundaries for v,_ in PINS.values()),'anchor boundaries')
    edges=[]
    for va,expected in [(0x4743973,0x4743bf4),(0x4743996,0x4743c52)]:
        bs=raw(va,6);target=va+6+struct.unpack('<i',bs[2:])[0]
        need(target==expected and target in boundaries,'guard branch target')
        edges.append({'site':hex(va),'target':hex(target),'raw_hex':bs.hex()})
    frame=next(s for s in ss if s['name']=='.eh_frame')
    dcmd=[LLVM+'llvm-dwarfdump','--eh-frame='+hex(f['fde']-frame['address']),'artifacts/node/94/hl-node']
    dout=subprocess.check_output(dcmd,cwd=str(ROOT),text=True)
    need('pc=04743490...04744152' in dout,'independent LLVM FDE')
    # Source-Location and diagnostic-slot RELATIVE binding, not a callee model.
    rela=next(s for s in ss if s['name']=='.rela.dyn')
    rels=[]
    for o in range(rela['offset'],rela['offset']+rela['size'],24):
        slot,info,addend=struct.unpack_from('<QQq',data,o)
        if slot in (0x572ec80,0x576e978):
            rels.append({'slot':hex(slot),'info':hex(info),'addend':hex(addend),
                         'file_offset':hex(o),'raw_hex':data[o:o+24].hex()})
    need(len(rels)==2 and all(r['info']=='0x8' for r in rels),'unique RELATIVE bindings')
    loc=raw(0x572ec80,24);ptr,length,line,column=struct.unpack('<QQII',loc)
    path_address=int(next(r for r in rels if r['slot']=='0x572ec80')['addend'],16)
    path=raw(path_address,length).decode('ascii')
    need(ptr==0 and path=='/home/ubuntu/hl/code_Mainnet/node/src/gossip_config.rs' and
         (line,column)==(421,9),'diagnostic Location')
    mask=(1<<64)-1
    domain=sorted(set([0,1,2,3,4,5,6,10,20,(1<<62),(1<<63)-1,1<<63,
                       mask//3-1,mask//3,mask//3+1,mask-1,mask]))
    math=[]
    for n in domain:
        for m in domain:
            low=(2*n)&mask;rhs=(3*m)&mask;borrow=int(low<rhs)
            # SBB high=(N>>63)-borrow clears CF iff it does not borrow.
            flag_form=(n>>63)>=borrow
            wide_form=2*n>=rhs
            need(flag_form==wide_form,'wide-integer threshold relation')
            math.append({'N':str(n),'M':str(m),'triple_mod_u64':str(rhs),
                         'numeric_tag_branch':flag_form,'ordinary_unwrapped_comparison':2*n>=3*m})
    changes=[(name,va+len(bytes.fromhex(hx))-1) for name,(va,hx) in PINS.items()]
    changes.append(('collector-direct-call',0x474395f))
    controls=[]
    for name,at in changes:
        def mutated(va,n):
            bs=bytearray(raw(va,n))
            if va<=at<va+n:bs[at-va]^=1
            return bytes(bs)
        try:validate(mutated)
        except ValueError as err:controls.append({'name':name,'mutated_va':hex(at),'rejected':str(err)})
        else:raise ValueError('unrejected mutation '+name)
    windows=[(0x4743963,0x47439a0),(0x4743bf4,0x4743c68)]
    record={'task':'RE-012','component':'node-runtime','target_sha256':DIGEST,'target_size':len(data),
            'source_base':'e5c9b6436876b2a4a39daef813171f9879317699',
            'reference_gitlink':'999556f6e0a474b8312db96ec3149e1c44e97c23',
            'coordinates':'linked ELF VAs; section-resolved offsets; ends exclusive',
            'owner':{**{k:hex(v) if isinstance(v,int) else v for k,v in f.items()},
                     'code_sha256':hashlib.sha256(raw(START,END-START)).hexdigest(),
                     'bytes':END-START,'LLVM_instruction_rows':len(rows)},
            'selected_windows':[{'start':hex(a),'end':hex(b),'bytes':b-a,
                'instruction_rows':sum(a<=va<b for va,_,_ in rows),'file_offset':hex(off(a,b-a)),
                'raw_hex':raw(a,b-a).hex()} for a,b in windows],
            'pins':{name:{'va':hex(va),'raw_hex':hx} for name,(va,hx) in PINS.items()},
            'direct_collector':{'site':'0x474395e','target':'0x47c0ec0',
                'raw_hex':raw(0x474395e,5).hex(),'scope':'opaque helper boundary'},
            'guard_edges':edges,'relative_bindings':rels,
            'diagnostic_location':{'va':'0x572ec80','raw_hex':loc.hex(),'path':path,'line':line,'column':column},
            'mathematical_domain':[str(v) for v in domain],'mathematical_probes':math,
            'negative_controls':controls,
            'counts':{'owner_bytes':END-START,'owner_rows':len(rows),'instruction_pins':len(PINS),
                      'selected_bytes':sum(b-a for a,b in windows),'math_probes':len(math),
                      'rejected_mutations':len(controls)},
            'Python':platform.python_version(),'platform':platform.system()+' '+platform.machine(),
            'LLVM_version':subprocess.check_output([LLVM+'llvm-objdump','--version'],text=True).splitlines()[0],
            'parser_sha256':{p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in ('tools/elf_index.py','tools/fde_extents.py')},
            'limits':['Scalar/layout names are inferred; no source-level peer or count types',
                      'No runtime reachability or unsafe-input/vulnerability claim',
                      'Opaque collector/diagnostic/cleanup and transitive alias effects remain open',
                      'No captured instruction evaluation, Rust reconstruction, equivalence or gate change']}
    (HERE/'owner.llvm.txt').write_text(' '.join(cmd)+'\n'+out.rstrip('\n')+'\n')
    (HERE/'owner-fde.llvm.txt').write_text(' '.join(dcmd)+'\n'+dout.rstrip('\n')+'\n')
    (HERE/'records.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps(record['counts'],sort_keys=True))


if __name__=='__main__':main()
