#!/usr/bin/env python3
"""RE-001: node94 checkpoint maintenance branch/call observations, static only."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from evm_amount_scale import ROOT,BINARY,SHA256,Image
from fde_extents import eh_frame_records

PACKET=ROOT/'research/work-items/RE-001-checkpoint-maintenance-94'
START,END=0x432f310,0x432f5ed
BODY_SHA='2bc1cee7929de30afb2d6d383af783abd5e0d074216ad1a0b42293989de25a00'
MIN=1<<63
ANCHORS={
    0x432f31d:'4889fb',0x432f32a:'4883c310',0x432f32e:'85f6',0x432f330:'0f84ba000000',
    0x432f34f:'8b7c2438',0x432f353:'85ff',0x432f355:'0f84ca010000',
    0x432f35b:'beffffffff',0x432f366:'85c0',0x432f368:'0f84cc010000',
    0x432f373:'4889de',0x432f376:'89c2',
    0x432f37e:'31c0',0x432f380:'483b442438',0x432f385:'0f81dc000000',
    0x432f3e9:'ff10',0x432f3eb:'e9fa000000',
    0x432f3f0:'be64000000',0x432f3f5:'4889df',0x432f3fe:'4885c0',0x432f401:'0f84fa000000',
    0x432f460:'ff10',0x432f462:'e99a000000',
    0x432f4b0:'4983c418',0x432f4b4:'49ffcf',0x432f4c9:'41ffd5',
    0x432f4ea:'4889df',0x432f4f3:'4885c0',0x432f4f6:'7409',
    0x432f501:'488b442450',0x432f506:'f048ff08',0x432f50a:'750b',
}
CALLS={
    0x432f339:(0x576e8a0,0x151cba0),0x432f349:(0x576ea48,0x151cec0),
    0x432f360:(0x576e8b0,0x151f870),0x432f378:(0x5775e90,0x37e2960),
    0x432f3db:(0x576e978,0x143d010),0x432f3f8:(0x5775ea0,0x37e3a70),
    0x432f452:(0x576e978,0x143d010),0x432f4ed:(0x5775eb0,0x37e3f40),
    0x432f4fb:(0x576e9a8,0x13cbce0),0x432f511:(0x5773070,0x34391b0),
}
MESSAGES=[
    (0x432f3c5,0x1fd66f,b'\x1ctar_evm_checkpoints failed: \xc0\0',0x432f3cc,0x571c948,279,25),
    (0x432f43c,0x1e78e4,b'%prune_lowest_evm_checkpoints failed: \xc0\0',0x432f443,0x571c930,286,17),
]


def require(ok,message):
    if not ok:raise ValueError(message)


def zero_minus_overflows(word):
    require(type(word) is int and 0<=word<(1<<64),'Expected u64 result word')
    signed=word-(1<<64) if word>>63 else word
    difference=-signed
    return not -MIN<=difference<MIN


def selected_trace(mode,tar_word,prune_word):
    """Normal-return call milestones, conditional on out-of-scope helpers."""
    require(type(mode) is int and 0<=mode<(1<<32),'Expected u32 mode')
    require(type(prune_word) is int and 0<=prune_word<(1<<64),'Expected u64 prune word')
    tar_error=zero_minus_overflows(tar_word)
    if mode:
        return ['tar']+(['critical_tar'] if tar_error else [])+['followup','cleanup']
    return ['prune_100']+(['critical_prune'] if prune_word else [])+['cleanup']


def observe(data):
    img=Image(data);read=img.read;relocs=img.relative_relocs()
    for va,raw in ANCHORS.items():
        require(read(va,len(bytes.fromhex(raw)))==bytes.fromhex(raw),f'Maintenance operand/control changed at {va:#x}')
    calls=[]
    for va,(slot,target) in CALLS.items():
        raw=read(va,6)
        require(raw[:2]==b'\xff\x15' and va+6+struct.unpack('<i',raw[2:])[0]==slot,'Maintenance call slot changed')
        require(relocs.get(slot)==target,'Maintenance call relocation changed')
        calls.append({'call_va':hex(va),'slot_va':hex(slot),'target_va':hex(target)})
    def lea(va,prefix,target):
        raw=read(va,7)
        require(raw[:3]==bytes.fromhex(prefix) and va+7+struct.unpack('<i',raw[3:])[0]==target,'Maintenance LEA changed')
    messages=[]
    for va,text,raw,loc_lea,loc,line,col in MESSAGES:
        lea(va,'488d35',text);lea(loc_lea,'488d0d',loc)
        require(read(text,len(raw))==raw,'Maintenance message prefix changed')
        require(relocs.get(loc)==0x1f53f5,'Engine source relocation changed')
        size,actual_line,actual_col=struct.unpack('<QII',read(loc+8,16))
        path=read(relocs[loc],size).decode('utf8')
        require(path=='/home/ubuntu/hl/code_Mainnet/l1/src/abci/engine.rs' and (actual_line,actual_col)==(line,col),'Engine source Location changed')
        messages.append({'template_va':hex(text),'retained_prefix_through_first_nul_hex':raw.hex(),
                         'source_location_va':hex(loc),'source_path':path,'line':line,'column':col})
    _,fdes=eh_frame_records(data);found=[f for f in fdes if f['start']==START]
    require(len(found)==1 and found[0]['end']==END,'Maintenance FDE changed')
    require(hashlib.sha256(read(START,END-START)).hexdigest()==BODY_SHA,'Maintenance body changed')
    f=found[0]
    probes=[0,1,MIN-1,MIN,MIN+1,(1<<64)-1]
    require(all(zero_minus_overflows(w)==(w==MIN) for w in probes),'Overflow predicate differs')
    return {'target_sha256':SHA256,'owner':{'start':hex(START),'end_exclusive':hex(END),'sha256':BODY_SHA,'fde':hex(f['fde']),'cie':hex(f['cie'])},
            'messages':messages,'calls':calls,'prune_count':read(0x432f3f0+1,1)[0],
            'dispatch':'ESI == 0 selects prune; nonzero selects tar preparation',
            'tar_diagnostic_predicate':'OF of signed 0 - result_word; true exactly for raw 0x8000000000000000',
            'prune_diagnostic_predicate':'RAX != 0',
            'normal_return_milestones':{'tar_with_diagnostic':selected_trace(1,MIN,0),
                                        'tar_without_diagnostic':selected_trace(1,0,0),
                                        'prune_with_diagnostic':selected_trace(0,0,1),
                                        'prune_without_diagnostic':selected_trace(0,0,0)},
            'limits':'Conditional control-flow milestones only. Date helpers, tar/prune/followup side effects, '
                     'critical helper policy, drop/unwind/OOM behavior, scheduling, full Rust signature and progress gates unproved.',
            'captured_binaries_executed':False}


def build(data):
    require(hashlib.sha256(data).hexdigest()==SHA256,'Wrong node94 SHA-256')
    return observe(data)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary',type=Path,default=ROOT/BINARY)
    p.add_argument('--out',type=Path,default=ROOT/'work/checkpoint-flow-94.json')
    args=p.parse_args();result=build(args.binary.read_bytes())
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(result,indent=2)+'\n',encoding='utf8',newline='\n')
    print(result['normal_return_milestones'])


if __name__=='__main__':main()
