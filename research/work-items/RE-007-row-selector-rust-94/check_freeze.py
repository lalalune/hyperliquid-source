#!/usr/bin/env python3
"""Offline pre-Rust vector/anchor controls; never compile or execute target code."""
import hashlib
import json
from pathlib import Path
import shutil
import struct
import sys

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
sys.path.insert(0,str(ROOT/'tools'))
from info_request_path import Elf
from elf_index import sections
from fde_extents import eh_frame_records

FREEZE_SHA='515b7a3abcbb4dab494632d381d1a9377d3ea4120a7090702c96ccebf9269f77'
TARGET_SHA='3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'


def require(ok,message):
    if not ok:
        raise ValueError(message)


def load_frozen():
    raw=(HERE/'PRE-RUST-FREEZE.json').read_bytes()
    require(hashlib.sha256(raw).hexdigest()==FREEZE_SHA,'freeze record changed')
    frozen=json.loads(raw)
    for name,digest in frozen['frozen_sha256'].items():
        require(hashlib.sha256((HERE/name).read_bytes()).hexdigest()==digest,'frozen payload changed: '+name)
    # Prior component hashes are historical pre-source provenance. The actual
    # integrated component is authenticated by the separate compiled freeze.
    return json.loads((HERE/'native-anchors.json').read_text()),json.loads((HERE/'vectors.json').read_text())


def structural(data,record):
    elf=Elf(data)
    _,frames=eh_frame_records(data,sections(data))
    matches=[f for f in frames if f['start']==0x36f57f0]
    require(len(matches)==1,'FDE missing/ambiguous')
    fde=matches[0]
    for field,value in record['fde'].items():
        require(fde[field]==(int(value,16) if value is not None else None),'FDE field changed: '+field)
    for key in ('fde','cie'):
        require(elf.read(fde[key],len(bytes.fromhex(record[key+'_bytes']))).hex()==record[key+'_bytes'],key+' record changed')
    # Named anchors precede whole-body SHA: each operative operand corruption
    # must fail its coordinate-bound admission even with full-digest bypassed.
    for anchor in record['anchors']:
        raw=bytes.fromhex(anchor['bytes'])
        require(elf.read(int(anchor['va'],16),len(raw))==raw,'native anchor changed: '+anchor['name'])
    require(hashlib.sha256(elf.read(0x36f57f0,344)).hexdigest()==record['body_sha256'],'body SHA changed')


def model(case,**wrong):
    count=case['count']
    controls=bytes.fromhex(case['controls_hex'])
    keys={int(i):bytes.fromhex(k) for i,k in case['keys'].items()}
    query=bytes.fromhex(case['query_hex'])
    need=case['state']!=0
    selected=None
    if count or wrong.get('ignore_count'):
        require(len(controls)>=16,'nonempty model table required')
        mask=len(controls)-1
        position=int(case['hash'],16)&mask
        fingerprint=int(case['hash'],16)>>wrong.get('shift',57)
        step=0
        for _ in range(len(controls)//16):
            empty=False
            for lane in range(16):
                index=position+lane if wrong.get('no_wrap') else (position+lane)&mask
                control=controls[index]
                if control==255:
                    if wrong.get('early_empty'):
                        return dict(choice='SharedDefault',index=None,initializer_needed=need)
                    empty=True
                if control==fingerprint:
                    length=wrong.get('key_bytes',20)
                    if keys[index][:length]==query[:length]:
                        selected=index
                        break
            if selected is not None or empty:
                break
            step=wrong.get('step_size',16) if wrong.get('linear_probe') else step+wrong.get('step_size',16)
            position=(position+step)&mask
        else:
            raise ValueError('normal termination not reached by this model')
    if wrong.get('init_only_miss'):
        need=need and selected is None
    return dict(choice='SharedDefault' if selected is None else 'Bucket',index=selected,initializer_needed=need)


def main():
    record,vectors=load_frozen()
    data=(ROOT/'artifacts/node/94/hl-node').read_bytes()
    require(hashlib.sha256(data).hexdigest()==TARGET_SHA,'target SHA mismatch')
    structural(data,record)
    mutations=[]
    for anchor in record['anchors']:
        changed=bytearray(data)
        changed[Elf(data).off(int(anchor['va'],16))] ^= 1
        try:
            structural(changed,record)
        except ValueError as error:
            require('anchor changed' in str(error),'expected an operative anchor rejection')
            mutations.append(anchor['name'])
        else:
            raise ValueError('native mutation survived: '+anchor['name'])
    cases=vectors['cases']
    for case in cases:
        require(model(case)==case['expected'],'frozen expectation mismatch: '+case['name'])
    base=next(c for c in cases if c['name']=='group_hit_after_empty')
    for byte in vectors['mutation_family']['byte_indices']:
        mutated=dict(base)
        query=bytearray.fromhex(base['query_hex']);query[byte] ^= 1
        mutated['query_hex']=query.hex()
        require(model(mutated)['choice']=='SharedDefault','query-byte control failed')
    mutant_options={
        'sixteen_byte_key':dict(key_bytes=16),
        'stop_on_first_empty':dict(early_empty=True),
        'wrong_fingerprint_shift':dict(shift=56),
        'omit_lane_mask':dict(no_wrap=True),
        'linear_group_step':dict(linear_probe=True),
        'eight_byte_group_step':dict(step_size=8),
        'initialize_only_missing':dict(init_only_miss=True),
        'omit_empty_count_shortcut':dict(ignore_count=True),
    }
    witnesses={}
    for name,options in mutant_options.items():
        for case in cases:
            try:
                differs=model(case,**options)!=case['expected']
            except (ValueError,IndexError,KeyError):
                differs=True
            if differs:
                witnesses[name]=case['name'];break
        require(name in witnesses,'model mutant survived: '+name)
    result=dict(status='static freeze controls pass; no Rust build or implementation result',
                native_anchor_corruptions_rejected=mutations,vector_cases=len(cases),query_byte_controls=20,
                model_mutant_witnesses=witnesses,rust_executed=False,captured_execution=False,
                compiler_pin='1.94.1',tools={n:shutil.which(n) is not None for n in ('rustc','cargo','rustup')})
    (HERE/'STATIC-CONTROLS.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    print(json.dumps(result,indent=2,sort_keys=True))


if __name__=='__main__':
    main()
