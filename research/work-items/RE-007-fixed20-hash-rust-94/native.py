#!/usr/bin/env python3
"""Authenticate the actual node94 fixed20 path without evaluating instructions."""
import hashlib
import json
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT/'tools'))
from info_request_path import Elf
from elf_index import sections
from fde_extents import eh_frame_records

FROZEN_SHA = '07719944d888e2820c856c79e6ef91de8de5b8eb3b20df81187518f83788de8f'
TARGET_SHA = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'


def need(ok, message):
    if not ok:
        raise ValueError(message)


def rows(name, decoder):
    result = []
    for line in (HERE/(name+'.'+decoder+'.txt')).read_text().splitlines():
        match = re.match(r'\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}(?:\s+|$))+)', line)
        if match is None:
            continue
        va, raw = int(match.group(1),16), bytes.fromhex(match.group(2))
        if decoder == 'gnu' and not line[match.end():].strip():
            old_va, old_raw = result[-1]
            need(old_va+len(old_raw)==va,'GNU continuation')
            result[-1] = old_va, old_raw+raw
        else:
            result.append((va,raw))
    return result


def structural(data, frozen):
    elf = Elf(data)
    # Named coordinate controls precede whole-body identity checks.
    for control in frozen['controls']:
        va, raw = int(control['va'],16), bytes.fromhex(control['hex'])
        need(elf.read(va,len(raw))==raw,'native coordinate changed: '+control['name'])
    _, fdes = eh_frame_records(data, sections(data))
    for function in frozen['functions']:
        start, end = int(function['start'],16), int(function['end'],16)
        matches = [f for f in fdes if f['start']==start]
        need(len(matches)==1,'FDE ambiguity')
        for key in ['end','fde','cie','lsda']:
            need(matches[0][key]==(None if function[key] is None else int(function[key],16)),'FDE field changed')
        for key in ['fde','cie']:
            raw = bytes.fromhex(function[key+'_bytes'])
            need(elf.read(int(function[key],16),len(raw))==raw,'raw unwind record changed')
        need(hashlib.sha256(elf.read(start,end-start)).hexdigest()==function['body_sha256'],'body changed')
    for name,start,end,count in [('hash',0x399c7a0,0x399c8e5,83),('write',0x3a00700,0x3a008d7,141)]:
        first, second = rows(name,'gnu'), rows(name,'llvm')
        need(first==second and len(first)==count,'decoder partition changed')
        need(first[0][0]==start and first[-1][0]+len(first[-1][1])==end,'incomplete FDE export')
        for index,(va,raw) in enumerate(first):
            need(elf.read(va,len(raw))==raw,'exported instruction byte changed')
            if index+1<len(first):
                need(va+len(raw)==first[index+1][0],'instruction gap')
    actual, sibling = elf.read(0x399c7a0,325), elf.read(0x2840fb0,325)
    named = {i for at,n in [(0x11,4),(0x23,4),(0x4f,4)] for i in range(at,at+n)}
    need(all(a==b for i,(a,b) in enumerate(zip(actual,sibling)) if i not in named),'adapter differs beyond named rel32 operands')
    actual, sibling = elf.read(0x3a00700,471), elf.read(0x288e280,471)
    need([i for i,(a,b) in enumerate(zip(actual,sibling)) if a!=b]==[0x23],'writer difference moved')
    need(actual[0x23]==0xf8 and sibling[0x23]==0xfb,'R8/R11 comparison changed')


def check():
    raw = (HERE/'native-freeze.json').read_bytes()
    need(hashlib.sha256(raw).hexdigest()==FROZEN_SHA,'native pre-model freeze changed')
    frozen = json.loads(raw)
    data = (ROOT/'artifacts/node/94/hl-node').read_bytes()
    need(hashlib.sha256(data).hexdigest()==TARGET_SHA and len(data)==91774280,'wrong node94 artifact')
    structural(data,frozen)
    return data,frozen


if __name__ == '__main__':
    _, frozen = check()
    print(json.dumps(dict(target_sha256=TARGET_SHA,coordinate_controls=len(frozen['controls']),
                         actual_fde_bytes=796,actual_instructions=224,fresh_ntail=0,
                         generic_writer_claim=False,captured_execution=False),indent=2))
