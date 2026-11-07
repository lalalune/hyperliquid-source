#!/usr/bin/env python3
"""Revalidate existing #115 TLS bodies and join their write regions to RE-012.

No captured execution or CPU emulation. Scalar interval/capacity worksheets
are conditional annotations, not allocator or pthread behavior models.
"""
import argparse
import copy
import importlib.util
import json
from pathlib import Path
import platform
import subprocess
import sys

import capstone
import collect as base
import helpers

MASK=(1<<64)-1
CAP_LIMIT=(1<<59)-1
FALLBACK=base.ROOT/'research/work-items/RE-001-node115-tls-fallback'
CAPACITY=base.ROOT/'research/work-items/RE-001-node115-capacity-request-layout'


def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    return m


def reference_check(data):
    f=module('retained_tls_fallback',FALLBACK/'collect.py')
    actual=f.collect(base.ROOT,FALLBACK)
    expected=json.loads((FALLBACK/'records.json').read_text())
    expected['capstone_version']=actual['capstone_version']
    path_changes=[]
    # Active blocker: the original Windows replay differs ONLY in ten path
    # separators. Keep the original failed checks; adapt only these metadata
    # fields locally. Imported evidence/tools and raw native bytes stay intact.
    for body in actual['bodies']:
        for capture in body['captures']:
            old=capture['path'];new=old.replace('\\','/')
            if old!=new:path_changes.append({'before':old,'after':new})
            capture['path']=new
    base.require(actual==expected,'Fallback drift beyond capture-path metadata')
    c=module('retained_capacity',CAPACITY/'verify.py')
    c.structural(data,json.loads((CAPACITY/'evidence.json').read_text()))
    return {'fallback_structural_and_native_replay':True,'capacity_structural_and_native_replay':True,
        'capture_path_metadata_adaptations':path_changes,'native_byte_masks':[],
        'inputs':{p.relative_to(base.ROOT).as_posix():base.sha(p.read_bytes()) for p in
            [FALLBACK/'collect.py',FALLBACK/'records.json',FALLBACK/'MANIFEST.sha256',
             CAPACITY/'verify.py',CAPACITY/'evidence.json',CAPACITY/'MANIFEST.sha256']}}


def bindings(im,spec):
    base.require(spec['target_sha256']==base.TARGET,'TLS join target')
    decoded={};actual_stores={}
    for r in spec['ranges']:
        start,end=int(r['start'],16),int(r['end'],16)
        base.require(len([f for f in im.fdes if f['start']==start and f['end']==end])==1,'TLS exact FDE')
        raw=im.read(start,end-start);base.require(base.sha(raw)==r['sha256'],'TLS body hash')
        ins=list(helpers.decoder().disasm(raw,start))
        base.require(sum(i.size for i in ins)==end-start,'TLS complete decode');decoded[start]=ins
        for i in ins:
            if i.operands and i.operands[0].type==capstone.CS_OP_MEM and i.mnemonic not in ('cmp','test','nop','jmp','call'):
                base.require(i.mnemonic in ('mov','inc','lock cmpxchg'),'Unclassified TLS store')
                actual_stores[i.address]=i
    rows={int(r['va'],16):r for r in spec['stores']}
    base.require(len(rows)==len(spec['stores']) and set(rows)==set(actual_stores),'TLS store census')
    for va,i in actual_stores.items():
        r=rows[va]
        base.require(i.bytes.hex()==r['bytes_hex'] and i.operands[0].size==r['width']
                     and i.mnemonic+' '+i.op_str==r['instruction'],'TLS store opcode/width')
    for r in spec['relocations']:
        base.require(im.relocs.get(int(r['slot'],16))==[(r['info'],r['addend'])],'TLS unique relocation')
        if r['symbol']:base.require(im.symbol(r['info']>>32)==r['symbol'],'TLS import name')
    for r in spec['data']:
        raw=bytes.fromhex(r['bytes_hex']);base.require(im.read(int(r['va'],16),len(raw))==raw,'TLS initial data')
    base.require(0x64feda8 not in im.relocs,'Unexpected key-word relocation')
    return decoded


def growth(capacity):
    base.require(type(capacity) is int and 0<=capacity<=CAP_LIMIT,'Outside admitted capacity domain')
    request=max((capacity+1)&MASK,(2*capacity)&MASK,4)
    size=(request<<4)&MASK
    accepted=(request>>60)==0 and size<=0x7ffffffffffffff8
    base.require(accepted==(capacity<=(1<<58)-1),'Composed size bound')
    return {'old_capacity':str(capacity),'request':str(request),'bytes':str(size),'gate_accepted':accepted,
            'old_count_plus_one_fits_request':capacity+1<=request}


def append_interval(buffer,count,capacity,field):
    base.require(all(type(v) is int for v in (buffer,count,capacity,field)),'Integer interval coordinates required')
    base.require(0<=count<capacity<=CAP_LIMIT,'Append outside declared valid list')
    base.require(0<=buffer and buffer+16*capacity<=1<<64 and 0<=field and field+2<=1<<64,'Address interval overflow')
    lo=buffer+16*count;hi=lo+16
    base.require(hi<=field or lo>=field+2,'Append overlaps tracked word')
    return {'buffer':hex(buffer),'count':str(count),'capacity':str(capacity),
            'write_interval':[hex(lo),hex(hi)],'tracked_interval':[hex(field),hex(field+2)],
            'scope':'only explicit 16-byte append intersection; not full ownership/allocator safety'}


def controls(im,spec):
    rejected=[]
    def reject(name,fn):
        try:fn()
        except ValueError:rejected.append(name)
        else:raise ValueError('Accepted invalid TLS join '+name)
    def mutate(va):
        bad=copy.copy(im)
        def read(start,count):
            raw=bytearray(im.read(start,count))
            if start<=va<start+count:raw[va-start]^=1
            return bytes(raw)
        bad.read=read;return bad
    for r in spec['stores']:
        va=int(r['va'],16)+len(bytes.fromhex(r['bytes_hex']))-1
        reject('store-byte:'+r['va'],lambda:bindings(mutate(va),spec))
    for r in spec['data']:
        reject('data-byte:'+r['va'],lambda:bindings(mutate(int(r['va'],16)),spec))
    for r in spec['relocations']:
        slot=int(r['slot'],16)
        for kind in ('changed','duplicate'):
            bad=copy.copy(im);bad.relocs=dict(im.relocs)
            bad.relocs[slot]=[(r['info'],r['addend']+1)] if kind=='changed' else im.relocs[slot]*2
            reject(kind+'-relocation:'+hex(slot),lambda:bindings(bad,spec))
    for r in spec['ranges']:
        bad=copy.deepcopy(spec);next(x for x in bad['ranges'] if x['name']==r['name'])['end']=hex(int(r['end'],16)-1)
        reject('truncated-fde:'+r['name'],lambda:bindings(im,bad))
    bad=copy.deepcopy(spec);bad['stores'].pop()
    reject('missing-store',lambda:bindings(im,bad))
    for c in (-1,CAP_LIMIT+1,1<<64):reject('capacity-scope:'+str(c),lambda:growth(c))
    for name,args in [('equal-count',(0x1000,1,1,0x20c8)),('count-over-capacity',(0x1000,2,1,0x20c8)),
        ('negative-count',(0x1000,-1,1,0x20c8)),('address-wrap',(MASK-8,0,1,0x20c8)),
        ('overlap-low',(0x20b9,0,1,0x20c8)),('overlap-start',(0x20c8,0,1,0x20c8)),
        ('overlap-high',(0x20c9,0,1,0x20c8))]:
        reject('interval-scope:'+name,lambda:append_interval(*args))
    reject('wrong-target',lambda:base.authenticate(b'not node115'))
    changed=bytearray(im.data);changed[-1]^=1;reject('changed-full-target',lambda:base.authenticate(changed))
    return rejected


def collect(out):
    data=(base.ROOT/'artifacts/node/115/hl-node').read_bytes();base.authenticate(data)
    references=reference_check(data);im=base.Image(data)
    spec=json.loads((base.PACKET/'tls-join-spec.json').read_text());decoded=bindings(im,spec)
    rejected=controls(im,spec);out.mkdir(parents=True,exist_ok=False)
    versions={'python':sys.version,'platform':platform.platform(),'capstone':capstone.__version__}
    for tool in ('objdump','llvm-objdump'):versions[tool]=subprocess.check_output([tool,'--version']).decode()
    ranges=[];commands=[]
    for r in spec['ranges']:
        start,end=int(r['start'],16),int(r['end'],16);ins=decoded[start]
        fde,=[f for f in im.fdes if f['start']==start and f['end']==end]
        row={**r,'fde':hex(fde['fde']),'lsda':hex(fde['lsda']) if fde['lsda'] is not None else None,
            'file_offset':hex(im.offset(start,end-start)),'bytes':end-start,'instructions':len(ins),
            'native':[],'transfers':helpers.transfers(im,ins),'ownership':'previously recorded #115 dependency context'}
        (out/(r['name']+'.capstone.txt')).write_text('\n'.join(f'{i.address:x}: {i.bytes.hex():32} {i.mnemonic:8} {i.op_str}' for i in ins)+'\n',encoding='utf-8',newline='\n')
        for tool,opts,suffix in [('objdump',['-z','--insn-width=16'],'gnu'),('llvm-objdump',['--disassemble-zeroes'],'llvm')]:
            args=[tool,'-d',*opts,f'--start-address={start}',f'--stop-address={end}','artifacts/node/115/hl-node']
            p=subprocess.run(args,cwd=base.ROOT,capture_output=True,check=True);name=r['name']+'.'+suffix+'.objdump'
            (out/name).write_bytes(p.stdout);(out/(name+'.stderr')).write_bytes(p.stderr)
            parsed=base.native_rows(p.stdout,im,start,end);splits=base.compare_boundaries(parsed,ins)
            if start==0x5ca0d20:base.require(p.stdout==(base.PACKET/'poll'/('tls_registration.'+suffix+'.objdump')).read_bytes(),'Prior registration export changed')
            row['native'].append({'file':name,'sha256':base.sha(p.stdout),'rows':len(parsed),'lock_prefix_splits':splits});commands.append(args)
        ranges.append(row)
    cases=sorted(set([0,1,2,3,4,7,(1<<58)-2,(1<<58)-1,1<<58,(1<<58)+1,CAP_LIMIT]))
    intervals=[append_interval(*a) for a in [(0x1000,0,1,0x20c8),(0x1000,3,4,0x20c8),
        (0x20b8,0,1,0x20c8),(0x20ca,0,1,0x20c8)]]
    result={'target_sha256':base.TARGET,'source_base':'05bc2de303c05525b71e7e257426e741bc66a390',
        'captured_code_executed_or_emulated':False,'ranges':ranges,'reference_validation':references,
        'relocations':spec['relocations'],'explicit_stores':spec['stores'],'initial_data':spec['data'],
        'capacity_worksheet':[growth(c) for c in cases],'append_interval_worksheet':intervals,
        'negative_and_scope_controls':rejected,'normalization_masks':[], 'new_function_body_credit':0,
        'manual_coordinate_joins':{'growth_control':'QWORD[FS:0] - 0x1148','caller_capacity':'FS.base - 0x1148',
            'required_identity':'QWORD[FS:0] == FS.base; not proved by static bytes',
            'buffer':'FS.base - 0x1140','count':'FS.base - 0x1138','guard':'FS.base - 0x1150',
            'tracked_word':'allocation P + [0xc8,0xca)'},
        'limitations':['Ordinary pthread/malloc/realloc contracts and normal successful paths are premises, not executed evidence',
            'Valid list bounds, compatible TLS self pointer, separate stack/global/TLS/buffer storage and allocator ownership',
            'No alias/concurrency, asynchronous callback or allocation lifetime proof',
            'No general safety claim for malformed list metadata or error/unwind branches',
            'No new source comparison or full-scope acceptance gate']}
    for name,value in [('records.json',result),('commands.json',commands),('versions.json',versions)]:
        (out/name).write_text(json.dumps(value,indent=2)+'\n',encoding='utf-8',newline='\n')
    print(json.dumps({'context_fdes':len(ranges),'context_bytes':sum(r['bytes'] for r in ranges),
        'instructions':sum(r['instructions'] for r in ranges),'stores':len(spec['stores']),
        'controls_rejected':len(rejected),'path_metadata_adaptations':len(references['capture_path_metadata_adaptations']),
        'new_function_body_credit':0}))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True)
    collect(p.parse_args().out)
