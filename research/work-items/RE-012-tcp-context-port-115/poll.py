#!/usr/bin/env python3
"""Static node115 poll-prefix field preservation, with explicit TLS scope."""
import argparse
import copy
import json
from pathlib import Path
import platform
import struct
import subprocess
import sys

import capstone
import collect as base
import helpers

LARGE = 0x2accee0
TLS = 0x5ca0d20
FIELD = (0xc8, 0xca)


def bindings(im, spec):
    base.require(spec['target_sha256'] == base.TARGET, 'Poll target')
    md = helpers.decoder(); decoded = {}
    for r in spec['ranges']:
        start, end = int(r['start'],16), int(r['end'],16)
        base.require(len([f for f in im.fdes if f['start']==start and f['end']==end]) == 1, 'Poll exact FDE')
        raw = im.read(start,end-start)
        base.require(base.sha(raw)==r['sha256'], 'Poll full body hash')
        ins = list(md.disasm(raw,start))
        base.require(sum(i.size for i in ins)==end-start,'Poll full decode')
        decoded[start] = ins
    all_ins = {i.address:i for ins in decoded.values() for i in ins}
    bounds = set(all_ins) | {int(r['end'],16) for r in spec['ranges']}
    for a in spec['anchors']:
        va,raw = int(a['va'],16),bytes.fromhex(a['bytes_hex'])
        base.require(im.read(va,len(raw))==raw,'Poll anchor '+a['name'])
        base.require(va in bounds and va+len(raw) in bounds,'Poll anchor boundary')
    for r in spec['relocations']:
        base.require(im.relocs.get(int(r['slot'],16))==[(r['info'],r['addend'])],'Poll unique relocation')
        if r['symbol']:
            base.require(im.symbol(r['info']>>32)==r['symbol'],'Poll relocation symbol')
    actual = {}
    for p in spec['pollers']:
        start,call,table = (int(p[k],16) for k in ('start','call','table'))
        lea = all_ins[start+0xb7]
        base.require(lea.mnemonic=='lea' and lea.reg_name(lea.operands[1].mem.base)=='rip'
                     and lea.address+lea.size+lea.operands[1].mem.disp==table,'Dispatch table LEA')
        base.require(im.read(table,16).hex()==p['table_bytes_hex'],'Dispatch table bytes')
        base.require(not any(table<=slot<table+16 for slot in im.relocs),'Relocated relative table')
        targets = [table+d for d in struct.unpack('<4i',im.read(table,16))]
        base.require([hex(v) for v in targets]==p['table_targets'],'Dispatch targets')
        base.require(all(v in {i.address for i in decoded[start]} for v in targets),'Dispatch target boundaries')
        i = all_ins[call]
        base.require(i.mnemonic=='call' and i.operands[0].type==capstone.CS_OP_IMM and i.operands[0].imm==LARGE,'Large caller target')
        for i in decoded[start]:
            if i.address>=call:
                break
            if not i.operands or i.operands[0].type!=capstone.CS_OP_MEM or i.mnemonic in ('test','cmp','call','nop','jmp'):
                continue
            base.require(i.mnemonic in ('mov','lock cmpxchg'),'Unclassified prefix memory destination')
            actual[i.address] = i
    rows = {int(r['va'],16):r for r in spec['prefix_stores']}
    base.require(len(rows)==len(spec['prefix_stores']) and set(rows)==set(actual),'Prefix store inventory')
    for va,i in actual.items():
        r=rows[va]
        base.require(i.bytes.hex()==r['bytes_hex'] and i.operands[0].size==r['width']
                     and i.mnemonic+' '+i.op_str==r['instruction'],'Prefix store bytes/width')
    return decoded


def selected_header(word):
    """Scalar worksheet of pinned masks, not machine-code execution."""
    base.require(type(word) is int and 0<=word<1<<64,'Header outside u64')
    base.require(word & 7 == 4 and word & 0x20 == 0,'Outside selected header branch')
    return {'dispatch_index':(word>>5)&1,'replacement':(word & ~7)+1}


def prefix_path(decoded, p, tls_state, override=None, dispatch_index=0):
    """Traverse encoded edges only; stop before executing the large call."""
    start,stop = int(p['start'],16),int(p['call'],16)
    base.require(tls_state in (1,2),'Excluded TLS state')
    decisions = {start+0x8b:False,start+0x93:True,start+0x87:True,
                 start+0xf8:False,start+0x11f:tls_state==1}
    if tls_state==2:
        decisions[start+0x128]=False
    if override:
        decisions.update(override)
    ins={i.address:i for i in decoded[start]};va=start;visited=[];used=set()
    while va in ins and va not in visited:
        i=ins[va];visited.append(va)
        if va==stop:
            base.require(used==set(decisions),'Unvisited selected guard')
            return visited
        base.require(i.mnemonic not in ('call','ret','ud2'),'Prefix reaches prior call/return/trap')
        if i.mnemonic.startswith('j'):
            if i.operands[0].type==capstone.CS_OP_REG:
                base.require(va==start+0xc5 and i.op_str=='rax' and 0<=dispatch_index<4,'Unresolved indirect branch')
                va=int(p['table_targets'][dispatch_index],16)
            else:
                base.require(i.operands[0].type==capstone.CS_OP_IMM,'Unknown prefix edge')
                if i.mnemonic=='jmp':va=i.operands[0].imm
                else:
                    base.require(va in decisions,'Unclassified conditional edge')
                    used.add(va);va=i.operands[0].imm if decisions[va] else va+i.size
        else:va+=i.size
    raise ValueError('Prefix cycle or extent exit')


def write_intervals(rows):
    result=[]
    for r in rows:
        base.require(r['width']>0,'Empty write')
        if r['space']=='P':
            lo,hi=r['offset'],r['offset']+r['width']
            base.require(lo>=0 and (hi<=FIELD[0] or lo>=FIELD[1]),'Prefix field overlap')
            overlap=False
        else:
            base.require(r['space'] in ('TLS','stack'),'Unrecognized write space')
            overlap='requires separate effective TLS/stack storage'
        result.append({**r,'field_overlap':overlap})
    return result


def controls(im,spec,decoded):
    rejected=[]
    def reject(name,fn):
        try:fn()
        except ValueError:rejected.append(name)
        else:raise ValueError('Accepted corrupt poll evidence: '+name)
    def mutate(va):
        bad=copy.copy(im)
        def read(start,count):
            raw=bytearray(im.read(start,count))
            if start<=va<start+count:raw[va-start]^=1
            return bytes(raw)
        bad.read=read;return bad
    for a in spec['anchors']:
        va=int(a['va'],16)+len(bytes.fromhex(a['bytes_hex']))-1
        reject('anchor-byte:'+a['name'],lambda:bindings(mutate(va),spec))
    for p in spec['pollers']:
        table=int(p['table'],16)
        for index in range(4):
            reject('table-entry:'+hex(table+4*index),lambda:bindings(mutate(table+4*index),spec))
        bad=copy.copy(im);bad.relocs=dict(im.relocs);bad.relocs[table]=[(8,0)]
        reject('unexpected-table-relocation:'+hex(table),lambda:bindings(bad,spec))
        start=int(p['start'],16)
        for off,taken in ((0x8b,True),(0x93,False),(0x87,False),(0xf8,True),(0x128,True)):
            reject('excluded-edge:'+hex(start+off),lambda:prefix_path(decoded,p,2,{start+off:taken}))
        for index in (1,2,3):
            reject('excluded-dispatch:'+p['name']+':'+str(index),lambda:prefix_path(decoded,p,2,dispatch_index=index))
    for r in spec['relocations']:
        slot=int(r['slot'],16)
        for kind in ('changed','duplicate'):
            bad=copy.copy(im);bad.relocs=dict(im.relocs)
            bad.relocs[slot]=[(r['info'],r['addend']+1)] if kind=='changed' else im.relocs[slot]*2
            reject(kind+'-relocation:'+hex(slot),lambda:bindings(bad,spec))
    for r in spec['ranges']:
        bad=copy.deepcopy(spec)
        next(x for x in bad['ranges'] if x['name']==r['name'])['end']=hex(int(r['end'],16)-1)
        reject('truncated-fde:'+r['name'],lambda:bindings(im,bad))
    for kind in ('missing','width'):
        bad=copy.deepcopy(spec)
        if kind=='missing':bad['prefix_stores'].pop()
        else:bad['prefix_stores'][0]['width']=1
        reject('store-inventory:'+kind,lambda:bindings(im,bad))
    for word in (-1,1<<64,0,0xcd,0xec):
        reject('header-scope:'+str(word),lambda:selected_header(word))
    for state in (0,3,255):
        reject('tls-scope:'+str(state),lambda:prefix_path(decoded,spec['pollers'][0],state))
    for offset in (0xc1,0xc8,0xc9):
        reject('interval-only-overlap:'+hex(offset),lambda:write_intervals([{'space':'P','offset':offset,'width':8}]))
    write_intervals([{'space':'P','offset':0xc0,'width':8},{'space':'P','offset':0xca,'width':8}])
    reject('wrong-target',lambda:base.authenticate(b'not node115'))
    changed=bytearray(im.data);changed[-1]^=1
    reject('changed-full-target',lambda:base.authenticate(changed))
    return rejected


def collect(out):
    data=(base.ROOT/'artifacts/node/115/hl-node').read_bytes();base.authenticate(data)
    im=base.Image(data);spec=json.loads((base.PACKET/'poll-spec.json').read_text())
    decoded=bindings(im,spec);rejected=controls(im,spec,decoded)
    out.mkdir(parents=True,exist_ok=False)
    versions={'python':sys.version,'platform':platform.platform(),'capstone':capstone.__version__}
    for tool in ('objdump','llvm-objdump'):
        versions[tool]=subprocess.check_output([tool,'--version']).decode()
    ranges=[];commands=[];paths=[]
    for r in spec['ranges']:
        start,end=int(r['start'],16),int(r['end'],16);ins=decoded[start]
        fde,=[f for f in im.fdes if f['start']==start and f['end']==end]
        row={**r,'fde':hex(fde['fde']),'lsda':hex(fde['lsda']),'file_offset':hex(im.offset(start,end-start)),
             'bytes':end-start,'instructions':len(ins),'native':[],'transfers':helpers.transfers(im,ins)}
        (out/(r['name']+'.capstone.txt')).write_text('\n'.join(
            f'{i.address:x}: {i.bytes.hex():32} {i.mnemonic:8} {i.op_str}' for i in ins)+'\n',encoding='utf-8',newline='\n')
        for tool,opts,suffix in [('objdump',['-z','--insn-width=16'],'gnu'),('llvm-objdump',['--disassemble-zeroes'],'llvm')]:
            args=[tool,'-d',*opts,f'--start-address={start}',f'--stop-address={end}','artifacts/node/115/hl-node']
            p=subprocess.run(args,cwd=base.ROOT,capture_output=True,check=True)
            name=r['name']+'.'+suffix+'.objdump';(out/name).write_bytes(p.stdout);(out/(name+'.stderr')).write_bytes(p.stderr)
            parsed=base.native_rows(p.stdout,im,start,end);splits=base.compare_boundaries(parsed,ins)
            prior=base.PACKET/'factory'/('body-'+format(start,'x')+'.'+suffix+'.objdump')
            if start!=TLS:base.require(p.stdout==prior.read_bytes(),'Prior factory poll/constructor export changed')
            row['native'].append({'file':name,'sha256':base.sha(p.stdout),'rows':len(parsed),'lock_prefix_splits':splits,
                                  'prior_factory_raw_equal':start!=TLS});commands.append(args)
        ranges.append(row)
    for p in spec['pollers']:
        for state in (1,2):
            visited=prefix_path(decoded,p,state)
            stores=[r for r in spec['prefix_stores'] if int(r['va'],16) in visited]
            paths.append({'poller':p['start'],'tls_state':state,'instruction_vas':[hex(v) for v in visited],
                'earlier_calls':0,'stop_call':p['call'],'target':hex(LARGE),'writes':write_intervals(stores),
                'argument_join':{'allocation_offset':0x38,'large_input_field':0x90,'tracked_offset':0xc8},
                'implicit_stack_effects':'push/pop and final call return address; separate valid stack required'})
    accepted=[]
    for low in range(256):
        try:row=selected_header(low)
        except ValueError:continue
        base.require(row['dispatch_index']==0 and row['replacement']&7==1,'Selected header arithmetic')
        accepted.append(low)
    base.require(selected_header(0xcc)=={'dispatch_index':0,'replacement':0xc9},'Constructor header case')
    result={'target_sha256':base.TARGET,'source_base':'05bc2de303c05525b71e7e257426e741bc66a390',
        'captured_code_executed_or_emulated':False,'ranges':ranges,'tables':spec['pollers'],
        'relocations':spec['relocations'],'lexical_prefix_stores':spec['prefix_stores'],'selected_paths':paths,
        'header_worksheet':{'accepted_low_bytes':accepted,'initial':0xcc,'replacement':0xc9,'dispatch_index':0},
        'negative_and_scope_controls':rejected,'normalization_masks':[],
        'limitations':['Selected first successful CAS, dispatch zero and P+0x30 zero only',
            'TLS flag 1 or 2; other values invoke registration helper with unclosed callees',
            'Register/region/TLS annotations are manually reviewed, not an automated alias analysis',
            'Separate valid stack/TLS storage and no concurrent mutation of the tracked allocation',
            'No scheduler-to-poller invocation identity or lifetime proof',
            'No behavior after entering large A, exceptions, retry history or full resumed-state closure',
            'No source implementation, captured execution or whole-node equivalence']}
    for name,value in [('records.json',result),('commands.json',commands),('versions.json',versions)]:
        (out/name).write_text(json.dumps(value,indent=2)+'\n',encoding='utf-8',newline='\n')
    print(json.dumps({'full_fdes':len(ranges),'bytes':sum(r['bytes'] for r in ranges),'instructions':sum(r['instructions'] for r in ranges),
        'selected_prefix_paths':len(paths),'lexical_prefix_stores':len(spec['prefix_stores']),'controls_rejected':len(rejected)}))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True)
    collect(p.parse_args().out)
