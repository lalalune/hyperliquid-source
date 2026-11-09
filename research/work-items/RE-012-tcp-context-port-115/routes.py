#!/usr/bin/env python3
"""Static sender/constructor xrefs and remaining context-pointer routes for #115."""
import argparse
import copy
import json
from pathlib import Path
import platform
import struct
import subprocess
import sys

import capstone
import collect as first

SEND = 0x2b7a290
CTOR = 0x4784d00
SLOT = 0x64e7540
EXPECTED_SENDER = [0x2ad03b2, 0x2ad43da, 0x2ae3ddd, 0x2b684b5, 0x2b6a6a6, 0x2b7a1b7]
EXPECTED_CTOR = [0x2afb7c7, 0x2b7877d, 0x2cc0cbb, 0x5a60328, 0x5ab41c4]


def selected_bindings(im, spec):
    for a in spec['anchors']:
        va = int(a['va'], 16)
        raw = bytes.fromhex(a['bytes_hex'])
        first.require(im.read(va, len(raw)) == raw, 'Route anchor: '+a['name'])
    for row in spec.get('dispatch', []):
        base, index, dest = (int(row[k], 0) for k in ['base', 'index', 'destination'])
        first.require(base+struct.unpack('<i', im.read(base+index*4, 4))[0] == dest, 'Route dispatch')
    first.require(im.relocs.get(SLOT) == [(8, CTOR)], 'Constructor relocation')
    copies = im.relocs.get(0x64df508, [])
    first.require(len(copies) == 1 and copies[0][0] & 0xffffffff == 6 and copies[0][1] == 0
                  and im.symbol(copies[0][0] >> 32) == 'memcpy', 'Route memcpy import')
    for row in spec.get('relocations', []):
        slot=int(row['slot'],16)
        rels=im.relocs.get(slot,[])
        first.require(len(rels)==1,'Route non-unique relocation '+hex(slot))
        info,addend=rels[0]
        if 'symbol' in row:
            first.require(info & 0xffffffff == 6 and addend==0 and im.symbol(info >> 32)==row['symbol'],
                          'Route import '+row['symbol'])
        else:
            first.require(info==8 and addend==int(row['target'],16),'Route relative target '+hex(slot))


def scan_encoded(im, targets):
    """Candidate byte scan then full-FDE instruction-boundary verification.

    Scope is E8/E9 and RIP-relative FF15/FF25 only. Register, vtable,
    address-taken and non-.text entry mechanisms remain unclosed.
    """
    text = next(s for s in im.sections if s['name'] == '.text')
    blob = im.data[text['offset']:text['offset']+text['size']]
    rows, decoded = [], {}
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    for op in [b'\xe8', b'\xe9', b'\xff\x15', b'\xff\x25']:
        pos = blob.find(op)
        size = len(op)+4
        while pos >= 0:
            if pos+size <= len(blob):
                va = text['address']+pos
                dest = va+size+struct.unpack_from('<i', blob, pos+len(op))[0]
                role = targets.get((len(op) == 2, dest))
                if role:
                    fs = [f for f in im.fdes if f['start'] <= va < f['end']]
                    first.require(len(fs) == 1, 'Candidate has no unique FDE: '+hex(va))
                    f = fs[0]
                    if f['start'] not in decoded:
                        ins = list(md.disasm(im.read(f['start'], f['end']-f['start']), f['start']))
                        first.require(sum(i.size for i in ins) == f['end']-f['start'], 'Incomplete xref FDE decode')
                        decoded[f['start']] = {i.address:i for i in ins}
                    i = decoded[f['start']].get(va)
                    valid = i is not None and i.size == size and i.mnemonic in ('call','jmp')
                    rows.append({'role':role,'va':hex(va),'bytes_hex':blob[pos:pos+size].hex(),
                                 'encoding':op.hex(),'destination_or_slot':hex(dest),
                                 'instruction_boundary_validated':valid,
                                 'fde_start':hex(f['start']),'fde_end':hex(f['end']),
                                 'body_sha256':first.sha(im.read(f['start'],f['end']-f['start']))})
            pos = blob.find(op, pos+1)
    return sorted(rows, key=lambda r:int(r['va'],16))


def qualify_census(rows):
    observed = {role:[int(r['va'],16) for r in rows if r['role']==role and r['instruction_boundary_validated']]
                for role in ['sender','constructor']}
    first.require(observed == {'sender':EXPECTED_SENDER,'constructor':EXPECTED_CTOR}, 'Encoded call-site set changed')


def corruption_controls(im, spec, rows):
    rejected = []
    def reject(name, fn):
        try:
            fn()
        except ValueError:
            rejected.append(name)
        else:
            raise ValueError('Accepted corrupt route evidence: '+name)
    for a in spec['anchors']:
        va = int(a['va'],16)+len(bytes.fromhex(a['bytes_hex']))-1
        bad = copy.copy(im)
        def read(start, count, va=va):
            raw = bytearray(im.read(start,count))
            if start <= va < start+count:
                raw[va-start] ^= 1
            return bytes(raw)
        bad.read = read
        reject(a['name'], lambda: selected_bindings(bad,spec))
    for table in spec.get('dispatch', []):
        va=int(table['base'],0)+4*int(table['index'],0)
        bad=copy.copy(im)
        def read(start,count,va=va):
            raw=bytearray(im.read(start,count))
            if start<=va<start+count: raw[va-start]^=1
            return bytes(raw)
        bad.read=read
        reject('dispatch:'+hex(va),lambda:selected_bindings(bad,spec))
    for slot in sorted({SLOT,0x64df508,*[int(r['slot'],16) for r in spec.get('relocations',[])]}):
        bad=copy.copy(im); bad.relocs=dict(im.relocs)
        bad.relocs[slot]=im.relocs[slot]*2
        reject('duplicate-relocation:'+hex(slot),lambda:selected_bindings(bad,spec))
        info, addend = im.relocs[slot][0]
        bad.relocs[slot]=[(info,addend+1)]
        reject('changed-relocation:'+hex(slot),lambda:selected_bindings(bad,spec))
    # Counterfactuals of the parsed census, separate from real-byte pin changes.
    reject('census-missing-site',lambda:qualify_census(rows[1:]))
    extra=dict(rows[0],va='0x2ad03b3')
    reject('census-extra-site',lambda:qualify_census([extra,*rows]))
    return rejected


def collect(out):
    data=(first.ROOT/'artifacts/node/115/hl-node').read_bytes()
    first.authenticate(data)
    im=first.Image(data)
    spec=json.loads((first.PACKET/'routes-spec.json').read_text())
    selected_bindings(im,spec)
    first.bindings(im,json.loads((first.PACKET/'anchors.json').read_text()))
    target_slots=[slot for slot,rels in im.relocs.items() if (8,CTOR) in rels]
    first.require(target_slots==[SLOT], 'Constructor RELATIVE slot census')
    rows=scan_encoded(im,{(False,SEND):'sender',(False,CTOR):'constructor',(True,SLOT):'constructor'})
    qualify_census(rows)
    rejected=corruption_controls(im,spec,rows)
    out.mkdir(parents=True,exist_ok=False)
    md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
    ranges=[]; commands=[]; covered=set()
    versions={'python':sys.version,'platform':platform.platform(),'capstone':capstone.__version__}
    for tool in ['objdump','llvm-objdump']:
        versions[tool]=subprocess.check_output([tool,'--version'],cwd=first.ROOT).decode()
    for r in spec['ranges']:
        start,end=int(r['start'],16),int(r['end'],16)
        fdes=[f for f in im.fdes if f['start']==start and f['end']==end]
        first.require(len(fdes)==1,'Route FDE mismatch')
        body=im.read(start,end-start)
        first.require(first.sha(body)==r['sha256'],'Route body hash')
        ins=list(md.disasm(body,start))
        first.require(sum(i.size for i in ins)==end-start,'Route incomplete decode')
        bounds={i.address for i in ins}|{end}
        for a in spec['anchors']:
            va=int(a['va'],16)
            if start<=va<end:
                first.require(va in bounds and va+len(bytes.fromhex(a['bytes_hex'])) in bounds,'Route pin boundary')
                covered.add(a['name'])
        name=r['name']
        (out/(name+'.capstone.txt')).write_text('\n'.join(f'{i.address:x}: {i.bytes.hex():32} {i.mnemonic:8} {i.op_str}' for i in ins)+'\n',encoding='utf-8',newline='\n')
        record={'name':name,'start':hex(start),'end':hex(end),'fde':hex(fdes[0]['fde']),
                'file_offset':im.offset(start,end-start),'length':end-start,'instructions':len(ins),
                'sha256':first.sha(body),'native':[]}
        for tool,extra,suffix in [('objdump',['-z','--insn-width=16'],'gnu'),('llvm-objdump',['--disassemble-zeroes'],'llvm')]:
            args=[tool,'-d',*extra,f'--start-address={start}',f'--stop-address={end}','artifacts/node/115/hl-node']
            p=subprocess.run(args,cwd=first.ROOT,capture_output=True,check=True)
            filename=name+'.'+suffix+'.objdump'
            (out/filename).write_bytes(p.stdout)
            (out/(filename+'.stderr')).write_bytes(p.stderr)
            native=first.native_rows(p.stdout,im,start,end)
            splits=first.compare_boundaries(native,ins)
            record['native'].append({'file':filename,'sha256':first.sha(p.stdout),'rows':len(native),'lock_prefix_splits':splits})
            commands.append(args)
        ranges.append(record)
    first.require(len(covered)==len(spec['anchors']),'Uncovered or duplicate anchor names')
    result={'target_sha256':first.TARGET,'source_base':'05bc2de303c05525b71e7e257426e741bc66a390',
            'captured_code_executed_or_emulated':False,'ranges':ranges,'encoded_census':rows,
            'census_scope':'Complete .text byte scan for E8/E9 targets and FF15/FF25 through the unique selected RELATIVE slot, then full-FDE instruction boundary checks. Excludes arbitrary register/vtable calls, address-taking, alternate encodings and code outside .text. Not a whole-program caller closure.',
            'exported_bytes':sum(r['length'] for r in ranges),'exported_instructions':sum(r['instructions'] for r in ranges),
            'anchor_spans':len(spec['anchors']),'negative_controls_rejected':rejected,
            'normalization_masks':[],'observations':spec['observations'],
            'scope_limitations':spec['scope_limitations']}
    for name,obj in [('records.json',result),('commands.json',commands),('versions.json',versions)]:
        (out/name).write_text(json.dumps(obj,indent=2)+'\n',encoding='utf-8',newline='\n')
    print(json.dumps({'exported_bytes':result['exported_bytes'],'instructions':result['exported_instructions'],
                      'pins':len(spec['anchors']),'rejected_controls':len(rejected),'encoded_sender_sites':len(EXPECTED_SENDER),
                      'encoded_constructor_sites':len(EXPECTED_CTOR)}))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,required=True)
    collect(parser.parse_args().out)
