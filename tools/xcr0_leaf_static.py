#!/usr/bin/env python3
"""RE-002: digest-bound node115 XCR0 probe leaf 0x5cae3e0 and its refresh-helper branch."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile
from artifacts import ROOT
from elf_index import sections
from fde_extents import fde_extents
from foundation_millis import decode_export

TARGET=ROOT/'artifacts/node/115/hl-node'
PACKET=ROOT/'research/work-items/RE-002-node115-xcr0-leaf'
SHA='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
OWNERS={
 'xcr0_leaf':(0x5cae3e0,0x5cae3ed,'f347a1395ba474e85f6c71330ca7f30e1d067cc6af42548744b6310ae2dbf0be'),
 'consumer_refresh':(0x5cadd50,0x5cae3da,'f4cc818ee02b994599bfc53910323d3edf8420d0b404c2e5060faab72524c349')}
LEAF=0x5cae3e0
CALL_SITE=0x5cae04c
LIMITS=('XCR0 probe leaf result, its static boundaries, and its sole consumer\'s first '
 'branch and pinned field extractions only. The leaf returns the full XCR0 value its '
 'XGETBV instruction produces; no captured runtime XCR0 value is observed or claimed. '
 'What the composed feature word means downstream, the consumer prefix\'s ten CPUID '
 'instructions and their composition, feature/ISA names for the tested bits, cache '
 'synchronization, and the publication equations are the scope of the merged RE-002 '
 'cache-publication packet and are not re-derived or re-claimed here. No captured code '
 'executed, no complete caller recovery beyond the full-.text direct-call census and '
 '.rela.dyn scan, no #94 correspondence, or reconstruction gate is claimed.')


def read(data,va,n):
    matches=[s for s in sections(data) if s['type']!=8 and s['address']<=va and va+n<=s['address']+s['size']]
    if len(matches)!=1:
        raise ValueError('expected one file-backed mapping')
    s=matches[0];o=s['offset']+va-s['address']
    return o,bytes(data[o:o+n])


def leaf_semantics(body):
    """Pin the leaf's five instructions: xor ecx,ecx / xgetbv / shl rdx,0x20 /
    or rax,rdx / ret. ECX=0 selects XCR0; the result is the full 64-bit XCR0."""
    if len(body)!=13:
        raise ValueError('xcr0 leaf body length changed')
    if body[0x00:0x02]!=b'\x31\xc9':
        raise ValueError('xcr0 leaf index clear changed')
    if body[0x02:0x05]!=b'\x0f\x01\xd0':
        raise ValueError('xcr0 leaf xgetbv changed')
    if body[0x05:0x08]!=b'\x48\xc1\xe2' or body[0x08]!=0x20:
        raise ValueError('xcr0 leaf high-half shift changed')
    if body[0x09:0x0c]!=b'\x48\x09\xd0':
        raise ValueError('xcr0 leaf compose or changed')
    if body[0x0c]!=0xc3:
        raise ValueError('xcr0 leaf return changed')
    return {'index_register':'ecx','index_value':0,'shift':body[0x08],
            'result':'rax = xgetbv(ecx=0), the full XCR0 value (edx:eax recomposed)'}


def _pin(body,base,va,hexbytes,what):
    off=va-base;want=bytes.fromhex(hexbytes)
    if body[off:off+len(want)]!=want:
        raise ValueError(f'consumer xcr0 {what} changed')


def consumer_trace(data):
    """Pin the refresh helper's use of the leaf result (RAX -> R14).

    Byte-level pins only: the call, the result move, the pre-branch field
    extraction, the first branch on the returned value, the fall-through
    mask field and its complement composition, and the two arms' shared
    convergence. No feature-name label is attached to any tested bit.
    """
    start,end,_=OWNERS['consumer_refresh']
    _,body=read(data,start,end-start)
    def rip_target(va,insn_len,disp_at):
        return va+insn_len+struct.unpack_from('<i',body,disp_at-start)[0]
    def rip_target8(va):
        return va+2+struct.unpack_from('<b',body,va+1-start)[0]
    # The sole call and the result move RAX -> R14.
    _pin(body,start,CALL_SITE,'e8','call opcode')
    if rip_target(CALL_SITE,5,CALL_SITE+1)!=LEAF:
        raise ValueError('consumer xcr0 call target changed')
    _pin(body,start,0x5cae051,'4989c6','result move')
    # Field extracted before the branch: EDI = R14d & 0x60000 (bits 17,18).
    _pin(body,start,0x5cae054,'4489f7','high field move')
    _pin(body,start,0x5cae057,'81e700000600','high field mask')
    # First branch on the returned value: NOT EAX / TEST AL,0x6 / JNE.
    _pin(body,start,0x5cae05d,'f7d0','branch not')
    _pin(body,start,0x5cae05f,'a806','branch test')
    _pin(body,start,0x5cae061,'0f85','branch jne opcode')
    branch_target=rip_target(0x5cae061,6,0x5cae061+2)
    if branch_target!=0x5cae260:
        raise ValueError('consumer xcr0 branch target changed')
    # Fall-through: R8d = R14d & 0xe0 (bits 5,6,7); H bit set into R12.
    _pin(body,start,0x5cae067,'4589f0','mask field move')
    _pin(body,start,0x5cae06a,'4181e0e0000000','mask field and')
    _pin(body,start,0x5cae071,'48b80000000000000080','h movabs')
    _pin(body,start,0x5cae07b,'4909c4','h or into r12')
    # The mask field is complemented and OR'd into the composed word.
    _pin(body,start,0x5cae0c4,'4981f0e0000000','mask field xor')
    _pin(body,start,0x5cae157,'4c09c0','mask field or')
    # Taken arm entry and both arms' shared high-field comparison.
    _pin(body,start,0x5cae260,'4c8b5db8','taken arm entry')
    _pin(body,start,0x5cae26c,'81ff00000600','taken arm high field cmp')
    _pin(body,start,0x5cae272,'757f','taken arm jne')
    if rip_target8(0x5cae272)!=0x5cae2f3:
        raise ValueError('consumer xcr0 taken arm convergence changed')
    _pin(body,start,0x5cae244,'81ff00000600','fallthrough high field cmp')
    _pin(body,start,0x5cae24a,'7428','fallthrough je')
    if rip_target8(0x5cae24a)!=0x5cae274:
        raise ValueError('consumer xcr0 shared block changed')
    _pin(body,start,0x5cae24c,'e9a2000000','fallthrough jmp')
    if rip_target(0x5cae24c,5,0x5cae24c+1)!=0x5cae2f3:
        raise ValueError('consumer xcr0 fallthrough convergence changed')
    return {'consumer':'consumer_refresh','call_site':hex(CALL_SITE),
            'result_register':'r14',
            'high_field':{'move':'0x5cae054','mask_site':'0x5cae057','mask':'0x60000','bits':[17,18]},
            'first_branch':{'not':'0x5cae05d','test':'0x5cae05f','mask':'0x6','bits':[1,2],
                            'jne':'0x5cae061','target':hex(branch_target),
                            'taken_when':'(xcr0 & 0x6) != 0x6'},
            'mask_field':{'move':'0x5cae067','and':'0x5cae06a','mask':'0xe0','bits':[5,6,7],
                          'h_set':{'movabs':'0x5cae071','or':'0x5cae07b','value':'0x8000000000000000','into':'r12'},
                          'complement_xor':'0x5cae0c4','composed_or':'0x5cae157'},
            'convergence':{'shared_block':'0x5cae274','site':'0x5cae2f3'}}


def call_census(data):
    text=next(s for s in sections(data) if s['name']=='.text')
    body=data[text['offset']:text['offset']+text['size']];base=text['address']
    sites=[];index=body.find(b'\xe8')
    while index!=-1:
        if base+index+5+struct.unpack_from('<i',body,index+1)[0]==LEAF:
            sites.append(base+index)
        index=body.find(b'\xe8',index+1)
    sec=next(s for s in sections(data) if s['name']=='.rela.dyn')
    rela_hits=0
    for a,i,v in struct.iter_unpack('<QQq',data[sec['offset']:sec['offset']+sec['size']]):
        if v==LEAF:
            rela_hits+=1
    return sites,rela_hits


def analyze(data):
    _,fs,_=fde_extents(data);fdes={(f['start'],f['end']):f for f in fs}
    owners=[]
    for role,(a,b,sha) in OWNERS.items():
        if (a,b) not in fdes:
            raise ValueError('xcr0 scope FDE changed')
        offset,raw=read(data,a,b-a)
        if hashlib.sha256(raw).hexdigest()!=sha:
            raise ValueError(f'xcr0 {role} body changed')
        records={}
        for kind in ['fde','cie']:
            va=fdes[(a,b)][kind];n=struct.unpack('<I',read(data,va,4)[1])[0]+4
            records[kind]={'va':hex(va),'bytes_hex':read(data,va,n)[1].hex()}
        owners.append({'role':role,'start':hex(a),'end':hex(b),'file_offset':hex(offset),
                       'bytes':b-a,'sha256':sha,'frames':records})
    leaf_body=read(data,LEAF,OWNERS['xcr0_leaf'][1]-LEAF)[1]
    leaf=leaf_semantics(leaf_body)
    sites,rela_hits=call_census(data)
    if sites!=[CALL_SITE]:
        raise ValueError('xcr0 leaf direct call census changed')
    if rela_hits!=0:
        raise ValueError('xcr0 leaf relocation reference appeared')
    consumer_start,consumer_end,_=OWNERS['consumer_refresh']
    if not (consumer_start<=CALL_SITE<consumer_end):
        raise ValueError('xcr0 call site outside consumer FDE')
    trace=consumer_trace(data)
    return {'target_sha256':SHA,'owners':owners,'leaf':dict(leaf,fde='0x5cae3e0..0x5cae3ed'),
            'call_census':{'direct_call_sites':[hex(s) for s in sites],
                           'relocation_references':rela_hits},
            'consumer_trace':trace,'direct_callers':len(sites),
            'captured_code_executed':False,'limits':LIMITS}


def generate(binary,output):
    data=binary.read_bytes()
    if len(data)!=105896032 or hashlib.sha256(data).hexdigest()!=SHA:
        raise ValueError('expected pinned node115')
    report=analyze(data);output.mkdir(parents=True,exist_ok=True);lines=[]
    with tempfile.TemporaryDirectory() as directory:
        snapshot=Path(directory)/'node115.elf';snapshot.write_bytes(data)
        native=subprocess.check_output(['readelf','-wf',str(snapshot)],text=True)
        for role,(a,b,_) in OWNERS.items():
            rows=[l for l in native.splitlines() if f'pc={a:016x}..{b:016x}' in l]
            if len(rows)!=1:
                raise ValueError('native xcr0 FDE disagreement')
            lines.extend(rows)
            asm=subprocess.check_output(['objdump','-d','-M','intel','--insn-width=16',f'--start-address={a:#x}',f'--stop-address={b:#x}',str(snapshot)],text=True)
            ins=decode_export(asm,a,b,read(data,a,b-a)[1])
            if role=='xcr0_leaf':
                required=[0x5cae3e0,0x5cae3e2,0x5cae3e5,0x5cae3e9,0x5cae3ec]
                if not set(required)<=set(ins):
                    raise ValueError('xcr0 leaf site not native instruction start')
                (output/'leaf.objdump.txt').write_bytes(asm.replace(str(snapshot),'<authenticated-node115>').encode('utf-8'))
            else:
                # No second full export of the merged packet's owner body is
                # retained; the trace sites are validated as native starts.
                required=[0x5cae04c,0x5cae051,0x5cae054,0x5cae057,0x5cae05d,0x5cae05f,
                          0x5cae061,0x5cae067,0x5cae06a,0x5cae071,0x5cae07b,0x5cae0c4,
                          0x5cae157,0x5cae244,0x5cae24a,0x5cae24c,0x5cae260,0x5cae26c,0x5cae272]
                if not set(required)<=set(ins):
                    raise ValueError('xcr0 consumer trace site not native instruction start')
    (output/'frames.txt').write_bytes(('\n'.join(lines)+'\n').encode('utf-8'))
    (output/'records.json').write_bytes((json.dumps(report,indent=2)+'\n').encode('utf-8'))
    return report


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary',type=Path,default=TARGET)
    p.add_argument('--output',type=Path,default=ROOT/'work/xcr0-leaf115')
    args=p.parse_args();report=generate(args.binary,args.output)
    print(json.dumps({'functions':len(report['owners']),'bytes':sum(x['bytes'] for x in report['owners']),'executed':False}))
