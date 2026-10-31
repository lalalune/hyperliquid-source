#!/usr/bin/env python3
"""RE-001: digest-bound node115 cache suffix selector and two concrete key callers."""
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
PACKET=ROOT/'research/work-items/RE-001-node115-cache-suffix'
SHA='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
OWNERS={
 'selector':(0x59429e0,0x5942b3e,'36c9c389476b1161cf220bfdc192d75ec7611e5cc71262a00b76653cad98c589'),
 'metadata_caller':(0x595aff0,0x595b1a0,'82412ede0b4b4a1b9cf14b4874f78f1a9377028311023435f153105eef403aba'),
 'artifact_caller':(0x4ec71b0,0x4ec79f7,'6834b58c26cb93063b2479b9de38156700f7ae266cb8efab0e244a956812324f'),
 'slice_callback':(0x5616320,0x5616333,'560f16b6305b72d04e99faa3ad62d0b35c063625ab2b7cb018223b32412bd4fc'),
 'owned_callback':(0x58621b0,0x58621c4,'03b3a07fb32c6fd6a99a8bfacb77235c9b6aa71c4badf48ac3191636764dad0e')}
KEYS={0x64b6818:b'node_metadata',0x649dbf8:b'node_artifact_2'}
BINDINGS={0x64df720:0x167fa70,0x64df6e8:0x141e3a0,0x64df4a0:0x635de30,0x64df9f0:0x5c87d50,0x64e0918:0x64f06c0}


def read(data,va,n):
    matches=[s for s in sections(data) if s['type']!=8 and s['address']<=va and va+n<=s['address']+s['size']]
    if len(matches)!=1:
        raise ValueError('expected one file-backed mapping')
    s=matches[0];o=s['offset']+va-s['address']
    return o,bytes(data[o:o+n])


def selector_constants(body):
    if body[0x1d:0x21]!=b'\x48\x83\x7e\x08' or body[0x27:0x29]!=b'\x48\xb9' or body[0x38:0x3b]!=b'\x48\x81\xf2':
        raise ValueError('selector operand opcode changed')
    return {'length':body[0x21], 'prefix':body[0x29:0x31], 'tail_xor':struct.unpack_from('<I',body,0x3b)[0]}


def suffix_layout(body):
    return {'special_pointer':0x5942a24+7+struct.unpack_from('<i',body,0x47)[0],
            'default_pointer':0x5942a2b+7+struct.unpack_from('<i',body,0x4e)[0],
            'base_length':body[0x5c],
            'length_without_ten_byte_test':struct.unpack_from('<I',body,0x9b)[0]}


def matches_selector(constants,key):
    """Algebraic equality condition of the observed length + 8/2-byte tests."""
    return len(key)==constants['length'] and len(key)>=10 and key[:8]==constants['prefix'] and int.from_bytes(key[8:10],'little')==constants['tail_xor']


def analyze(data):
    _,fs,_=fde_extents(data);fdes={(f['start'],f['end']):f for f in fs}
    body=read(data,0x59429e0,350)[1];constants=selector_constants(body)
    if constants!={'length':10,'prefix':b'abci_sta','tail_xor':0x6574}:
        raise ValueError('selector key condition changed')
    if body[0x52:0x56]!=bytes.fromhex('480f44ca') or body[0x56:0x59]!=bytes.fromhex('0f95c0') or body[0x59:0x5d]!=bytes.fromhex('4883c003'):
        raise ValueError('selector conditional pointer/length changed')
    layout=suffix_layout(body)
    if layout!={'special_pointer':0x9382b9,'default_pointer':0x459f60,'base_length':3,'length_without_ten_byte_test':4}:
        raise ValueError('suffix pointer/length layout changed')
    sec=next(s for s in sections(data) if s['name']=='.rela.dyn')
    rels={a:(i,v) for a,i,v in struct.iter_unpack('<QQq',data[sec['offset']:sec['offset']+sec['size']])}
    if any(rels.get(a)!=(8,v) for a,v in BINDINGS.items()):
        raise ValueError('cache formatting/global relocation changed')
    literals={0x9382b9:b'rmp',0x459f60:b'json',0x43d024:b'\xc0\x01.\xc0\0',0x44f615:b'\xc0\x12/hyperliquid_data/\xc0\0'}
    for a,value in literals.items():
        if read(data,a,len(value))[1]!=value:
            raise ValueError('suffix or descriptor bytes changed')
    consumers=[]
    for site,slot,call in [(0x595b000,0x64b6818,0x595b00f),(0x4ec7244,0x649dbf8,0x4ec7256)]:
        key=KEYS[slot];info,pointer=rels.get(slot,(None,None))
        if info!=8 or read(data,slot+8,8)[1]!=struct.pack('<Q',len(key)) or read(data,pointer,len(key))[1]!=key:
            raise ValueError('cache key fat string changed')
        code=read(data,site,7)[1]
        if code[:3]!=b'\x48\x8d\x35' or site+7+struct.unpack_from('<i',code,3)[0]!=slot:
            raise ValueError('cache key LEA changed')
        code=read(data,call,5)[1]
        if code[0]!=0xe8 or call+5+struct.unpack_from('<i',code,1)[0]!=0x59429e0:
            raise ValueError('cache selector call changed')
        consumers.append({'key':key.decode(),'slot':hex(slot),'string_va':hex(pointer),'lea':hex(site),'call':hex(call),'suffix':'json'})
    # Same actual source Location is passed by both contextual callers.
    slot=0x64b6778;info,pointer=rels.get(slot,(None,None));path=b'base/src/data_cache.rs'
    if info!=8 or read(data,pointer,len(path))[1]!=path or read(data,slot+8,16)[1]!=struct.pack('<QII',len(path),97,9):
        raise ValueError('cache source Location changed')
    owners=[]
    for role,(a,b,sha) in OWNERS.items():
        if (a,b) not in fdes:
            raise ValueError('cache scope FDE changed')
        offset,raw=read(data,a,b-a)
        if hashlib.sha256(raw).hexdigest()!=sha:
            raise ValueError('cache instruction/argument dataflow changed')
        records={}
        for kind in ['fde','cie']:
            va=fdes[(a,b)][kind];n=struct.unpack('<I',read(data,va,4)[1])[0]+4
            records[kind]={'va':hex(va),'bytes_hex':read(data,va,n)[1].hex()}
        owners.append({'role':role,'start':hex(a),'end':hex(b),'file_offset':hex(offset),'bytes':b-a,'sha256':sha,'frames':records})
    return {'target_sha256':SHA,'owners':owners,'special_key':'abci_state','special_length':constants['length'],
            'selector_first_eight_bytes_hex':constants['prefix'].hex(),'selector_last_two_xor':hex(constants['tail_xor']),
            'suffixes':{'exact_special_key':{'va':'0x9382b9','length':3,'bytes':'rmp'},'all_other_keys':{'va':'0x459f60','length':4,'bytes':'json'}},
            'concrete_consumers':consumers,'source_location':{'slot':hex(slot),'path_va':hex(pointer),'path':path.decode(),'line':97,'column':9},
            'relative_bindings':{hex(a):hex(v) for a,v in BINDINGS.items()},
            'descriptors':{hex(a):v.hex() for a,v in literals.items() if a in [0x43d024,0x44f615]},
            'argument_bindings':'inner: key then selected suffix via callback5616320; outer: global+0x18 then temporary inner output via callback58621b0',
            'callbacks':'5616320 reads pointer/length at +0/+8; 58621b0 reads +8/+0x10; both tail-call slot64df720',
            'captured_code_executed':False,
            'limits':'Suffix selection and actual key/call/format-argument bindings only. No serialization format inference from extension, file I/O, runtime root path, opaque initialization/formatting effects, complete caller recovery, #94 correspondence, or reconstruction gate.'}


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
                raise ValueError('native cache FDE disagreement')
            lines.extend(rows)
            asm=subprocess.check_output(['objdump','-d','-M','intel','--insn-width=16',f'--start-address={a:#x}',f'--stop-address={b:#x}',str(snapshot)],text=True)
            ins=decode_export(asm,a,b,read(data,a,b-a)[1])
            required={'selector':[0x59429fd,0x5942a07,0x5942a18,0x5942a32,0x5942a36,0x5942a39,0x5942a90,0x5942ac8,0x5942adf,0x5942af6],
                      'metadata_caller':[0x595b000,0x595b00f,0x595b024],
                      'artifact_caller':[0x4ec7244,0x4ec7256,0x4ec726b],
                      'slice_callback':[0x5616323,0x5616326,0x561632d],
                      'owned_callback':[0x58621b3,0x58621b7,0x58621be]}[role]
            if not set(required)<=set(ins):
                raise ValueError('cache evidence site not native instruction start')
            (output/f'{role}.objdump.txt').write_bytes(asm.replace(str(snapshot),'<authenticated-node115>').encode('utf-8'))
    (output/'frames.txt').write_bytes(('\n'.join(lines)+'\n').encode('utf-8'))
    (output/'records.json').write_bytes((json.dumps(report,indent=2)+'\n').encode('utf-8'))
    return report


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary',type=Path,default=TARGET)
    p.add_argument('--output',type=Path,default=ROOT/'work/cache-suffix115')
    args=p.parse_args();report=generate(args.binary,args.output)
    print(json.dumps({'functions':len(report['owners']),'bytes':sum(x['bytes'] for x in report['owners']),'executed':False}))
