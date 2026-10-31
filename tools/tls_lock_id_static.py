#!/usr/bin/env python3
"""RE-001: node115 TLS identity probe and two lazy-mutex-associated callers."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import tempfile
from artifacts import ROOT
from elf_index import sections
from fde_extents import fde_extents
from foundation_millis import decode_export

TARGET = ROOT/'artifacts/node/115/hl-node'
PACKET = ROOT/'research/work-items/RE-001-node115-tls-lock-id'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
OWNERS = {'probe':(0x154cd10,0x154ce3b,'2c00741fbd09b30733a9b6bb922e630f40ed166a9e82f5e46e83e650554d0f79'),
          'caller_three':(0x14c2a40,0x14c2b4c,'3859bdfff5581cd4525e6c586973fbf0e01d847b4f676b5afcefd76137bb1d84'),
          'caller_two':(0x14c2b50,0x14c2c47,'074affff6e4b9cdde4a45cde23119c255abf8f58d91fed46e8362100e5af0efc')}
LOCATIONS = {0x63f8db0:('base/src/lazy_mutex.rs',46,17),0x64015b8:('base/src/lock_id.rs',52,49)}
BINDINGS = {0x64dffe0:0x154cd10,0x64df4b8:0x5c9b900,0x64df4a0:0x635de30,
            0x64e1090:0x1680ba0,0x64e09a8:0x5c9d1c0,0x64e0510:0x5ca0d20}
RIP_SITES = {0x14c2a69:0x64dffe0,0x14c2b79:0x64dffe0,
             0x14c2a91:0x64df4b8,0x14c2ba1:0x64df4b8,
             0x14c2aa5:0x64df4a0,0x14c2aba:0x64df4a0,0x14c2ad1:0x64df4a0,
             0x14c2bb5:0x64df4a0,0x14c2bcc:0x64df4a0,
             0x154cdfb:0x64df9f8,0x154cd42:0x64e09a8,0x154cd68:0x64e0510,0x154ce35:0x64e1090}
DIRECT = {0x14c2b1d:0x154c2c0,0x14c2c18:0x154c4e0,
          0x14c2b2f:0x15d3214,0x14c2c2a:0x15d32ae,
          0x14c2b3f:0x14c5640,0x14c2c3a:0x14c56b0,
          0x14c2b47:0x63f0a50,0x14c2c42:0x63f0a50}


def read(data,va,n):
    rows=[s for s in sections(data) if s['type']!=8 and s['address']<=va and va+n<=s['address']+s['size']]
    if len(rows)!=1:
        raise ValueError('expected one file-backed mapping')
    s=rows[0];o=s['offset']+va-s['address']
    return o,bytes(data[o:o+n])


def probe_layout(body):
    fields=[]
    for at,opcode,width in [(0xc9,'4d397c1d',8),(0xd0,'4539641d',4),(0xd7,'4d39741d',8)]:
        if body[at:at+4]!=bytes.fromhex(opcode):
            raise ValueError('identity comparison opcode changed')
        fields.append({'record_offset':body[at+4],'input_offset':{0xc9:24,0xd0:16,0xd7:8}[at],'width':width})
    return {'fields':fields,'stride_multiply':body[0x9d],'stride_increment':body[0xc3],
            'enabled_offset':body[0x10],'enabled_value':body[0x11],
            'tls_offset':struct.unpack_from('<i',body,0x17)[0],
            'borrow_limit':struct.unpack_from('<Q',body,0x6d)[0]}


def scalar_identity(layout,record,key):
    """Independent field projection used in corruption controls, not a CPU model."""
    return all(record[f['record_offset']:f['record_offset']+f['width']]
               ==key[f['input_offset']:f['input_offset']+f['width']] for f in layout['fields'])


def analyze(data):
    _,fs,_=fde_extents(data)
    fdes={(f['start'],f['end']):f for f in fs}
    secs=sections(data);rs=next(s for s in secs if s['name']=='.rela.dyn')
    rels={a:(i,v) for a,i,v in struct.iter_unpack('<QQq',data[rs['offset']:rs['offset']+rs['size']])}
    body=read(data,0x154cd10,299)[1]
    layout=probe_layout(body)
    expected={'fields':[{'record_offset':24,'input_offset':24,'width':8},{'record_offset':16,'input_offset':16,'width':4},{'record_offset':8,'input_offset':8,'width':8}],
              'stride_multiply':56,'stride_increment':56,'enabled_offset':32,'enabled_value':1,'tls_offset':-4480,'borrow_limit':(1<<63)-1}
    if layout!=expected:
        raise ValueError('TLS identity layout changed')
    if any(rels.get(a)!=(8,v) for a,v in BINDINGS.items()):
        raise ValueError('TLS/caller relocation changed')
    # Resolve the imported comparison through actual ELF symbol metadata.
    if rels.get(0x64df9f8)!=((11<<32)|6,0):
        raise ValueError('bcmp dynamic relocation changed')
    syms=next(s for s in secs if s['name']=='.dynsym');strings=next(s for s in secs if s['name']=='.dynstr')
    sym=read(data,syms['address']+11*24,24)[1]
    if sym!=bytes.fromhex('930000001200000000000000000000000000000000000000') or read(data,strings['address']+0x93,5)[1]!=b'bcmp\0':
        raise ValueError('bcmp dynamic symbol changed')
    if read(data,0x448a8e,17)[1]!=b'\x0clazy mutex: \xc0\x01\n\0':
        raise ValueError('lazy-mutex descriptor changed')
    locations=[]
    for slot,(path,line,column) in LOCATIONS.items():
        info,target=rels.get(slot,(None,None))
        if info!=8 or read(data,slot+8,16)[1]!=struct.pack('<QII',len(path),line,column) or read(data,target,len(path))[1]!=path.encode():
            raise ValueError('source Location changed')
        locations.append({'slot':hex(slot),'path_va':hex(target),'path':path,'line':line,'column':column})
    for site,slot in RIP_SITES.items():
        code=read(data,site,6)[1]
        if code[:2]!=b'\xff\x15' or site+6+struct.unpack_from('<i',code,2)[0]!=slot:
            raise ValueError('indirect call slot changed')
    for site,target in DIRECT.items():
        code=read(data,site,5)[1]
        if code[0]!=0xe8 or site+5+struct.unpack_from('<i',code,1)[0]!=target:
            raise ValueError('direct call target changed')
    for site,slot in [(0x14c2b0b,0x63f8db0),(0x14c2c06,0x63f8db0),(0x154ce2e,0x64015b8)]:
        code=read(data,site,7)[1]
        if code[:2]!=b'\x48\x8d' or site+7+struct.unpack_from('<i',code,3)[0]!=slot:
            raise ValueError('source Location LEA changed')
    owners=[]
    for name,(a,b,sha) in OWNERS.items():
        if (a,b) not in fdes:
            raise ValueError('TLS scope FDE changed')
        offset,raw=read(data,a,b-a)
        if hashlib.sha256(raw).hexdigest()!=sha:
            raise ValueError('TLS/caller instruction dataflow changed')
        f=fdes[(a,b)];records={}
        for kind in ['fde','cie']:
            v=f[kind];n=struct.unpack('<I',read(data,v,4)[1])[0]+4
            records[kind]={'va':hex(v),'bytes_hex':read(data,v,n)[1].hex()}
        owners.append({'role':name,'start':hex(a),'end':hex(b),'file_offset':hex(offset),'bytes':b-a,'sha256':sha,'frames':records})
    return {'target_sha256':SHA,'owners':owners,'probe_layout':layout,'locations':locations,
            'relative_bindings':{hex(a):hex(v) for a,v in BINDINGS.items()},
            'rip_calls':{hex(a):hex(v) for a,v in RIP_SITES.items()},
            'direct_calls':{hex(a):hex(v) for a,v in DIRECT.items()},
            'comparison_import':{'slot':'0x64df9f8','symbol_index':11,'symbol':'bcmp','relocation_type':6},
            'normal_ready_tls_scope':'enabled byte=1, TLS readiness byte=1, borrow counter<2^63-1; valid bounded 56-byte vector and input byte slices',
            'loop_relation':'three scalar fields equal and imported bcmp returns zero; any matching record yields AL1, empty/exhausted vector AL0',
            'borrow_counter':'saved original incremented for scan, then restored on both local returning outcomes',
            'caller_true_path':'same probe input at object+0x18; opaque formatting call, 3/2 conditional cleanup calls, then AL1',
            'caller_false_path':'separate opaque direct helper; returned AL is not classified',
            'captured_code_executed':False,
            'limits':'No source type ABI, mutex acquisition/ordering guarantee, global xref completeness, initialization/destruction/panic/unwind closure, full caller effects, or reconstruction gate. Byte equality assumes the imported libc bcmp contract and normal ABI-preserving returns; its actual implementation is not in this packet.'}


def generate(binary,output):
    data=binary.read_bytes()
    if len(data)!=105896032 or hashlib.sha256(data).hexdigest()!=SHA:
        raise ValueError('expected pinned node115')
    report=analyze(data)
    output.mkdir(parents=True,exist_ok=True)
    rows=[]
    with tempfile.TemporaryDirectory() as directory:
        snap=Path(directory)/'node115.elf';snap.write_bytes(data)
        frames=subprocess.check_output(['readelf','-wf',str(snap)],text=True)
        for name,(a,b,_) in OWNERS.items():
            matched=[l for l in frames.splitlines() if f'pc={a:016x}..{b:016x}' in l]
            if len(matched)!=1:
                raise ValueError('native TLS FDE disagreement')
            rows.extend(matched)
            asm=subprocess.check_output(['objdump','-d','-M','intel','--insn-width=16',f'--start-address={a:#x}',f'--stop-address={b:#x}',str(snap)],text=True)
            ins=decode_export(asm,a,b,read(data,a,b-a)[1])
            sites={v for v in RIP_SITES if a<=v<b}|{v for v in DIRECT if a<=v<b}
            sites|=({0x154cdd9,0x154cde0,0x154cde7,0x154ce1b} if name=='probe' else set())
            if not sites<=set(ins):
                raise ValueError('TLS dataflow site not native instruction start')
            (output/f'{name}.objdump.txt').write_bytes(asm.replace(str(snap),'<authenticated-node115>').encode('utf-8'))
        relocations=subprocess.check_output(['readelf','-rW',str(snap)],text=True)
        chosen=[l for l in relocations.splitlines() if re.match(r'^000000000(?:64df9f8|64dffe0|63f8db0|64015b8)\s',l)]
        if len(chosen)!=4 or 'bcmp@GLIBC_2.2.5' not in '\n'.join(chosen):
            raise ValueError('native comparison/source relocation disagreement')
        (output/'selected-relocations.txt').write_bytes(('\n'.join(chosen)+'\n').encode('utf-8'))
    (output/'frames.txt').write_bytes(('\n'.join(rows)+'\n').encode('utf-8'))
    (output/'records.json').write_bytes((json.dumps(report,indent=2)+'\n').encode('utf-8'))
    return report


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary',type=Path,default=TARGET)
    p.add_argument('--output',type=Path,default=ROOT/'work/tls-lock-id115')
    args=p.parse_args();r=generate(args.binary,args.output)
    print(json.dumps({'functions':len(r['owners']),'bytes':sum(x['bytes'] for x in r['owners']),'executed':False}))
