#!/usr/bin/env python3
"""RE-001: message-bound cumulative-counter cutoffs in node94 EVM KVS paths."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

from artifacts import ROOT
from elf_index import sections
from fde_extents import eh_frame_records

SHA256='3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
K=0x2e90edc
MAX=(1<<64)-1
CASES=[
    {'cmp':0x1fd6660,'shift':10,'branch':0x1fd6666,'branch_prefix':'76','branch_size':2,'branch_target':0x1fd66be,
     'large_arm':0x1fd6668,'context':0x1fd6654,'load':0x1fd6658,'load_hex':'488b4368','gap':'',
     'template_lea':0x1fd669d,'template':0x1f2116,'location_lea':0x1fd66a4,'location':0x5692d58,'line':96,'column':9,
     'call':0x1fd66b8,'owner_start':33383168,'owner_end':33388556,
     'owner_sha256':'d1d9f8ebb16bb7f408b51351d6f9351b511e67214567990cf96cdb1b7a8517c0'},
    {'cmp':0x2266b45,'shift':11,'branch':0x2266b50,'branch_prefix':'0f86','branch_size':6,'branch_target':0x2266d76,
     'large_arm':0x2266b56,'context':0x2266b39,'load':0x2266b3e,'load_hex':'488b01','gap':'488b5c2408',
     'template_lea':0x2266b96,'template':0x1e65ff,'location_lea':0x2266b9d,'location':0x569e858,'line':151,'column':13,
     'call':0x2266bb4,'owner_start':36050352,'owner_end':36080112,
     'owner_sha256':'541304bb4269d1d3698734b27a4ca082b129ae3c108be4e504b7643221940249'},
    {'cmp':0x435aca3,'shift':11,'branch':0x435acb8,'branch_prefix':'0f86','branch_size':6,'branch_target':0x435af05,
     'large_arm':0x435acbe,'context':0x435ac97,'load':0x435ac9c,'load_hex':'488b01','gap':'4c8b6c241848bb0000000000000080',
     'template_lea':0x435acfe,'template':0x1e65ff,'location_lea':0x435ad05,'location':0x571d078,'line':151,'column':13,
     'call':0x435ad1c,'owner_start':70610064,'owner_end':70634261,
     'owner_sha256':'388921e18e585dec288036773585a4d53442cdb9a9051c18fd95725b8a2b6635'},
    {'cmp':0x47475b2,'shift':11,'branch':0x47475c5,'branch_prefix':'0f87','branch_size':6,'branch_target':0x4747c06,
     'large_arm':0x4747c06,'context':0x47475a6,'load':0x47475ab,'load_hex':'488b01','gap':'4c8b7c2408488bac24a8000000',
     'template_lea':0x4747c46,'template':0x1e65ff,'location_lea':0x4747c4d,'location':0x572eea8,'line':151,'column':13,
     'call':0x4747c64,'owner_start':74727776,'owner_end':74744367,
     'owner_sha256':'1e122bfde4ad0d8a63b9583226572274d37221ce55ee155344b7326fa5fcb338'},
    {'cmp':0x4b2dc3e,'shift':11,'branch':0x4b2dc49,'branch_prefix':'0f86','branch_size':6,'branch_target':0x4b2e070,
     'large_arm':0x4b2dc4f,'context':0x4b2dc2f,'load':0x4b2dc37,'load_hex':'488b01','gap':'488b5c2410',
     'template_lea':0x4b2dc8f,'template':0x1e65ff,'location_lea':0x4b2dc96,'location':0x5738638,'line':151,'column':13,
     'call':0x4b2dcad,'owner_start':78813024,'owner_end':78839192,
     'owner_sha256':'dcee85c38ce06b88ad8fa55df8c2978c058e62d7a94fb43fa73af8ad22e5d05b'},
]
TEMPLATES={0x1f2116:b'1rocksdb from tcp stream large @@ [n_total_bytes: \xc0\x01]\0',
           0x1e65ff:b'>rocksdb from tcp stream too large, exiting @@ [n_total_bytes: \xc0\x01]\0'}


def require(value,message):
    if not value:raise ValueError(message)


def enters_large_arm(word,shift,compare):
    require(type(word) is int and 0<=word<=MAX,'Expected unsigned 64-bit counter word')
    return (word>>shift)>compare


def observe(data):
    secs=sections(data)

    def read(va,size):
        ss=[s for s in secs if s['type']!=8 and s['address']<=va and va+size<=s['address']+s['size']]
        require(len(ss)==1,'Expected one file-backed mapping')
        off=ss[0]['offset']+va-ss[0]['address'];require(off+size<=len(data),'Truncated mapped bytes')
        return data[off:off+size]

    def code(va,prefix,size):
        raw=read(va,size);require(raw.startswith(bytes.fromhex(prefix)),f'Instruction changed at {va:#x}')
        return raw

    _,frames=eh_frame_records(data,secs)
    relsec=next(s for s in secs if s['name']=='.rela.dyn')
    relocs={}
    for slot,info,addend in struct.iter_unpack('<QQq',read(relsec['address'],relsec['size'])):
        if info==8:
            require(slot not in relocs,'Duplicate RELATIVE relocation');relocs[slot]=addend
    require(relocs.get(0x576e978)==0x143d010,'Critical-message call binding changed')
    for va,expected in TEMPLATES.items():
        require(read(va,len(expected))==expected,'RocksDB diagnostic template changed')
    records=[]
    for case in CASES:
        fs=[f for f in frames if f['start']==case['owner_start']]
        require(len(fs)==1 and fs[0]['end']==case['owner_end'],'Size comparison owner FDE changed')
        require(read(case['load'],len(bytes.fromhex(case['load_hex'])))==bytes.fromhex(case['load_hex']),
                'Counter word load changed')
        shift=code(case['cmp']-4,'48c1e8',4)[3]
        compare=struct.unpack_from('<I',code(case['cmp'],'483d',6),2)[0]
        require((shift,compare)==(case['shift'],K),'Counter shift/compare changed')
        gap=read(case['cmp']+6,case['branch']-(case['cmp']+6))
        require(gap==bytes.fromhex(case['gap']),'Flag-preserving move gap changed')
        branch=code(case['branch'],case['branch_prefix'],case['branch_size'])
        disp=struct.unpack_from('<b',branch,1)[0] if len(branch)==2 else struct.unpack_from('<i',branch,2)[0]
        target=case['branch']+len(branch)+disp
        require(target==case['branch_target'],'Size branch target changed')
        expected_large=target if case['branch_prefix']=='0f87' else case['branch']+len(branch)
        require(case['large_arm']==expected_large,'Large-arm relation changed')
        raw=code(case['template_lea'],'488d35',7)
        template=case['template_lea']+7+struct.unpack_from('<i',raw,3)[0]
        require(template==case['template'],'Diagnostic template reference changed')
        raw=code(case['location_lea'],'488d0d',7)
        location=case['location_lea']+7+struct.unpack_from('<i',raw,3)[0]
        require(location==case['location'] and relocs.get(location)==0x1f3f0f,'EVM KVS source binding changed')
        length,line,column=struct.unpack('<QII',read(location+8,16))
        path=read(relocs[location],length).decode('utf8')
        require(path=='/home/ubuntu/hl/code_Mainnet/node/src/evm_kvs.rs' and
                (line,column)==(case['line'],case['column']),'EVM KVS source Location changed')
        raw=code(case['call'],'ff15',6)
        slot=case['call']+6+struct.unpack_from('<i',raw,2)[0]
        require(slot==0x576e978,'Diagnostic call slot changed')
        body=read(case['owner_start'],case['owner_end']-case['owner_start'])
        require(hashlib.sha256(body).hexdigest()==case['owner_sha256'],'Enclosing size-path body changed')
        threshold=(compare+1)<<shift
        probes=sorted({0,1,(compare<<shift),(compare<<shift)+1,threshold-1,threshold,threshold+1,MAX})
        require(all(enters_large_arm(v,shift,compare)==(v>=threshold) for v in probes),'Integer cutoff form differs')
        records.append({'compare_va':hex(case['cmp']),'shift':shift,'compare_constant':hex(compare),
                        'large_arm_threshold':threshold,'branch_va':hex(case['branch']),
                        'branch_kind':'ja' if case['branch_prefix']=='0f87' else 'jbe',
                        'branch_target_va':hex(target),'large_arm_va':hex(case['large_arm']),
                        'input_load_va':hex(case['load']),'input_load_hex':case['load_hex'],
                        'template_va':hex(template),'source_location_va':hex(location),'source_path':path,
                        'line':line,'column':column,'critical_call_va':hex(case['call']),
                        'owner':{'start_va':hex(case['owner_start']),'end_va_exclusive':hex(case['owner_end']),
                                 'sha256':case['owner_sha256'],'fde_va':hex(fs[0]['fde']),'cie_va':hex(fs[0]['cie'])},
                        'excerpt_ranges':[[hex(case['context']),hex(case['branch']+case['branch_size'])],
                                          [hex(case['large_arm']),hex(case['call']+6)]],
                        'boundary_probes':[{'word':v,'enters_large_arm':enters_large_arm(v,shift,compare)} for v in probes]})
    return {'target_sha256':SHA256,'selected_predicates':len(records),'comparisons':records,
            'templates':{hex(v):b.hex() for v,b in TEMPLATES.items()},
            'critical_message_slot':{'slot_va':'0x576e978','addend_va':'0x143d010'},
            'integer_identity':'For u64 x and these shifts: (x >> s) > K iff x >= (K+1)*2**s.',
            'captured_binaries_executed':False,
            'limits':'Five selected message-bound branch predicates only. Counter update/overflow, what bytes '
                     'are counted, actual log emission, error propagation/process exit, stream/storage protocol, '
                     'full async/helper semantics, Rust reconstruction and progress gates remain unproved.'}


def build(data):
    require(hashlib.sha256(data).hexdigest()==SHA256,'Wrong node94 SHA-256')
    return observe(data)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary',type=Path,default=ROOT/'artifacts/node/94/hl-node')
    p.add_argument('--out',type=Path,default=ROOT/'work/rocksdb-cutoffs-94.json')
    args=p.parse_args();record=build(args.binary.read_bytes())
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(record,indent=2)+'\n',encoding='utf8',newline='\n')
    print([r['large_arm_threshold'] for r in record['comparisons']])


if __name__=='__main__':main()
