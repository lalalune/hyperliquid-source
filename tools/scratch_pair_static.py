#!/usr/bin/env python3
"""RE-015: digest-bound node115 scratch-name value pair of config accessor 0x1568d80."""
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
PACKET=ROOT/'research/work-items/RE-015-node115-scratch-name-pair'
SHA='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
OWNERS={
 'accessor':(0x1568d80,0x1568dd6,'eede37f66a7a8978a19fa8e70980ce0fadf45657e3ab0f256727a65d88b267a0'),
 'consumer_defaults':(0x1506840,0x15069f2,'34189b04fb9454d33dbe002156516ed83a2d63ae8e98c63b88a6d87119287c71'),
 'consumer_large':(0x15a3b90,0x15a6509,'7995f7af57e2be27ca6ed1e307d9bcce9d6140f72b0ff0cf0804d7f09e5505fb')}
ACCESSOR=0x1568d80
CONFIG_SLOT=0x64e0918
CONFIG_OBJECT=0x64f06c0
ACCESSOR_CELL=0x64f01b0
DESCRIPTOR_ARRAY=0x6410ce8
DESCRIPTOR_COUNT=79
NAMES=['Ec','DummyTokyo','DummyTokyo2','GaOnchain','GbOnchain',
 'NodeTestnet','NodeTestnet2','NodeTestnet3','NodeTestnet4','Ea',
 'Ea2','Ea3','EaMm','EaTx','HeavyTestnet',
 'HeavyMainnet','Eb','Ed','Ee','SoloTestnet',
 'SoloMainnet','LockerTestnet','LockerMainnet','RpcTestnet','RpcSandbox',
 'RpcMainnet','RpcMainnet2','Sa','Sb','Sc',
 'Sd','WebSandbox','SoloSandbox','NvTestnet','NvTestnet2',
 'NvMainnet','NvMainnet2','NvMainnet3','JoinMainnet','DummyNv',
 'FBinSpot','FBinSpot2','FBinSpot3','FBinSpot4','FBinSpot5',
 'FBinSpot6','FBinSpot7','FBinSpot8','FBinPerp','FBinPerp2',
 'FOkexSpot','FOkexSpot2','FOkexPerp','FHuobiSpot','FHuobiSpot2',
 'FHuobiSpot3','FHuobiSpot4','FHuobiPi','FHuobiPerp','FCobSpot',
 'FKraSpot','FBybitSpot','ScratchDummy','ScratchCron','OBinSpot',
 'FHlPerp','GaHlPerp','GaHlPerp2','GaHlPerp3','GbHlPerp',
 'GbHlPerp2','GbHlPerp3','GcHlPerp','GcHlPerp2','GdHlPerp',
 'GdHlPerp2','GsHlPerp','EaHlPerp','EbHlPerp']
ANCHORS={5:'NodeTestnet',18:'Ee',32:'SoloSandbox',33:'NvTestnet',62:'ScratchDummy',63:'ScratchCron'}
FLAG_STRING_VA=0x468b0f
FLAG_STRING=b'assertion failed: !is_live'
FLAG_EMIT_SLOT=0x64df730
LIMITS=('Pair result, its static boundaries, and the large consumer\'s first branch on the '
 'cached flag byte only. The pair\'s downstream semantic label '
 '(what the constant 2 counts or limits and what the boolean means beyond that branch) is NOT established '
 'by these bytes; the defaults consumer is recorded as a boundary for the first component only. '
 'The configured-name-to-tag classifier stage is context owned by open PRs '
 '#2042/#2054 and is cited here, not re-derived beyond the descriptor order and its anchors. '
 'No captured code executed, no runtime value, complete caller recovery (the accessor is '
 'reached through its lazy-static cell, not direct calls), #94 correspondence, or '
 'reconstruction gate is claimed.')


def read(data,va,n):
    matches=[s for s in sections(data) if s['type']!=8 and s['address']<=va and va+n<=s['address']+s['size']]
    if len(matches)!=1:
        raise ValueError('expected one file-backed mapping')
    s=matches[0];o=s['offset']+va-s['address']
    return o,bytes(data[o:o+n])


def relocations(data):
    sec=next(s for s in sections(data) if s['name']=='.rela.dyn')
    by_offset={}
    accessor_hits=[]
    for a,i,v in struct.iter_unpack('<QQq',data[sec['offset']:sec['offset']+sec['size']]):
        by_offset.setdefault(a,[]).append((i,v))
        if v==ACCESSOR:
            accessor_hits.append(a)
    return by_offset,accessor_hits


def accessor_constants(body):
    if len(body)!=86 or body[0x05:0x08]!=b'\x48\x8b\x1d':
        raise ValueError('accessor config slot load changed')
    slot=0x1568d85+7+struct.unpack_from('<i',body,0x08)[0]
    if slot!=CONFIG_SLOT:
        raise ValueError('accessor config slot load changed')
    if body[0x0c:0x0f]!=b'\x8b\x43\x50':
        raise ValueError('accessor guard load changed')
    if body[0x0f:0x13]!=b'\x85\xc0\x75\x13':
        raise ValueError('accessor guard branch changed')
    if body[0x13:0x17]!=b'\x0f\xb6\x43\x48':
        raise ValueError('accessor tag load changed')
    if body[0x17]!=0x24 or body[0x19]!=0x3c or body[0x1b:0x1e]!=b'\x0f\x95\xc2':
        raise ValueError('accessor mask/compare opcode changed')
    if body[0x1e]!=0xb0 or body[0x20:0x26]!=bytes.fromhex('4883c4105bc3'):
        raise ValueError('accessor result/return sequence changed')
    if body[0x32:0x36]!=b'\x48\x8d\x7b\x50':
        raise ValueError('accessor slow-path guard argument changed')
    if body[0x4e:0x50]!=b'\xff\x15' or 0x1568dce+6+struct.unpack_from('<i',body,0x50)[0]!=0x64df9f0:
        raise ValueError('accessor slow-path helper slot changed')
    constants={'config_slot':slot,'guard_offset':body[0x0e],'tag_offset':body[0x16],
               'mask':body[0x18],'compare':body[0x1a],'first':body[0x1f]}
    if (constants['mask'],constants['compare'],constants['first'])!=(0x7e,62,2):
        raise ValueError('accessor mask/compare/result constant changed')
    return constants


def _pin(body,base,va,hexbytes,what):
    off=va-base;want=bytes.fromhex(hexbytes)
    if body[off:off+len(want)]!=want:
        raise ValueError(f'consumer flag {what} changed')


def consumer_flag_trace(data):
    """Pin the large consumer's use of the cached flag byte (cell+1).

    Byte-level pins only: the load of both cell bytes, the stack flag byte,
    the two branch sites on it, and the assertion-string emit block the
    flag-1 route reaches. No semantic label is attached.
    """
    start,end,_=OWNERS['consumer_large']
    _,body=read(data,start,end-start)
    def at(va,n):
        return body[va-start:va-start+n]
    def rip_target(va,insn_len,disp_at):
        return va+insn_len+struct.unpack_from('<i',body,disp_at-start)[0]
    # Load: cmp byte [cell+0],0 / setne al / and al,[cell+1].
    _pin(body,start,0x15a3bc5,'803d','flag load cmp opcode')
    if rip_target(0x15a3bc5,7,0x15a3bc5+2)!=ACCESSOR_CELL or at(0x15a3bc5+6,1)!=b'\x00':
        raise ValueError('consumer flag load cmp target changed')
    _pin(body,start,0x15a3bcc,'0f95c0','flag load setne')
    _pin(body,start,0x15a3bcf,'2205','flag load and opcode')
    if rip_target(0x15a3bcf,6,0x15a3bcf+2)!=ACCESSOR_CELL+1:
        raise ValueError('consumer flag load and target changed')
    # Flag byte stored at [rsp+0x16]; derived (NOT flag OR input byte) at +0x15.
    _pin(body,start,0x15a3c55,'88442416','flag store')
    _pin(body,start,0x15a3c59,'3401','flag negate')
    _pin(body,start,0x15a3c5b,'0a464d','flag derived or')
    _pin(body,start,0x15a3c5e,'88442415','flag derived store')
    # Branch sites on the flag byte.
    branches=[]
    for site,jne in [(0x15a3f80,0x15a3f85),(0x15a4276,0x15a427b)]:
        _pin(body,start,site,'807c241600','branch cmp')
        _pin(body,start,jne,'0f85','branch jne opcode')
        branches.append({'site':hex(site),'target':hex(rip_target(jne,6,jne+2))})
    if [b['target'] for b in branches]!=['0x15a5afb','0x15a5b17']:
        raise ValueError('consumer flag branch target changed')
    # Emit block: lea rdi,string / mov esi,26 / call [emit slot].
    _pin(body,start,0x15a5b22,'488d3d','emit lea opcode')
    if rip_target(0x15a5b22,7,0x15a5b22+3)!=FLAG_STRING_VA:
        raise ValueError('consumer flag emit string target changed')
    _pin(body,start,0x15a5b30,'be1a000000','emit length')
    _pin(body,start,0x15a5b35,'ff15','emit call opcode')
    if rip_target(0x15a5b35,6,0x15a5b35+2)!=FLAG_EMIT_SLOT:
        raise ValueError('consumer flag emit slot changed')
    if read(data,FLAG_STRING_VA,len(FLAG_STRING))[1]!=FLAG_STRING:
        raise ValueError('consumer flag assertion string changed')
    return {'consumer':'consumer_large','flag_load':{'cmp':'0x15a3bc5','setne':'0x15a3bcc','and':'0x15a3bcf'},
            'flag_stack_offset':'0x16','derived_stack_offset':'0x15','branches':branches,
            'emit':{'string_va':hex(FLAG_STRING_VA),'string':FLAG_STRING.decode('ascii'),
                    'call_site':'0x15a5b35','call_slot':hex(FLAG_EMIT_SLOT)}}


def pair_for_tag(tag):
    """Observed accessor result: constant 2, and (tag & 0x7e) != 62 as the flag."""
    return (2,(tag & 0x7e)!=62)


def descriptor_entries(data,by_offset):
    entries=[]
    for tag in range(DESCRIPTOR_COUNT):
        slot=DESCRIPTOR_ARRAY+tag*16
        found=by_offset.get(slot)
        if not found or len(found)!=1 or found[0][0]!=8:
            raise ValueError('descriptor relocation changed')
        pointer=found[0][1];length=struct.unpack_from('<Q',read(data,slot,16)[1],8)[0]
        raw=read(data,pointer,length)[1]
        try:
            name=raw.decode('ascii')
        except UnicodeDecodeError:
            raise ValueError('descriptor name bytes changed')
        entries.append({'tag':tag,'name':name,'pointer':pointer,'length':length})
    for tag,name in ANCHORS.items():
        if entries[tag]['name']!=name:
            raise ValueError('descriptor anchor changed')
    if [e['name'] for e in entries]!=NAMES:
        raise ValueError('descriptor name/order changed')
    return entries


def direct_callers(data):
    text=next(s for s in sections(data) if s['name']=='.text')
    body=data[text['offset']:text['offset']+text['size']];base=text['address']
    count=0;index=body.find(b'\xe8')
    while index!=-1:
        if base+index+5+struct.unpack_from('<i',body,index+1)[0]==ACCESSOR:
            count+=1
        index=body.find(b'\xe8',index+1)
    return count


def analyze(data):
    _,fs,_=fde_extents(data);fdes={(f['start'],f['end']):f for f in fs}
    by_offset,accessor_hits=relocations(data)
    if by_offset.get(CONFIG_SLOT)!=[(8,CONFIG_OBJECT)]:
        raise ValueError('config object relocation changed')
    if accessor_hits!=[ACCESSOR_CELL] or by_offset.get(ACCESSOR_CELL)!=[(8,ACCESSOR)]:
        raise ValueError('accessor relocation reference changed')
    body=read(data,ACCESSOR,86)[1];constants=accessor_constants(body)
    entries=descriptor_entries(data,by_offset)
    if direct_callers(data)!=0:
        raise ValueError('accessor direct caller appeared')
    owners=[]
    for role,(a,b,sha) in OWNERS.items():
        if (a,b) not in fdes:
            raise ValueError('scratch scope FDE changed')
        offset,raw=read(data,a,b-a)
        if hashlib.sha256(raw).hexdigest()!=sha:
            raise ValueError(f'scratch {role} body changed')
        records={}
        for kind in ['fde','cie']:
            va=fdes[(a,b)][kind];n=struct.unpack('<I',read(data,va,4)[1])[0]+4
            records[kind]={'va':hex(va),'bytes_hex':read(data,va,n)[1].hex()}
        owners.append({'role':role,'start':hex(a),'end':hex(b),'file_offset':hex(offset),'bytes':b-a,'sha256':sha,'frames':records})
    table=[]
    for entry in entries:
        first,flag=pair_for_tag(entry['tag'])
        table.append({'tag':entry['tag'],'name':entry['name'],'first':first,'flag':flag})
    flag_trace=consumer_flag_trace(data)
    return {'target_sha256':SHA,'owners':owners,'consumer_flag':flag_trace,
            'accessor':{'fde':'0x1568d80..0x1568dd6','config_slot':hex(CONFIG_SLOT),
                        'config_object':hex(CONFIG_OBJECT),'guard_offset':hex(constants['guard_offset']),
                        'tag_offset':hex(constants['tag_offset']),'mask':hex(constants['mask']),
                        'compare':constants['compare'],'first':constants['first'],
                        'slow_path_helper_slot':'0x64df9f0'},
            'descriptor_array':{'va':hex(DESCRIPTOR_ARRAY),'count':DESCRIPTOR_COUNT,
                                'anchors':{str(tag):name for tag,name in ANCHORS.items()}},
            'result_table':table,
            'relocation_cell':hex(ACCESSOR_CELL),'direct_callers':0,
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
                raise ValueError('native scratch FDE disagreement')
            lines.extend(rows)
            if role=='consumer_large':
                # No 10,617-byte objdump export is retained, but the flag
                # trace sites are validated as native instruction starts.
                asm=subprocess.check_output(['objdump','-d','-M','intel','--insn-width=16',f'--start-address={a:#x}',f'--stop-address={b:#x}',str(snapshot)],text=True)
                ins=decode_export(asm,a,b,read(data,a,b-a)[1])
                required=[0x15a3bc5,0x15a3bcc,0x15a3bcf,0x15a3c55,0x15a3c59,0x15a3c5b,0x15a3c5e,
                          0x15a3f80,0x15a3f85,0x15a4276,0x15a427b,0x15a5b22,0x15a5b30,0x15a5b35]
                if not set(required)<=set(ins):
                    raise ValueError('scratch flag trace site not native instruction start')
                continue
            asm=subprocess.check_output(['objdump','-d','-M','intel','--insn-width=16',f'--start-address={a:#x}',f'--stop-address={b:#x}',str(snapshot)],text=True)
            ins=decode_export(asm,a,b,read(data,a,b-a)[1])
            required={'accessor':[0x1568d85,0x1568d8c,0x1568d93,0x1568d97,0x1568d99,0x1568d9b,0x1568d9e,0x1568db2,0x1568dce],
                      'consumer_defaults':[0x1506840,0x150685e,0x150686e]}[role]
            if not set(required)<=set(ins):
                raise ValueError('scratch evidence site not native instruction start')
            (output/f'{role}.objdump.txt').write_bytes(asm.replace(str(snapshot),'<authenticated-node115>').encode('utf-8'))
    (output/'frames.txt').write_bytes(('\n'.join(lines)+'\n').encode('utf-8'))
    (output/'records.json').write_bytes((json.dumps(report,indent=2)+'\n').encode('utf-8'))
    return report


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary',type=Path,default=TARGET)
    p.add_argument('--output',type=Path,default=ROOT/'work/scratch-pair115')
    args=p.parse_args();report=generate(args.binary,args.output)
    print(json.dumps({'functions':len(report['owners']),'bytes':sum(x['bytes'] for x in report['owners']),'executed':False}))
