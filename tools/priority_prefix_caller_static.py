#!/usr/bin/env python3
"""RE-003: digest-bound node115 bin supply of the priority-prefix byte-fed entries."""
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

TARGET=ROOT/'artifacts/node/115/hl-node'
PACKET=ROOT/'research/work-items/RE-003-node115-priority-prefix-caller'
SHA='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
# The three byte-fed entries are owned by the merged packet
# RE-003-node115-priority-prefix; their body hashes below are that packet's
# records.json values, re-derived here from the pinned capture.
ENTRIES={
 'entry_a':(0x1839480,0x1839913,'5ef2d445afe17b291aa6511b388d51f3af8e6c8d307afb6175a98970377ee599'),
 'entry_b':(0x2fbf570,0x2fbfa03,'343e8e4224ea4c8f9c4967308a924f53db400c115d919ecffd797a80e4939d10'),
 'entry_c':(0x48117a0,0x4811c33,'1d2820eacbc68823a431eb1d1515666889348dc416be0ec9c16a3f4cf7378d23')}
CALLERS={
 'caller_a':{'fde':(0x1a63db0,0x1a6559d,'cca2ed56f1335dc23f92026f8918b685f8e5ab2b3573f685a8aa28bd070de57f'),
             'entry':'entry_a','parent':'parent_a','table':0x5375e4,'alt_target':0x2b87440},
 'caller_b':{'fde':(0x33210f0,0x33228dd,'1a6cc860b73d6531adc5fecba1cd2860bbb2e111aa3b459637544d1f3e595623'),
             'entry':'entry_b','parent':'parent_b','table':0x739460,'alt_target':0x3b9c8a0},
 'caller_c':{'fde':(0x4adf150,0x4ae093d,'a48b304a5813c32500f96c7b9cbe93f1d0117a901f9ae2f0064c56f0b8d2041d'),
             'entry':'entry_c','parent':'parent_c','table':0x8ab3ac,'alt_target':0x54552c0}}
PARENTS={
 'parent_a':{'fde':(0x19271c0,0x19292b3,'d65ced3db0413c8e408d48af1868d97271a9365d964737586ad143c7b8149a87'),
             'caller':'caller_a','sites':[0x1927e69,0x1928cd4]},
 'parent_b':{'fde':(0x32e15c0,0x32e36b3,'b21b756d0fea8d799a8223704ad948b11db50170610fbbf36347ac5f6cfb97e3'),
             'caller':'caller_b','sites':[0x32e2269,0x32e30d4]},
 'parent_c':{'fde':(0x4b76720,0x4b78813,'5a8d39ce4e8ff8c529d006d258acb65cb3647a040bd4ab8f67b9d2033fa41414'),
             'caller':'caller_c','sites':[0x4b773c9,0x4b78234]}}
# Uniform instruction windows inside every caller FDE, offsets from its start.
# Each window was verified byte-identical across the three monomorphizations;
# the only address-dependent bytes in the traced region (dispatch LEA target,
# entry call displacement, alternate call displacement) are checked
# relationally instead of by literal.
OFF={'dispatch_lea':0x87,'dispatch_ops':0x8e,'bin32_guard':0xb2c,'bin16_guard':0xb4b,
     'short_block':0xb5d,'bin8_block':0xc05,'join':0xc1b,'u16_window':0xe3a,'tail':0xe54,
     'state':0xe6f,'call':0xe8a,'post_jmp':0xe8f,'error_block':0xed0,'alt':0x113c,
     'alt_jmp':0x114a,'error_tail':0x1649,'epilogue':0x1650}
WINDOWS={
 'dispatch_ops':(0x8e,0x98,'4e630c814901c941ffe1'),
 'bin32_guard':(0xb2c,0xb4b,'488b4610488b7e184883ff0472234883c7fc8b084883c0040fc9e9d0000000'),
 'bin16_guard':(0xb4b,0xb5d,'488b4610488b7e184883ff020f83dd020000'),
 'short_block':(0xb5d,0xb65,'4801f8e906010000'),
 'bin8_block':(0xc05,0xc1b,'488b7e184885ff7469488b461048ffcf0fb60848ffc0'),
 'join':(0xc1b,0xc28,'4889461048897e18e92c020000'),
 'u16_window':(0xe3a,0xe54,'4883c7fe0fb70866c1c1084883c0024889461048897e180fb7c9'),
 'tail':(0xe54,0xe6f,'89c94829cf72754c8d04084c89461048897e1884d20f85cd020000'),
 'state':(0xe6f,0xe8a,'48894424204c8944242848c744243000000000488d7424204889df'),
 'post_jmp':(0xe8f,0xe94,'e9bc070000'),
 'error_block':(0xed0,0xee7,'c643080148b8030000002500000048894310e962070000'),
 'error_tail':(0x1649,0x1650,'48c70302000000'),
 'alt_prefix':(0x113c,0x1145,'4889df4889c64889ca'),
 'alt_jmp':(0x114a,0x114f,'e901050000'),
 'epilogue':(0x1650,0x1665,'4889d84881c4580100005b415c415d415e415f5dc3')}
MARKERS={'0xc4':1,'0xc5':2,'0xc6':4}  # bin8/bin16/bin32 -> length-header bytes
ROUTE_GUARD={'0xc4':'bin8_block','0xc5':'bin16_guard','0xc6':'bin32_guard'}
ERROR_QWORD=0x2500000003
LIMITS=('Bin supply contract of the three priority-prefix entries only: the three bin '
 'marker routes of each sole caller, the shared tail, the boundary error record and '
 'the dl split between the byte-fed entry and the alternate slice decoder. What '
 'could set dl nonzero is NOT established by these bytes: both call sites of each '
 'decoder pass rdx=0 and no dl-writing instruction sits on the jump-table path, so '
 'as wired the byte-fed entry route is the taken one; the alternate decoder '
 '(0x2b87440 and its siblings) is not traced. The peeked-marker entry path of the '
 'decoder (reader bytes at +0x20/+0x21) and the marker taxonomy beyond the three '
 'bin markers are not traced. The caller imposes no payload-length cap beyond the '
 'reader remaining count and never inspects the entry count cell; what the entry '
 'does with payload bytes past its certified three-byte prefix (the merged '
 'packet\'s optional-suffix question) is not established here. Semantic type '
 'names beyond the merged packet\'s diagnostic label, caller-of-parent provenance '
 'and any reconstruction gate are not claimed. No captured code executed.')


def read(data,va,n):
    matches=[s for s in sections(data) if s['type']!=8 and s['address']<=va and va+n<=s['address']+s['size']]
    if len(matches)!=1:
        raise ValueError('expected one file-backed mapping')
    s=matches[0];o=s['offset']+va-s['address']
    return o,bytes(data[o:o+n])


def relocation_hits(data,targets):
    sec=next(s for s in sections(data) if s['name']=='.rela.dyn')
    hits={t:[] for t in targets}
    for a,i,v in struct.iter_unpack('<QQq',data[sec['offset']:sec['offset']+sec['size']]):
        if v in hits:
            hits[v].append(a)
    return hits


def e8_census(data,targets):
    """One .text pass: {target: [call-site VAs]} for E8 rel32 calls."""
    text=next(s for s in sections(data) if s['name']=='.text')
    body=data[text['offset']:text['offset']+text['size']];base=text['address']
    found={t:[] for t in targets}
    index=body.find(b'\xe8')
    while index!=-1:
        target=base+index+5+struct.unpack_from('<i',body,index+1)[0]
        if target in found:
            found[target].append(base+index)
        index=body.find(b'\xe8',index+1)
    return found


def supply_route(marker,remaining,length,dl):
    """The pinned supply contract, as a model over the traced guards.

    remaining is the reader's byte count after the marker byte; length is the
    decoded big-endian payload length. Header consumption is 1/2/4 bytes for
    markers 0xc4/0xc5/0xc6. A short header never reaches the shared tail; a
    short payload produces the pinned error record; otherwise dl selects the
    byte-fed entry (dl == 0) or the alternate slice decoder (dl != 0).
    """
    header=MARKERS[marker]
    if remaining<header:
        return ('short_header',None)
    if remaining-header<length:
        return ('error_record',ERROR_QWORD)
    return ('entry',length) if dl==0 else ('nested',length)


def _pin(body,start,off,hexbytes,what,who):
    want=bytes.fromhex(hexbytes)
    if body[off:off+len(want)]!=want:
        raise ValueError(f'{who} {what} changed')


def caller_trace(data,key,spec):
    start,end,_=spec['fde']
    _,body=read(data,start,end-start)
    def at(off,n):
        return body[off:off+n]
    def rip(off,insn_len,disp_at):
        return start+off+insn_len+struct.unpack_from('<i',body,disp_at)[0]
    # Jump-table dispatch: LEA loads the table, movsxd/add/jmp r9 consume it.
    if at(OFF['dispatch_lea'],3)!=b'\x48\x8d\x0d':
        raise ValueError(f'{key} caller trace dispatch lea changed')
    table=rip(OFF['dispatch_lea'],7,OFF['dispatch_lea']+3)
    if table!=spec['table']:
        raise ValueError(f'{key} caller jump table target changed')
    _pin(body,start,WINDOWS['dispatch_ops'][0],WINDOWS['dispatch_ops'][2],'dispatch ops','caller trace')
    # Shared instruction windows (byte-identical across the three callers).
    for name,(a,b,hx) in WINDOWS.items():
        if name=='dispatch_ops':
            continue
        _pin(body,start,a,hx,f'{name} window','caller trace')
    # Entry call: displacement must name this caller's own entry.
    if at(OFF['call'],1)!=b'\xe8' or rip(OFF['call'],5,OFF['call']+1)!=ENTRIES[spec['entry']][0]:
        raise ValueError(f'{key} caller trace entry call target changed')
    # Alternate slice-decoder call: own sibling target per monomorphization.
    alt_call=OFF['alt']+9
    if at(alt_call,1)!=b'\xe8' or rip(alt_call,5,alt_call+1)!=spec['alt_target']:
        raise ValueError(f'{key} caller trace alternate call target changed')
    # Jump table: decode all 256 marker landings (int32 offsets from table).
    landings={}
    for marker in range(256):
        rel=struct.unpack_from('<i',read(data,table+4*marker,4)[1],0)[0]
        landings[marker]=table+rel
    for mhex,guard in ROUTE_GUARD.items():
        if landings[int(mhex,16)]!=start+WINDOWS[guard][0]:
            raise ValueError(f'{key} caller jump table landing for {mhex} changed')
        if {m for m,t in landings.items() if t==start+WINDOWS[guard][0]}!={int(mhex,16)}:
            raise ValueError(f'{key} caller jump table guard {guard} shared')
    for name in ('join','tail','state','error_block','alt','epilogue'):
        if start+OFF[name] in landings.values():
            raise ValueError(f'{key} caller jump table lands on {name}')
    # Header sizes and the error record are read back out of the pinned bytes.
    headers={'0xc4':1,
             '0xc5':body[WINDOWS['bin16_guard'][0]+11],
             '0xc6':body[WINDOWS['bin32_guard'][0]+11]}
    if headers!=MARKERS:
        raise ValueError(f'{key} caller trace header size changed')
    qword=struct.unpack_from('<Q',body,WINDOWS['error_block'][0]+6)[0]
    if qword!=ERROR_QWORD:
        raise ValueError(f'{key} caller trace error record changed')
    return {'caller':key,'fde':f'{start:#x}..{end:#x}','entry':spec['entry'],
            'jump_table':hex(table),
            'landings':{mhex:hex(start+WINDOWS[g][0]) for mhex,g in ROUTE_GUARD.items()},
            'header_bytes':headers,
            'routes':{'bin8':{'guard':hex(start+OFF['bin8_block']),'short':hex(start+0xc77),
                              'join':hex(start+OFF['join'])},
                      'bin16':{'guard':hex(start+OFF['bin16_guard']),'window':hex(start+OFF['u16_window']),
                               'short':hex(start+OFF['short_block'])},
                      'bin32':{'guard':hex(start+OFF['bin32_guard']),'join':hex(start+OFF['join']),
                               'short':hex(start+OFF['short_block'])}},
            'tail':{'join':hex(start+OFF['tail']),'length_sub':hex(start+OFF['tail']+2),
                    'error_branch':hex(start+OFF['tail']+5),'dl_test':hex(start+0xe67),
                    'alt_branch':hex(start+0xe69)},
            'state':{'base':'rsp+0x20','fields':['payload','payload_end','0'],
                     'build':hex(start+OFF['state']),'call_site':hex(start+OFF['call']),
                     'call_target':hex(ENTRIES[spec['entry']][0]),
                     'post_call_jump':hex(start+OFF['post_jmp'])},
            'error':{'block':hex(start+OFF['error_block']),'tag_byte':1,
                     'record_qword':hex(qword),'common_tail':hex(start+OFF['error_tail']),
                     'common_tail_qword':2},
            'alternate':{'block':hex(start+OFF['alt']),'call_target':hex(spec['alt_target'])},
            'epilogue':hex(start+OFF['epilogue'])}


def parent_wiring(data,key,spec):
    start,end,_=spec['fde']
    _,body=read(data,start,end-start)
    caller_start=CALLERS[spec['caller']]['fde'][0]
    found=[]
    index=body.find(b'\xe8')
    while index!=-1:
        if start+index+5+struct.unpack_from('<i',body,index+1)[0]==caller_start:
            found.append(start+index)
        index=body.find(b'\xe8',index+1)
    if found!=spec['sites']:
        raise ValueError(f'{key} parent call census changed')
    for site in spec['sites']:
        off=site-start
        if body[off-5:off]!=bytes.fromhex('4c89f631d2') or body[off]!=0xe8:
            raise ValueError(f'{key} parent call site changed')
    return {'parent':key,'fde':f'{start:#x}..{end:#x}','caller':spec['caller'],
            'call_sites':[hex(s) for s in spec['sites']],'rdx_at_call':0,
            'rsi_from':'r14','pre_call_bytes':'4c89f631d2'}


def owner_records(data,fdes,role,a,b,sha):
    if (a,b) not in fdes:
        raise ValueError(f'priority supply {role} FDE changed')
    offset,raw=read(data,a,b-a)
    if hashlib.sha256(raw).hexdigest()!=sha:
        raise ValueError(f'priority supply {role} body changed')
    records={}
    for kind in ['fde','cie']:
        va=fdes[(a,b)][kind];n=struct.unpack('<I',read(data,va,4)[1])[0]+4
        records[kind]={'va':hex(va),'bytes_hex':read(data,va,n)[1].hex()}
    return {'role':role,'start':hex(a),'end':hex(b),'file_offset':hex(offset),
            'bytes':b-a,'sha256':sha,'frames':records}


def analyze(data):
    _,fs,_=fde_extents(data);fdes={(f['start'],f['end']):f for f in fs}
    all_specs={**ENTRIES,**{k:v['fde'] for k,v in CALLERS.items()},**{k:v['fde'] for k,v in PARENTS.items()}}
    for role,(a,b,_) in all_specs.items():
        if (a,b) not in fdes:
            raise ValueError(f'priority supply {role} FDE changed')
    starts=[a for a,_,_ in all_specs.values()]
    hits=relocation_hits(data,starts)
    if any(hits.values()):
        raise ValueError('priority supply relocation reference appeared')
    traces=[caller_trace(data,k,CALLERS[k]) for k in ('caller_a','caller_b','caller_c')]
    parents=[parent_wiring(data,k,PARENTS[k]) for k in ('parent_a','parent_b','parent_c')]
    entry_starts=[ENTRIES[k][0] for k in ('entry_a','entry_b','entry_c')]
    caller_starts=[CALLERS[k]['fde'][0] for k in ('caller_a','caller_b','caller_c')]
    census=e8_census(data,entry_starts+caller_starts)
    for k in ('entry_a','entry_b','entry_c'):
        if census[ENTRIES[k][0]]!=[CALLERS['caller_'+k[-1]]['fde'][0]+OFF['call']]:
            raise ValueError(f'priority supply {k} caller census changed')
    for k in ('caller_a','caller_b','caller_c'):
        if census[CALLERS[k]['fde'][0]]!=PARENTS['parent_'+k[-1]]['sites']:
            raise ValueError(f'priority supply {k} parent census changed')
    raw={hex(s):data.count(struct.pack('<Q',s)) for s in starts}
    if any(raw.values()):
        raise ValueError('priority supply address-as-data reference appeared')
    owners=[]
    for role,(a,b,sha) in ENTRIES.items():
        owners.append(owner_records(data,fdes,role,a,b,sha))
    for k in ('caller_a','caller_b','caller_c'):
        a,b,sha=CALLERS[k]['fde'];owners.append(owner_records(data,fdes,k,a,b,sha))
    for k in ('parent_a','parent_b','parent_c'):
        a,b,sha=PARENTS[k]['fde'];owners.append(owner_records(data,fdes,k,a,b,sha))
    return {'target_sha256':SHA,'owners':owners,'caller_traces':traces,'parents':parents,
            'census':{'entry_direct_callers':{k:1 for k in ENTRIES},
                      'caller_direct_callers':{k:2 for k in CALLERS},
                      'relocation_references':0,'address_as_data':0},
            'entry_citation':{'packet':'RE-003-node115-priority-prefix',
                              'body_sha256':{k:ENTRIES[k][2] for k in ENTRIES}},
            'supply_model':{'header_bytes':MARKERS,'error_qword':hex(ERROR_QWORD),
                            'routes':['short_header','error_record','entry','nested']},
            'captured_code_executed':False,'limits':LIMITS}


def branch_edges(asm,start):
    """Explicit direct-branch edges of one caller, parsed from objdump text."""
    edges={}
    for line in asm.splitlines():
        m=re.match(r'^\s*([0-9a-f]+):\t((?:[0-9a-f]{2} )+|[0-9a-f]+ )\s*\t(.*)$',line)
        if not m:
            continue
        site=int(m.group(1),16);text=m.group(3).strip()
        b=re.match(r'(j[a-z]+)\s+([0-9a-f]+)',text)
        if b:
            edges.setdefault(int(b.group(2),16),[]).append(site)
    return edges


def generate(binary,output):
    data=binary.read_bytes()
    if len(data)!=105896032 or hashlib.sha256(data).hexdigest()!=SHA:
        raise ValueError('expected pinned node115')
    report=analyze(data);output.mkdir(parents=True,exist_ok=True);lines=[]
    with tempfile.TemporaryDirectory() as directory:
        snapshot=Path(directory)/'node115.elf';snapshot.write_bytes(data)
        native=subprocess.check_output(['readelf','-wf',str(snapshot)],text=True)
        specs=[(a,b) for a,b,_ in ENTRIES.values()]
        specs+=[v['fde'][0:2] for v in CALLERS.values()]
        specs+=[v['fde'][0:2] for v in PARENTS.values()]
        for a,b in specs:
            rows=[l for l in native.splitlines() if f'pc={a:016x}..{b:016x}' in l]
            if len(rows)!=1:
                raise ValueError('native priority supply FDE disagreement')
            lines.extend(rows)
        for key,spec in CALLERS.items():
            a,b,_=spec['fde']
            asm=subprocess.check_output(['objdump','-d','-M','intel','--insn-width=16',
                                         f'--start-address={a:#x}',f'--stop-address={b:#x}',
                                         str(snapshot)],text=True)
            ins=decode_export(asm,a,b,read(data,a,b-a)[1])
            required=set()
            for wa,wb,_ in WINDOWS.values():
                required.add(a+wa);required.add(a+wb)
            required.add(a+OFF['call']+5)
            if not required<=set(ins)|{b}:
                raise ValueError(f'{key} trace site not native instruction start')
            edges=branch_edges(asm,a)
            expect={a+OFF['join']:[a+0xb46],a+OFF['tail']:[a+0xc23],a+OFF['state']:[],
                    a+OFF['error_block']:[a+0xe59],a+OFF['alt']:[a+0xe69],
                    a+OFF['epilogue']:[a+x for x in (0xad,0xe8f,0xf76,0x102a,0x10a9,0x1102,0x114a,0x1561)]}
            for target,sites in expect.items():
                if edges.get(target,[])!=sites:
                    raise ValueError(f'{key} branch edge census changed at {target:#x}')
    (output/'frames.txt').write_bytes(('\n'.join(lines)+'\n').encode('utf-8'))
    (output/'records.json').write_bytes((json.dumps(report,indent=2)+'\n').encode('utf-8'))
    return report


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary',type=Path,default=TARGET)
    p.add_argument('--output',type=Path,default=ROOT/'work/priority-prefix-caller115')
    args=p.parse_args();report=generate(args.binary,args.output)
    print(json.dumps({'functions':len(report['owners']),'bytes':sum(x['bytes'] for x in report['owners']),'executed':False}))
