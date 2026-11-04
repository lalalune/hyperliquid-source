#!/usr/bin/env python3
"""RE-003: digest-bound node115 dl route of the priority-prefix bin supply.

The packet RE-003-node115-priority-prefix-caller (#2442) pinned the dl split
inside the three MessagePack decoders (caller_a/b/c): the shared tail tests
dl, the byte-fed entry is called when dl == 0, and an alternate function is
called when dl != 0. It left two questions open: what could set dl nonzero,
and what the alternate (0x2b87440 for caller_a) does with the slice.

This checker establishes, against the pinned capture only:

1. A complete static reference census for the three decoder FDE starts:
   E8 calls, E9 jumps, rel8 jumps, 0f 8x conditional jumps, RIP-relative
   references (ff 15 / ff 25 / REX lea+mov), .rela.dyn addends, raw 8-byte
   and 4-byte occurrences, and the int3 gap before each start. The only
   references are the two parent E8 call sites per decoder, and every one
   of those sites passes rdx = 0 (parent boundary wiring re-derived here
   from the caller packet's records). So no static caller can deliver
   dl != 0, and the dl != 0 route is unreachable from any censused caller.

2. A complete trace of the three alternate functions (126 bytes each):
   each stores its slice arguments under discriminant byte 6, builds a
   stack descriptor, calls one 154-byte helper with the shared message
   piece at 0x44f07a, writes qword 2 at the output base and returns. The
   alternate never calls the byte-fed entry and never dereferences the
   payload. Each alternate also has a second call site inside its
   decoder (offset +0x1066), behind a shared .got gate function, pinned
   here with its argument setup.
"""
import argparse
import bisect
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
PACKET=ROOT/'research/work-items/RE-003-node115-priority-prefix-dl-route'
SHA='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
SIZE=105896032

# Byte-fed entries: owned by the merged packet RE-003-node115-priority-prefix;
# hashes are that packet's records.json values (cited, not re-traced).
ENTRIES={'entry_a':0x1839480,'entry_b':0x2fbf570,'entry_c':0x48117a0}
# Decoder FDEs and parents: boundaries owned by RE-003-node115-priority-prefix-
# caller; body hashes below are that packet's records.json values, re-derived
# here from the pinned capture.
CALLERS={
 'caller_a':{'fde':(0x1a63db0,0x1a6559d,'cca2ed56f1335dc23f92026f8918b685f8e5ab2b3573f685a8aa28bd070de57f'),
             'entry':'entry_a','parent':'parent_a','alt':'alt_a'},
 'caller_b':{'fde':(0x33210f0,0x33228dd,'1a6cc860b73d6531adc5fecba1cd2860bbb2e111aa3b459637544d1f3e595623'),
             'entry':'entry_b','parent':'parent_b','alt':'alt_b'},
 'caller_c':{'fde':(0x4adf150,0x4ae093d,'a48b304a5813c32500f96c7b9cbe93f1d0117a901f9ae2f0064c56f0b8d2041d'),
             'entry':'entry_c','parent':'parent_c','alt':'alt_c'}}
PARENTS={
 'parent_a':{'fde':(0x19271c0,0x19292b3,'d65ced3db0413c8e408d48af1868d97271a9365d964737586ad143c7b8149a87'),
             'caller':'caller_a','sites':[0x1927e69,0x1928cd4]},
 'parent_b':{'fde':(0x32e15c0,0x32e36b3,'b21b756d0fea8d799a8223704ad948b11db50170610fbbf36347ac5f6cfb97e3'),
             'caller':'caller_b','sites':[0x32e2269,0x32e30d4]},
 'parent_c':{'fde':(0x4b76720,0x4b78813,'5a8d39ce4e8ff8c529d006d258acb65cb3647a040bd4ab8f67b9d2033fa41414'),
             'caller':'caller_c','sites':[0x4b773c9,0x4b78234]}}
# The alternate functions (this packet's owners). Per-sibling constants are
# relational targets inside an otherwise byte-identical 126-byte template.
ALTS={
 'alt_a':{'fde':(0x2b87440,0x2b874be), 'caller':'caller_a','helper':'helper_a',
          'data':0x644bb18,'fnptr':'shim_a'},
 'alt_b':{'fde':(0x3b9c8a0,0x3b9c91e), 'caller':'caller_b','helper':'helper_b',
          'data':0x64746b8,'fnptr':'shim_b'},
 'alt_c':{'fde':(0x54552c0,0x545533e), 'caller':'caller_c','helper':'helper_c',
          'data':0x64a8ed8,'fnptr':'shim_c'}}
HELPERS={
 'helper_a':{'fde':(0x18be120,0x18be1ba,'1843d78f492ce208e9a206c7f17e56e5a81e9d88fe9a463346655d81943e8a00')},
 'helper_b':{'fde':(0x3046740,0x30467da,'40ef1ad92e3adc408f3b333089544c5107035e6ec4ae1bf44cf00611c80f3954')},
 'helper_c':{'fde':(0x4892290,0x489232a,'bb7baea73cd6d71e297979fe1ded9f4b637c5a9d9c4331b35528f7f3fa8a766a')}}
# 16-byte method-dispatch shims stored in each alternate's third descriptor
# pair; all three bodies are byte-identical.
SHIMS={'shim_a':(0x2d49fb0,0x2d49fc0,'73a266c7c8ee86fa2addcc6aa746ed789ec1220b78c9de8360c56c6bd74aabbe'),
       'shim_b':(0x452a050,0x452a060,'73a266c7c8ee86fa2addcc6aa746ed789ec1220b78c9de8360c56c6bd74aabbe'),
       'shim_c':(0x57a6f70,0x57a6f80,'73a266c7c8ee86fa2addcc6aa746ed789ec1220b78c9de8360c56c6bd74aabbe')}
DESCRIPTOR_FN=(0x5c4f380,0x5c4f641,'d21c179d2cbb1e3fb510920f0fcf91f0ed90abf342042d4b00e161201b3a94e5')  # via .got slot 0x64dfed0
GATE_FN=(0x16815e0,0x16817d7,'3ff2fdb7228f89579b15327cfe53871b0d275e0c54668dfeca9b349800836de0')        # via .got slot 0x64dfca8
HELPER_SLOT_FN=(0x141e3a0,0x141e538,'aa4d4d0611c533e38c65e1577c0426b5163846c01225556743d4d4345cadd1fe')  # via .got slot 0x64df6e8
SLOTS={'descriptor':0x64dfed0,'gate':0x64dfca8,'helper_first':0x64df6e8}
PIECE_VA=0x44f07a
PIECE_HEX='0e696e76616c696420747970653a20c00b2c20657870656374656420'
# Alternate body template: the full 126 bytes with the five rel32/rip32
# displacement fields zeroed (lea data +0x28, slot load +0x3e, lea fnptr
# +0x54, lea piece +0x60, helper call +0x6a).
ALT_TEMPLATE=('534883ec504889fb48897424204889542428c6442418064883c708488d4424074889442408'
 '488d05000000004889442410488d4424184889442430488b05000000004889442438488d4424084889442440'
 '488d05000000004889442448488d3500000000488d542430e80000000048c703020000004889d84883c4505bc3')
ALT_MASKS=[(0x28,0x2c),(0x3e,0x42),(0x54,0x58),(0x60,0x64),(0x6a,0x6e)]
# Uniform caller windows (offsets from the decoder FDE start), byte-identical
# across the three decoders except the masked displacement fields.
OFF={'tail':0xe54,'state':0xe6f,'call':0xe8a,'alt':0x113c,'alt_jmp':0x114a,
     'site2':0x102f,'site2_gate_call':0x104a,'site2_cmp':0x106b,'site2_alt_call':0x1066}
WINDOWS={
 'tail':(0xe54,0xe6f,'89c94829cf72754c8d04084c89461048897e1884d20f85cd020000'),
 'state':(0xe6f,0xe8a,'48894424204c8944242848c744243000000000488d7424204889df'),
 'alt_prefix':(0x113c,0x1145,'4889df4889c64889ca'),
 'alt_jmp':(0x114a,0x114f,'e901050000'),
 'site2_cmp':(0x106b,0x1070,'837c242002')}
SITE2_WINDOW=(0x102f,0x106b,
 '4c8b7e104b8d04374889461048894e18488d7c24704c89fe4c89f2ff1500000000837c2470010f8592000000'
 '488d7c24204c89fe4c89f2e800000000')
SITE2_MASKS=[(0x104c,0x1050),(0x1067,0x106b)]  # absolute offsets from caller start
HELPER_PINS={'tag_test':(0x11,'41f6c601'),'copies':(0x68,'48894318488b042448894308488b44240848894310'),
             'byte6_store':(0x7d,'c60306')}
LIMITS=('dl-route closure and alternate trace of the three priority-prefix bin decoders only. '
 'The reference census covers direct E8/E9/rel8/0f 8x branches, RIP-relative references over the '
 'ff 15 / ff 25 / REX.W lea+mov encodings, .rela.dyn addends and raw 4/8-byte occurrences of the six '
 'FDE starts, plus the int3 gaps before those starts; a caller that computed a decoder address '
 'arithmetically into a register, or a relative jump table whose base-plus-offset lands on a start, '
 'would not be enumerated by these passes and is not claimed absent. Within a decoder, only the '
 'parent packet\'s pinned bin path is relied on for the statement that the entry dl reaches the shared '
 'tail unmodified; the decoder\'s other routes are not re-traced, and the gated second alternate call '
 'site is pinned at its argument setup and gate call only - the route that feeds its length window and '
 'the gate function\'s internals are not traced. What the 154-byte helper and its .got callees do with '
 'the descriptor beyond the pinned writes (byte 6 at the destination, the three copied qwords) is not '
 'traced; the discriminant number and the message piece are recorded as bytes, not named types. The '
 'parents\' own input provenance and any reconstruction gate are not claimed. No captured code executed.')


def read(data,va,n):
    matches=[s for s in sections(data) if s['type']!=8 and s['address']<=va and va+n<=s['address']+s['size']]
    if len(matches)!=1:
        raise ValueError('expected one file-backed mapping')
    s=matches[0];o=s['offset']+va-s['address']
    return o,bytes(data[o:o+n])


def relocations(data):
    sec=next(s for s in sections(data) if s['name']=='.rela.dyn')
    return {a:(i&0xffffffff,v) for a,i,v in struct.iter_unpack('<QQq',data[sec['offset']:sec['offset']+sec['size']])}


def branch_census(data,targets):
    """Direct-branch reference census over .text for each target VA.

    Kinds: E8 call, E9 jump, EB rel8 jump, 0f 8x conditional jump, and
    RIP-relative references (ff 15/ff 25 and REX.W lea/mov with a
    RIP-relative ModRM). Returns {target: {kind: [site VAs]}}.
    """
    text=next(s for s in sections(data) if s['name']=='.text')
    body=data[text['offset']:text['offset']+text['size']];base=text['address']
    found={t:{k:[] for k in ('e8','e9','eb','jcc','rip')} for t in targets}
    def scan_op(op,kind,size,disp_at,extra=0):
        idx=body.find(op)
        while idx!=-1:
            tgt=base+idx+size+extra+struct.unpack_from('<i',body,idx+disp_at)[0]
            if tgt in found:
                found[tgt][kind].append(base+idx)
            idx=body.find(op,idx+1)
    scan_op(b'\xe8','e8',5,1)
    scan_op(b'\xe9','e9',5,1)
    for cc in range(0x80,0x90):
        scan_op(bytes([0x0f,cc]),'jcc',6,2)
    # EB rel8: a site reaching a target must start within [t-129, t+126].
    for t in targets:
        lo=max(0,t-129-base);hi=min(len(body),t+127-base)
        for idx in range(lo,hi):
            if body[idx]==0xeb and base+idx+2+struct.unpack_from('<b',body,idx+1)[0]==t:
                found[t]['eb'].append(base+idx)
    scan_op(b'\xff\x15','rip',6,2)
    scan_op(b'\xff\x25','rip',6,2)
    for rex in (b'\x48',b'\x4c',b'\x49'):
        for op in (b'\x8d',b'\x8b'):
            for modrm in (0x05,0x0d,0x15,0x1d,0x25,0x2d,0x35,0x3d):
                scan_op(rex+op+bytes([modrm]),'rip',7,3)
    return found


def _pin(body,off,hexbytes,what,who):
    want=bytes.fromhex(hexbytes)
    if body[off:off+len(want)]!=want:
        raise ValueError(f'{who} {what} changed')


def _disp(body,off):
    return struct.unpack_from('<i',body,off)[0]


def caller_boundary(data,key,spec,fdes):
    a,b,sha=spec['fde']
    _,body=read(data,a,b-a)
    # Window and relational pins run before the whole-body hash (checked
    # again by fde_record in analyze) so a mutated pin reports its window.
    # Shared tail: dl tested at +0xe67, alternate branch at +0xe69 (parent pins).
    for name,(lo,hi,hx) in WINDOWS.items():
        _pin(body,lo,hx,f'{name} window','caller boundary')
    # Entry call (dl == 0 route): displacement names this decoder's entry.
    if body[OFF['call']] != 0xe8 or a+OFF['call']+5+_disp(body,OFF['call']+1)!=ENTRIES[spec['entry']]:
        raise ValueError(f'{key} caller boundary entry call target changed')
    # Alternate block (dl != 0 route): argument moves + call to own alternate.
    alt_call=OFF['alt']+9
    if body[alt_call] != 0xe8 or a+alt_call+5+_disp(body,alt_call+1)!=ALTS[spec['alt']]['fde'][0]:
        raise ValueError(f'{key} caller boundary alternate call target changed')
    # Gated second alternate call site: window byte-identical modulo the two
    # displacement fields; the ff 15 gate names the shared slot and the E8
    # names this decoder's own alternate.
    lo,hi,hx=SITE2_WINDOW
    want=bytearray(bytes.fromhex(hx));got=bytearray(body[lo:hi])
    for mlo,mhi in SITE2_MASKS:
        want[mlo-lo:mhi-lo]=b'\0'*(mhi-mlo);got[mlo-lo:mhi-lo]=b'\0'*(mhi-mlo)
    if bytes(want)!=bytes(got):
        raise ValueError(f'{key} caller boundary gated site window changed')
    gate=OFF['site2_gate_call']
    slot=a+gate+6+_disp(body,gate+2)
    if slot!=SLOTS['gate']:
        raise ValueError(f'{key} caller boundary gate slot changed')
    if body[OFF['site2_alt_call']] != 0xe8 or \
       a+OFF['site2_alt_call']+5+_disp(body,OFF['site2_alt_call']+1)!=ALTS[spec['alt']]['fde'][0]:
        raise ValueError(f'{key} caller boundary gated alternate target changed')
    if hashlib.sha256(body).hexdigest()!=sha:
        raise ValueError(f'dl route {key} body changed')
    return {'caller':key,'fde':f'{a:#x}..{b:#x}','entry':spec['entry'],
            'dl_test':hex(a+0xe67),'alt_branch':hex(a+0xe69),
            'entry_call_site':hex(a+OFF['call']),
            'alt_sites':{'dl_tail':hex(a+alt_call),'gated':hex(a+OFF['site2_alt_call'])},
            'gate':{'call_site':hex(a+gate),'slot':hex(slot),
                    'result_temp':'rsp+0x70','tag_compare':1,
                    'alt_result_temp':'rsp+0x20','post_compare':2},
            'sha256':sha}


def parent_wiring(data,key,spec):
    a,b,sha=spec['fde']
    _,body=read(data,a,b-a)
    caller_start=CALLERS[spec['caller']]['fde'][0]
    found=[];index=body.find(b'\xe8')
    while index!=-1:
        if a+index+5+struct.unpack_from('<i',body,index+1)[0]==caller_start:
            found.append(a+index)
        index=body.find(b'\xe8',index+1)
    if found!=spec['sites']:
        raise ValueError(f'{key} parent call census changed')
    for site in spec['sites']:
        off=site-a
        if body[off-5:off]!=bytes.fromhex('4c89f631d2') or body[off]!=0xe8:
            raise ValueError(f'{key} parent call site changed')
    if hashlib.sha256(body).hexdigest()!=sha:
        raise ValueError(f'dl route {key} body changed')
    return {'parent':key,'fde':f'{a:#x}..{b:#x}','caller':spec['caller'],
            'call_sites':[hex(s) for s in spec['sites']],'rdx_at_call':0,
            'rsi_from':'r14','pre_call_bytes':'4c89f631d2','sha256':sha}


def alt_trace(data,key,spec):
    a,b=spec['fde']
    _,body=read(data,a,b-a)
    got=bytearray(body)
    for lo,hi in ALT_MASKS:
        got[lo:hi]=b'\0'*(hi-lo)
    if bytes(got).hex()!=ALT_TEMPLATE:
        raise ValueError(f'{key} alternate trace body changed')
    def rip(off,size):
        return a+off+size+_disp(body,off+size-4)
    fields={'data':rip(0x25,7),'slot':rip(0x3b,7),'fnptr':rip(0x51,7),
            'piece':rip(0x5d,7),'helper_call':rip(0x69,5)}
    if fields['data']!=spec['data'] or fields['slot']!=SLOTS['descriptor'] or \
       fields['fnptr']!=SHIMS[spec['fnptr']][0] or fields['piece']!=PIECE_VA or \
       fields['helper_call']!=HELPERS[spec['helper']]['fde'][0]:
        raise ValueError(f'{key} alternate trace relational target changed')
    return {'alternate':key,'fde':f'{a:#x}..{b:#x}','caller':spec['caller'],
            'slice_stores':{'discriminant_byte':{'at':'rsp+0x18','value':6},
                            'payload_pointer':{'from':'rsi','at':'rsp+0x20'},
                            'payload_length':{'from':'rdx','at':'rsp+0x28'}},
            'descriptor':{'at':'rsp+0x30','data_word':'rsp+0x18',
                          'meta_word':f"qword loaded from .got slot {SLOTS['descriptor']:#x}"},
            'expected_pair':{'at':'rsp+0x8','data_word':'rsp+0x7','meta_word':hex(fields['data'])},
            'argument_pair':{'at':'rsp+0x40','data_word':'rsp+0x8','meta_word':hex(fields['fnptr'])},
            'helper':{'call_site':hex(a+0x69),'target':hex(fields['helper_call']),
                      'args':{'rdi':'out+0x8','rsi':hex(fields['piece']),'rdx':'rsp+0x30'}},
            'result_write':{'at':'[out]','qword':2},'returns':'out',
            'calls_entry':False,'dereferences_payload':False}


def helper_boundary(data,key,spec):
    a,b,sha=spec['fde']
    _,body=read(data,a,b-a)
    if hashlib.sha256(body).hexdigest()!=sha:
        raise ValueError(f'dl route {key} body changed')
    for name,(off,hx) in HELPER_PINS.items():
        _pin(body,off,hx,f'helper {name}','helper boundary')
    slot=a+0x1d+6+_disp(body,0x1f)
    if body[0x1d:0x1f]!=b'\xff\x15' or slot!=SLOTS['helper_first']:
        raise ValueError(f'{key} helper boundary first slot changed')
    return {'helper':key,'fde':f'{a:#x}..{b:#x}','sha256':sha,
            'tag_test':hex(a+0x11),'first_slot':hex(slot),
            'byte6_store':hex(a+HELPER_PINS['byte6_store'][0]),
            'copies':'three qwords from its stack triple to [rdi+0x8], [rdi+0x10], [rdi+0x18]'}


def fde_record(data,fdes,role,a,b,sha=None):
    if (a,b) not in fdes:
        raise ValueError(f'dl route {role} FDE changed')
    offset,raw=read(data,a,b-a)
    digest=hashlib.sha256(raw).hexdigest()
    if sha is not None and digest!=sha:
        raise ValueError(f'dl route {role} body changed')
    records={}
    for kind in ('fde','cie'):
        va=fdes[(a,b)][kind];n=struct.unpack('<I',read(data,va,4)[1])[0]+4
        records[kind]={'va':hex(va),'bytes_hex':read(data,va,n)[1].hex()}
    return {'role':role,'start':hex(a),'end':hex(b),'file_offset':hex(offset),
            'bytes':b-a,'sha256':digest,'frames':records}


def analyze(data):
    _,fs,_=fde_extents(data);fdes={(f['start'],f['end']):f for f in fs}
    extents=sorted((f['start'],f['end']) for f in fs)
    rela=relocations(data)
    # Slot bindings relied on by the traces.
    for name,(a,b,sha) in (('descriptor_fn',DESCRIPTOR_FN),('gate_fn',GATE_FN),
                           ('helper_slot_fn',HELPER_SLOT_FN)):
        slot={'descriptor_fn':SLOTS['descriptor'],'gate_fn':SLOTS['gate'],
              'helper_slot_fn':SLOTS['helper_first']}[name]
        if rela.get(slot)!=(8,a):
            raise ValueError(f'dl route {name} slot binding changed')
    if read(data,PIECE_VA,len(bytes.fromhex(PIECE_HEX)))[1].hex()!=PIECE_HEX:
        raise ValueError('dl route message piece changed')
    # Reference census over the six FDE starts.
    targets={}
    for k,v in CALLERS.items(): targets[v['fde'][0]]=k
    for k,v in ALTS.items(): targets[v['fde'][0]]=k
    census=branch_census(data,list(targets))
    def expect_sites(va,sites):
        got=census[va]
        if got['e8']!=sites or got['e9'] or got['eb'] or got['jcc'] or got['rip']:
            raise ValueError(f'dl route reference census changed for {targets[va]}')
    for k,v in CALLERS.items():
        expect_sites(v['fde'][0],PARENTS['parent_'+k[-1]]['sites'])
    for k,v in ALTS.items():
        ca=CALLERS[v['caller']]['fde'][0]
        expect_sites(v['fde'][0],[ca+OFF['site2_alt_call'],ca+OFF['alt']+9])
    starts=list(targets)
    hits={t:[a for a,(ty,v) in rela.items() if v==t] for t in starts}
    if any(hits.values()):
        raise ValueError('dl route relocation reference appeared')
    eh=next(s for s in sections(data) if s['name']=='.eh_frame')
    raw={}
    for t in starts:
        q=data.count(struct.pack('<Q',t))
        dpos=[];idx=data.find(struct.pack('<I',t))
        while idx!=-1:
            dpos.append(idx);idx=data.find(struct.pack('<I',t),idx+1)
        raw[t]=(q,dpos)
        if q:
            raise ValueError('dl route address-as-data reference appeared')
    # The single dword occurrence in the whole capture is the initial_location
    # delta of the .eh_frame FDE at section offset 0x1d3500 (range
    # 0x419b4d0..0x419b640): 0x419b4d0 - 0xe7a3e0 == caller_b start. Verify the
    # FDE extent and the arithmetic identity instead of treating it as a hit.
    dword_notes={}
    dpos_all=[p for _,ps in raw.values() for p in ps]
    if dpos_all!=[0xe7a3e0]:
        raise ValueError('dl route raw dword census changed')
    if (0x419b4d0,0x419b640) not in fdes:
        raise ValueError('dl route dword explanation FDE changed')
    if 0x419b4d0-0xe7a3e0!=CALLERS['caller_b']['fde'][0]:
        raise ValueError('dl route dword explanation arithmetic changed')
    dword_notes['caller_b']={'file_offset':'0xe7a3e0','section':'.eh_frame',
        'explanation':'initial_location pcrel delta of the FDE at .eh_frame+0x1d3500 '
                      '(range 0x419b4d0..0x419b640): 0x419b4d0 - 0xe7a3e0 = 0x33210f0'}
    # Int3 gaps: no fall-through entry into any of the six starts.
    gaps={}
    ends=sorted(e for _,e in extents)
    for t in starts:
        i=bisect.bisect_left(ends,t);prev_end=ends[i-1]
        gap=read(data,prev_end,t-prev_end)[1]
        if not gap or set(gap)!={0xcc}:
            raise ValueError(f'dl route int3 gap changed for {targets[t]}')
        gaps[targets[t]]=t-prev_end
    # Boundaries and owners.
    callers=[caller_boundary(data,k,CALLERS[k],fdes) for k in ('caller_a','caller_b','caller_c')]
    parents=[parent_wiring(data,k,PARENTS[k]) for k in ('parent_a','parent_b','parent_c')]
    helpers=[helper_boundary(data,k,HELPERS[k]) for k in ('helper_a','helper_b','helper_c')]
    traces=[alt_trace(data,k,ALTS[k]) for k in ('alt_a','alt_b','alt_c')]
    owners=[]
    for k in ('alt_a','alt_b','alt_c'):
        a,b=ALTS[k]['fde']
        rec=fde_record(data,fdes,k,a,b)
        rec['caller']=ALTS[k]['caller'];rec['helper']=ALTS[k]['helper']
        owners.append(rec)
    boundary_records=[]
    for k in ('caller_a','caller_b','caller_c'):
        a,b,sha=CALLERS[k]['fde'];boundary_records.append(fde_record(data,fdes,k,a,b,sha))
    for k in ('parent_a','parent_b','parent_c'):
        a,b,sha=PARENTS[k]['fde'];boundary_records.append(fde_record(data,fdes,k,a,b,sha))
    for k in ('helper_a','helper_b','helper_c'):
        a,b,sha=HELPERS[k]['fde'];boundary_records.append(fde_record(data,fdes,k,a,b,sha))
    for k,(a,b,sha) in SHIMS.items():
        boundary_records.append(fde_record(data,fdes,k,a,b,sha))
    for name,(a,b,sha) in (('descriptor_fn',DESCRIPTOR_FN),('gate_fn',GATE_FN),
                           ('helper_slot_fn',HELPER_SLOT_FN)):
        boundary_records.append(fde_record(data,fdes,name,a,b,sha))
    census_out={
        'decoder_callers':{k:{'e8_call_sites':[hex(s) for s in PARENTS['parent_'+k[-1]]['sites']],
                              'e9_jumps':0,'rel8_jumps':0,'conditional_jumps':0,
                              'rip_relative_references':0,'rela_dyn_addends':0,
                              'raw_qword_occurrences':0,'int3_gap_bytes':gaps[k],
                              'raw_dword_occurrences':([dword_notes[k]] if k in dword_notes else [])}
                           for k in CALLERS},
        'alternates':{k:{'e8_call_sites':[hex(CALLERS[v['caller']]['fde'][0]+OFF['site2_alt_call']),
                                          hex(CALLERS[v['caller']]['fde'][0]+OFF['alt']+9)],
                         'e9_jumps':0,'rel8_jumps':0,'conditional_jumps':0,
                         'rip_relative_references':0,'rela_dyn_addends':0,
                         'raw_qword_occurrences':0,'raw_dword_occurrences':[],
                         'int3_gap_bytes':gaps[k]} for k,v in ALTS.items()},
        'slot_bindings':{name:hex(rela[slot][1]) for name,slot in SLOTS.items()},
        'established_rdx_at_decoder_entries':[0]}
    return {'target_sha256':SHA,'owners':owners,'boundaries':boundary_records,
            'caller_boundaries':callers,'parents':parents,'helpers':helpers,
            'traces':traces,'census':census_out,
            'piece':{'va':hex(PIECE_VA),'bytes_hex':PIECE_HEX,
                     'legible_fragments':['invalid type: ',', expected ']},
            'route_model':{'dl_values_at_censused_entries':[0],
                           'route_for_dl_zero':'byte-fed entry',
                           'route_for_dl_nonzero':'alternate (traced here)',
                           'alternate_reachable_from_censused_callers':False},
            'entry_citation':{'packet':'RE-003-node115-priority-prefix',
                              'caller_packet':'RE-003-node115-priority-prefix-caller',
                              'entry_starts':{k:hex(v) for k,v in ENTRIES.items()}},
            'captured_code_executed':False,'limits':LIMITS}


def branch_edges(asm):
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
    if len(data)!=SIZE or hashlib.sha256(data).hexdigest()!=SHA:
        raise ValueError('expected pinned node115')
    report=analyze(data);output.mkdir(parents=True,exist_ok=True);lines=[]
    with tempfile.TemporaryDirectory() as directory:
        snapshot=Path(directory)/'node115.elf';snapshot.write_bytes(data)
        native=subprocess.check_output(['readelf','-wf',str(snapshot)],text=True)
        specs=[v['fde'][0:2] for v in ALTS.values()]
        specs+=[v['fde'][0:2] for v in CALLERS.values()]
        specs+=[v['fde'][0:2] for v in PARENTS.values()]
        specs+=[v['fde'][0:2] for v in HELPERS.values()]
        specs+=[v[0:2] for v in SHIMS.values()]
        specs+=[DESCRIPTOR_FN[0:2],GATE_FN[0:2],HELPER_SLOT_FN[0:2]]
        for a,b in specs:
            rows=[l for l in native.splitlines() if f'pc={a:016x}..{b:016x}' in l]
            if len(rows)!=1:
                raise ValueError('native dl route FDE disagreement')
            lines.extend(rows)
        # Native validation per decoder: pinned sites are instruction starts
        # and the alternate block's only direct branch predecessor is the
        # shared tail's dl branch.
        for key,spec in CALLERS.items():
            a,b,_=spec['fde']
            asm=subprocess.check_output(['objdump','-d','-M','intel','--insn-width=16',
                                         f'--start-address={a:#x}',f'--stop-address={b:#x}',
                                         str(snapshot)],text=True)
            ins=decode_export(asm,a,b,read(data,a,b-a)[1])
            required={a+OFF['tail'],a+0xe67,a+0xe69,a+OFF['state'],a+OFF['call'],
                      a+OFF['alt'],a+OFF['alt']+9,a+OFF['site2'],a+OFF['site2_gate_call'],
                      a+OFF['site2_alt_call'],a+OFF['site2_cmp']}
            if not required<=set(ins):
                raise ValueError(f'{key} dl route site not native instruction start')
            edges=branch_edges(asm)
            if edges.get(a+OFF['alt'],[])!=[a+0xe69]:
                raise ValueError(f'{key} dl route alternate branch edge census changed')
        # Retain full exports of the three 126-byte alternates.
        for key,spec in ALTS.items():
            a,b=spec['fde']
            asm=subprocess.check_output(['objdump','-d','-M','intel','--insn-width=16',
                                         f'--start-address={a:#x}',f'--stop-address={b:#x}',
                                         str(snapshot)],text=True)
            ins=decode_export(asm,a,b,read(data,a,b-a)[1])
            if set(ins)|{b}!={a+i for i in range(0,b-a)} and len(ins)<20:
                raise ValueError(f'{key} dl route export decode disagreement')
            (output/f'{key}_objdump.txt').write_bytes(
                asm.replace(str(snapshot),'<authenticated-node115>').encode('utf-8'))
    (output/'frames.txt').write_bytes(('\n'.join(lines)+'\n').encode('utf-8'))
    (output/'records.json').write_bytes((json.dumps(report,indent=2)+'\n').encode('utf-8'))
    return report


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary',type=Path,default=TARGET)
    p.add_argument('--output',type=Path,default=ROOT/'work/priority-prefix-dl-route115')
    args=p.parse_args();report=generate(args.binary,args.output)
    print(json.dumps({'owners':len(report['owners']),'bytes':sum(x['bytes'] for x in report['owners']),'executed':False}))
