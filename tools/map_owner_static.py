#!/usr/bin/env python3
"""RE-015: digest-bound node115 map owner of the flag-group chain."""
import argparse
import bisect
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
PACKET=ROOT/'research/work-items/RE-015-node115-map-owner'
SHA='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
OWNERS={
 'large_consumer':(0x15a3b90,0x15a6509,'7995f7af57e2be27ca6ed1e307d9bcce9d6140f72b0ff0cf0804d7f09e5505fb'),
 'map_insert':(0x156d840,0x156d9ac,'4e0f958aa9013a7f869f4ca6e17a9c1a66a7dda80a5caf4421b8d659251ff36b'),
 'insert_delegate':(0x1495230,0x1495ffc,'4638a38d17f41f44494a62a92c981585f8b74bf6692031e5764e96ce2e0ac229'),
 'collect_helper':(0x153ba90,0x153be3a,'a5c096486429b29251c1adf8a1b25f31766b5c31a4db944805b6eda072d3868f')}
BOUNDARIES={
 'caller_wrapper':(0x15a6510,0x15a6674,'f89a14d39fba3e107a6f843895ed7bc4f718f8e462a3977f4b152265d2586f79'),
 'second_structure_helper':(0x1542870,0x15429b2,'1112794f86fd4eb9eb110927bb2f59d6da9dd87d7aa4ffa966cc725791abb218'),
 'format_consumer':(0x141e3a0,0x141e538,'aa4d4d0611c533e38c65e1577c0426b5163846c01225556743d4d4345cadd1fe'),
 'derived_byte_callee':(0x15ae430,0x15ae5ae,'4cfb1633d772df3d0e75abf5864ea242a85e7732e479b5351ae80c97842d7acf')}
CONSUMER=0x15a3b90
CONSUMER_END=0x15a6509
INSERT=0x156d840
DELEGATE=0x1495230
DELEGATE_END=0x1495ffc
DELEGATE_RET=0x1495d9a
COLLECT=0x153ba90
COLLECT_END=0x153be3a
WRAPPER=0x15a6510
# The sorted-node map handle is a 24-byte header in the large
# consumer's frame: root pointer at [rsp+0x178], tree height at
# [rsp+0x180] (the descent countdown of every walk), element
# count at [rsp+0x188].
HANDLE={'root':0x178,'height':0x180,'size':0x188}
HANDLE_LAYOUT={'root':'+0x0','height':'+0x8','size':'+0x10'}
# Node layout, as written by the insert family: first child at
# +0x0, entry count word at +0x112, key bytes at +0x114 (the
# consumer walks address key i as [node + (i-1) + 0x115]),
# children from +0x120, and the 24-byte value entries at
# node-0x10 + index*0x18. A leaf node is 0x120 bytes, an
# internal node 0x180; a node holds at most 11 entries.
NODE_LAYOUT={'first_child':'+0x0','count_word':'+0x112',
             'key_bytes':'+0x114','children':'+0x120',
             'entries':'node-0x10 + index*0x18',
             'leaf_bytes':'0x120','internal_bytes':'0x180',
             'max_entries':11}
SENTINEL=0x8000000000000000
ALLOC_SLOT=0x64df480
ALLOC_TARGET=0x6355830
DEALLOC_SLOT=0x64df4a0
DEALLOC_TARGET=0x635de30
MEMMOVE_SLOT=0x64df568
MEMMOVE_RELOCATION=(6,8)
MEMMOVE_NAME='memmove'
SLOT_BINDINGS={'alloc':(ALLOC_SLOT,8,ALLOC_TARGET),
               'dealloc':(DEALLOC_SLOT,8,DEALLOC_TARGET),
               'bounds_panic':(0x64df570,8,0x16817e0),
               'assert_format':(0x64df730,8,0x1680e60),
               'other_panic':(0x64df830,8,0x1680c10),
               'alloc_error':(0x64df490,8,0x141e251)}
# Whole-body access census for the handle words: every
# rsp-relative access to [rsp+0x178]/[rsp+0x180]/[rsp+0x188]
# in the large consumer body is one of these encodings, with
# exactly these sites. The height word has NO store encoding
# anywhere in the body.
HANDLE_CENSUS={
 'root_store_imm':('48c784247801000000000000',[0x15a3d24]),
 'size_store_imm':('48c784248801000000000000',[0x15a3d30]),
 'root_load_rax':('488b842478010000',[0x15a4055,0x15a4353,0x15a453c]),
 'root_load_rcx':('488b8c2478010000',[0x15a5506,0x15a63d1]),
 'root_lea_rcx':('488d8c2478010000',[0x15a417c,0x15a4456]),
 'height_load_rcx':('488b8c2480010000',[0x15a4066,0x15a4364,0x15a4560]),
 'height_load_rdx':('488b942480010000',[0x15a5513,0x15a63e4]),
 'size_load_rax':('488b842488010000',[0x15a551b,0x15a63ec])}
HEIGHT_STORE_PATTERNS=['48c784248001000000000000','48898c2480010000',
 '4889842480010000','4889942480010000','48899c2480010000',
 '4c898c2480010000','4c89942480010000']
# Pinned instruction bytes per owner, each validated as a
# native instruction start against the retained exports.
CONSUMER_PINS={
 'init_root_store':(0x15a3d24,'48c784247801000000000000'),
 'init_size_store':(0x15a3d30,'48c784248801000000000000'),
 'seg_a_root_load':(0x15a4055,'488b842478010000'),
 'seg_a_height_load':(0x15a4066,'488b8c2480010000'),
 'seg_a_count_load':(0x15a4081,'0fb7b012010000'),
 'seg_a_key_load':(0x15a40aa,'440fb68c1015010000'),
 'seg_a_child_load':(0x15a40fd,'488b84d020010000'),
 'miss_a_handle_lea':(0x15a417c,'488d8c2478010000'),
 'insert_call_a':(0x15a41eb,'e85096fcff'),
 'phase2_root_load':(0x15a453c,'488b842478010000'),
 'phase2_height_load':(0x15a4560,'488b8c2480010000'),
 'phase2_count_load':(0x15a4568,'0fb7b012010000'),
 'phase2_key_load':(0x15a458a,'440fb6841015010000'),
 'phase2_child_load':(0x15a45cd,'488b84d020010000'),
 'phase2_capacity_cmp':(0x15a45e0,'48392b'),
 'drain_record1_zero':(0x15a5523,'48c744242800000000'),
 'drain_record1_root':(0x15a552c,'48894c2430'),
 'drain_record1_height':(0x15a5531,'4889542438'),
 'collect_call':(0x15a5580,'e80b65f9ff'),
 'drain_free_word_load':(0x15a55ad,'488b74c808'),
 'drain_free_sentinel_cmp':(0x15a55b2,'4839ee'),
 'drain_free_call':(0x15a55ca,'41ffd6'),
 'drain_back_edge':(0x15a5746,'0f85a4e5ffff'),
 'drain_child_load':(0x15a57a0,'488b8020010000'),
 'drain_node_free_call':(0x15a5845,'41ffd7'),
 'tail_root_load':(0x15a63d1,'488b8c2478010000'),
 'tail_height_load':(0x15a63e4,'488b942480010000'),
 'tail_size_load':(0x15a63ec,'488b842488010000'),
 'tail_collect_call':(0x15a6459,'e83256f9ff')}
INSERT_PINS={
 'node_test':(0x156d857,'48837e0800'),
 'key_copy_lea':(0x156d85e,'498d4608'),
 'key_copy_load':(0x156d86b,'0f1000'),
 'key_dword_load':(0x156d877,'418b5620'),
 'delegate_call':(0x156d88b,'e8a079f2ff'),
 'creation_alloc_call':(0x156d8ac,'ff15ce1bf704'),
 'creation_count_zero':(0x156d8c2,'66c780120100000000'),
 'creation_root_store':(0x156d8cb,'48894500'),
 'creation_height_zero':(0x156d8cf,'48c7450800000000'),
 'creation_count_load':(0x156d8de,'0fb78812010000'),
 'creation_count_store':(0x156d8f7,'6689b812010000'),
 'creation_key_store':(0x156d8fe,'4088b40814010000'),
 'creation_entry_word0':(0x156d90a,'4c8964f008'),
 'creation_entry_word1':(0x156d90f,'4c896cf010'),
 'creation_entry_word2':(0x156d914,'488954f018'),
 'size_increment':(0x156d91b,'48ff4510')}
DELEGATE_PINS={
 'count_load':(0x1495251,'450fb7b912010000'),
 'key_shift_call':(0x1495307,'ff155ba20405'),
 'key_store':(0x1495311,'4288ac2814010000'),
 'entry_shift_call':(0x1495350,'ff1512a20405'),
 'entry_store_word2':(0x149537c,'49894cc118'),
 'entry_store_words01':(0x1495386,'410f1144c108'),
 'count_store':(0x149538c,'664589b912010000'),
 'split_handle_reload':(0x1495c8e,'488b8424a8000000'),
 'split_root_load':(0x1495c99,'4d8b2c24'),
 'split_child_store':(0x1495cd2,'4c89a820010000'),
 'split_root_store':(0x1495cf3,'49891c24'),
 'split_height_store':(0x1495cf7,'4989442408'),
 'normal_return':(0x1495d9a,'c3')}
COLLECT_PINS={
 'child_load':(0x153baf0,'488bbf20010000'),
 'count_load':(0x153bb67,'0fb78f12010000'),
 'iterator_record_zero':(0x153bbe8,'48c70600000000'),
 'dealloc_slot_load':(0x153bc17,'488b1d8238fa04'),
 'node_free_call':(0x153bc35,'ffd3'),
 'count_compare':(0x153bc8e,'66453bb712010000'),
 'teardown_free_call':(0x153bde6,'ff15b436fa04'),
 'teardown_root_zero':(0x153bdec,'49c7450000000000')}
WRAPPER_PINS={'consumer_call':(0x15a6556,'e835d6ffff')}
# The delegate's only dealloc-slot calls: six sites, all in
# the post-return tail (panic and unwind landing pads).
DELEGATE_DEALLOC_SITES=[0x1495ed2,0x1495f3f,0x1495f4f,0x1495f9d,0x1495fd3,0x1495fee]
# The collect helper's node-layout accesses: count loads and
# compares at +0x112 and child loads at +0x120, each a native
# instruction start in the retained full export.
COLLECT_COUNT_PATTERNS={'count_load':'0fb78f12010000',
                        'count_compare':'66453bb712010000'}
COLLECT_CHILD_PATTERNS=['488bbf20010000','488b8f20010000',
 '488b8920010000','488bb920010000','488b8020010000','488d8820010000']
LIMITS=('Map ownership for the RE-015 flag-group chain\'s '
 'instance only: the large consumer 0x15a3b90 (its complete '
 '16-access handle census, its segment walks, the phase-2 '
 'probe walk, and the drain region on the field loop\'s '
 'back-edge), the map insert 0x156d840, its general delegate '
 '0x1495230, and the collect helper 0x153ba90 where the '
 'consumer drives it. The node layout is a generic family: '
 'over a hundred monomorphised sibling instantiations share '
 'the +0x112/+0x120 offsets for other key and value types, '
 'and no binary-wide reader census for the layout is claimed '
 '-- instance scope is established by the direct-call '
 'census (the insert is called only from the large consumer, '
 'the delegate only from the insert). The drain region\'s '
 'later record processing (including the second stack '
 'structure at [rsp+0x1b8] and the helper 0x149e5b0), the '
 'phase-2 probe\'s record consumers (0x474d890 and the call '
 'through slot 0x64e1458), the allocator/deallocator targets '
 'behind slots 0x64df480/0x64df4a0, and the collect helper\'s '
 '61 call sites in other instantiations are NOT traced. No '
 'captured code executed, no runtime value, indirect-call '
 'recovery beyond the pinned slot bindings, #94 '
 'correspondence, or reconstruction gate is claimed.')


def read(data,va,n):
    matches=[s for s in sections(data) if s['type']!=8 and s['address']<=va and va+n<=s['address']+s['size']]
    if len(matches)!=1:
        raise ValueError('expected one file-backed mapping')
    s=matches[0];o=s['offset']+va-s['address']
    return o,bytes(data[o:o+n])


def relocations(data):
    sec=next(s for s in sections(data) if s['name']=='.rela.dyn')
    by_offset={}
    for a,i,v in struct.iter_unpack('<QQq',data[sec['offset']:sec['offset']+sec['size']]):
        by_offset.setdefault(a,[]).append((i&0xffffffff,i>>32,v))
    return by_offset


def dynsym_name(data,index):
    ds=next(s for s in sections(data) if s['name']=='.dynsym')
    st=next(s for s in sections(data) if s['name']=='.dynstr')
    name_off=struct.unpack_from('<I',data,ds['offset']+24*index)[0]
    end=data.find(b'\0',st['offset']+name_off)
    return data[st['offset']+name_off:end].decode('ascii')


def slot_bindings(data):
    by_offset=relocations(data)
    out={}
    for role,(slot,rtype,addend) in SLOT_BINDINGS.items():
        if by_offset.get(slot,[])!=[(rtype,0,addend)]:
            raise ValueError('slot binding changed')
        out[role]={'slot':hex(slot),'type':rtype,
                   'type_name':'R_X86_64_RELATIVE','addend':hex(addend)}
    entries=by_offset.get(MEMMOVE_SLOT,[])
    if len(entries)!=1 or entries[0][0]!=MEMMOVE_RELOCATION[0] or \
       entries[0][1]!=MEMMOVE_RELOCATION[1] or entries[0][2]!=0:
        raise ValueError('memmove binding changed')
    if dynsym_name(data,MEMMOVE_RELOCATION[1])!=MEMMOVE_NAME:
        raise ValueError('memmove binding changed')
    out['memmove']={'slot':hex(MEMMOVE_SLOT),'section':'.got',
                    'relocation_type':MEMMOVE_RELOCATION[0],
                    'relocation_type_name':'R_X86_64_GLOB_DAT',
                    'symbol_index':MEMMOVE_RELOCATION[1],
                    'symbol':MEMMOVE_NAME}
    return out


def _pin(data,site,expected,label):
    raw=read(data,site,len(bytes.fromhex(expected)))[1]
    if raw.hex()!=expected:
        raise ValueError(f'{label} changed')
    return hex(site)


def _pins(data,table):
    return {name:_pin(data,site,expected,f'{name} pin')
            for name,(site,expected) in table.items()}


def initialise_handle(height):
    """The consumer's field-loop head, modelling the pinned
    stores: the root and the element count are zeroed in the
    body at every iteration; the height word is never stored
    by the consumer, so it keeps whatever the insert family
    last wrote through the handle pointer."""
    return {'root':0,'height':height,'size':0}


def insert_into_empty(handle,node):
    """The insert's creation path, modelling the pinned
    stores: a fresh 0x120-byte node is written as the root
    through the handle pointer, the height word is zeroed
    through the same pointer, and the common exit increments
    the element count through the pointer."""
    return {'root':node,'height':0,'size':handle['size']+1}


def insert_existing(handle):
    """The delegate's non-split path, modelling the pinned
    bytes: no handle word is written by the delegate, and the
    insert's common exit still increments the count."""
    return {'root':handle['root'],'height':handle['height'],
            'size':handle['size']+1}


def root_split(handle,new_root):
    """The delegate's root-split path, modelling the pinned
    stores through the record's handle pointer: the new
    0x180-byte root replaces the old root word, and the
    height word is stored incremented by one; the insert's
    common exit increments the count."""
    return {'root':new_root,'height':handle['height']+1,
            'size':handle['size']+1}


def phase2_probe_present(entry_capacity):
    """The phase-2 readback, modelling the pinned compare:
    the walk reads only the found entry's capacity word and
    branches on whether it equals the sentinel; the entry is
    present exactly when the capacity differs."""
    return entry_capacity!=SENTINEL


def drain_should_free(pointer_word):
    """The drain free loop's guard, modelling the pinned
    compares: a collected element's buffer is freed through
    the dealloc slot unless the checked word is 0 or the
    sentinel."""
    return pointer_word not in (0,SENTINEL)


def handle_census(data):
    body=read(data,CONSUMER,CONSUMER_END-CONSUMER)[1]
    census={}
    for name,(hexpat,expected) in HANDLE_CENSUS.items():
        pat=bytes.fromhex(hexpat);sites=[];index=body.find(pat)
        while index!=-1:
            sites.append(CONSUMER+index);index=body.find(pat,index+1)
        if sites!=expected:
            raise ValueError(f'handle census {name} changed')
        census[name]=[hex(s) for s in sites]
    for hexpat in HEIGHT_STORE_PATTERNS:
        if body.find(bytes.fromhex(hexpat))!=-1:
            raise ValueError('consumer height store census changed')
    census['height_stores']=[]
    census['total_accesses']=sum(len(v) for v in census.values() if isinstance(v,list))
    return census


def direct_call_census(data):
    """One pass over .text: every E8 rel32 site for the four
    traced targets, each attributed to its containing FDE."""
    sec=next(s for s in sections(data) if s['name']=='.text')
    body=bytes(data[sec['offset']:sec['offset']+sec['size']])
    base=sec['address']
    targets={CONSUMER:'large_consumer',INSERT:'map_insert',
             DELEGATE:'insert_delegate',COLLECT:'collect_helper'}
    found={role:[] for role in targets.values()}
    index=body.find(b'\xe8')
    while index!=-1:
        if index+5<=len(body):
            rel=struct.unpack_from('<i',body,index+1)[0]
            target=base+index+5+rel
            if target in targets:
                found[targets[target]].append(base+index)
        index=body.find(b'\xe8',index+1)
    _,fs,_=fde_extents(data)
    starts=sorted(f['start'] for f in fs)
    ends={f['start']:f['end'] for f in fs}
    def containing(site):
        i=bisect.bisect_right(starts,site)-1
        if i<0 or site>=ends[starts[i]]:
            return None
        return starts[i]
    out={}
    for role,sites in found.items():
        out[role]={'sites':[hex(s) for s in sites],
                   'containing_fdes':[hex(containing(s)) if containing(s) is not None else None for s in sites]}
    if found['large_consumer']!=[0x15a6556]:
        raise ValueError('consumer direct-call census changed')
    if found['map_insert']!=[0x15a41eb,0x15a44c8]:
        raise ValueError('insert direct-call census changed')
    if found['insert_delegate']!=[0x156d88b]:
        raise ValueError('delegate direct-call census changed')
    if [s for s in found['collect_helper'] if CONSUMER<=s<CONSUMER_END]!=[0x15a5580,0x15a6459,0x15a64b5]:
        raise ValueError('collect direct-call census changed')
    return out


def slot_call_targets(data,body,base):
    """Every ff15 slot call in a body, resolved to its slot."""
    out=[]
    index=body.find(bytes.fromhex('ff15'))
    while index!=-1:
        if index+6<=len(body):
            disp=struct.unpack_from('<i',body,index+2)[0]
            out.append((base+index,base+index+6+disp))
        index=body.find(bytes.fromhex('ff15'),index+1)
    return out


def delegate_dealloc_census(data):
    body=read(data,DELEGATE,DELEGATE_END-DELEGATE)[1]
    sites=[site for site,slot in slot_call_targets(data,body,DELEGATE) if slot==DEALLOC_SLOT]
    if sites!=DELEGATE_DEALLOC_SITES:
        raise ValueError('delegate dealloc site census changed')
    if not all(s>DELEGATE_RET for s in sites):
        raise ValueError('delegate dealloc site census changed')
    return [hex(s) for s in sites]


def collect_layout_census(data):
    body=read(data,COLLECT,COLLECT_END-COLLECT)[1]
    out={}
    for name,hexpat in COLLECT_COUNT_PATTERNS.items():
        pat=bytes.fromhex(hexpat);sites=[];index=body.find(pat)
        while index!=-1:
            sites.append(COLLECT+index);index=body.find(pat,index+1)
        out[name]=[hex(s) for s in sites]
    children=[]
    for hexpat in COLLECT_CHILD_PATTERNS:
        pat=bytes.fromhex(hexpat);index=body.find(pat)
        while index!=-1:
            children.append(COLLECT+index);index=body.find(pat,index+1)
    out['child_accesses']=[hex(s) for s in sorted(set(children))]
    if out['count_load']!=['0x153bb67'] or out['count_compare']!=['0x153bc8e']:
        raise ValueError('collect count census changed')
    if '0x153baf0' not in out['child_accesses']:
        raise ValueError('collect child census changed')
    return out


def consumer_trace(data):
    pins=_pins(data,CONSUMER_PINS)
    census=handle_census(data)
    return {'handle':{'frame_offsets':{k:hex(v) for k,v in HANDLE.items()},
                      'layout':HANDLE_LAYOUT,
                      'access_census':census,
                      'provenance':'The handle is local to the '
                      'consumer frame. At the head of every '
                      'field-loop iteration the consumer itself '
                      'zeroes the root word (0x15a3d24) and the '
                      'element count (0x15a3d30); the height '
                      'word has no store anywhere in the body '
                      'and is written only through the handle '
                      'pointer by the insert family. No caller '
                      'argument or field supplies any handle '
                      'word: the sole direct caller passes an '
                      'out scratch, a record pointer, and a '
                      'scalar only.'},
            'segment_walks':{'root_loads':['0x15a4055','0x15a4353'],
                             'height_loads':['0x15a4066','0x15a4364'],
                             'count_load':'0x15a4081',
                             'key_load':'0x15a40aa',
                             'child_load':'0x15a40fd',
                             'note':'Both flag segments walk the '
                             'same handle; the miss record built '
                             'by each segment carries the handle '
                             'address as its first word (lea at '
                             '0x15a417c / 0x15a4456) into the '
                             'insert call.'},
            'phase2_probe':{'root_load':pins['phase2_root_load'],
                            'height_load':pins['phase2_height_load'],
                            'count_load':pins['phase2_count_load'],
                            'key_load':pins['phase2_key_load'],
                            'child_load':pins['phase2_child_load'],
                            'capacity_compare':pins['phase2_capacity_cmp'],
                            'reads':'The probe walk reads only '
                            'the found entry\'s capacity word and '
                            'compares it against the sentinel '
                            '0x8000000000000000; the stored '
                            'pointer and length words are never '
                            'loaded in this window, and nothing '
                            'is copied or freed on either branch '
                            '-- both branches build descriptor '
                            'records from .rodata strings and '
                            'the consumer\'s argument block.'},
            'drain':{'record1':{'zero':pins['drain_record1_zero'],
                                'root':pins['drain_record1_root'],
                                'height':pins['drain_record1_height']},
                     'collect_call':pins['collect_call'],
                     'free_word_load':pins['drain_free_word_load'],
                     'free_sentinel_compare':pins['drain_free_sentinel_cmp'],
                     'free_call':pins['drain_free_call'],
                     'child_load':pins['drain_child_load'],
                     'node_free_call':pins['drain_node_free_call'],
                     'back_edge':pins['drain_back_edge'],
                     'reads':'After the collect call the '
                     'consumer walks the collected vector of '
                     '24-byte elements (base at [rsp+0x90], '
                     'count at [rsp+0xa0]) from the last '
                     'element down, and for each element whose '
                     'checked word is neither 0 nor the '
                     'sentinel calls the dealloc slot value '
                     'with the element\'s next word -- the '
                     'only free of stored buffers in the '
                     'traced code. A child-descent region in '
                     'the same drain window frees nodes '
                     'through the same slot (call at '
                     '0x15a5845, size 0x180) before the '
                     'back-edge returns to the field-loop '
                     'head.'},
            'tail_handle_loads':{'root':pins['tail_root_load'],
                                 'height':pins['tail_height_load'],
                                 'size':pins['tail_size_load'],
                                 'collect_call':pins['tail_collect_call'],
                                 'note':'The unwind-region twin of '
                                 'the drain: the same handle '
                                 'triple is loaded and the same '
                                 'collect helper called.'},
            'pins':pins}


def insert_trace(data):
    pins=_pins(data,INSERT_PINS)
    return {'dispatch':{'node_test':pins['node_test'],
                        'note':'The insert branches on the '
                        'record\'s second word: nonzero is an '
                        'existing node and goes to the '
                        'delegate; zero is the empty tree and '
                        'goes to the creation path.'},
            'delegate_path':{'key_copy_lea':pins['key_copy_lea'],
                             'key_copy_load':pins['key_copy_load'],
                             'key_dword_load':pins['key_dword_load'],
                             'call':pins['delegate_call'],
                             'note':'The key copy is built from '
                             'the record at +0x8.. on the '
                             'insert\'s own stack; the delegate '
                             'receives (out, key copy, key '
                             'dword, value record, record).'},
            'creation_path':{'alloc_call':pins['creation_alloc_call'],
                             'count_zero':pins['creation_count_zero'],
                             'root_store':pins['creation_root_store'],
                             'height_zero':pins['creation_height_zero'],
                             'count_load':pins['creation_count_load'],
                             'count_store':pins['creation_count_store'],
                             'key_store':pins['creation_key_store'],
                             'entry_stores':[pins['creation_entry_word0'],
                                             pins['creation_entry_word1'],
                                             pins['creation_entry_word2']],
                             'note':'A 0x120-byte node is '
                             'allocated through the alloc slot; '
                             'its first child and count word are '
                             'zeroed; the node is written as '
                             'the root through the handle '
                             'pointer ([rbp] where rbp = the '
                             'record\'s first word), the height '
                             'word is zeroed through the same '
                             'pointer ([rbp+0x8]), and the '
                             'first entry\'s key byte and '
                             '24-byte triple are stored.'},
            'common_exit':{'size_increment':pins['size_increment'],
                           'note':'Both paths join at the '
                           'increment of the element count '
                           'through the handle pointer '
                           '([rbp+0x10]) before the out record '
                           'is written.'},
            'pins':pins}


def delegate_trace(data):
    pins=_pins(data,DELEGATE_PINS)
    body=read(data,DELEGATE,DELEGATE_END-DELEGATE)[1]
    for name,site in (('key_shift_call',0x1495307),('entry_shift_call',0x1495350)):
        disp=struct.unpack_from('<i',body,site-DELEGATE+2)[0]
        if site+6+disp!=MEMMOVE_SLOT:
            raise ValueError(f'delegate {name} target changed')
    return {'direct_insert':{'count_load':pins['count_load'],
                             'key_shift_call':pins['key_shift_call'],
                             'key_store':pins['key_store'],
                             'entry_shift_call':pins['entry_shift_call'],
                             'entry_stores':[pins['entry_store_words01'],
                                             pins['entry_store_word2']],
                             'count_store':pins['count_store'],
                             'note':'Below 11 entries the value '
                             'triple is stored into the node '
                             'after the trailing key bytes and '
                             'entries are shifted through the '
                             'memmove slot; stored triples are '
                             'moved verbatim, their buffers '
                             'never dereferenced.'},
            'root_split':{'handle_reload':pins['split_handle_reload'],
                          'root_load':pins['split_root_load'],
                          'child_store':pins['split_child_store'],
                          'root_store':pins['split_root_store'],
                          'height_store':pins['split_height_store'],
                          'note':'On a root split the delegate '
                          'reloads the record pointer, takes '
                          'the handle address from its first '
                          'word, allocates a 0x180-byte node, '
                          'makes the old root its first child, '
                          'and writes the new root and the '
                          'incremented height through the '
                          'handle pointer ([r12] and '
                          '[r12+0x8]).'},
            'dealloc_sites':delegate_dealloc_census(data),
            'dealloc_note':'Every dealloc-slot call in the '
            'delegate sits after its normal return, in panic '
            'and unwind landing pads that free the delegate\'s '
            'own in-flight allocations (the new node, the local '
            'value copy) before ud2 or _Unwind_Resume; no '
            'stored entry is freed in the normal flow.',
            'pins':pins}


def collect_trace(data):
    pins=_pins(data,COLLECT_PINS)
    return {'layout_census':collect_layout_census(data),
            'node_free':{'slot_load':pins['dealloc_slot_load'],
                         'call':pins['node_free_call'],
                         'teardown_call':pins['teardown_free_call'],
                         'teardown_root_zero':pins['teardown_root_zero'],
                         'note':'The helper reads the node '
                         'count word (+0x112) and descends '
                         'child pointers (+0x120) across the '
                         'tree, and its teardown arm frees '
                         'nodes through the dealloc slot with '
                         'the node size (0x120 leaf, 0x180 '
                         'internal) before zeroing the root '
                         'word of the record it was handed. '
                         'It contains no 0x18-stride entry '
                         'copy: no stored triple is copied by '
                         'this helper.'},
            'iterator_record_zero':pins['iterator_record_zero'],
            'pins':pins}


def wrapper_citation(data):
    pins=_pins(data,WRAPPER_PINS)
    return {'call':pins['consumer_call'],
            'arguments':{'rdi':'wrapper stack scratch at '
                          '[rsp+0x48] (the out record)',
                          'rsi':'the wrapper\'s own record '
                          'argument, forwarded verbatim',
                          'edx':'a dword produced by a slot '
                          'call on a wrapper-local value, '
                          'forwarded as a scalar'},
            'note':'The wrapper is the large consumer\'s only '
            'direct caller in the binary. It passes no map '
            'state: the map handle is created and owned '
            'entirely inside the consumer frame.'}


def analyze(data):
    bindings=slot_bindings(data)
    trace={'consumer':consumer_trace(data),
           'insert':insert_trace(data),
           'delegate':delegate_trace(data),
           'collect':collect_trace(data),
           'sole_caller':wrapper_citation(data),
           'direct_calls':direct_call_census(data),
           'node_layout':NODE_LAYOUT}
    _,fs,_=fde_extents(data);fdes={(f['start'],f['end']):f for f in fs}
    def frame_records(a,b,sha,role):
        if (a,b) not in fdes:
            raise ValueError(f'{role} scope FDE changed')
        offset,raw=read(data,a,b-a)
        if hashlib.sha256(raw).hexdigest()!=sha:
            raise ValueError(f'{role} body changed')
        records={}
        for kind in ['fde','cie']:
            va=fdes[(a,b)][kind];n=struct.unpack('<I',read(data,va,4)[1])[0]+4
            records[kind]={'va':hex(va),'bytes_hex':read(data,va,n)[1].hex()}
        return {'role':role,'start':hex(a),'end':hex(b),
                'file_offset':hex(offset),'bytes':b-a,'sha256':sha,
                'frames':records}
    owners=[frame_records(a,b,sha,role) for role,(a,b,sha) in OWNERS.items()]
    boundaries=[frame_records(a,b,sha,role) for role,(a,b,sha) in BOUNDARIES.items()]
    return {'target_sha256':SHA,'owners':owners,
            'map_owner':trace,
            'slot_bindings':bindings,
            'boundaries':boundaries,
            'map_verdict':'The sorted-node map the RE-015 '
                            'flag-group chain stores into is '
                            'owned by the large consumer '
                            '0x15a3b90 itself. Its 24-byte '
                            'handle {root, height, size} lives '
                            'in the consumer\'s frame at '
                            '[rsp+0x178]: the consumer zeroes '
                            'the root and the size at the head '
                            'of every field-loop iteration, and '
                            'never stores the height word at '
                            'all. The handle never arrives from '
                            'a caller or a field -- the '
                            'consumer\'s only direct caller '
                            '(the wrapper FDE at 0x15a6510) '
                            'passes an out scratch, a record '
                            'pointer, and a scalar. The insert '
                            'family writes the handle only '
                            'through the pointer the consumer '
                            'hands it as the miss record\'s '
                            'first word: the insert\'s creation '
                            'path writes the fresh root and '
                            'zeroes the height, the delegate\'s '
                            'root split replaces the root and '
                            'increments the height, and the '
                            'insert\'s common exit increments '
                            'the size. Stored values are read '
                            'back in three places: the segment '
                            'walks themselves (the map-hit '
                            'replacement, traced by the '
                            'out-buffer-owner packet), a phase-2 '
                            'probe walk that loads only the '
                            'found entry\'s capacity word and '
                            'compares it against the sentinel '
                            '-- never the pointer or length, '
                            'and nothing is copied or freed '
                            'there -- and the per-iteration '
                            'drain on the loop\'s back-edge, '
                            'where the collect helper '
                            '0x153ba90 walks the tree by its '
                            'count and child offsets and frees '
                            'the nodes, and the consumer frees '
                            'each collected element\'s buffer '
                            'through the dealloc slot under '
                            'the 0/sentinel guard. Inside the '
                            'insert family, splits move stored '
                            'triples verbatim through the '
                            'memmove slot and no stored entry '
                            'is freed: the delegate\'s six '
                            'dealloc calls all sit in post-'
                            'return panic/unwind pads freeing '
                            'its own in-flight allocations.',
            'captured_code_executed':False,'limits':LIMITS}


WINDOWS=[('loop_head',0x15a3cc8,0x15a3d61),
         ('phase2_walk',0x15a44e0,0x15a4737),
         ('drain',0x15a5501,0x15a5861)]
FULL_EXPORTS=[('map_insert',INSERT,0x156d9ac),
              ('insert_delegate',DELEGATE,DELEGATE_END),
              ('collect_helper',COLLECT,COLLECT_END)]


def _objdump(snapshot,a,b):
    return subprocess.check_output(['objdump','-d','-M','intel','--insn-width=16',f'--start-address={a:#x}',f'--stop-address={b:#x}',str(snapshot)],text=True)


def generate(binary,output):
    data=binary.read_bytes()
    if len(data)!=105896032 or hashlib.sha256(data).hexdigest()!=SHA:
        raise ValueError('expected pinned node115')
    report=analyze(data);output.mkdir(parents=True,exist_ok=True);lines=[]
    with tempfile.TemporaryDirectory() as directory:
        snapshot=Path(directory)/'node115.elf';snapshot.write_bytes(data)
        native=subprocess.check_output(['readelf','-wf',str(snapshot)],text=True)
        for role,(a,b,_) in list(OWNERS.items())+list(BOUNDARIES.items()):
            rows=[l for l in native.splitlines() if f'pc={a:016x}..{b:016x}' in l]
            if len(rows)!=1:
                raise ValueError('native FDE disagreement')
            lines.extend(rows)
        # Every pinned or censused consumer site must be a
        # native instruction start in the full owner body.
        asm=_objdump(snapshot,CONSUMER,CONSUMER_END)
        ins=decode_export(asm,CONSUMER,CONSUMER_END,read(data,CONSUMER,CONSUMER_END-CONSUMER)[1])
        sites={site for site,_ in CONSUMER_PINS.values()}
        for _,sites_list in [(k,v) for k,v in report['map_owner']['consumer']['handle']['access_census'].items() if isinstance(v,list)]:
            sites.update(int(s,16) for s in sites_list)
        sites.update([0x15a41eb,0x15a44c8,0x15a5580,0x15a6459,0x15a64b5])
        if not sites<=set(ins):
            raise ValueError('consumer evidence site not native instruction start')
        for name,wa,wb in WINDOWS:
            wasm=_objdump(snapshot,wa,wb)
            decode_export(wasm,wa,wb,read(data,wa,wb-wa)[1])
            (output/f'{name}_window_{wa:x}_{wb:x}_objdump.txt').write_bytes(wasm.replace(str(snapshot),'<authenticated-node115>').encode('utf-8'))
        # Full exports for the three smaller owners, with every
        # pinned and censused site validated as an instruction
        # start.
        pin_tables={'map_insert':INSERT_PINS,'insert_delegate':DELEGATE_PINS,
                    'collect_helper':COLLECT_PINS}
        extra_sites={'insert_delegate':DELEGATE_DEALLOC_SITES,
                     'collect_helper':[int(s,16) for s in report['map_owner']['collect']['layout_census']['child_accesses']]}
        for name,a,b in FULL_EXPORTS:
            easm=_objdump(snapshot,a,b)
            eins=decode_export(easm,a,b,read(data,a,b-a)[1])
            esites={site for site,_ in pin_tables[name].values()}
            esites.update(extra_sites.get(name,[]))
            if not esites<=set(eins):
                raise ValueError(f'{name} evidence site not native instruction start')
            (output/f'{name}_objdump.txt').write_bytes(easm.replace(str(snapshot),'<authenticated-node115>').encode('utf-8'))
        # The caller boundary's consumer call site must be a
        # native instruction start in its FDE.
        wasm=_objdump(snapshot,WRAPPER,0x15a6674)
        wins=decode_export(wasm,WRAPPER,0x15a6674,read(data,WRAPPER,0x15a6674-WRAPPER)[1])
        if WRAPPER_PINS['consumer_call'][0] not in wins:
            raise ValueError('wrapper evidence site not native instruction start')
    (output/'frames.txt').write_bytes(('\n'.join(lines)+'\n').encode('utf-8'))
    (output/'records.json').write_bytes((json.dumps(report,indent=2)+'\n').encode('utf-8'))
    return report


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary',type=Path,default=TARGET)
    p.add_argument('--output',type=Path,default=ROOT/'work/map-owner115')
    args=p.parse_args();report=generate(args.binary,args.output)
    print(json.dumps({'functions':len(report['owners']),'bytes':sum(x['bytes'] for x in report['owners']),'executed':False}))
