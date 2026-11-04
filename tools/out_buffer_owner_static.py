#!/usr/bin/env python3
"""RE-015: digest-bound node115 out-buffer owner of the flag-group chain."""
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
PACKET=ROOT/'research/work-items/RE-015-node115-out-buffer-owner'
SHA='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
OWNERS={
 'large_consumer':(0x15a3b90,0x15a6509,'7995f7af57e2be27ca6ed1e307d9bcce9d6140f72b0ff0cf0804d7f09e5505fb')}
BOUNDARIES={
 'format_consumer':(0x141e3a0,0x141e538,'aa4d4d0611c533e38c65e1577c0426b5163846c01225556743d4d4345cadd1fe'),
 'derived_byte_callee':(0x15ae430,0x15ae5ae,'4cfb1633d772df3d0e75abf5864ea242a85e7732e479b5351ae80c97842d7acf'),
 'map_insert':(0x156d840,0x156d9ac,'4e0f958aa9013a7f869f4ca6e17a9c1a66a7dda80a5caf4421b8d659251ff36b')}
OWNER=0x15a3b90
OWNER_END=0x15a6509
FORMAT_CONSUMER=0x141e3a0
CALLEE=0x15ae430
MAP_INSERT=0x156d840
# The chain's terminal out header is a 24-byte stack slot in the
# large consumer's frame at [rsp+0x158]: capacity +0x0, buffer
# pointer +0x8, length +0x10 -- the same layout the format
# consumer constructs and the descriptor table method appends to.
OUT_OFFSET=0x158
OUT_LAYOUT={'capacity':'+0x0','buffer_pointer':'+0x8','length':'+0x10'}
# .got slot bindings, each an R_X86_64_RELATIVE relocation except
# the memcpy slot (R_X86_64_GLOB_DAT to the dynamic symbol).
CONSUMER_SLOT=0x64df6e8
ALLOC_SLOT=0x64df480
ALLOC_TARGET=0x6355830
DEALLOC_SLOT=0x64df4a0
DEALLOC_TARGET=0x635de30
WRITE_SLOT=0x64df6f0
WRITE_TARGET=0x1680500
MEMCPY_SLOT=0x64df508
MEMCPY_RELOCATION=(6,7)
MEMCPY_NAME='memcpy'
SLOT_BINDINGS={'consumer':(CONSUMER_SLOT,8,FORMAT_CONSUMER),
               'alloc':(ALLOC_SLOT,8,ALLOC_TARGET),
               'dealloc':(DEALLOC_SLOT,8,DEALLOC_TARGET),
               'write_target':(WRITE_SLOT,8,WRITE_TARGET)}
# Whole-body access census for the out slot: every rsp-relative
# access to [rsp+0x158]/[rsp+0x160]/[rsp+0x168] in the owner body
# is one of these six instruction encodings, with these counts.
CENSUS_PATTERNS={
 'lea_out':('488dbc2458010000',4),
 'store_capacity':('4889bc2458010000',2),
 'store_pointer':('48899c2460010000',2),
 'store_length':('4889bc2468010000',2),
 'load_length':('488b842468010000',4),
 'load_head':('0f10842458010000',4)}
CALLEE_CALLS=[0x15a3f5f,0x15a401e,0x15a4263,0x15a431c]
INSERT_CALLS=[0x15a41eb,0x15a44c8]
# The old-buffer free guard at both map-hit sites: the free is
# skipped when the replaced entry's capacity word is 0 or is one
# of the two sentinel values the movabs/cmp pair brackets
# (signed-less-than against 0x8000000000000002).
FREE_SENTINELS=(0x8000000000000000,0x8000000000000001)
LIMITS=('Out-buffer ownership for the RE-015 flag-group chain '
 'only: the large consumer 0x15a3b90 stack out slot at '
 '[rsp+0x158] (its complete 18-access census, the four callee '
 'call setups that pass its address, the two inline prefill '
 'windows, and the two post-call consumption windows per '
 'segment -- the sorted-node map hit store with the replaced '
 'buffer\'s guarded free and the miss path\'s insert-record '
 'build), plus hash-pinned boundary FDEs whose construction '
 'and delivery sites are re-pinned but whose full traces are '
 'owned by the sibling packets (the format consumer '
 '0x141e3a0\'s buffer construction by the flag-group-format '
 'packet, the callee 0x15ae430\'s scratch delivery by the '
 'derived-byte-callee packet). The map insert function '
 '0x156d840, the allocator/deallocator targets behind slots '
 '0x64df480/0x64df4a0, the map root\'s own provenance and '
 'lifetime beyond the large consumer, the value the map '
 'handle register holds on the format paths, and every other '
 'caller of the format consumer are NOT traced. No captured '
 'code executed, no runtime value, indirect-call recovery '
 'beyond the pinned slot bindings, #94 correspondence, or '
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
    entries=by_offset.get(MEMCPY_SLOT,[])
    if len(entries)!=1 or entries[0][0]!=MEMCPY_RELOCATION[0] or \
       entries[0][1]!=MEMCPY_RELOCATION[1] or entries[0][2]!=0:
        raise ValueError('memcpy binding changed')
    if dynsym_name(data,MEMCPY_RELOCATION[1])!=MEMCPY_NAME:
        raise ValueError('memcpy binding changed')
    out['memcpy']={'slot':hex(MEMCPY_SLOT),'section':'.got',
                   'relocation_type':MEMCPY_RELOCATION[0],
                   'relocation_type_name':'R_X86_64_GLOB_DAT',
                   'symbol_index':MEMCPY_RELOCATION[1],
                   'symbol':MEMCPY_NAME}
    return out


def should_free(capacity):
    """The map-hit free guard, modelling the pinned bytes: the
    replaced entry's buffer is freed unless its capacity word is
    0 or one of the two sentinel values bracketed by the
    movabs/cmp pair (signed-less-than 0x8000000000000002)."""
    return capacity!=0 and capacity not in FREE_SENTINELS


def inline_prefill(size,events=None):
    """The large consumer's non-format prefill of the out slot,
    modelling the pinned bytes: allocate size bytes through the
    alloc slot, copy size bytes through the memcpy slot, and
    store the triple {capacity=size, pointer, length=size}."""
    if events is not None:
        events.append(('alloc',size))
        events.append(('copy',size))
    return size,size


def store_into_entry(old,new):
    """The map-hit consumption, modelling the pinned bytes: the
    out triple replaces the entry's triple; the replaced buffer
    is freed through the dealloc slot exactly when should_free
    holds for the replaced capacity."""
    freed=None
    if should_free(old[0]):
        freed=(old[1],old[0])
    return new,freed


def _pin(body,base,va,hexbytes,what):
    off=va-base;want=bytes.fromhex(hexbytes)
    if body[off:off+len(want)]!=want:
        raise ValueError(f'{what} changed')


def _call_target(body,base,va):
    return va+5+struct.unpack_from('<i',body,va-base+1)[0]


def _rip_target(body,base,va,insn_len,disp_at):
    return va+insn_len+struct.unpack_from('<i',body,disp_at-base)[0]


def access_census(body):
    census={}
    for role,(hexpat,count) in CENSUS_PATTERNS.items():
        pat=bytes.fromhex(hexpat);sites=[];index=body.find(pat)
        while index!=-1:
            sites.append(OWNER+index)
            index=body.find(pat,index+1)
        if len(sites)!=count:
            raise ValueError('out slot access census changed')
        census[role]=[hex(s) for s in sites]
    direct={}
    for op in (b'\xe8',):
        sites=[];index=body.find(op)
        while index!=-1:
            va=OWNER+index
            target=va+5+struct.unpack_from('<i',body,index+1)[0]
            if target in (CALLEE,MAP_INSERT):
                sites.append((va,target))
            index=body.find(op,index+1)
        direct=sites
    if [s for s,_ in direct if _==CALLEE]!=CALLEE_CALLS:
        raise ValueError('callee call census changed')
    if [s for s,_ in direct if _==MAP_INSERT]!=INSERT_CALLS:
        raise ValueError('insert call census changed')
    census['callee_direct_calls']=[hex(s) for s in CALLEE_CALLS]
    census['insert_direct_calls']=[hex(s) for s in INSERT_CALLS]
    return census


def owner_trace(data):
    _,body=read(data,OWNER,OWNER_END-OWNER)
    def pin(va,hx,what): _pin(body,OWNER,va,hx,what)
    # Segment markers: the flag-group first byte each segment
    # writes (1 in segment A, 0 in segment B) -- the segments are
    # the two value blocks of the flag-group-first-byte packet;
    # only their out-slot windows are traced here.
    pin(0x15a3f10,'c644241401','segment A flag store')
    pin(0x15a420c,'c644241400','segment B flag store')
    # The four callee call setups: rdi is the out slot address at
    # every site; the arguments block and the flag group are the
    # same stack addresses at every site.
    setups=[]
    for lea,args,call in ((0x15a3f3a,0x15a3f4a,0x15a3f5f),
                          (0x15a3ff2,0x15a4002,0x15a401e),
                          (0x15a423e,0x15a424e,0x15a4263),
                          (0x15a42f0,0x15a4300,0x15a431c)):
        pin(lea,'488dbc2458010000','callee out argument')
        pin(args,'488d9424c0000000','callee arguments argument')
        if _call_target(body,OWNER,call)!=CALLEE:
            raise ValueError('callee call target changed')
        setups.append({'out_lea':hex(lea),'arguments_lea':hex(args),
                       'call':hex(call)})
    pin(0x15a3f5f,'e8cca40000','callee call A1')
    pin(0x15a401e,'e80da40000','callee call A2')
    pin(0x15a4263,'e8c8a10000','callee call B1')
    pin(0x15a431c,'e80fa10000','callee call B2')
    # Inline prefill (one per segment): when the segment's value
    # is already materialised, the consumer itself allocates a
    # fresh buffer of the recorded size, copies the recorded
    # bytes into it, and stores {size, pointer, size} into the
    # out slot -- no format call is made on this path.
    prefill=[]
    for size_load,alloc_call,src_load,memcpy_call,stores in (
            (0x15a3f8b,0x15a3f9f,0x15a3fb4,0x15a3fbf,(0x15a402a,0x15a4032,0x15a403a)),
            (0x15a4281,0x15a4295,0x15a42aa,0x15a42b5,(0x15a4328,0x15a4330,0x15a4338))):
        pin(alloc_call,'ff15','prefill alloc call')
        if _rip_target(body,OWNER,alloc_call,6,alloc_call+2)!=ALLOC_SLOT:
            raise ValueError('prefill alloc slot changed')
        pin(memcpy_call,'ff15','prefill memcpy call')
        if _rip_target(body,OWNER,memcpy_call,6,memcpy_call+2)!=MEMCPY_SLOT:
            raise ValueError('prefill memcpy slot changed')
        pin(stores[0],'4889bc2458010000','prefill capacity store')
        pin(stores[1],'48899c2460010000','prefill pointer store')
        pin(stores[2],'4889bc2468010000','prefill length store')
        prefill.append({'size_load':hex(size_load),
                        'alloc_call':hex(alloc_call),
                        'alloc_slot':hex(ALLOC_SLOT),
                        'source_load':hex(src_load),
                        'memcpy_call':hex(memcpy_call),
                        'memcpy_slot':hex(MEMCPY_SLOT),
                        'triple_stores':[hex(s) for s in stores],
                        'triple':'{capacity=size, pointer=allocation, length=size}'})
    pin(0x15a3f8b,'488bbc2400020000','prefill A size load')
    pin(0x15a3fb4,'488bb42490020000','prefill A source load')
    pin(0x15a4281,'488bbc2488020000','prefill B size load')
    pin(0x15a42aa,'488bb42480020000','prefill B source load')
    # The post-call map walk (one per segment): the root handle
    # is the consumer's stack word at [rsp+0x178] with a companion
    # word at [rsp+0x180]; nodes carry a u16 count at +0x112, key
    # bytes at +0x115, child pointers at +0x120, and 24-byte
    # value entries from node-0x10 in steps of 0x18.
    walks=[]
    for root_load,count_load in ((0x15a4055,0x15a4081),(0x15a4353,0x15a437f)):
        pin(root_load,'488b842478010000','map root load')
        pin(count_load,'0fb7b012010000','map node count load')
        walks.append({'root_load':hex(root_load),
                      'root_stack_offset':'0x178',
                      'count_load':hex(count_load)})
    pin(0x15a4066,'488b8c2480010000','map companion load')
    pin(0x15a40aa,'440fb68c1015010000','map key byte load')
    pin(0x15a40c7,'4983c018','map entry step')
    pin(0x15a40fd,'488b84d020010000','map child load')
    # Map hit (one per segment): the out triple is stored into
    # the entry (length word first, then capacity+pointer), the
    # replaced entry's words are loaded first, and its buffer is
    # freed through the dealloc slot exactly under the guard.
    pin(0x15a406e,'4c8b352bb4f304','segment A dealloc pointer load')
    if _rip_target(body,OWNER,0x15a406e,7,0x15a406e+3)!=DEALLOC_SLOT:
        raise ValueError('segment A dealloc slot changed')
    hits=[]
    for old_cap,old_ptr,len_load,len_store,head_load,head_store in (
            (0x15a4110,0x15a4113,0x15a4117,0x15a411f,0x15a4123,0x15a412b),
            (0x15a4406,0x15a4409,0x15a440d,0x15a4415,0x15a4419,0x15a4421)):
        pin(old_cap,'498b30','hit old capacity load')
        pin(old_ptr,'498b7808','hit old pointer load')
        pin(len_load,'488b842468010000','hit length load')
        pin(len_store,'49894010','hit length store')
        pin(head_load,'0f10842458010000','hit head load')
        pin(head_store,'410f1100','hit head store')
        hits.append({'old_capacity_load':hex(old_cap),
                     'old_pointer_load':hex(old_ptr),
                     'length_load':hex(len_load),
                     'length_store':hex(len_store),
                     'head_load':hex(head_load),
                     'head_store':hex(head_store)})
    pin(0x15a412f,'48b80200000000000080','hit A sentinel bound')
    pin(0x15a4139,'4839c6','hit A sentinel compare')
    pin(0x15a4143,'31d2','hit A free align')
    pin(0x15a4145,'41ffd6','hit A free call')
    pin(0x15a4425,'48b80200000000000080','hit B sentinel bound')
    pin(0x15a442f,'4839c6','hit B sentinel compare')
    pin(0x15a443b,'0f85c2faffff','hit B free branch')
    if _branch_target(body,OWNER,0x15a443b,6)!=0x15a3f03:
        raise ValueError('hit B free branch changed')
    # The shared free block segment B jumps into: the dealloc
    # slot call with the zeroed third argument; on segment B's
    # entry the first two arguments are the replaced entry's
    # pointer and capacity loaded at the hit site.
    pin(0x15a3f03,'31d2','shared free align')
    pin(0x15a3f05,'ff1595b5f304','shared free call')
    if _rip_target(body,OWNER,0x15a3f05,6,0x15a3f05+2)!=DEALLOC_SLOT:
        raise ValueError('shared free slot changed')
    # Map miss (one per segment): a stack record is built around
    # the root slot address, a value record receives the out
    # triple verbatim (head by movaps, length by store), and the
    # insert boundary is called with (map handle, record, value).
    misses=[]
    for root_lea,flag_store,len_load,len_store,head_load,head_store,call in (
            (0x15a417c,0x15a41a8,0x15a41b0,0x15a41b8,0x15a41c0,0x15a41c8,0x15a41eb),
            (0x15a4456,0x15a4482,0x15a448a,0x15a4492,0x15a449a,0x15a44a2,0x15a44c8)):
        pin(root_lea,'488d8c2478010000','miss record root lea')
        pin(len_load,'488b842468010000','miss length load')
        pin(len_store,'48898424e0010000','miss length store')
        pin(head_load,'0f10842458010000','miss head load')
        pin(head_store,'0f298424d0010000','miss head store')
        if _call_target(body,OWNER,call)!=MAP_INSERT:
            raise ValueError('miss insert target changed')
        misses.append({'record_root_lea':hex(root_lea),
                       'flag_store':hex(flag_store),
                       'length_load':hex(len_load),
                       'length_store':hex(len_store),
                       'head_load':hex(head_load),
                       'head_store':hex(head_store),
                       'insert_call':hex(call)})
    pin(0x15a41a8,'c68424e000000001','miss A flag byte')
    pin(0x15a4482,'c68424e000000000','miss B flag byte')
    pin(0x15a41eb,'e85096fcff','miss A insert call')
    pin(0x15a44c8,'e87393fcff','miss B insert call')
    return {'out_slot':{'stack_offset':hex(OUT_OFFSET),
                        'layout':OUT_LAYOUT,
                        'role':'the callee\'s out argument at all four call sites; written in full by the callee on the format paths and by the consumer itself on the prefill paths; read only after the calls, by the consumption windows'},
            'callee_call_setups':setups,
            'inline_prefill':prefill,
            'map_walk':{'walks':walks,
                        'companion_load':'0x15a4066',
                        'node_layout':{'count_word':'+0x112',
                                       'key_bytes':'+0x115',
                                       'child_pointers':'+0x120',
                                       'value_entries':'node-0x10, step 0x18, 24-byte {capacity, pointer, length} triples'},
                        'key_byte_load':'0x15a40aa',
                        'entry_step':'0x15a40c7',
                        'child_load':'0x15a40fd'},
            'map_hit':{'hits':hits,
                       'segment_a_free':{'pointer_load':'0x15a406e',
                                         'slot':hex(DEALLOC_SLOT),
                                         'sentinel_bound':'0x15a412f',
                                         'compare':'0x15a4139',
                                         'call':'0x15a4145',
                                         'form':'call r14 (the dealloc slot value)'},
                       'segment_b_free':{'branch':'0x15a443b',
                                         'shared_block':'0x15a3f03',
                                         'call':'0x15a3f05',
                                         'slot':hex(DEALLOC_SLOT)},
                       'free_guard':'skip when the replaced capacity is 0 or signed-less-than 0x8000000000000002 (the sentinel values 0x8000000000000000/0x8000000000000001); otherwise free (pointer, capacity, 0) through the dealloc slot'},
            'map_miss':{'misses':misses,
                        'insert_target':hex(MAP_INSERT),
                        'value_record':'the out triple copied verbatim into a stack value record at [rsp+0x1d0] (head) / [rsp+0x1e0] (length)',
                        'arguments':{'rdi':'map handle register (set before the segments; not traced)',
                                     'rsi':'stack record at [rsp+0xc0] built around the root slot address',
                                     'rdx':'value record at [rsp+0x1d0]'}},
            'access_census':access_census(body)}


def _branch_target(body,base,va,insn_len):
    return va+insn_len+struct.unpack_from('<i',body,va-base+insn_len-4)[0]


def boundary_citations(data):
    # Construction sites inside the format-consumer boundary,
    # re-pinned here; the full trace of that body is the
    # flag-group-format packet's. The consumer scans its
    # template for a capacity (doubled, or 0 when the total is
    # under 0x10 and a placeholder came first), allocates it
    # through the alloc slot, stores {capacity, pointer, 0}
    # into a stack triple, calls the write target with the
    # triple's address, and on success copies the whole triple
    # into its caller's out slot.
    a,b,_=BOUNDARIES['format_consumer']
    _,body=read(data,a,b-a)
    def cpin(va,hx,what): _pin(body,a,va,hx,what)
    cpin(0x141e45b,'4983fc10','consumer capacity compare')
    cpin(0x141e466,'4531e4','consumer capacity zero')
    cpin(0x141e46b,'4d01e4','consumer capacity double')
    cpin(0x141e479,'4c89e7','consumer alloc argument')
    cpin(0x141e47c,'ff15fe0f0c05','consumer alloc call')
    if _rip_target(body,a,0x141e47c,6,0x141e47c+2)!=ALLOC_SLOT:
        raise ValueError('consumer alloc slot changed')
    cpin(0x141e49d,'4c8965c0','consumer capacity store')
    cpin(0x141e4a1,'488945c8','consumer pointer store')
    cpin(0x141e4a5,'48c745d000000000','consumer length store')
    cpin(0x141e4b4,'488d7dc0','consumer out lea')
    cpin(0x141e4be,'ff152c120c05','consumer write call')
    if _rip_target(body,a,0x141e4be,6,0x141e4be+2)!=WRITE_SLOT:
        raise ValueError('consumer write slot changed')
    cpin(0x141e4c8,'488b45d0','consumer result length load')
    cpin(0x141e4cc,'48894310','consumer result length store')
    cpin(0x141e4d0,'0f1045c0','consumer result head load')
    cpin(0x141e4d4,'0f1103','consumer result head store')
    construction={'capacity_rule':{'compare':'0x141e45b',
                                   'zero':'0x141e466',
                                   'double':'0x141e46b'},
                  'alloc':{'argument':'0x141e479','call':'0x141e47c',
                           'slot':hex(ALLOC_SLOT)},
                  'triple_stores':{'capacity':'0x141e49d',
                                   'pointer':'0x141e4a1',
                                   'length':'0x141e4a5',
                                   'values':'{capacity, allocation pointer, 0}'},
                  'write_call':{'out_lea':'0x141e4b4','call':'0x141e4be',
                                'slot':hex(WRITE_SLOT)},
                  'success_copy':{'length_load':'0x141e4c8',
                                  'length_store':'0x141e4cc',
                                  'head_load':'0x141e4d0',
                                  'head_store':'0x141e4d4',
                                  'copies':'the whole triple into the caller\'s out slot'},
                  'traced_by':'RE-015 flag-group-format packet (#2408)'}
    # Delivery sites inside the callee boundary, re-pinned here;
    # the full trace of that body is the derived-byte-callee
    # packet's. The callee formats twice into its own scratch
    # out slots through the consumer slot, then stores the
    # second format's triple into its caller's out slot; on the
    # zero path it copies its aux argument's triple instead.
    a,b,_=BOUNDARIES['derived_byte_callee']
    _,body=read(data,a,b-a)
    def dpin(va,hx,what): _pin(body,a,va,hx,what)
    dpin(0x15ae46c,'488d7c2428','callee first out lea')
    dpin(0x15ae476,'ff156c12f304','callee first consumer call')
    if _rip_target(body,a,0x15ae476,6,0x15ae476+2)!=CONSUMER_SLOT:
        raise ValueError('callee consumer slot changed')
    dpin(0x15ae4eb,'488d7c2410','callee second out lea')
    dpin(0x15ae4f5,'ff15ed11f304','callee second consumer call')
    if _rip_target(body,a,0x15ae4f5,6,0x15ae4f5+2)!=CONSUMER_SLOT:
        raise ValueError('callee consumer slot changed')
    dpin(0x15ae4fb,'488b442420','callee delivery length load')
    dpin(0x15ae500,'49894610','callee delivery length store')
    dpin(0x15ae504,'0f10442410','callee delivery head load')
    dpin(0x15ae509,'410f1106','callee delivery head store')
    dpin(0x15ae53f,'488b4310','callee copy length load')
    dpin(0x15ae543,'49894610','callee copy length store')
    dpin(0x15ae547,'0f1003','callee copy head load')
    dpin(0x15ae54a,'410f1106','callee copy head store')
    delivery={'consumer_calls':[{'out_lea':'0x15ae46c','call':'0x15ae476',
                                 'out_slot':'callee stack [rsp+0x28]'},
                                {'out_lea':'0x15ae4eb','call':'0x15ae4f5',
                                 'out_slot':'callee stack [rsp+0x10]'}],
              'consumer_slot':hex(CONSUMER_SLOT),
              'delivery_stores':{'length_load':'0x15ae4fb',
                                 'length_store':'0x15ae500',
                                 'head_load':'0x15ae504',
                                 'head_store':'0x15ae509'},
              'copy_path_stores':{'length_load':'0x15ae53f',
                                  'length_store':'0x15ae543',
                                  'head_load':'0x15ae547',
                                  'head_store':'0x15ae54a'},
              'traced_by':'RE-015 derived-byte-callee packet (#2396)'}
    return {'format_consumer_construction':construction,
            'callee_delivery':delivery}


def analyze(data):
    bindings=slot_bindings(data)
    trace=owner_trace(data)
    citations=boundary_citations(data)
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
            'out_owner':trace,
            'boundary_citations':citations,
            'slot_bindings':bindings,
            'boundaries':boundaries,
            'chain_verdict':'The out buffer of the RE-015 '
                            'flag-group chain is owned in three '
                            'stages. Each format\'s buffer is '
                            'allocated by the format consumer '
                            '0x141e3a0 itself: it sizes a capacity '
                            'from its template scan, allocates it '
                            'through the alloc slot (0x64df480 -> '
                            '0x6355830), builds the 24-byte header '
                            '{capacity, pointer, 0} on its own '
                            'stack, formats into it through the '
                            'write target, and copies the whole '
                            'header into its caller\'s out slot. '
                            'The callee 0x15ae430 receives those '
                            'headers in its own scratch slots, and '
                            'delivers the second format\'s header '
                            'into its caller\'s out slot. The '
                            'terminal owner is the large consumer '
                            '0x15a3b90: all four of its callee '
                            'calls pass the same stack slot '
                            '[rsp+0x158] as the out argument (on '
                            'the non-format paths the large '
                            'consumer prefills that slot itself '
                            'with an allocated copy stored as '
                            '{size, pointer, size}), and after '
                            'the calls it moves the header out of '
                            'the slot into its sorted-node map -- '
                            'on a walk hit, into the found '
                            'entry\'s 24-byte triple, freeing the '
                            'replaced buffer through the dealloc '
                            'slot under the sentinel guard; on a '
                            'miss, verbatim into the value record '
                            'of the map insert call 0x156d840. '
                            'The chain never frees the delivered '
                            'buffer itself: ownership passes to '
                            'the map entry.',
            'captured_code_executed':False,'limits':LIMITS}


WINDOWS=[('segment_a',0x15a3ee2,0x15a420c),('segment_b',0x15a420c,0x15a44e0)]
PIN_WINDOWS=[(0x15a3ee2,0x15a420c),(0x15a420c,0x15a44e0)]


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
        # Every pinned owner site must be a native instruction
        # start inside its retained window export.
        body=read(data,OWNER,OWNER_END-OWNER)[1]
        pinned=set()
        for (hexpat,_) in CENSUS_PATTERNS.values():
            pat=bytes.fromhex(hexpat);index=body.find(pat)
            while index!=-1:
                pinned.add(OWNER+index);index=body.find(pat,index+1)
        for name,wa,wb in WINDOWS:
            asm=subprocess.check_output(['objdump','-d','-M','intel','--insn-width=16',f'--start-address={wa:#x}',f'--stop-address={wb:#x}',str(snapshot)],text=True)
            ins=decode_export(asm,wa,wb,read(data,wa,wb-wa)[1])
            inside={s for s in pinned if wa<=s<wb}
            if not inside<=set(ins):
                raise ValueError('owner evidence site not native instruction start')
            (output/f'{name}_window_{wa:x}_{wb:x}_objdump.txt').write_bytes(asm.replace(str(snapshot),'<authenticated-node115>').encode('utf-8'))
        # Boundary citation sites must be native instruction
        # starts inside their boundary FDEs.
        for role,(a,b,_) in BOUNDARIES.items():
            if role=='map_insert':
                continue
            asm=subprocess.check_output(['objdump','-d','-M','intel','--insn-width=16',f'--start-address={a:#x}',f'--stop-address={b:#x}',str(snapshot)],text=True)
            ins=decode_export(asm,a,b,read(data,a,b-a)[1])
            sites={'format_consumer':[0x141e45b,0x141e466,0x141e46b,0x141e479,0x141e47c,0x141e49d,0x141e4a1,0x141e4a5,0x141e4b4,0x141e4be,0x141e4c8,0x141e4cc,0x141e4d0,0x141e4d4],
                   'derived_byte_callee':[0x15ae46c,0x15ae476,0x15ae4eb,0x15ae4f5,0x15ae4fb,0x15ae500,0x15ae504,0x15ae509,0x15ae53f,0x15ae543,0x15ae547,0x15ae54a]}[role]
            if not set(sites)<=set(ins):
                raise ValueError('boundary evidence site not native instruction start')
    (output/'frames.txt').write_bytes(('\n'.join(lines)+'\n').encode('utf-8'))
    (output/'records.json').write_bytes((json.dumps(report,indent=2)+'\n').encode('utf-8'))
    return report


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary',type=Path,default=TARGET)
    p.add_argument('--output',type=Path,default=ROOT/'work/out-owner115')
    args=p.parse_args();report=generate(args.binary,args.output)
    print(json.dumps({'functions':len(report['owners']),'bytes':sum(x['bytes'] for x in report['owners']),'executed':False}))
