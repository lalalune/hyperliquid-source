#!/usr/bin/env python3
"""RE-015: digest-bound node115 write target 0x1680500 of the flag-group chain."""
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
PACKET=ROOT/'research/work-items/RE-015-node115-flag-group-write-target'
SHA='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
OWNERS={
 'write_target':(0x1680500,0x16806c0,'1d04ea71bff68d24b04f11ccfc52b1341ef49aabea0b199d73e0c2f7edd43561')}
WRITE=0x1680500
SLOT_WRITE=0x64df6f0
TABLE_METHOD_OFFSET=0x18
DEFAULT_SPEC=0x60000020
CONSUMER_TABLE=0x63f3d50
CONSUMER_METHOD=0x141e8f0
ADAPTER_TABLE=0x64078f8
ADAPTER_METHOD=0x1686bd0
CHAIN_CALL_SITE=0x141e4be
CHAIN_JUMP_SITE=0x168aa1d
EXPECTED_CENSUS=(1143,86,626)
EXPECTED_LOADS=[0x1456774,0x163394e,0x166e9eb,0x16881a1,0x168821e,0x2967bcc,
                0x29fcc18,0x43be3f8,0x4738fbb,0x47390b9,0x4fb1688,0x5bb7820,
                0x5bb8460,0x5bda621,0x5be3208,0x5c4f2a3]
LIMITS=('Write target 0x1680500 only: the tagged fourth argument (odd is an inline length for a '
 'single literal write of the third argument through the table method at +0x18; even is the '
 'arguments-block pointer), the template token scan over the third argument, the 16-byte '
 'argument records (value word at +0, formatter word at +0x8), the tag field grammar and the '
 'two indirection bits, the 24-byte descriptor built for each formatter call, the sequential '
 'argument counter rule, and the byte-sized error contract in AL. What the table method at '
 '+0x18 computes, what any argument formatter computes with the value word and the descriptor, '
 'what the descriptor fields mean to a formatter, and the behaviour of the other callers that '
 'reach this function through the same slot are NOT established by these bytes. The flag-group '
 'arguments-block construction is owned by the RE-015 derived-byte-callee packet, the template '
 'and tagged-word forwarding by the RE-015 flag-group-format packet, and the adapter-table shim '
 'tail call by the RE-014 field-adapter-table-shim packet; all three are cited here, not '
 're-derived. No captured code executed, no runtime value, indirect-call recovery, #94 '
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
    target_hits=[]
    for a,i,v in struct.iter_unpack('<QQq',data[sec['offset']:sec['offset']+sec['size']]):
        by_offset.setdefault(a,[]).append((i,v))
        if v==WRITE:
            target_hits.append(a)
    return by_offset,target_hits


def slot_bindings(data):
    by_offset,_=relocations(data)
    if by_offset.get(SLOT_WRITE)!=[(8,WRITE)]:
        raise ValueError('slot binding changed')
    return {hex(SLOT_WRITE):hex(WRITE)}


def table_method(data,table):
    by_offset,_=relocations(data)
    va=table+TABLE_METHOD_OFFSET
    if by_offset.get(va):
        if len(by_offset[va])!=1 or by_offset[va][0][0]!=8:
            raise ValueError('table method changed')
        return by_offset[va][0][1]
    return struct.unpack('<Q',read(data,va,8)[1])[0]


def table_methods(data):
    out={}
    for table,expected in ((CONSUMER_TABLE,CONSUMER_METHOD),(ADAPTER_TABLE,ADAPTER_METHOD)):
        got=table_method(data,table)
        if got!=expected:
            raise ValueError('table method changed')
        out[hex(table)]=hex(got)
    return out


def address_as_data_count(data):
    sec=next(s for s in sections(data) if s['name']=='.rela.dyn')
    needle=struct.pack('<Q',WRITE);count=0;index=data.find(needle)
    while index!=-1:
        if not (sec['offset']<=index<sec['offset']+sec['size']):
            count+=1
        index=data.find(needle,index+1)
    return count


def slot_call_census(data,fdes):
    text=next(s for s in sections(data) if s['name']=='.text')
    body=data[text['offset']:text['offset']+text['size']];base=text['address']
    def via_slot(op):
        out=[];index=body.find(op)
        while index!=-1:
            va=base+index
            if va+6+struct.unpack_from('<i',body,index+2)[0]==SLOT_WRITE:
                out.append(va)
            index=body.find(op,index+1)
        return out
    ff15=via_slot(b'\xff\x15');ff25=via_slot(b'\xff\x25')
    direct=[]
    for op in (b'\xe8',b'\xe9'):
        index=body.find(op)
        while index!=-1:
            va=base+index
            if va+5+struct.unpack_from('<i',body,index+1)[0]==WRITE:
                direct.append(va)
            index=body.find(op,index+1)
    loads=[]
    for prefix,size in ((b'\x48\x8b',7),(b'\x4c\x8b',7),(b'\x8b',6)):
        index=body.find(prefix)
        while index!=-1:
            va=base+index;modrm=body[index+len(prefix)]
            if size==6 and index>0 and body[index-1] in (0x48,0x4c):
                index=body.find(prefix,index+1);continue
            if modrm&0xc7==0x05 and va+size+struct.unpack_from('<i',body,index+len(prefix)+1)[0]==SLOT_WRITE:
                loads.append(va)
            index=body.find(prefix,index+1)
    loads.sort()
    def owner_of(va):
        for f in fdes:
            if f['start']<=va<f['end']:
                return (f['start'],f['end'])
        return None
    distinct=len({owner_of(s) for s in ff15})
    return ff15,ff25,direct,distinct,loads


def tagged_path(tagged):
    """The fourth argument is a tagged word: odd carries an inline length
    (tagged >> 1) for one literal write of the third argument; even is an
    arguments-block pointer and selects the template scan."""
    if tagged&1:
        return ('inline_length',tagged>>1)
    return ('scan',None)


def parse_tag(tag,payload):
    """Field grammar of a generic placeholder tag (any tag byte >= 0x81
    except the fast-path 0xc0). Payload bytes are consumed in a fixed
    order after the tag byte: bit 0 replaces the default spec with the
    little-endian u32 at the cursor; bit 1 reads field A as a u16; bit 2
    reads field B as a u16; bit 3 reads an explicit argument index as a
    u16. Bits 4 and 5 mark fields A and B indirect (the u16 read is an
    argument index whose record supplies the value). Bit 6 is never
    tested by the target."""
    spec=DEFAULT_SPEC;field_a=0;field_b=0;explicit=None;pos=0
    if tag&1:
        spec=struct.unpack_from('<I',payload,pos)[0];pos+=4
    if tag&2:
        field_a=struct.unpack_from('<H',payload,pos)[0];pos+=2
    if tag&4:
        field_b=struct.unpack_from('<H',payload,pos)[0];pos+=2
    if tag&8:
        explicit=struct.unpack_from('<H',payload,pos)[0];pos+=2
    return {'spec':spec,'field_a':field_a,'field_b':field_b,
            'explicit_index':explicit,'indirect_a':bool(tag&0x10),
            'indirect_b':bool(tag&0x20),'payload_len':pos}


def descriptor_block(spec,field_a,field_b):
    """The third word of the 24-byte descriptor handed to a formatter:
    the spec dword, then field A and field B as u16s."""
    return struct.pack('<IHH',spec,field_a,field_b)


def record_value(block,index):
    return struct.unpack_from('<Q',block,index*16)[0]


def record_formatter(block,index):
    return struct.unpack_from('<Q',block,index*16+8)[0]


def record_field(block,index):
    """The u16 read by the indirection bits: the low half of the record's
    formatter word at +0x8."""
    return struct.unpack_from('<H',block,index*16+8)[0]


def simulate_inline(data,tagged,write_literal):
    """Odd fourth argument: a single tail-called literal write of the
    third argument's first tagged>>1 bytes through the table method;
    its error byte is the function's result."""
    kind,length=tagged_path(tagged)
    if kind!='inline_length':
        raise ValueError('not an inline tagged word')
    return 1 if write_literal(data[:length]) else 0


def simulate_scan(template,args_block,write_literal,dispatch):
    """Even fourth argument: the template token walk. write_literal is
    called with each literal run's bytes, dispatch with (value word,
    8-byte descriptor block) per placeholder; either returning true
    (an error byte) stops the walk with result 1. Reaching the zero
    terminator returns 0. Models the pinned bytes, including the
    counter rule: after a dispatch the sequential index becomes the
    dispatched index plus one."""
    if not template:
        raise ValueError('empty template stream')
    if template[0]==0:
        return 0
    index=0;pos=0
    while True:
        b=template[pos]
        if b==0:
            return 0
        pos+=1
        if b<0x80:
            if write_literal(template[pos:pos+b]):
                return 1
            pos+=b
        elif b==0x80:
            n=struct.unpack_from('<H',template,pos)[0]
            if write_literal(template[pos+2:pos+2+n]):
                return 1
            pos+=2+n
        else:
            if b==0xc0:
                spec=DEFAULT_SPEC;field_a=0;field_b=0;used=index
            else:
                fields=parse_tag(b,template[pos:])
                pos+=fields['payload_len']
                spec=fields['spec'];field_a=fields['field_a'];field_b=fields['field_b']
                used=fields['explicit_index'] if fields['explicit_index'] is not None else index
                if fields['indirect_a']:
                    field_a=record_field(args_block,field_a)
                if fields['indirect_b']:
                    field_b=record_field(args_block,field_b)
            if dispatch(record_value(args_block,used),
                        descriptor_block(spec,field_a,field_b)):
                return 1
            index=used+1


def _pin(body,base,va,hexbytes,what):
    off=va-base;want=bytes.fromhex(hexbytes)
    if body[off:off+len(want)]!=want:
        raise ValueError(f'write target {what} changed')


def _rip(body,base,va,insn_len,disp_at):
    return va+insn_len+struct.unpack_from('<i',body,disp_at-base)[0]


def _rip8(body,base,va,insn_len,disp_at):
    return va+insn_len+struct.unpack_from('<b',body,disp_at-base)[0]


def write_target_trace(data):
    start,end,_=OWNERS['write_target']
    _,body=read(data,start,end-start)
    def pin(va,hx,what): _pin(body,start,va,hx,what)
    def rip(va,ln,at): return _rip(body,start,va,ln,at)
    def rip8(va,ln,at): return _rip8(body,start,va,ln,at)
    # Prologue and argument saves: rcx -> rbx, rdx -> r13, rdi -> r14.
    pin(0x1680500,'55','prologue')
    pin(0x1680501,'4889e5','frame')
    pin(0x168050d,'4883ec38','stack alloc')
    pin(0x1680511,'4889cb','arguments save')
    pin(0x1680514,'4989d5','template save')
    pin(0x1680517,'4989fe','out save')
    # Tag test on the fourth argument: odd -> inline length path.
    pin(0x168051a,'f6c301','tag test')
    pin(0x168051d,'0f85','tag branch opcode')
    if rip(0x168051d,6,0x168051d+2)!=0x168068b:
        raise ValueError('tag branch target changed')
    # Scan entry: first template byte, table save, writer cache, index zero.
    pin(0x1680523,'410fb64500','first byte load')
    pin(0x1680528,'84c0','first byte test')
    pin(0x168052a,'0f84','empty branch opcode')
    if rip(0x168052a,6,0x168052a+2)!=0x16806ab:
        raise ValueError('empty branch target changed')
    pin(0x1680530,'488975b0','table store')
    pin(0x1680534,'488b4e18','writer load')
    pin(0x1680538,'48894da8','writer cache')
    pin(0x168053c,'48c745d000000000','index zero')
    pin(0x1680544,'eb1a','scan enter')
    if rip8(0x1680544,2,0x1680544+1)!=0x1680560:
        raise ValueError('scan enter target changed')
    # Loop head: read token, zero ends the walk.
    pin(0x1680550,'410fb60424','token load')
    pin(0x1680555,'4d89e5','token cursor')
    pin(0x1680558,'84c0','token test')
    pin(0x168055a,'0f84','end branch opcode')
    if rip(0x168055a,6,0x168055a+2)!=0x16806ab:
        raise ValueError('end branch target changed')
    pin(0x1680560,'4d8d6501','payload cursor')
    pin(0x1680564,'440fb6f8','token copy')
    pin(0x1680568,'84c0','class test')
    pin(0x168056a,'7824','class branch')
    if rip8(0x168056a,2,0x168056a+1)!=0x1680590:
        raise ValueError('class branch target changed')
    # Literal run (b < 0x80): table method writes the payload.
    pin(0x168056c,'4c89f7','literal out')
    pin(0x168056f,'4c89e6','literal data')
    pin(0x1680572,'4c89fa','literal length')
    pin(0x1680575,'ff55a8','literal call')
    pin(0x1680578,'84c0','literal result test')
    pin(0x168057a,'0f85','literal error opcode')
    if rip(0x168057a,6,0x168057a+2)!=0x16806af:
        raise ValueError('literal error target changed')
    pin(0x1680580,'4d01fc','literal advance')
    pin(0x1680583,'ebcb','literal loop')
    if rip8(0x1680583,2,0x1680583+1)!=0x1680550:
        raise ValueError('literal loop target changed')
    # Tag classify: 0x80 is the wide run, 0xc0 the default placeholder.
    pin(0x1680590,'3c80','wide compare')
    pin(0x1680592,'7421','wide branch')
    if rip8(0x1680592,2,0x1680592+1)!=0x16805b5:
        raise ValueError('wide branch target changed')
    pin(0x1680594,'4181ffc0000000','default compare')
    pin(0x168059b,'753f','default branch')
    if rip8(0x168059b,2,0x168059b+1)!=0x16805dc:
        raise ValueError('default branch target changed')
    # Default placeholder (tag 0xc0): sequential index, default spec block.
    pin(0x168059d,'4c8b7dd0','default index load')
    pin(0x16805a1,'4c89f8','default index copy')
    pin(0x16805a4,'48c1e004','default index scale')
    pin(0x16805a8,'48c745c820000060','default spec store')
    pin(0x16805b0,'e9','default join opcode')
    if rip(0x16805b0,5,0x16805b0+1)!=0x1680652:
        raise ValueError('default join target changed')
    # Wide literal run (b == 0x80): u16 length follows the token.
    pin(0x16805b5,'450fb77d01','wide length load')
    pin(0x16805ba,'498d7503','wide data')
    pin(0x16805be,'4c89f7','wide out')
    pin(0x16805c1,'4c89fa','wide length arg')
    pin(0x16805c4,'ff55a8','wide call')
    pin(0x16805c7,'84c0','wide result test')
    pin(0x16805c9,'0f85','wide error opcode')
    if rip(0x16805c9,6,0x16805c9+2)!=0x16806af:
        raise ValueError('wide error target changed')
    pin(0x16805cf,'4f8d242f','wide advance')
    pin(0x16805d3,'4983c403','wide advance tail')
    pin(0x16805d7,'e9','wide loop opcode')
    if rip(0x16805d7,5,0x16805d7+1)!=0x1680550:
        raise ValueError('wide loop target changed')
    # Generic tag: spec, field A, field B, explicit index, in payload order.
    pin(0x16805dc,'b920000060','spec default')
    pin(0x16805e1,'a801','spec flag test')
    pin(0x16805e3,'740b','spec flag branch')
    if rip8(0x16805e3,2,0x16805e3+1)!=0x16805f0:
        raise ValueError('spec flag target changed')
    pin(0x16805e5,'418b4d01','spec load')
    pin(0x16805e9,'4983c505','spec advance')
    pin(0x16805ed,'4d89ec','spec cursor')
    pin(0x16805f0,'a802','field a flag test')
    pin(0x16805f2,'7519','field a flag branch')
    if rip8(0x16805f2,2,0x16805f2+1)!=0x168060d:
        raise ValueError('field a flag target changed')
    pin(0x16805f4,'31d2','field a zero')
    pin(0x16805f6,'4c8b7dd0','index load a')
    pin(0x16805fa,'a804','field b flag test')
    pin(0x16805fc,'7420','field b flag branch')
    if rip8(0x16805fc,2,0x16805fc+1)!=0x168061e:
        raise ValueError('field b flag target changed')
    pin(0x16805fe,'410fb73424','field b load')
    pin(0x1680603,'4983c402','field b advance')
    pin(0x1680607,'a808','index flag test')
    pin(0x1680609,'7519','index flag branch')
    if rip8(0x1680609,2,0x1680609+1)!=0x1680624:
        raise ValueError('index flag target changed')
    pin(0x168060b,'eb20','index skip')
    if rip8(0x168060b,2,0x168060b+1)!=0x168062d:
        raise ValueError('index skip target changed')
    pin(0x168060d,'410fb71424','field a load')
    pin(0x1680612,'4983c402','field a advance')
    pin(0x1680616,'4c8b7dd0','index load b')
    pin(0x168061a,'a804','field b flag test 2')
    pin(0x168061c,'75e0','field b flag branch 2')
    if rip8(0x168061c,2,0x168061c+1)!=0x16805fe:
        raise ValueError('field b flag 2 target changed')
    pin(0x168061e,'31f6','field b zero')
    pin(0x1680620,'a808','index flag test 2')
    pin(0x1680622,'7409','index flag branch 2')
    if rip8(0x1680622,2,0x1680622+1)!=0x168062d:
        raise ValueError('index flag 2 target changed')
    pin(0x1680624,'450fb73c24','explicit index load')
    pin(0x1680629,'4983c402','explicit index advance')
    # Indirection bits: 4 replaces field A, 5 replaces field B, each with
    # the u16 at arguments[field * 16 + 8].
    pin(0x168062d,'a810','indirect a flag test')
    pin(0x168062f,'7549','indirect a flag branch')
    if rip8(0x168062f,2,0x168062f+1)!=0x168067a:
        raise ValueError('indirect a flag target changed')
    pin(0x1680631,'a820','indirect b flag test')
    pin(0x1680633,'740b','indirect b flag branch')
    if rip8(0x1680633,2,0x1680633+1)!=0x1680640:
        raise ValueError('indirect b flag target changed')
    pin(0x1680635,'0fb7c6','indirect b index')
    pin(0x1680638,'c1e004','indirect b scale')
    pin(0x168063b,'0fb7740308','indirect b load')
    pin(0x168067a,'0fb7d2','indirect a index')
    pin(0x168067d,'c1e204','indirect a scale')
    pin(0x1680680,'0fb7541308','indirect a load')
    pin(0x1680685,'a820','indirect b flag test 3')
    pin(0x1680687,'75ac','indirect b flag branch 3')
    if rip8(0x1680687,2,0x1680687+1)!=0x1680635:
        raise ValueError('indirect b flag 3 target changed')
    pin(0x1680689,'ebb5','indirect join')
    if rip8(0x1680689,2,0x1680689+1)!=0x1680640:
        raise ValueError('indirect join target changed')
    # Descriptor stores and the dispatch through the record's +0x8 word.
    pin(0x1680640,'4c89f8','dispatch index copy')
    pin(0x1680643,'48c1e004','dispatch index scale')
    pin(0x1680647,'894dc8','spec store')
    pin(0x168064a,'668955cc','field a store')
    pin(0x168064e,'668975ce','field b store')
    pin(0x1680652,'4c8975b8','descriptor out store')
    pin(0x1680656,'488b4db0','descriptor table load')
    pin(0x168065a,'48894dc0','descriptor table store')
    pin(0x168065e,'488b3c03','value load')
    pin(0x1680662,'488d75b8','descriptor lea')
    pin(0x1680666,'ff540308','dispatch call')
    pin(0x168066a,'84c0','dispatch result test')
    pin(0x168066c,'7541','dispatch error branch')
    if rip8(0x168066c,2,0x168066c+1)!=0x16806af:
        raise ValueError('dispatch error target changed')
    pin(0x168066e,'49ffc7','counter increment')
    pin(0x1680671,'4c897dd0','counter store')
    pin(0x1680675,'e9','dispatch loop opcode')
    if rip(0x1680675,5,0x1680675+1)!=0x1680550:
        raise ValueError('dispatch loop target changed')
    # Inline path: length = tagged >> 1, tail call through table + 0x18.
    pin(0x168068b,'48d1eb','inline shift')
    pin(0x168068e,'488b4618','inline writer load')
    pin(0x1680692,'4c89f7','inline out')
    pin(0x1680695,'4c89ee','inline data')
    pin(0x1680698,'4889da','inline length')
    pin(0x16806a9,'ffe0','inline tail jump')
    # Exits: success zeroes EAX, error sets AL to 1.
    pin(0x16806ab,'31c0','success zero')
    pin(0x16806ad,'eb02','success join')
    if rip8(0x16806ad,2,0x16806ad+1)!=0x16806b1:
        raise ValueError('success join target changed')
    pin(0x16806af,'b001','error one')
    pin(0x16806bf,'c3','return')
    return {'arguments':{'out':'rdi','table':'rsi','template':'rdx','tagged':'rcx'},
            'saves':{'arguments':'0x1680511','template':'0x1680514','out':'0x1680517'},
            'tag_test':{'test':'0x168051a','branch':'0x168051d','inline_path':'0x168068b'},
            'scan_entry':{'first_byte_load':'0x1680523','first_byte_test':'0x1680528',
                          'empty_branch':'0x168052a','table_store':'0x1680530',
                          'writer_load':'0x1680534','writer_cache':'0x1680538',
                          'index_zero':'0x168053c','enter':'0x1680544'},
            'loop_head':{'token_load':'0x1680550','token_cursor':'0x1680555',
                         'end_branch':'0x168055a','payload_cursor':'0x1680560',
                         'class_branch':'0x168056a','tag_classify':'0x1680590'},
            'literal_run':{'out':'0x168056c','data':'0x168056f','length':'0x1680572',
                           'call':'0x1680575','error_branch':'0x168057a','advance':'0x1680580'},
            'wide_run':{'compare':'0x1680590','branch':'0x1680592','length_load':'0x16805b5',
                        'data':'0x16805ba','call':'0x16805c4','error_branch':'0x16805c9',
                        'advance':'0x16805cf'},
            'default_tag':{'compare':'0x1680594','branch':'0x168059b','index_load':'0x168059d',
                           'spec_store':'0x16805a8','join':'0x16805b0','value':'0xc0'},
            'generic_tag':{'spec':{'default':'0x16805dc','flag_test':'0x16805e1','load':'0x16805e5'},
                           'field_a':{'flag_test':'0x16805f0','zero':'0x16805f4','load':'0x168060d'},
                           'field_b':{'flag_test':'0x16805fa','load':'0x16805fe','zero':'0x168061e'},
                           'explicit_index':{'flag_test':'0x1680607','load':'0x1680624'},
                           'indirect_a':{'flag_test':'0x168062d','load':'0x1680680'},
                           'indirect_b':{'flag_test':'0x1680631','load':'0x168063b'}},
            'first_arguments_reads':{'indirect_b_load':'0x168063b','value_load':'0x168065e',
                                     'dispatch_call':'0x1680666','indirect_a_load':'0x1680680'},
            'dispatch':{'index_scale':'0x1680643','spec_store':'0x1680647',
                        'field_a_store':'0x168064a','field_b_store':'0x168064e',
                        'descriptor_out_store':'0x1680652','descriptor_table_store':'0x168065a',
                        'value_load':'0x168065e','descriptor_lea':'0x1680662','call':'0x1680666',
                        'error_branch':'0x168066c','counter_increment':'0x168066e',
                        'counter_store':'0x1680671'},
            'inline_path':{'shift':'0x168068b','writer_load':'0x168068e','out':'0x1680692',
                           'data':'0x1680695','length':'0x1680698','tail_jump':'0x16806a9'},
            'exits':{'success':'0x16806ab','error':'0x16806af','return':'0x16806bf'},
            'descriptor':{'words':['out','table','spec block'],
                          'spec_block':['spec dword','field a u16','field b u16']},
            'record':{'bytes':16,'value_offset':0,'formatter_offset':8}}


def analyze(data):
    _,fs,_=fde_extents(data);fdes={(f['start'],f['end']):f for f in fs}
    by_offset,target_hits=relocations(data)
    if target_hits!=[SLOT_WRITE]:
        raise ValueError('write target relocation reference changed')
    bindings=slot_bindings(data)
    methods=table_methods(data)
    if address_as_data_count(data)!=0:
        raise ValueError('write target address-as-data reference appeared')
    ff15,ff25,direct,distinct,loads=slot_call_census(data,fs)
    if direct:
        raise ValueError('direct call census changed')
    if (len(ff15),len(ff25),distinct)!=EXPECTED_CENSUS or loads!=EXPECTED_LOADS:
        raise ValueError('slot call census changed')
    if CHAIN_CALL_SITE not in ff15 or CHAIN_JUMP_SITE not in ff25:
        raise ValueError('chain call census changed')
    owners=[]
    for role,(a,b,sha) in OWNERS.items():
        if (a,b) not in fdes:
            raise ValueError('write scope FDE changed')
        offset,raw=read(data,a,b-a)
        if hashlib.sha256(raw).hexdigest()!=sha:
            raise ValueError(f'{role} body changed')
        records={}
        for kind in ['fde','cie']:
            va=fdes[(a,b)][kind];n=struct.unpack('<I',read(data,va,4)[1])[0]+4
            records[kind]={'va':hex(va),'bytes_hex':read(data,va,n)[1].hex()}
        owners.append({'role':role,'start':hex(a),'end':hex(b),'file_offset':hex(offset),'bytes':b-a,'sha256':sha,'frames':records})
    return {'target_sha256':SHA,'owners':owners,
            'write_target':write_target_trace(data),
            'slot_bindings':bindings,
            'table_methods':methods,
            'call_census':{'direct':0,'via_slot_ff15':len(ff15),
                           'via_slot_ff25':[hex(s) for s in ff25],
                           'via_slot_loads':[hex(s) for s in loads],
                           'distinct_fdes_ff15':distinct,
                           'chain_call_site':hex(CHAIN_CALL_SITE),
                           'chain_jump_site':hex(CHAIN_JUMP_SITE),
                           'relocation_references':[hex(s) for s in target_hits],
                           'address_as_data':0},
            'tag_model':{'rule':'bit 0 of the fourth argument selects the inline path; on the scan '
                                'path a template byte below 0x80 is a literal run of that length, '
                                '0x80 is a u16-length literal run, any other byte >= 0x81 is a '
                                'placeholder tag: 0xc0 dispatches the sequential record with the '
                                'default spec block, other tags read spec (bit 0), field A (bit 1), '
                                'field B (bit 2) and an explicit index (bit 3) from the payload in '
                                'that order, and bits 4/5 replace fields A/B with the u16 at '
                                'arguments[field * 16 + 8]',
                          'descriptor_rule':'each dispatch builds a 24-byte descriptor '
                                            '{out, table, spec dword, field A u16, field B u16} and '
                                            'calls the record formatter word at +0x8 with the '
                                            'record value word at +0x0 as its first argument',
                          'counter_rule':'after a successful dispatch the sequential index '
                                         'becomes the dispatched index plus one',
                          'return_rule':'AL is 0 iff the walk reaches the template terminator '
                                        'with no callee error; any literal write or dispatch '
                                        'error returns AL 1; the inline path returns the table '
                                        "method's AL unchanged"},
            'flag_group_verdict':'The write target is the first reader of the arguments block: '
                                 'inside a placeholder dispatch it loads the selected record '
                                 'value word (0x168065e) and calls through the record formatter '
                                 'word (0x1680666); the indirection bits read the u16 at a '
                                 'record +0x8 first (0x1680680 / 0x168063b). For both RE-015 '
                                 'chain calls the templates open with tag 0xc0, so record 0 is '
                                 'dispatched with the default spec block: on chain call 1 that '
                                 'value word is the flag-group pointer, which reaches its '
                                 'formatter as a value, still not dereferenced by this function.',
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
                raise ValueError('native write FDE disagreement')
            lines.extend(rows)
            asm=subprocess.check_output(['objdump','-d','-M','intel','--insn-width=16',f'--start-address={a:#x}',f'--stop-address={b:#x}',str(snapshot)],text=True)
            ins=decode_export(asm,a,b,read(data,a,b-a)[1])
            required=[0x1680500,0x1680511,0x1680514,0x1680517,0x168051a,0x168051d,0x1680523,
                      0x168052a,0x1680530,0x1680534,0x168053c,0x1680550,0x168055a,0x1680560,
                      0x168056a,0x1680575,0x168057a,0x1680590,0x1680592,0x1680594,0x168059b,
                      0x168059d,0x16805a8,0x16805b5,0x16805c4,0x16805dc,0x16805e5,0x16805fe,
                      0x168060d,0x1680624,0x168062d,0x168063b,0x1680647,0x168065e,0x1680662,
                      0x1680666,0x168066c,0x168066e,0x1680680,0x168068b,0x168068e,0x16806a9,
                      0x16806ab,0x16806af]
            if not set(required)<=set(ins):
                raise ValueError('write evidence site not native instruction start')
            (output/'write_target.objdump.txt').write_bytes(asm.replace(str(snapshot),'<authenticated-node115>').encode('utf-8'))
    (output/'frames.txt').write_bytes(('\n'.join(lines)+'\n').encode('utf-8'))
    (output/'records.json').write_bytes((json.dumps(report,indent=2)+'\n').encode('utf-8'))
    return report


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary',type=Path,default=TARGET)
    p.add_argument('--output',type=Path,default=ROOT/'work/flag-group-write115')
    args=p.parse_args();report=generate(args.binary,args.output)
    print(json.dumps({'functions':len(report['owners']),'bytes':sum(x['bytes'] for x in report['owners']),'executed':False}))
