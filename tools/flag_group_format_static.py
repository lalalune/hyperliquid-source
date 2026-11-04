#!/usr/bin/env python3
"""RE-015: digest-bound node115 format consumer 0x141e3a0 of the flag-group pointer."""
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
PACKET=ROOT/'research/work-items/RE-015-node115-flag-group-format'
SHA='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
OWNERS={
 'format_consumer':(0x141e3a0,0x141e538,'aa4d4d0611c533e38c65e1577c0426b5163846c01225556743d4d4345cadd1fe')}
CONSUMER=0x141e3a0
SLOT_SELF=0x64df6e8
SLOT_WRITE=0x64df6f0
WRITE_TARGET=0x1680500
SLOT_ALLOC=0x64df480
ALLOC_TARGET=0x6355830
SLOT_ERR=0x64df498
ERR_TARGET=0x141e264
SLOT_PANIC=0x64df6a0
PANIC_TARGET=0x1680c30
SLOT_DEALLOC=0x64df4a0
DEALLOC_TARGET=0x635de30
VTABLE=0x63f3d50
VTABLE_WORDS=[0x141c960,0x18,0x8,0x141e8f0,0x141e7e0,0x141ed80]
PANIC_MSG=0x456d84
PANIC_MSG_LEN=86
PANIC_MSG_SHA='3238c68f5d7ffb50295fcd66860d1d6e70ed9066ee6aa0b0a4268c173613ad8d'
PANIC_LOC=0x63f3ca0
PANIC_FILE=0x63f3d80
UNWIND_RESUME=0x63f0a50
TEMPLATES=[0x43b857,0x440e47,0x43b859]
EXPECTED_TEMPLATES={0x43b857:(2,0,True,0),0x440e47:(8,2,True,0),0x43b859:(49,44,False,88)}
EXPECTED_CENSUS=(840,3,586)
CHAIN_SITES=[0x15ae476,0x15ae4f5]
LIMITS=('Format consumer 0x141e3a0 only: the tagged third argument (odd is an inline length, '
 'even is an arguments-block pointer that is never dereferenced here), the template literal-length '
 'scan over the second argument, the initial-capacity rule, the allocation and dangling cases, '
 'the virtual write call that receives the third argument verbatim, the panic and cleanup paths, '
 'and the slot call census. What the write target 0x1680500 computes with the arguments pointer, '
 'what the rendered arguments mean, and the behaviour of the other 586 FDEs that call through '
 'the same slot are NOT established by these bytes. The flag-group pair construction is owned by '
 'the RE-015 derived-byte-callee packet and is cited here, not re-derived. '
 'No captured code executed, no runtime value, indirect-call recovery, #94 correspondence, '
 'or reconstruction gate is claimed.')


def read(data,va,n):
    matches=[s for s in sections(data) if s['type']!=8 and s['address']<=va and va+n<=s['address']+s['size']]
    if len(matches)!=1:
        raise ValueError('expected one file-backed mapping')
    s=matches[0];o=s['offset']+va-s['address']
    return o,bytes(data[o:o+n])


def relocations(data):
    sec = next((s for s in sections(data) if s['name'] == '.rela.dyn'), None)
    if sec is None:
        raise ValueError('missing.rela.dyn section')
    if sec['size'] % 24 != 0:
        raise ValueError('truncated.rela.dyn section')
    by_offset = {}
    target_hits = []
    for a, i, v in struct.iter_unpack('<QQq', data[sec['offset']:sec['offset'] + sec['size']]):
        by_offset.setdefault(a,[]).append((i,v))
        if v==CONSUMER:
            target_hits.append(a)
    return by_offset,target_hits


def slot_bindings(data):
    by_offset,_=relocations(data)
    expected={SLOT_SELF:CONSUMER,SLOT_WRITE:WRITE_TARGET,SLOT_ALLOC:ALLOC_TARGET,
              SLOT_ERR:ERR_TARGET,SLOT_PANIC:PANIC_TARGET,SLOT_DEALLOC:DEALLOC_TARGET}
    out={}
    for slot,target in expected.items():
        if by_offset.get(slot)!=[(8,target)]:
            raise ValueError('slot binding changed')
        out[hex(slot)]=hex(target)
    return out


def vtable_words(data):
    by_offset,_=relocations(data)
    words=[]
    for i in range(6):
        va=VTABLE+8*i
        if by_offset.get(va):
            if len(by_offset[va])!=1 or by_offset[va][0][0]!=8:
                raise ValueError('vtable changed')
            words.append(by_offset[va][0][1])
        else:
            words.append(struct.unpack('<Q',read(data,va,8)[1])[0])
    if words!=VTABLE_WORDS:
        raise ValueError('vtable changed')
    return [hex(w) for w in words]


def scan_template(stream):
    """Model of the consumer's template walk: returns (literal_len,
    placeholder_at_zero, consumed). Token kinds: 0x00 ends the stream;
    b < 0x80 is a literal run of b bytes; 0x80 is a literal run whose
    length is the following little-endian u16; any other b >= 0x81 is a
    placeholder tag that adds nothing, sets the flag iff the literal
    length so far is zero, and skips ((b&1)<<2)|(b&2) plus 2 per set
    bit among b&4 and b&8."""
    if not stream or stream[0]==0:
        return (0,False,1)
    literal=0;flag=False;i=0
    while True:
        b=stream[i]
        if b==0:
            return (literal,flag,i+1)
        i+=1
        if b<0x80:
            literal+=b;i+=b
        elif b==0x80:
            n=struct.unpack_from('<H',stream,i)[0]
            literal+=n;i+=n+2
        else:
            if literal==0:
                flag=True
            i+=((b&1)<<2)|(b&2)
            if b&4:i+=2
            if b&8:i+=2


def scan_capacity(literal,flag):
    """Initial capacity on the scan path: zero when a placeholder tag was
    seen at literal length zero and the literal length is below 16,
    otherwise twice the literal length; a literal length at or above
    2**63 takes the reserve-error path instead (None)."""
    if flag and literal<16:
        return 0
    if literal>=2**63:
        return None
    return 2*literal


def rdx_path(rdx):
    """The third argument is a tagged word: odd carries an inline length
    (rdx >> 1, used as the capacity verbatim); even is an arguments-block
    pointer and selects the template scan."""
    if rdx&1:
        return ('inline_length',rdx>>1)
    return ('scan',None)


def address_as_data_count(data):
    sec = next((s for s in sections(data) if s['name'] == '.rela.dyn'), None)
    if sec is None:
        raise ValueError('missing.rela.dyn section')
    needle=struct.pack('<Q',CONSUMER);count=0;index=data.find(needle)
    while index!=-1:
        if not (sec['offset']<=index<sec['offset']+sec['size']):
            count+=1
        index=data.find(needle,index+1)
    return count


def slot_call_census(data,fdes):
    text = next((s for s in sections(data) if s['name'] == '.text'), None)
    if text is None:
        raise ValueError('missing.text section')
    body=data[text['offset']:text['offset']+text['size']];base=text['address']
    ff15=[];index=body.find(b'\xff\x15')
    while index!=-1:
        va=base+index
        if va+6+struct.unpack_from('<i',body,index+2)[0]==SLOT_SELF:
            ff15.append(va)
        index=body.find(b'\xff\x15',index+1)
    ff25=[];index=body.find(b'\xff\x25')
    while index!=-1:
        va=base+index
        if va+6+struct.unpack_from('<i',body,index+2)[0]==SLOT_SELF:
            ff25.append(va)
        index=body.find(b'\xff\x25',index+1)
    direct=[];index=body.find(b'\xe8')
    while index!=-1:
        va=base+index
        if va+5+struct.unpack_from('<i',body,index+1)[0]==CONSUMER:
            direct.append(va)
        index=body.find(b'\xe8',index+1)
    def owner_of(va):
        for f in fdes:
            if f['start']<=va<f['end']:
                return (f['start'],f['end'])
        return None
    distinct=len({owner_of(s) for s in ff15})
    chain=[s for s in ff15 if s in CHAIN_SITES]
    return ff15,ff25,direct,distinct,chain


def _pin(body,base,va,hexbytes,what):
    off=va-base;want=bytes.fromhex(hexbytes)
    if body[off:off+len(want)]!=want:
        raise ValueError(f'format consumer {what} changed')


def _rip(body,base,va,insn_len,disp_at):
    return va+insn_len+struct.unpack_from('<i',body,disp_at-base)[0]


def _rip8(body,base,va,insn_len,disp_at):
    return va+insn_len+struct.unpack_from('<b',body,disp_at-base)[0]


def consumer_trace(data):
    start,end,_=OWNERS['format_consumer']
    _,body=read(data,start,end-start)
    def pin(va,hx,what): _pin(body,start,va,hx,what)
    def rip(va,ln,at): return _rip(body,start,va,ln,at)
    def rip8(va,ln,at): return _rip8(body,start,va,ln,at)
    # Prologue and argument saves: rdx -> r14, rsi -> r15, rdi -> rbx.
    pin(0x141e3a0,'55','prologue')
    pin(0x141e3a1,'4889e5','frame')
    pin(0x141e3af,'4989d6','tagged save')
    pin(0x141e3b2,'4989f7','template save')
    pin(0x141e3b5,'4889fb','out save')
    # Tag test on the third argument: odd -> inline length path.
    pin(0x141e3b8,'41f6c601','tag test')
    pin(0x141e3bc,'0f85','tag branch opcode')
    if rip(0x141e3bc,6,0x141e3bc+2)!=0x141e453:
        raise ValueError('tag branch target changed')
    pin(0x141e453,'4d89f4','odd copy')
    pin(0x141e456,'49d1ec','odd shift')
    pin(0x141e459,'eb19','odd join')
    if rip8(0x141e459,2,0x141e459+1)!=0x141e474:
        raise ValueError('odd join target changed')
    # First template byte: zero -> empty path.
    pin(0x141e3c2,'410fb617','first byte load')
    pin(0x141e3c6,'84d2','first byte test')
    pin(0x141e3c8,'0f84','empty branch opcode')
    if rip(0x141e3c8,6,0x141e3c8+2)!=0x141e495:
        raise ValueError('empty branch target changed')
    pin(0x141e3ce,'31c0','flag zero')
    pin(0x141e3d0,'4c89f9','cursor init')
    pin(0x141e3d3,'4531e4','length zero')
    pin(0x141e3d6,'eb18','scan enter')
    if rip8(0x141e3d6,2,0x141e3d6+1)!=0x141e3f0:
        raise ValueError('scan enter target changed')
    # Scan loop head: read token, zero ends the walk.
    pin(0x141e3e9,'0fb611','token load')
    pin(0x141e3ec,'84d2','token test')
    pin(0x141e3ee,'746b','token end branch')
    if rip8(0x141e3ee,2,0x141e3ee+1)!=0x141e45b:
        raise ValueError('token end target changed')
    # Literal run (b < 0x80): add and skip b payload bytes.
    pin(0x141e3f0,'48ffc1','token consume')
    pin(0x141e3f3,'84d2','run classify test')
    pin(0x141e3f5,'79e9','run branch')
    if rip8(0x141e3f5,2,0x141e3f5+1)!=0x141e3e0:
        raise ValueError('run branch target changed')
    pin(0x141e3e0,'0fb6d2','run reload')
    pin(0x141e3e3,'4901d4','run length add')
    pin(0x141e3e6,'4801d1','run skip')
    # Wide literal run (b == 0x80): u16 length follows.
    pin(0x141e3f7,'89d6','wide copy')
    pin(0x141e3f9,'40f6de','wide neg')
    pin(0x141e3fc,'710f','wide branch')
    if rip8(0x141e3fc,2,0x141e3fc+1)!=0x141e40d:
        raise ValueError('wide branch target changed')
    pin(0x141e3fe,'0fb711','wide length load')
    pin(0x141e401,'4901d4','wide length add')
    pin(0x141e404,'4801d1','wide skip')
    pin(0x141e407,'4883c102','wide length skip')
    pin(0x141e40b,'ebdc','wide loop')
    if rip8(0x141e40b,2,0x141e40b+1)!=0x141e3e9:
        raise ValueError('wide loop target changed')
    # Placeholder tag (b >= 0x81): flag iff length still zero; skip from bits.
    pin(0x141e40d,'4d85e4','tag flag test')
    pin(0x141e410,'400f94c6','tag flag set')
    pin(0x141e414,'4008f0','tag flag or')
    for va,hx,what in [(0x141e417,'89d6','tag bits a'),(0x141e419,'40c0e607','tag bits b'),
                       (0x141e41d,'89d7','tag bits c'),(0x141e41f,'40c0e705','tag bits d'),
                       (0x141e423,'4080e740','tag bits e'),(0x141e427,'4008f7','tag bits f'),
                       (0x141e42a,'40c0ef05','tag bits g'),(0x141e42e,'400fb6f7','tag bits h'),
                       (0x141e432,'89d7','tag bits i'),(0x141e434,'40d0ef','tag bits j'),
                       (0x141e437,'4080e702','tag bits k'),(0x141e43b,'400fb6ff','tag bits l'),
                       (0x141e43f,'c0ea02','tag bits m'),(0x141e442,'80e202','tag bits n'),
                       (0x141e445,'0fb6d2','tag bits o')]:
        pin(va,hx,what)
    pin(0x141e448,'4801f9','tag skip a')
    pin(0x141e44b,'4801d1','tag skip b')
    pin(0x141e44e,'4801f1','tag skip c')
    pin(0x141e451,'eb96','tag loop')
    if rip8(0x141e451,2,0x141e451+1)!=0x141e3e9:
        raise ValueError('tag loop target changed')
    # Capacity rule: zero for placeholder-at-zero with literal < 16, else double.
    pin(0x141e45b,'4983fc10','capacity compare')
    pin(0x141e45f,'0f92c1','capacity setb')
    pin(0x141e462,'84c8','capacity test')
    pin(0x141e464,'7405','capacity branch')
    if rip8(0x141e464,2,0x141e464+1)!=0x141e46b:
        raise ValueError('capacity branch target changed')
    pin(0x141e466,'4531e4','capacity zero')
    pin(0x141e469,'eb09','capacity zero join')
    if rip8(0x141e469,2,0x141e469+1)!=0x141e474:
        raise ValueError('capacity zero join target changed')
    pin(0x141e46b,'4d01e4','capacity double')
    pin(0x141e46e,'0f88','capacity overflow opcode')
    if rip(0x141e46e,6,0x141e46e+2)!=0x141e50d:
        raise ValueError('capacity overflow target changed')
    # Allocation: zero capacity -> dangling pointer word 1, no call.
    pin(0x141e474,'4d85e4','alloc zero test')
    pin(0x141e477,'741c','alloc zero branch')
    if rip8(0x141e477,2,0x141e477+1)!=0x141e495:
        raise ValueError('alloc zero target changed')
    pin(0x141e479,'4c89e7','alloc arg')
    pin(0x141e47c,'ff15','alloc opcode')
    if rip(0x141e47c,6,0x141e47c+2)!=SLOT_ALLOC:
        raise ValueError('alloc slot changed')
    pin(0x141e482,'4885c0','alloc null test')
    pin(0x141e485,'7516','alloc null branch')
    if rip8(0x141e485,2,0x141e485+1)!=0x141e49d:
        raise ValueError('alloc null target changed')
    pin(0x141e487,'bf01000000','alloc fail kind')
    pin(0x141e48c,'4c89e6','alloc fail size')
    pin(0x141e48f,'ff15','alloc fail opcode')
    if rip(0x141e48f,6,0x141e48f+2)!=SLOT_ERR:
        raise ValueError('alloc fail slot changed')
    pin(0x141e495,'b801000000','empty pointer')
    pin(0x141e49a,'4531e4','empty capacity')
    # Output triple {capacity, pointer, 0} on the stack.
    pin(0x141e49d,'4c8965c0','triple capacity store')
    pin(0x141e4a1,'488945c8','triple pointer store')
    pin(0x141e4a5,'48c745d000000000','triple length store')
    # Virtual write: rdi=&triple, rsi=vtable, rdx=template, rcx=third argument verbatim.
    pin(0x141e4ad,'488d35','write vtable opcode')
    if rip(0x141e4ad,7,0x141e4ad+3)!=VTABLE:
        raise ValueError('write vtable changed')
    pin(0x141e4b4,'488d7dc0','write out lea')
    pin(0x141e4b8,'4c89fa','write template mov')
    pin(0x141e4bb,'4c89f1','write arguments mov')
    pin(0x141e4be,'ff15','write opcode')
    if rip(0x141e4be,6,0x141e4be+2)!=SLOT_WRITE:
        raise ValueError('write slot changed')
    pin(0x141e4c4,'84c0','write result test')
    pin(0x141e4c6,'751f','write error branch')
    if rip8(0x141e4c6,2,0x141e4c6+1)!=0x141e4e7:
        raise ValueError('write error target changed')
    # Success: the triple is copied to the out argument; return out.
    pin(0x141e4c8,'488b45d0','success third load')
    pin(0x141e4cc,'48894310','success third store')
    pin(0x141e4d0,'0f1045c0','success head load')
    pin(0x141e4d4,'0f1103','success head store')
    pin(0x141e4d7,'4889d8','success return')
    pin(0x141e4e6,'c3','success ret')
    # Panic path on a write error: fixed message, length 86, then ud2.
    pin(0x141e4e7,'488d3d','panic message opcode')
    if rip(0x141e4e7,7,0x141e4e7+3)!=PANIC_MSG:
        raise ValueError('panic message changed')
    pin(0x141e4ee,'488d0d','panic location opcode')
    if rip(0x141e4ee,7,0x141e4ee+3)!=PANIC_LOC:
        raise ValueError('panic location changed')
    pin(0x141e4f5,'4c8d05','panic file opcode')
    if rip(0x141e4f5,7,0x141e4f5+3)!=PANIC_FILE:
        raise ValueError('panic file changed')
    pin(0x141e4fc,'488d55df','panic stack lea')
    pin(0x141e500,'be56000000','panic length')
    pin(0x141e505,'ff15','panic opcode')
    if rip(0x141e505,6,0x141e505+2)!=SLOT_PANIC:
        raise ValueError('panic slot changed')
    pin(0x141e50b,'0f0b','panic trap')
    # Reserve-error path (capacity overflow): same error slot, kind 0.
    pin(0x141e50d,'31ff','reserve kind')
    pin(0x141e50f,'4c89e6','reserve size')
    pin(0x141e512,'ff15','reserve opcode')
    if rip(0x141e512,6,0x141e512+2)!=SLOT_ERR:
        raise ValueError('reserve slot changed')
    # Cleanup pad: drop the local triple if its first word is nonzero.
    pin(0x141e518,'4889c3','cleanup save')
    pin(0x141e51b,'488b75c0','cleanup word load')
    pin(0x141e51f,'4885f6','cleanup word test')
    pin(0x141e522,'740c','cleanup skip')
    if rip8(0x141e522,2,0x141e522+1)!=0x141e530:
        raise ValueError('cleanup skip target changed')
    pin(0x141e524,'488b7dc8','cleanup pointer load')
    pin(0x141e528,'31d2','cleanup zero')
    pin(0x141e52a,'ff15','cleanup opcode')
    if rip(0x141e52a,6,0x141e52a+2)!=SLOT_DEALLOC:
        raise ValueError('cleanup slot changed')
    pin(0x141e530,'4889df','resume arg')
    pin(0x141e533,'e8','resume opcode')
    if rip(0x141e533,5,0x141e533+1)!=UNWIND_RESUME:
        raise ValueError('resume target changed')
    return {'arguments':{'out':'rdi','template':'rsi','tagged':'rdx'},
            'saves':{'tagged':'0x141e3af','template':'0x141e3b2','out':'0x141e3b5'},
            'tag_test':{'test':'0x141e3b8','branch':'0x141e3bc','odd_path':'0x141e453',
                        'odd_shift':'0x141e456','odd_join':'0x141e459','even_fallthrough':'0x141e3c2'},
            'scan':{'first_byte':{'load':'0x141e3c2','test':'0x141e3c6','empty_branch':'0x141e3c8',
                                  'empty_path':'0x141e495'},
                    'init':{'flag_zero':'0x141e3ce','cursor':'0x141e3d0','length_zero':'0x141e3d3',
                            'enter':'0x141e3d6'},
                    'read':'0x141e3e9','end_test':'0x141e3ec','end_branch':'0x141e3ee','finish':'0x141e45b',
                    'run':{'consume':'0x141e3f0','classify_test':'0x141e3f3','branch':'0x141e3f5',
                           'reload':'0x141e3e0','length_add':'0x141e3e3','skip':'0x141e3e6'},
                    'wide_run':{'copy':'0x141e3f7','neg':'0x141e3f9','branch':'0x141e3fc',
                                'length_load':'0x141e3fe','length_add':'0x141e401','skip':'0x141e404',
                                'length_skip':'0x141e407','loop':'0x141e40b'},
                    'tag':{'flag_test':'0x141e40d','flag_set':'0x141e410','flag_or':'0x141e414',
                           'skip_adds':['0x141e448','0x141e44b','0x141e44e'],'loop':'0x141e451'}},
            'capacity':{'compare':'0x141e45b','setb':'0x141e45f','test':'0x141e462','branch':'0x141e464',
                        'zero':'0x141e466','zero_join':'0x141e469','double':'0x141e46b',
                        'overflow_branch':'0x141e46e','overflow_site':'0x141e50d'},
            'allocation':{'zero_test':'0x141e474','zero_branch':'0x141e477','arg':'0x141e479',
                          'call':'0x141e47c','slot':hex(SLOT_ALLOC),'null_test':'0x141e482',
                          'null_branch':'0x141e485','fail_kind':'0x141e487','fail_size':'0x141e48c',
                          'fail_call':'0x141e48f','fail_slot':hex(SLOT_ERR),
                          'empty_pointer':'0x141e495','empty_capacity':'0x141e49a'},
            'triple':{'capacity_store':'0x141e49d','pointer_store':'0x141e4a1','length_store':'0x141e4a5',
                      'words':['capacity','pointer','0']},
            'write_call':{'vtable_lea':'0x141e4ad','vtable':hex(VTABLE),'out_lea':'0x141e4b4',
                          'template_mov':'0x141e4b8','arguments_mov':'0x141e4bb','call':'0x141e4be',
                          'slot':hex(SLOT_WRITE),'result_test':'0x141e4c4','error_branch':'0x141e4c6'},
            'success_copy':{'third_load':'0x141e4c8','third_store':'0x141e4cc','head_load':'0x141e4d0',
                            'head_store':'0x141e4d4','return':'0x141e4d7'},
            'panic':{'message_lea':'0x141e4e7','message':hex(PANIC_MSG),'message_len':PANIC_MSG_LEN,
                     'location_lea':'0x141e4ee','location':hex(PANIC_LOC),'file_lea':'0x141e4f5',
                     'file':hex(PANIC_FILE),'stack_lea':'0x141e4fc','length_mov':'0x141e500',
                     'call':'0x141e505','slot':hex(SLOT_PANIC),'trap':'0x141e50b'},
            'reserve_error':{'kind':'0x141e50d','size':'0x141e50f','call':'0x141e512','slot':hex(SLOT_ERR)},
            'cleanup_pad':{'save':'0x141e518','word_load':'0x141e51b','word_test':'0x141e51f',
                           'skip':'0x141e522','pointer_load':'0x141e524','zero':'0x141e528',
                           'call':'0x141e52a','slot':hex(SLOT_DEALLOC),'resume_arg':'0x141e530',
                           'resume':'0x141e533','resume_target':hex(UNWIND_RESUME)}}


def template_records(data):
    out=[]
    for va in TEMPLATES:
        _,window=read(data,va,8192)
        literal,flag,consumed=scan_template(window)
        if (consumed,literal,flag,scan_capacity(literal,flag))!=EXPECTED_TEMPLATES[va]:
            raise ValueError('template decode changed')
        raw=window[:consumed]
        out.append({'va':hex(va),'bytes':consumed,'stream_hex':raw.hex(),
                    'sha256':hashlib.sha256(raw).hexdigest(),
                    'literal_len':literal,'placeholder_at_zero':flag,
                    'initial_capacity':scan_capacity(literal,flag)})
    return out


def analyze(data):
    _,fs,_=fde_extents(data);fdes={(f['start'],f['end']):f for f in fs}
    by_offset,target_hits=relocations(data)
    if target_hits!=[SLOT_SELF]:
        raise ValueError('consumer relocation reference changed')
    bindings=slot_bindings(data)
    words=vtable_words(data)
    if address_as_data_count(data)!=0:
        raise ValueError('consumer address-as-data reference appeared')
    ff15,ff25,direct,distinct,chain=slot_call_census(data,fs)
    if direct:
        raise ValueError('direct call census changed')
    if (len(ff15),len(ff25),distinct)!=EXPECTED_CENSUS:
        raise ValueError('slot call census changed')
    if chain!=CHAIN_SITES:
        raise ValueError('chain call census changed')
    msg=read(data,PANIC_MSG,PANIC_MSG_LEN)[1]
    if hashlib.sha256(msg).hexdigest()!=PANIC_MSG_SHA:
        raise ValueError('panic message changed')
    owners=[]
    for role,(a,b,sha) in OWNERS.items():
        if (a,b) not in fdes:
            raise ValueError('format scope FDE changed')
        offset,raw=read(data,a,b-a)
        if hashlib.sha256(raw).hexdigest()!=sha:
            raise ValueError(f'{role} body changed')
        records={}
        for kind in ['fde','cie']:
            va=fdes[(a,b)][kind];n=struct.unpack('<I',read(data,va,4)[1])[0]+4
            records[kind]={'va':hex(va),'bytes_hex':read(data,va,n)[1].hex()}
        owners.append({'role':role,'start':hex(a),'end':hex(b),'file_offset':hex(offset),'bytes':b-a,'sha256':sha,'frames':records})
    return {'target_sha256':SHA,'owners':owners,
            'consumer':consumer_trace(data),
            'vtable':{'va':hex(VTABLE),'words':words},
            'templates':template_records(data),
            'slot_bindings':bindings,
            'call_census':{'direct':0,'via_slot_ff15':len(ff15),'via_slot_ff25':[hex(s) for s in ff25],
                           'distinct_fdes_ff15':distinct,'chain_sites':[hex(s) for s in chain],
                           'chain_fde':'0x15ae430..0x15ae5ae',
                           'relocation_references':[hex(s) for s in target_hits],
                           'address_as_data':0},
            'scan_model':{'rule':'0x00 ends; b<0x80 literal run of b; 0x80 u16-length literal run; '
                                 'b>=0x81 placeholder tag, flag iff literal so far is zero, '
                                 'skip ((b&1)<<2)|(b&2) + 2*(b&4 set) + 2*(b&8 set)',
                          'capacity_rule':'zero if placeholder-at-zero and literal < 16, else 2*literal; '
                                          'literal >= 2**63 takes the reserve-error path',
                          'rdx_rule':'odd rdx is an inline length (rdx>>1) used verbatim as capacity; '
                                     'even rdx selects the scan and is forwarded verbatim to the write call'},
            'flag_group_verdict':'The consumer never dereferences the third argument: it tests bit 0, '
                                 'and on the even path forwards the word verbatim as the fourth argument '
                                 'of the write call. For both RE-015 chain calls the word is an aligned '
                                 'stack address (bit 0 clear), both templates put a placeholder tag before '
                                 'any literal, so both calls enter with initial capacity 0.',
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
                raise ValueError('native format FDE disagreement')
            lines.extend(rows)
            asm=subprocess.check_output(['objdump','-d','-M','intel','--insn-width=16',f'--start-address={a:#x}',f'--stop-address={b:#x}',str(snapshot)],text=True)
            ins=decode_export(asm,a,b,read(data,a,b-a)[1])
            required=[0x141e3a0,0x141e3af,0x141e3b2,0x141e3b5,0x141e3b8,0x141e3bc,0x141e3c2,
                      0x141e3c8,0x141e3ce,0x141e3e0,0x141e3e9,0x141e3ee,0x141e3f0,0x141e3f5,
                      0x141e3f9,0x141e3fc,0x141e3fe,0x141e40d,0x141e410,0x141e448,0x141e451,
                      0x141e45b,0x141e464,0x141e466,0x141e46b,0x141e46e,0x141e474,0x141e477,
                      0x141e47c,0x141e485,0x141e48f,0x141e495,0x141e49d,0x141e4ad,0x141e4b4,
                      0x141e4b8,0x141e4bb,0x141e4be,0x141e4c6,0x141e4c8,0x141e4e7,0x141e505,
                      0x141e50b,0x141e50d,0x141e512,0x141e51b,0x141e52a,0x141e533]
            if not set(required)<=set(ins):
                raise ValueError('consumer evidence site not native instruction start')
            (output/'format_consumer.objdump.txt').write_bytes(asm.replace(str(snapshot),'<authenticated-node115>').encode('utf-8'))
    (output/'frames.txt').write_bytes(('\n'.join(lines)+'\n').encode('utf-8'))
    (output/'records.json').write_bytes((json.dumps(report,indent=2)+'\n').encode('utf-8'))
    return report


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary',type=Path,default=TARGET)
    p.add_argument('--output',type=Path,default=ROOT/'work/flag-group-format115')
    args=p.parse_args();report=generate(args.binary,args.output)
    print(json.dumps({'functions':len(report['owners']),'bytes':sum(x['bytes'] for x in report['owners']),'executed':False}))
