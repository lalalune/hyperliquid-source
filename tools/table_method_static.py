#!/usr/bin/env python3
"""RE-015: digest-bound node115 descriptor table method 0x141e8f0 of the flag-group chain."""
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
PACKET=ROOT/'research/work-items/RE-015-node115-table-method'
SHA='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
OWNERS={
 'table_method':(0x141e8f0,0x141e951,'cca62c47ceefd6b3d4ae5288e6a18da83949305483fcd284be4e52b1c701f712')}
BOUNDARIES={
 'grow':(0x141c980,0x141c9f2,'0d7d86caca16b63ec8781e212843d490b18b5981ac4dac000e961a18466ee6a7'),
 'table_word0_function':(0x141c960,0x141c975,'eea4768c2b16bea6910e54a26dcd08e2d71bd752f0a15e5af7d7dba25ed1f99d')}
METHOD=0x141e8f0
GROW=0x141c980
# The chain's consumer descriptor table: a 32-byte block in
# .data.rel.ro. Two of its words are link-time constants held in the
# file (+0x8 = 0x18, +0x10 = 8); the other two are zero in the file
# and filled at load by R_X86_64_RELATIVE relocations whose addends
# are the word targets (+0x0 -> 0x141c960, +0x18 -> the method).
# Exactly one relocation slot in the whole binary carries the
# method as its addend.
TABLE=0x63f3d50
TABLE_SECTION='.data.rel.ro'
TABLE_WORDS=[
 {'offset':0,'file_value':0,'relocation':{'type':8,'addend':0x141c960}},
 {'offset':8,'file_value':0x18,'relocation':None},
 {'offset':0x10,'file_value':8,'relocation':None},
 {'offset':0x18,'file_value':0,'relocation':{'type':8,'addend':0x141e8f0}}]
METHOD_SLOT=0x63f3d68
# The copy is a call through a .got slot bound by an
# R_X86_64_GLOB_DAT relocation to the dynamic symbol memcpy.
MEMCPY_SLOT=0x64df508
MEMCPY_RELOCATION=(6,7)
MEMCPY_NAME='memcpy'
# The only rip-relative references to the table in .text are two
# lea sites (descriptor construction); nothing references the
# method or its slot address directly.
TABLE_LEA_SITES=[0x141e4ad,0x141ed86]
LEA_FDES={'0x141e4ad':[0x141e3a0,0x141e538],'0x141ed86':[0x141ed80,0x141ed93]}
LIMITS=('Descriptor table method 0x141e8f0 only: the capacity/length '
 'check against the out words (+0x0 capacity, +0x8 buffer pointer, '
 '+0x10 length), the verbatim byte copy through the .got memcpy '
 'slot (0x64df508), the single length store back to out +0x10, the '
 'always-zero return byte, and the slow path that saves the string '
 'pointer, calls the grow boundary (0x141c980) with (out, current '
 'length, requested length) and rejoins the copy without '
 're-checking capacity; plus the consumer table binding at '
 '0x63f3d50, whose +0x18 word is zero in the file and filled at '
 'load by the binary\'s only R_X86_64_RELATIVE relocation carrying '
 'the method as addend (slot 0x63f3d68). The grow callee\'s body, '
 'the table word +0x0 function (0x141c960), the two lea sites\' '
 'containing bodies, the out structure\'s construction and '
 'lifetime, and every other descriptor table\'s method are NOT '
 'traced: the grow is recorded as a boundary FDE with its call '
 'site and argument registers only, since it never receives the '
 'string pointer. No captured code executed, no runtime value, '
 'indirect-call recovery beyond the pinned table word, #94 '
 'correspondence, or reconstruction gate is claimed.')


def read(data,va,n):
    matches=[s for s in sections(data) if s['type']!=8 and s['address']<=va and va+n<=s['address']+s['size']]
    if len(matches)!=1:
        raise ValueError('expected one file-backed mapping')
    s=matches[0];o=s['offset']+va-s['address']
    return o,bytes(data[o:o+n])


def relocations(data):
    sec=next((s for s in sections(data) if s['name']=='.rela.dyn'),None)
    if sec is None:raise ValueError('missing.rela.dyn section')
    if sec['size']%24:raise ValueError('truncated.rela.dyn section')
    by_offset={}
    for a,i,v in struct.iter_unpack('<QQq',data[sec['offset']:sec['offset']+sec['size']]):
        by_offset.setdefault(a,[]).append((i&0xffffffff,i>>32,v))
    return by_offset


def dynsym_name(data,index):
    ds=next((s for s in sections(data) if s['name']=='.dynsym'),None)
    st=next((s for s in sections(data) if s['name']=='.dynstr'),None)
    if ds is None:raise ValueError('missing.dynsym section')
    if st is None:raise ValueError('missing.dynstr section')
    name_off=struct.unpack_from('<I',data,ds['offset']+24*index)[0]
    end=data.find(b'\0',st['offset']+name_off)
    try:return data[st['offset']+name_off:end].decode('ascii')
    except UnicodeDecodeError:raise ValueError('dynamic symbol name is not valid ASCII')


def table_binding(data):
    by_offset=relocations(data)
    words=[]
    for spec in TABLE_WORDS:
        slot=TABLE+spec['offset']
        _,raw=read(data,slot,8)
        file_value=struct.unpack('<Q',raw)[0]
        entries=by_offset.get(slot,[])
        if spec['relocation'] is None:
            if entries:
                raise ValueError('table binding changed')
            rel=None
        else:
            want=(spec['relocation']['type'],0,spec['relocation']['addend'])
            if entries!=[want]:
                raise ValueError('table binding changed')
            rel={'slot':hex(slot),'type':spec['relocation']['type'],
                 'type_name':'R_X86_64_RELATIVE',
                 'addend':hex(spec['relocation']['addend'])}
        if file_value!=spec['file_value']:
            raise ValueError('table word changed')
        words.append({'offset':spec['offset'],'file_value':file_value,
                      'relocation':rel})
    slots=sorted(a for a,entries in by_offset.items()
                 for (_,_,v) in entries if v==METHOD)
    if slots!=[METHOD_SLOT]:
        raise ValueError('table binding changed')
    section=next(s['name'] for s in sections(data)
                 if s['type']!=8 and s['address']<=TABLE<s['address']+s['size'])
    if section!=TABLE_SECTION:
        raise ValueError('table binding changed')
    return {'table':hex(TABLE),'section':section,'words':words,
            'method_slot':hex(METHOD_SLOT),
            'method_addend_slots':[hex(s) for s in slots]}


def memcpy_binding(data):
    by_offset=relocations(data)
    entries=by_offset.get(MEMCPY_SLOT,[])
    if len(entries)!=1 or entries[0][0]!=MEMCPY_RELOCATION[0] or \
       entries[0][1]!=MEMCPY_RELOCATION[1] or entries[0][2]!=0:
        raise ValueError('memcpy binding changed')
    if dynsym_name(data,MEMCPY_RELOCATION[1])!=MEMCPY_NAME:
        raise ValueError('memcpy binding changed')
    return {'slot':hex(MEMCPY_SLOT),'section':'.got',
            'relocation_type':MEMCPY_RELOCATION[0],
            'relocation_type_name':'R_X86_64_GLOB_DAT',
            'symbol_index':MEMCPY_RELOCATION[1],'symbol':MEMCPY_NAME}


def address_as_data_count(data,va):
    sec=next((s for s in sections(data) if s['name']=='.rela.dyn'),None)
    if sec is None:raise ValueError('missing.rela.dyn section')
    needle=struct.pack('<Q',va);count=0;index=data.find(needle)
    while index!=-1:
        if not (sec['offset']<=index<sec['offset']+sec['size']):
            count+=1
        index=data.find(needle,index+1)
    return count


def rip_refs(data,target):
    text=next((s for s in sections(data) if s['name']=='.text'),None)
    if text is None:raise ValueError('missing.text section')
    body=data[text['offset']:text['offset']+text['size']];base=text['address']
    refs=[]
    pats=[]
    for rex in range(0x40,0x50):
        for op in (0x8b,0x89,0x8d):
            pats.append((bytes([rex,op]),2,7))
    for op in (0x8b,0x89,0x8d):
        pats.append((bytes([op]),1,6))
    for pat,modrm_off,length in pats:
        index=body.find(pat)
        while index!=-1:
            va=base+index
            if length==6 and index>0 and 0x40<=body[index-1]<=0x4f:
                index=body.find(pat,index+1);continue
            if body[index+modrm_off]&0xc7==0x05 and \
               va+length+struct.unpack_from('<i',body,index+modrm_off+1)[0]==target:
                refs.append(va)
            index=body.find(pat,index+1)
    return sorted(set(refs))


def reference_census(data):
    text=next((s for s in sections(data) if s['name']=='.text'),None)
    if text is None:raise ValueError('missing.text section')
    body=data[text['offset']:text['offset']+text['size']];base=text['address']
    direct=[]
    for op in (b'\xe8',b'\xe9'):
        index=body.find(op)
        while index!=-1:
            va=base+index
            if va+5+struct.unpack_from('<i',body,index+1)[0]==METHOD:
                direct.append(va)
            index=body.find(op,index+1)
    return {'method_direct':sorted(direct),
            'method_rip_relative_refs':rip_refs(data,METHOD),
            'method_address_as_data':address_as_data_count(data,METHOD),
            'table_rip_relative_refs':rip_refs(data,TABLE),
            'method_slot_rip_relative_refs':rip_refs(data,METHOD_SLOT)}


def simulate_write(capacity,current_length,source_length,events=None):
    """The method's observable contract, modelling the pinned bytes.
    (out, string pointer, length) with the out words read as
    capacity (+0x0), buffer pointer (+0x8) and length (+0x10): when
    the requested length exceeds capacity - length, the grow
    boundary is called once with (current length, requested
    length) and the copy proceeds without a second check; a
    nonzero length is then copied verbatim to buffer + length, the
    stored length advances by the requested length, and the return
    byte is always 0. The grow's own capacity arithmetic is a
    boundary and is modelled only as the event, with the length
    unchanged across it (the method reloads the same length word
    after the call)."""
    length=current_length
    if source_length>capacity-length:
        if events is not None:
            events.append(('grow',length,source_length))
    copied=0
    if source_length!=0:
        if events is not None:
            events.append(('copy',length,source_length))
        copied=source_length
    return 0,length+source_length,copied


def _pin(body,base,va,hexbytes,what):
    off=va-base;want=bytes.fromhex(hexbytes)
    if body[off:off+len(want)]!=want:
        raise ValueError(f'method {what} changed')


def _branch8(body,base,va,insn_len):
    return va+insn_len+struct.unpack_from('<b',body,va-base+insn_len-1)[0]


def _call_target(body,base,va):
    return va+5+struct.unpack_from('<i',body,va-base+1)[0]


def _rip_target(body,base,va,insn_len,disp_at):
    return va+insn_len+struct.unpack_from('<i',body,disp_at-base)[0]


def method_trace(data):
    start,end,_=OWNERS['table_method']
    _,body=read(data,start,end-start)
    def pin(va,hx,what): _pin(body,start,va,hx,what)
    # Argument saves: the requested length and the out pointer are
    # held in callee-saved registers across the whole body.
    pin(0x141e8fb,'4889d3','length save')
    pin(0x141e8fe,'4989fe','out save')
    # Out header reads: capacity at +0x0, length at +0x10; the
    # remaining space is capacity - length.
    pin(0x141e901,'488b07','capacity load')
    pin(0x141e904,'4c8b7f10','length load')
    pin(0x141e908,'4c29f8','remaining subtraction')
    pin(0x141e90b,'4839c2','capacity compare')
    pin(0x141e90e,'7727','grow branch')
    if _branch8(body,start,0x141e90e,2)!=0x141e937:
        raise ValueError('method grow branch changed')
    # A zero-length request skips the copy but still stores the
    # (unchanged) length and returns 0.
    pin(0x141e910,'4885db','zero length test')
    pin(0x141e913,'7410','copy skip branch')
    if _branch8(body,start,0x141e913,2)!=0x141e925:
        raise ValueError('method copy skip branch changed')
    # The copy: destination is the buffer word (+0x8) plus the
    # current length; the string pointer argument is never
    # rewritten on this path, so memcpy receives it verbatim.
    pin(0x141e915,'498b7e08','buffer load')
    pin(0x141e919,'4c01ff','destination add')
    pin(0x141e91c,'4889da','copy count move')
    pin(0x141e91f,'ff15e30b0c05','memcpy slot call')
    if _rip_target(body,start,0x141e91f,6,0x141e91f+2)!=MEMCPY_SLOT:
        raise ValueError('method memcpy slot changed')
    # The body's only store to the out structure: the advanced
    # length back to +0x10. The return byte is always 0.
    pin(0x141e925,'4901df','length advance')
    pin(0x141e928,'4d897e10','length store')
    pin(0x141e92c,'31c0','return zero')
    pin(0x141e936,'c3','return')
    # Slow path: the string pointer is saved across the grow call
    # (which receives out, the current length and the requested
    # length, never the string pointer), restored afterwards, the
    # length word reloaded, and the copy rejoined with no second
    # capacity check.
    pin(0x141e937,'4c89f7','grow out argument')
    pin(0x141e93a,'4989f4','string save')
    pin(0x141e93d,'4c89fe','grow length argument')
    pin(0x141e940,'4889da','grow request argument')
    pin(0x141e943,'e838e0ffff','grow call')
    if _call_target(body,start,0x141e943)!=GROW:
        raise ValueError('method grow call changed')
    pin(0x141e948,'4c89e6','string restore')
    pin(0x141e94b,'4d8b7e10','length reload')
    pin(0x141e94f,'ebc4','copy rejoin jump')
    if _branch8(body,start,0x141e94f,2)!=0x141e915:
        raise ValueError('method copy rejoin changed')
    return {'arguments':{'out':'rdi','string':'rsi','length':'rdx'},
            'out_layout':{'capacity':'+0x0','buffer_pointer':'+0x8',
                          'length':'+0x10'},
            'capacity_load':{'site':'0x141e901','reads':'out +0x0'},
            'length_load':{'site':'0x141e904','reads':'out +0x10'},
            'remaining':{'site':'0x141e908',
                         'computes':'capacity - length',
                         'compare':'0x141e90b',
                         'branch':'0x141e90e',
                         'branch_target':'0x141e937',
                         'taken_when':'requested length > remaining'},
            'zero_length':{'test':'0x141e910','branch':'0x141e913',
                           'skips_to':'0x141e925'},
            'copy':{'buffer_load':'0x141e915',
                    'destination':'buffer pointer + current length',
                    'destination_add':'0x141e919',
                    'count_move':'0x141e91c',
                    'call':'0x141e91f',
                    'form':'call qword ptr [rip + disp32] through the .got slot',
                    'slot':hex(MEMCPY_SLOT),
                    'arguments':{'rdi':'buffer pointer + current length',
                                 'rsi':'the string pointer argument, verbatim',
                                 'rdx':'the requested length'}},
            'length_store':{'site':'0x141e928',
                            'stores':'advanced length to out +0x10',
                            'only_store_to_out':True},
            'return':{'site':'0x141e92c','value':0,
                      'form':'xor eax, eax; the byte in AL is the result'},
            'slow_path':{'entry':'0x141e937',
                         'string_save':'0x141e93a',
                         'string_restore':'0x141e948',
                         'grow_call':'0x141e943',
                         'grow_target':hex(GROW),
                         'grow_arguments':{'rdi':'out',
                                           'rsi':'current length',
                                           'rdx':'requested length'},
                         'length_reload':'0x141e94b',
                         'rejoin':'0x141e94f',
                         'rejoin_target':'0x141e915',
                         'capacity_rechecked':False}}


def analyze(data):
    binding=table_binding(data)
    memcpy=memcpy_binding(data)
    census=reference_census(data)
    if census['method_direct'] or census['method_rip_relative_refs'] or \
       census['method_address_as_data']!=0 or \
       census['table_rip_relative_refs']!=TABLE_LEA_SITES or \
       census['method_slot_rip_relative_refs']:
        raise ValueError('reference census changed')
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
            'method':method_trace(data),
            'table_binding':binding,
            'memcpy_binding':memcpy,
            'reference_census':{'method_direct':0,
                                'method_rip_relative_refs':[],
                                'method_address_as_data':0,
                                'table_rip_relative_refs':[hex(s) for s in census['table_rip_relative_refs']],
                                'table_lea_fdes':LEA_FDES,
                                'method_slot_rip_relative_refs':[]},
            'boundaries':boundaries,
            'chain_verdict':'The descriptor table method at +0x18 for '
                            'the chain\'s consumer table (0x63f3d50) is '
                            '0x141e8f0, a byte-append writer over a '
                            '24-byte out header (capacity at +0x0, '
                            'buffer pointer at +0x8, length at +0x10). '
                            'Given (out, string pointer, length), it '
                            'copies the bytes verbatim to buffer + '
                            'length through the .got memcpy slot when '
                            'they fit in capacity - length, first '
                            'calling the grow boundary (out, current '
                            'length, requested length) when they do '
                            'not, and in both cases stores the advanced '
                            'length to out +0x10 and returns 0. The '
                            'pointer formatter\'s tail-called write of '
                            'the selected level name is exactly this '
                            'append: the name lands at the out buffer\'s '
                            'current end and the method\'s 0 is the '
                            'formatter\'s result byte.',
            'captured_code_executed':False,'limits':LIMITS}


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
        a,b,_=OWNERS['table_method']
        asm=subprocess.check_output(['objdump','-d','-M','intel','--insn-width=16',f'--start-address={a:#x}',f'--stop-address={b:#x}',str(snapshot)],text=True)
        ins=decode_export(asm,a,b,read(data,a,b-a)[1])
        required=[0x141e8fb,0x141e8fe,0x141e901,0x141e904,0x141e908,0x141e90b,
                  0x141e90e,0x141e910,0x141e913,0x141e915,0x141e919,0x141e91c,
                  0x141e91f,0x141e925,0x141e928,0x141e92c,0x141e936,0x141e937,
                  0x141e93a,0x141e93d,0x141e940,0x141e943,0x141e948,0x141e94b,
                  0x141e94f]
        if not set(required)<=set(ins):
            raise ValueError('method evidence site not native instruction start')
        (output/'method.objdump.txt').write_bytes(asm.replace(str(snapshot),'<authenticated-node115>').encode('utf-8'))
        # The two table lea sites must be native instruction starts
        # inside their containing FDEs (boundary decodes, not
        # retained as exports).
        for site,(fa,fb) in LEA_FDES.items():
            asm=subprocess.check_output(['objdump','-d','-M','intel','--insn-width=16',f'--start-address={fa:#x}',f'--stop-address={fb:#x}',str(snapshot)],text=True)
            starts=decode_export(asm,fa,fb,read(data,fa,fb-fa)[1])
            if int(site,16) not in starts:
                raise ValueError('table lea site not native instruction start')
    (output/'frames.txt').write_bytes(('\n'.join(lines)+'\n').encode('utf-8'))
    (output/'records.json').write_bytes((json.dumps(report,indent=2)+'\n').encode('utf-8'))
    return report


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary',type=Path,default=TARGET)
    p.add_argument('--output',type=Path,default=ROOT/'work/table-method115')
    args=p.parse_args();report=generate(args.binary,args.output)
    print(json.dumps({'functions':len(report['owners']),'bytes':sum(x['bytes'] for x in report['owners']),'executed':False}))
