#!/usr/bin/env python3
"""RE-015: digest-bound node115 record-0 formatter 0x16035e0 of the flag-group chain."""
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
PACKET=ROOT/'research/work-items/RE-015-node115-record0-formatter'
SHA='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
OWNERS={
 'record0_formatter':(0x16035e0,0x160361a,'a764351ae22010d7b789b2e29e7cd777f9b08cd34c585b6a8062c073f1db36d5')}
FORMATTER=0x16035e0
FORMATTER_SLOT=0x64e1490
WRITE_TARGET=0x1680500
WRITE_SLOT=0x64df6f0
NEXT_FORMATTER=0x15eadd0
NEXT_FDE=(0x15eadd0,0x15eadff)
TEMPLATE=0x43b857
TEMPLATE_STREAM=bytes.fromhex('c000')
TEMPLATE_SHA='e9aff84fdb699ca706c0a1fed47bb095cb25e3c95aa5d1c5d216ff2cfbcd4998'
SLOT_LOAD_SITE=0x15ae459
SLOT_STORE_SITE=0x15ae460
CONSTRUCTOR_FDE=(0x15ae430,0x15ae5ae)
EXPECTED_SLOT_REFS=[SLOT_LOAD_SITE]
LIMITS=('Record-0 formatter 0x16035e0 only: the 24-byte stack frame it builds (the value '
 'word stored at +0x0 and the single argument record at +0x8 whose value word is the '
 'address of that stored word and whose formatter word is 0x15eadd0), the two descriptor '
 'words it reads (out at +0x0 and table at +0x8; the spec dword and field A/B are never '
 'read), the single nested call it makes to the write target 0x1680500 through slot '
 '0x64df6f0 with the two-byte template at 0x43b857, and the byte-sized contract that the '
 "nested call's AL is returned unchanged. What the next formatter 0x15eadd0 computes "
 'with the pointer to the stored value word, and what the write target does with the '
 'record, are NOT established by these bytes: the write target is owned by the RE-015 '
 'flag-group-write-target packet, the arguments-block construction that pairs this '
 'formatter with the flag-group pointer by the RE-015 derived-byte-callee packet, and '
 'the template forwarding by the RE-015 flag-group-format packet; all three are cited '
 'here, not re-derived. No captured code executed, no runtime value, indirect-call '
 'recovery, #94 correspondence, or reconstruction gate is claimed.')


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
    fmt_hits = []
    write_hits = []
    for a, i, v in struct.iter_unpack('<QQq', data[sec['offset']:sec['offset'] + sec['size']]):
        by_offset.setdefault(a,[]).append((i,v))
        if v==FORMATTER:
            fmt_hits.append(a)
        if v==WRITE_TARGET:
            write_hits.append(a)
    return by_offset,fmt_hits,write_hits


def slot_bindings(data):
    by_offset,fmt_hits,write_hits=relocations(data)
    if fmt_hits!=[FORMATTER_SLOT] or write_hits!=[WRITE_SLOT]:
        raise ValueError('slot binding changed')
    if by_offset.get(FORMATTER_SLOT)!=[(8,FORMATTER)]:
        raise ValueError('slot binding changed')
    if by_offset.get(WRITE_SLOT)!=[(8,WRITE_TARGET)]:
        raise ValueError('slot binding changed')
    return {hex(FORMATTER_SLOT):hex(FORMATTER),hex(WRITE_SLOT):hex(WRITE_TARGET)}


def address_as_data_count(data):
    sec = next((s for s in sections(data) if s['name'] == '.rela.dyn'), None)
    if sec is None:
        raise ValueError('missing.rela.dyn section')
    needle=struct.pack('<Q',FORMATTER);count=0;index=data.find(needle)
    while index!=-1:
        if not (sec['offset']<=index<sec['offset']+sec['size']):
            count+=1
        index=data.find(needle,index+1)
    return count


def reference_census(data):
    text = next((s for s in sections(data) if s['name'] == '.text'), None)
    if text is None:
        raise ValueError('missing.text section')
    body=data[text['offset']:text['offset']+text['size']];base=text['address']
    direct=[]
    for op in (b'\xe8',b'\xe9'):
        index=body.find(op)
        while index!=-1:
            va=base+index
            if va+5+struct.unpack_from('<i',body,index+1)[0]==FORMATTER:
                direct.append(va)
            index=body.find(op,index+1)
    via_slot=[]
    for op in (b'\xff\x15',b'\xff\x25'):
        index=body.find(op)
        while index!=-1:
            va=base+index
            if va+6+struct.unpack_from('<i',body,index+2)[0]==FORMATTER_SLOT:
                via_slot.append(va)
            index=body.find(op,index+1)
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
               va+length+struct.unpack_from('<i',body,index+modrm_off+1)[0]==FORMATTER_SLOT:
                refs.append(va)
            index=body.find(pat,index+1)
    return {'direct':sorted(direct),'via_formatter_slot':sorted(via_slot),
            'formatter_slot_refs':sorted(set(refs)),
            'address_as_data':address_as_data_count(data)}


def build_stack_frame(value):
    """The formatter's 24-byte stack frame, modelled symbolically: the
    value word is stored at offset +0x0, and the single argument record
    at offset +0x8 has as its value word the ADDRESS of that stored word
    (the symbolic handle 'value_slot') and as its formatter word
    NEXT_FORMATTER. The formatter itself never loads the stored word's
    pointee: the record carries the slot's address, not the value."""
    return {'value_slot':value,
            'record':{'value':'value_slot','formatter':NEXT_FORMATTER,
                      'value_offset':8,'formatter_offset':16}}


def simulate_formatter(value,descriptor,write_target):
    """One nested write-target call, modelling the pinned bytes.
    descriptor is the 24-byte descriptor block: only its out word
    (+0x0) and table word (+0x8) are read; the spec dword and fields
    are never read, so they cannot affect the call. write_target is
    invoked once as write_target(out, table, template_stream,
    records) with records holding the symbolic slot handle, and its
    result byte is returned unchanged."""
    out,table=struct.unpack_from('<QQ',descriptor,0)
    frame=build_stack_frame(value)
    records=[(frame['record']['value'],frame['record']['formatter'])]
    return write_target(out,table,TEMPLATE_STREAM,records)


def _pin(body,base,va,hexbytes,what):
    off=va-base;want=bytes.fromhex(hexbytes)
    if body[off:off+len(want)]!=want:
        raise ValueError(f'formatter {what} changed')


def _rip(body,base,va,insn_len,disp_at):
    return va+insn_len+struct.unpack_from('<i',body,disp_at-base)[0]


def formatter_trace(data):
    start,end,_=OWNERS['record0_formatter']
    _,body=read(data,start,end-start)
    def pin(va,hx,what): _pin(body,start,va,hx,what)
    def rip(va,ln,at): return _rip(body,start,va,ln,at)
    # Frame: 24 bytes; the value argument is stored, never dereferenced.
    pin(0x16035e0,'4883ec18','stack alloc')
    pin(0x16035e4,'48893c24','value store')
    # Record build: value word is the address of the stored word; the
    # formatter word is the next formatter, materialised by lea.
    pin(0x16035e8,'4889e0','slot address')
    pin(0x16035eb,'4889442408','record value store')
    pin(0x16035f0,'488d05','next formatter lea')
    if rip(0x16035f0,7,0x16035f0+3)!=NEXT_FORMATTER:
        raise ValueError('formatter next lea target changed')
    pin(0x16035f7,'4889442410','record formatter store')
    # Descriptor reads: out and table only; spec and fields are unread.
    pin(0x16035fc,'488b3e','out load')
    pin(0x16035ff,'488b7608','table load')
    # Nested call: same two-byte template as chain call 1, block at
    # rsp+0x8 (even, so the write target takes its scan path), through
    # the write target's slot.
    pin(0x1603603,'488d15','template lea')
    if rip(0x1603603,7,0x1603603+3)!=TEMPLATE:
        raise ValueError('formatter template lea target changed')
    pin(0x160360a,'488d4c2408','block lea')
    pin(0x160360f,'ff15','nested call')
    if rip(0x160360f,6,0x160360f+2)!=WRITE_SLOT:
        raise ValueError('formatter nested call slot changed')
    pin(0x1603615,'4883c418','stack restore')
    pin(0x1603619,'c3','return')
    return {'arguments':{'value':'rdi','descriptor':'rsi'},
            'frame':{'alloc':'0x16035e0','bytes':24,'restore':'0x1603615',
                     'return':'0x1603619'},
            'value_store':{'site':'0x16035e4','slot_offset':0,
                           'dereferenced_by_formatter':False},
            'record':{'base_offset':8,'value_offset':8,'formatter_offset':16,
                      'slot_address':'0x16035e8','value_store':'0x16035eb',
                      'formatter_lea':'0x16035f0','formatter_store':'0x16035f7',
                      'formatter':hex(NEXT_FORMATTER),
                      'value_word':'address of the stored value word'},
            'descriptor_reads':{'out_load':'0x16035fc','table_load':'0x16035ff',
                                'spec_dword':None,'field_a':None,'field_b':None},
            'nested_call':{'template_lea':'0x1603603','template':hex(TEMPLATE),
                           'block_lea':'0x160360a','call':'0x160360f',
                           'slot':hex(WRITE_SLOT),'target':hex(WRITE_TARGET),
                           'tagged':'block pointer (even: scan path)'},
            'return':'the nested call AL is returned unchanged'}


def analyze(data):
    bindings=slot_bindings(data)
    _,raw=read(data,TEMPLATE,len(TEMPLATE_STREAM))
    if raw!=TEMPLATE_STREAM or hashlib.sha256(raw).hexdigest()!=TEMPLATE_SHA:
        raise ValueError('template changed')
    census=reference_census(data)
    if census['direct'] or census['via_formatter_slot'] or \
       census['formatter_slot_refs']!=EXPECTED_SLOT_REFS or census['address_as_data']!=0:
        raise ValueError('reference census changed')
    _,fs,_=fde_extents(data);fdes={(f['start'],f['end']):f for f in fs}
    if NEXT_FDE not in fdes:
        raise ValueError('next formatter FDE changed')
    owners=[]
    for role,(a,b,sha) in OWNERS.items():
        if (a,b) not in fdes:
            raise ValueError('formatter scope FDE changed')
        offset,raw=read(data,a,b-a)
        if hashlib.sha256(raw).hexdigest()!=sha:
            raise ValueError(f'{role} body changed')
        records={}
        for kind in ['fde','cie']:
            va=fdes[(a,b)][kind];n=struct.unpack('<I',read(data,va,4)[1])[0]+4
            records[kind]={'va':hex(va),'bytes_hex':read(data,va,n)[1].hex()}
        owners.append({'role':role,'start':hex(a),'end':hex(b),'file_offset':hex(offset),'bytes':b-a,'sha256':sha,'frames':records})
    return {'target_sha256':SHA,'owners':owners,
            'formatter':formatter_trace(data),
            'slot_bindings':bindings,
            'template':{'va':hex(TEMPLATE),'stream_hex':TEMPLATE_STREAM.hex(),
                        'sha256':TEMPLATE_SHA,
                        'walk':'one default-spec dispatch of record 0, then the terminator'},
            'reference_census':{'direct':0,'via_formatter_slot':0,
                                'formatter_slot_refs':[hex(s) for s in census['formatter_slot_refs']],
                                'formatter_slot_store':hex(SLOT_STORE_SITE),
                                'constructor_fde':[hex(CONSTRUCTOR_FDE[0]),hex(CONSTRUCTOR_FDE[1])],
                                'relocation_references':[hex(FORMATTER_SLOT)],
                                'address_as_data':0},
            'next_formatter':{'start':hex(NEXT_FDE[0]),'end':hex(NEXT_FDE[1]),
                              'bytes':NEXT_FDE[1]-NEXT_FDE[0]},
            'chain_verdict':'The record-0 formatter never dereferences the flag-group '
                            'pointer it receives: it stores the value word on its stack, '
                            'builds one record whose value word is the address of that '
                            'stored word and whose formatter word is 0x15eadd0, and '
                            're-enters the write target with the same two-byte template '
                            '(c0 00) and the descriptor out/table words forwarded '
                            'unchanged. The descriptor spec dword and fields are never '
                            'read. The flag-group pointer therefore reaches the next '
                            'formatter one indirection deeper, as a pointer to the word '
                            'holding it, and its first dereference is deferred again.',
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
                raise ValueError('native formatter FDE disagreement')
            lines.extend(rows)
            asm=subprocess.check_output(['objdump','-d','-M','intel','--insn-width=16',f'--start-address={a:#x}',f'--stop-address={b:#x}',str(snapshot)],text=True)
            ins=decode_export(asm,a,b,read(data,a,b-a)[1])
            required=[0x16035e0,0x16035e4,0x16035e8,0x16035eb,0x16035f0,0x16035f7,
                      0x16035fc,0x16035ff,0x1603603,0x160360a,0x160360f,0x1603615,
                      0x1603619]
            if not set(required)<=set(ins):
                raise ValueError('formatter evidence site not native instruction start')
            (output/'formatter.objdump.txt').write_bytes(asm.replace(str(snapshot),'<authenticated-node115>').encode('utf-8'))
    (output/'frames.txt').write_bytes(('\n'.join(lines)+'\n').encode('utf-8'))
    (output/'records.json').write_bytes((json.dumps(report,indent=2)+'\n').encode('utf-8'))
    return report


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary',type=Path,default=TARGET)
    p.add_argument('--output',type=Path,default=ROOT/'work/record0-formatter115')
    args=p.parse_args();report=generate(args.binary,args.output)
    print(json.dumps({'functions':len(report['owners']),'bytes':sum(x['bytes'] for x in report['owners']),'executed':False}))
