#!/usr/bin/env python3
"""RE-015: digest-bound node115 pointer formatter 0x15eadd0 of the flag-group chain."""
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
PACKET=ROOT/'research/work-items/RE-015-node115-pointer-formatter'
SHA='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
OWNERS={
 'pointer_formatter':(0x15eadd0,0x15eadff,'4e4d3a1a67401cbceb6f4bdb72d100eca0676a13fa66f9c82f73f1a6d8d8aec3')}
FORMATTER=0x15eadd0
LENGTH_TABLE=0x457fc0
POINTER_TABLE=0x46a838
# The established selection: flag byte -> (string pointer, length, bytes).
# Both tables are indexed unchecked; entries past index 3 are not part
# of either table (the length table's fifth qword is already the bytes
# of an unrelated string constant), so only these four are pinned.
SELECTIONS={
 0:(0x46a5c4,5,b'Error'),
 1:(0x459e50,4,b'Warn'),
 2:(0x45a19c,4,b'Info'),
 3:(0x46a5c9,5,b'Debug')}
LEA_SITE=0x16035f0
LEA_FDE=(0x16035e0,0x160361a)
CHAIN_TABLE=0x63f3d50
CHAIN_METHOD_SLOT=0x63f3d68
CHAIN_METHOD=0x141e8f0
EXPECTED_RIP_REFS=[LEA_SITE]
LIMITS=('Pointer formatter 0x15eadd0 only: the two loads that dereference the '
 'pointer-to-pointer value argument (the flag-group pointer loaded from [rdi] at '
 '0x15eadd0 and the flag group\'s first byte loaded at 0x15eadd3 — the first '
 'dereference of the flag-group pointer itself in the chain), the unchecked '
 'indexing of the two .rodata tables (the qword length table at 0x457fc0 and the '
 'relative-pointer table at 0x46a838) whose four established entries select the '
 'byte strings Error/Warn/Info/Debug, the two descriptor words it reads (out at '
 '+0x0 and table at +0x8; the spec dword and field A/B are never read), the '
 'method word it loads from table +0x18, and the tail jump through that method '
 'with (out, selected pointer, selected length). Which byte value the flag '
 'group\'s first byte actually holds on the chain call — who writes that byte '
 'of the block the derived-byte callee\'s pair record points at — and what the '
 'table method at +0x18 computes are NOT established by these bytes: the '
 'descriptor construction is owned by the RE-015 flag-group-write-target '
 'packet, the pair-block construction by the RE-015 derived-byte-callee '
 'packet, and the method binding for the chain\'s consumer table (slot '
 '0x63f3d68 -> 0x141e8f0) is cited from the write-target packet, not '
 're-derived. Entries of either table past index 3 are NOT established: the '
 'body performs no bounds check, and the bytes that follow the length '
 'table\'s fourth entry are an unrelated string constant. No captured code '
 'executed, no runtime value, indirect-call recovery, #94 correspondence, or '
 'reconstruction gate is claimed.')


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
    for a, i, v in struct.iter_unpack('<QQq', data[sec['offset']:sec['offset'] + sec['size']]):
        by_offset.setdefault(a,[]).append((i,v))
        if v==FORMATTER:
            fmt_hits.append(a)
    return by_offset,fmt_hits


def chain_method_binding(data):
    by_offset,_=relocations(data)
    if by_offset.get(CHAIN_METHOD_SLOT)!=[(8,CHAIN_METHOD)]:
        raise ValueError('chain method binding changed')
    return {'table':hex(CHAIN_TABLE),'slot':hex(CHAIN_METHOD_SLOT),
            'method':hex(CHAIN_METHOD)}


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
    _,fmt_hits=relocations(data)
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
               va+length+struct.unpack_from('<i',body,index+modrm_off+1)[0]==FORMATTER:
                refs.append(va)
            index=body.find(pat,index+1)
    return {'direct':sorted(direct),'relocation_references':sorted(fmt_hits),
            'rip_relative_refs':sorted(set(refs)),
            'address_as_data':address_as_data_count(data)}


def selection(flag_byte):
    """The established (pointer, length, bytes) the two tables assign to
    a flag byte. Only indices 0..3 are pinned: the body indexes both
    tables unchecked, and the bytes past the fourth length entry are an
    unrelated string constant, so no entry past index 3 is established."""
    if flag_byte not in SELECTIONS:
        raise ValueError('table index not pinned')
    return SELECTIONS[flag_byte]


def simulate_formatter(flag_byte,descriptor,write_method):
    """One tail-called write, modelling the pinned bytes. descriptor is
    the 24-byte descriptor block: only its out word (+0x0) and table
    word (+0x8) are read; the spec dword and fields are never read, so
    they cannot affect the call. The method word loaded from
    table +0x18 is modelled by the write_method callable, invoked once
    as write_method(out, selected_pointer, selected_length); its
    result byte is the function's result (tail jump)."""
    out,table=struct.unpack_from('<QQ',descriptor,0)
    pointer,length,_=selection(flag_byte)
    return write_method(out,pointer,length)


def _pin(body,base,va,hexbytes,what):
    off=va-base;want=bytes.fromhex(hexbytes)
    if body[off:off+len(want)]!=want:
        raise ValueError(f'formatter {what} changed')


def _rip(body,base,va,insn_len,disp_at):
    return va+insn_len+struct.unpack_from('<i',body,disp_at-base)[0]


def formatter_trace(data):
    start,end,_=OWNERS['pointer_formatter']
    _,body=read(data,start,end-start)
    def pin(va,hx,what): _pin(body,start,va,hx,what)
    def rip(va,ln,at): return _rip(body,start,va,ln,at)
    # The value argument is a pointer to the word holding the
    # flag-group pointer: load the pointer, then load its first byte.
    # This is the first dereference of the flag-group pointer itself
    # anywhere in the chain.
    pin(0x15eadd0,'488b07','value load')
    pin(0x15eadd3,'0fb600','first byte load')
    # Unchecked byte indexing of the length table into rdx.
    pin(0x15eadd6,'488d0d','length table lea')
    if rip(0x15eadd6,7,0x15eadd6+3)!=LENGTH_TABLE:
        raise ValueError('formatter length table lea target changed')
    pin(0x15eaddd,'488b14c1','length load')
    # Unchecked byte indexing of the relative-pointer table; the
    # selected pointer is table base + sign-extended dword entry.
    pin(0x15eade1,'488d0d','pointer table lea')
    if rip(0x15eade1,7,0x15eade1+3)!=POINTER_TABLE:
        raise ValueError('formatter pointer table lea target changed')
    pin(0x15eade8,'48630481','relative pointer load')
    pin(0x15eadec,'4801c8','pointer add')
    # Descriptor reads: out and table only; spec and fields are unread.
    pin(0x15eadef,'488b3e','out load')
    pin(0x15eadf2,'488b4e08','table load')
    pin(0x15eadf6,'488b4918','method load')
    pin(0x15eadfa,'4889c6','pointer argument move')
    pin(0x15eadfd,'ffe1','tail jump')
    selections=[]
    for index,(pointer,length,text) in sorted(SELECTIONS.items()):
        _,raw_len=read(data,LENGTH_TABLE+8*index,8)
        if struct.unpack('<Q',raw_len)[0]!=length:
            raise ValueError('selection changed')
        _,raw_rel=read(data,POINTER_TABLE+4*index,4)
        if POINTER_TABLE+struct.unpack('<i',raw_rel)[0]!=pointer:
            raise ValueError('selection changed')
        _,raw_text=read(data,pointer,length)
        if raw_text!=text:
            raise ValueError('selection changed')
        selections.append({'index':index,'pointer':hex(pointer),'length':length,
                           'bytes_hex':text.hex(),
                           'sha256':hashlib.sha256(text).hexdigest(),
                           'text':text.decode('ascii')})
    return {'arguments':{'value':'rdi','descriptor':'rsi'},
            'value_load':{'site':'0x15eadd0',
                          'loads':'the flag-group pointer from [rdi]'},
            'first_byte_load':{'site':'0x15eadd3','offset':0,
                               'reads':'the first byte of the flag group',
                               'first_dereference_in_chain':True},
            'length_table':{'base':hex(LENGTH_TABLE),'lea':'0x15eadd6',
                            'load':'0x15eaddd','index':'flag byte, unchecked'},
            'pointer_table':{'base':hex(POINTER_TABLE),'lea':'0x15eade1',
                             'load':'0x15eade8','add':'0x15eadec',
                             'index':'flag byte, unchecked',
                             'entry':'sign-extended dword, added to the table base'},
            'selections':selections,
            'descriptor_reads':{'out_load':'0x15eadef','table_load':'0x15eadf2',
                                'method_load':'0x15eadf6',
                                'spec_dword':None,'field_a':None,'field_b':None},
            'tail_call':{'site':'0x15eadfd','form':'jmp rcx (tail call)',
                         'target':'the method word at descriptor table +0x18',
                         'arguments':{'rdi':'descriptor out',
                                      'rsi':'selected string pointer',
                                      'rdx':'selected string length'},
                         'return':"the method's AL is the function's result"},
            'writes_to_out':'none directly; the tail-called table method performs the write',
            'builds_records':False,'dispatches_formatter':False}


def analyze(data):
    binding=chain_method_binding(data)
    census=reference_census(data)
    if census['direct'] or census['relocation_references'] or \
       census['rip_relative_refs']!=EXPECTED_RIP_REFS or census['address_as_data']!=0:
        raise ValueError('reference census changed')
    _,fs,_=fde_extents(data);fdes={(f['start'],f['end']):f for f in fs}
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
            'chain_method_binding':binding,
            'reference_census':{'direct':0,'via_formatter_slot':0,
                                'relocation_references':[],
                                'rip_relative_refs':[hex(s) for s in census['rip_relative_refs']],
                                'lea_site':hex(LEA_SITE),
                                'lea_fde':[hex(LEA_FDE[0]),hex(LEA_FDE[1])],
                                'address_as_data':0},
            'chain_verdict':'The pointer formatter is where the flag-group '
                            'pointer is first dereferenced in the chain: it '
                            'loads the flag-group pointer from its value '
                            'argument and reads the flag group\'s first byte, '
                            'then uses that byte as an unchecked index into '
                            'two .rodata tables — a qword length table at '
                            '0x457fc0 and a relative-pointer table at '
                            '0x46a838 — whose four established entries select '
                            'the byte strings Error (5), Warn (4), Info (4) '
                            'and Debug (5). It reads only the descriptor\'s '
                            'out and table words, loads the method word at '
                            'table +0x18, and tail-jumps to it with (out, '
                            'selected pointer, selected length); the spec '
                            'dword and fields are never read. It builds no '
                            'record and dispatches no further formatter.',
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
            required=[0x15eadd0,0x15eadd3,0x15eadd6,0x15eaddd,0x15eade1,0x15eade8,
                      0x15eadec,0x15eadef,0x15eadf2,0x15eadf6,0x15eadfa,0x15eadfd]
            if not set(required)<=set(ins):
                raise ValueError('formatter evidence site not native instruction start')
            (output/'formatter.objdump.txt').write_bytes(asm.replace(str(snapshot),'<authenticated-node115>').encode('utf-8'))
    (output/'frames.txt').write_bytes(('\n'.join(lines)+'\n').encode('utf-8'))
    (output/'records.json').write_bytes((json.dumps(report,indent=2)+'\n').encode('utf-8'))
    return report


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary',type=Path,default=TARGET)
    p.add_argument('--output',type=Path,default=ROOT/'work/pointer-formatter115')
    args=p.parse_args();report=generate(args.binary,args.output)
    print(json.dumps({'functions':len(report['owners']),'bytes':sum(x['bytes'] for x in report['owners']),'executed':False}))
