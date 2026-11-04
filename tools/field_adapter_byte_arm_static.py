#!/usr/bin/env python3
"""RE-014: digest-bound node115 field-adapter byte-arm callee 0x1686b70."""
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
PACKET=ROOT/'research/work-items/RE-014-node115-field-adapter-byte-arm'
SHA='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
OWNER=(0x1686b70,0x1686bcf,'f6b8b87fe6061bbd9d6ac77b92485bb94fa838e6f8c3c36f31d339dd7da98b86')
TABLE=0x64078f8
HEADER_WORDS=(0,0x18,0x8)
SLOTS={24:0x1686bd0,32:0x1686b70,40:0x168aa10}
SLOT_ROLES={24:'bulk piece callee, qualified by the merged RE-014 newline packet',
            32:'byte-arm callee, qualified by this packet',
            40:'argument-shifting shim, behaviour opaque'}
LITERAL_VA=0x45a128
LITERAL=b'    '
LF=0x0a
INDENT_METHOD=0x18
BYTE_METHOD=0x20
FLAG_TARGET=0x1686bb7
LIMITS=('Only the callee\'s own 95 bytes are qualified. The argument is taken to point at '
 'the 24-byte state its three loads describe (data pointer at +0, callback table at +8, '
 'flag-byte pointer at +0x10), and both callback methods are taken to return normally '
 'with a status byte in AL; these are the same premises the merged newline packet states '
 'for the sibling +0x18 method. What the +0x18 and +0x20 methods do inside the callback '
 'owner, which concrete writer a given state names, the flag byte\'s history before this '
 'call, the full ESI register\'s provenance beyond the pinned equality compare, the +40 '
 'callee 0x168aa10 and its slot target 0x1680500, and any nominal type for the state or '
 'the table remain unestablished. The sibling bulk callee at table+24 is qualified by '
 'the merged RE-014 newline packet and is cited context, not re-derived. '
 'No captured code executed.')


def read(data,va,n):
    matches=[s for s in sections(data) if s['type']!=8 and s['address']<=va and va+n<=s['address']+s['size']]
    if len(matches)!=1:
        raise ValueError('expected one file-backed mapping')
    s=matches[0];o=s['offset']+va-s['address']
    return o,bytes(data[o:o+n])


def relocations(data):
    sec=next(s for s in sections(data) if s['name']=='.rela.dyn')
    by_offset={}
    by_addend={}
    addend_field={}
    blob=data[sec['offset']:sec['offset']+sec['size']]
    for index,(a,i,v) in enumerate(struct.iter_unpack('<QQq',blob)):
        by_offset.setdefault(a,[]).append((i,v))
        by_addend.setdefault(v,[]).append(a)
        if a==TABLE+32:
            addend_field[v]=sec['offset']+index*24+16
    return by_offset,by_addend,addend_field


def _pin(body,base,va,hexbytes,what):
    off=va-base;want=bytes.fromhex(hexbytes)
    if body[off:off+len(want)]!=want:
        raise ValueError(f'byte-arm {what} changed')


def byte_arm_constants(body):
    base=OWNER[0]
    if len(body)!=OWNER[1]-OWNER[0]:
        raise ValueError('byte-arm body extent changed')
    _pin(body,base,0x1686b70,'554889e541574156415453','prologue')
    _pin(body,base,0x1686b7b,'4c8b7710','state flag field load')
    _pin(body,base,0x1686b7f,'488b1f','state data field load')
    _pin(body,base,0x1686b82,'4c8b7f08','state table field load')
    _pin(body,base,0x1686b86,'41803e00','flag test')
    _pin(body,base,0x1686b8a,'742b','flag branch opcode')
    if 0x1686b8c+body[0x1b]!=FLAG_TARGET:
        raise ValueError('byte-arm flag branch target changed')
    _pin(body,base,0x1686b8c,'488d05','indent literal reference opcode')
    if 0x1686b93+struct.unpack_from('<i',body,0x1f)[0]!=LITERAL_VA:
        raise ValueError('byte-arm indent literal reference changed')
    _pin(body,base,0x1686b93,'ba04000000','indent length')
    _pin(body,base,0x1686b98,'4889df','indent data argument')
    _pin(body,base,0x1686b9b,'4189f4','byte save')
    _pin(body,base,0x1686b9e,'4889c6','indent text argument')
    _pin(body,base,0x1686ba1,'41ff5718','indent method call')
    _pin(body,base,0x1686ba5,'4489e6','byte restore')
    _pin(body,base,0x1686ba8,'84c0','indent result test')
    _pin(body,base,0x1686baa,'740b','indent result branch opcode')
    if 0x1686bac+body[0x3b]!=FLAG_TARGET:
        raise ValueError('byte-arm indent result branch target changed')
    _pin(body,base,0x1686bac,'b001','error result')
    _pin(body,base,0x1686bae,'5b415c415e415f5dc3','error epilogue')
    _pin(body,base,0x1686bb7,'83fe0a','flag compare')
    _pin(body,base,0x1686bba,'410f9406','flag store')
    _pin(body,base,0x1686bbe,'498b4720','byte method load')
    _pin(body,base,0x1686bc2,'4889df','byte data argument')
    _pin(body,base,0x1686bc5,'5b415c415e415f5d','tail epilogue')
    _pin(body,base,0x1686bcd,'ffe0','byte tail jump')
    return {'flag_offset':0x10,'data_offset':0,'table_offset':8,
            'indent_length':struct.unpack_from('<I',body,0x24)[0],
            'indent_method':body[0x34],'byte_method':body[0x51],
            'flag_constant':body[0x49]}


def byte_arm(flag_set,indent_al,byte):
    """Pinned control flow of 0x1686b70.

    flag_set: the flag byte at state+0x10's pointer is nonzero on entry.
    indent_al: status byte of the V+0x18 indent call; consulted only when
    flag_set, because the call happens only on that arm.
    byte: the ESI value; only its equality with 0x0a is observed.
    """
    if flag_set and indent_al!=0:
        return {'indent_call':True,'flag_written':False,'flag_value':None,
                'outcome':'early_return_al_1'}
    return {'indent_call':bool(flag_set),'flag_written':True,
            'flag_value':byte==LF,'outcome':'tail_byte_call'}


def truth_table():
    rows=[]
    for flag_set in [False,True]:
        for indent_al in ([None] if not flag_set else [0,1]):
            for byte in [LF,0x61]:
                row=byte_arm(flag_set,indent_al or 0,byte)
                rows.append({'flag_set':flag_set,'indent_al':indent_al,
                             'byte':hex(byte),**row})
    return rows


def direct_callers(data):
    text=next(s for s in sections(data) if s['name']=='.text')
    body=data[text['offset']:text['offset']+text['size']];base=text['address']
    count=0;index=body.find(b'\xe8')
    while index!=-1:
        if base+index+5+struct.unpack_from('<i',body,index+1)[0]==OWNER[0]:
            count+=1
        index=body.find(b'\xe8',index+1)
    return count


def raw_va_occurrences(data,expected_field_offset):
    needle=struct.pack('<Q',OWNER[0]);hits=[]
    for s in sections(data):
        if s['type']==8 or not s['size']:
            continue
        chunk=data[s['offset']:s['offset']+s['size']]
        index=chunk.find(needle)
        while index!=-1:
            hits.append(s['offset']+index)
            index=chunk.find(needle,index+1)
    if hits!=[expected_field_offset]:
        raise ValueError('byte-arm raw reference changed')
    return len(hits)


def analyze(data):
    _,fs,_=fde_extents(data);fdes={(f['start'],f['end']):f for f in fs}
    if (OWNER[0],OWNER[1]) not in fdes:
        raise ValueError('byte-arm FDE changed')
    offset,body=read(data,OWNER[0],OWNER[1]-OWNER[0])
    constants=byte_arm_constants(body)
    if hashlib.sha256(body).hexdigest()!=OWNER[2]:
        raise ValueError('byte-arm body changed')
    if (constants['indent_length'],constants['indent_method'],
        constants['byte_method'],constants['flag_constant'])!=(4,INDENT_METHOD,BYTE_METHOD,LF):
        raise ValueError('byte-arm pinned constant changed')
    by_offset,by_addend,addend_field=relocations(data)
    for slot,target in SLOTS.items():
        if by_offset.get(TABLE+slot)!=[(8,target)]:
            raise ValueError('adapter table relocation changed')
    header=struct.unpack_from('<3Q',read(data,TABLE,24)[1],0)
    if tuple(header)!=HEADER_WORDS:
        raise ValueError('adapter table header changed')
    if struct.unpack_from('<3Q',read(data,TABLE+24,24)[1],0)!=(0,0,0):
        raise ValueError('adapter table inline pointer changed')
    if read(data,LITERAL_VA,len(LITERAL))[1]!=LITERAL:
        raise ValueError('byte-arm indent literal changed')
    if direct_callers(data)!=0:
        raise ValueError('byte-arm direct caller appeared')
    refs=by_addend.get(OWNER[0],[])
    if refs!=[TABLE+32]:
        raise ValueError('byte-arm relocation reference changed')
    occurrences=raw_va_occurrences(data,addend_field[OWNER[0]])
    frames={}
    for kind in ['fde','cie']:
        va=fdes[(OWNER[0],OWNER[1])][kind];n=struct.unpack('<I',read(data,va,4)[1])[0]+4
        frames[kind]={'va':hex(va),'bytes_hex':read(data,va,n)[1].hex()}
    owner={'role':'adapter_table_byte_callee','start':hex(OWNER[0]),'end':hex(OWNER[1]),
           'file_offset':hex(offset),'bytes':OWNER[1]-OWNER[0],'sha256':OWNER[2],'frames':frames}
    table={'va':hex(TABLE),'header_words':[hex(w) for w in HEADER_WORDS],
           'slots':[{'offset':slot,'slot':hex(TABLE+slot),'target':hex(SLOTS[slot]),
                     'status':SLOT_ROLES[slot]} for slot in sorted(SLOTS)]}
    protocol={'state':{'data_offset':hex(constants['data_offset']),
                       'table_offset':hex(constants['table_offset']),
                       'flag_pointer_offset':hex(constants['flag_offset'])},
              'flag_test':{'site':'0x1686b86','branch':'0x1686b8a','taken_target':hex(FLAG_TARGET)},
              'indent':{'literal_va':hex(LITERAL_VA),'literal':'    ','length':constants['indent_length'],
                        'method_offset':hex(INDENT_METHOD),'call_site':'0x1686ba1',
                        'result_test':'0x1686ba8','result_branch':'0x1686baa'},
              'error_return':{'site':'0x1686bac','result':'AL = 1','flag_written':False},
              'flag_update':{'compare_site':'0x1686bb7','constant':LF,'store_site':'0x1686bba'},
              'byte_tail':{'method_offset':hex(BYTE_METHOD),'load_site':'0x1686bbe','jump_site':'0x1686bcd'}}
    return {'target_sha256':SHA,'owner':owner,'adapter_table':table,'protocol':protocol,
            'truth_table':truth_table(),
            'census':{'direct_callers':0,'relocation_references':[hex(TABLE+32)],
                      'raw_va_occurrences':occurrences},
            'captured_code_executed':False,'limits':LIMITS}


def generate(binary,output):
    data=binary.read_bytes()
    if len(data)!=105896032 or hashlib.sha256(data).hexdigest()!=SHA:
        raise ValueError('expected pinned node115')
    report=analyze(data);output.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory() as directory:
        snapshot=Path(directory)/'node115.elf';snapshot.write_bytes(data)
        native=subprocess.check_output(['readelf','-wf',str(snapshot)],text=True)
        rows=[l for l in native.splitlines() if f'pc={OWNER[0]:016x}..{OWNER[1]:016x}' in l]
        if len(rows)!=1:
            raise ValueError('native byte-arm FDE disagreement')
        asm=subprocess.check_output(['objdump','-d','-M','intel','--insn-width=16',
            f'--start-address={OWNER[0]:#x}',f'--stop-address={OWNER[1]:#x}',str(snapshot)],text=True)
        ins=decode_export(asm,OWNER[0],OWNER[1],read(data,OWNER[0],OWNER[1]-OWNER[0])[1])
        required=[0x1686b70,0x1686b7b,0x1686b7f,0x1686b82,0x1686b86,0x1686b8a,0x1686b8c,0x1686b93,
                  0x1686b98,0x1686b9b,0x1686b9e,0x1686ba1,0x1686ba5,0x1686ba8,0x1686baa,0x1686bac,
                  0x1686bae,0x1686bb7,0x1686bba,0x1686bbe,0x1686bc2,0x1686bc5,0x1686bcd]
        if not set(required)<=set(ins):
            raise ValueError('byte-arm evidence site not native instruction start')
        (output/'byte_arm.objdump.txt').write_bytes(asm.replace(str(snapshot),'<authenticated-node115>').encode('utf-8'))
        (output/'frames.txt').write_bytes((rows[0]+'\n').encode('utf-8'))
    (output/'records.json').write_bytes((json.dumps(report,indent=2)+'\n').encode('utf-8'))
    return report


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary',type=Path,default=TARGET)
    p.add_argument('--output',type=Path,default=ROOT/'work/field-adapter-byte-arm')
    args=p.parse_args();report=generate(args.binary,args.output)
    print(json.dumps({'functions':1,'bytes':report['owner']['bytes'],'executed':False}))
