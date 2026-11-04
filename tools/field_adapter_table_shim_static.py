#!/usr/bin/env python3
"""RE-014: digest-bound node115 field-adapter table shim 0x168aa10."""
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
PACKET=ROOT/'research/work-items/RE-014-node115-field-adapter-table-shim'
SHA='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
OWNER=(0x168aa10,0x168aa23,'1e45d7cc5bb1bb477901c86a4259ef3edefc85c705a1302c1de97345edacde82')
TABLE=0x64078f8
HEADER_WORDS=(0,0x18,0x8)
SLOTS={24:0x1686bd0,32:0x1686b70,40:0x168aa10}
SLOT_ROLES={24:'bulk piece callee, qualified by the merged RE-014 newline packet',
            32:'byte-arm callee, qualified by the RE-014 field-adapter byte-arm packet',
            40:'argument-shifting shim, qualified by this packet'}
TAIL_SLOT=0x64df6f0
TAIL_TARGET=0x1680500
LIMITS=('Only the shim\'s own 19 bytes are qualified. The transformation is stated for the '
 'six integer/pointer argument registers of the System V AMD64 calling convention; the '
 'shim writes no stack slot, adjusts no stack pointer and, because mov/lea/indirect-jmp '
 'modify no flags, hands the entry flags to the tail target unchanged. What 0x1680500 '
 'computes with (argument 1, the adapter table, argument 2, argument 3, argument 5, '
 'argument 6), which callers invoke the shim through the table with which argument '
 'values, the fate of the caller\'s fourth argument beyond its overwrite here, and any '
 'nominal type for the table or the arguments remain unestablished. The adapter table, '
 'its header words and the tail slot binding are pinned context, not counted as '
 'recovered function bytes. The sibling callees at table+24 and table+32 are qualified '
 'by the merged RE-014 newline packet and the RE-014 field-adapter byte-arm packet '
 'and are cited context, not re-derived. No captured code executed.')


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
        if a in (TABLE+40,TAIL_SLOT):
            addend_field[a]=sec['offset']+index*24+16
    return by_offset,by_addend,addend_field


def _pin(body,base,va,hexbytes,what):
    off=va-base;want=bytes.fromhex(hexbytes)
    if body[off:off+len(want)]!=want:
        raise ValueError(f'shim {what} changed')


def shim_constants(body):
    base=OWNER[0]
    if len(body)!=OWNER[1]-OWNER[0]:
        raise ValueError('shim body extent changed')
    _pin(body,base,0x168aa10,'4889d1','argument 3 to 4 shift')
    _pin(body,base,0x168aa13,'4889f2','argument 2 to 3 shift')
    _pin(body,base,0x168aa16,'488d35','table insertion opcode')
    if 0x168aa1d+struct.unpack_from('<i',body,9)[0]!=TABLE:
        raise ValueError('shim table insertion reference changed')
    _pin(body,base,0x168aa1d,'ff25','tail jump opcode')
    if 0x168aa23+struct.unpack_from('<i',body,15)[0]!=TAIL_SLOT:
        raise ValueError('shim tail jump slot changed')
    return {'inserted_table':TABLE,'tail_slot':TAIL_SLOT}


def transform(a1,a2,a3,a4,a5,a6):
    """Pinned argument transformation of 0x168aa10.

    The values are the six argument registers at shim entry
    (rdi, rsi, rdx, rcx, r8, r9). The return maps each register at the
    tail jump to the value it then holds: rdi is forwarded unchanged,
    rsi is replaced by the adapter table, rdx takes the entry rsi,
    rcx takes the entry rdx, and r8/r9 pass through. The entry rcx
    value is overwritten by the shift and reaches no register.
    """
    return {'rdi':a1,'rsi':TABLE,'rdx':a2,'rcx':a3,'r8':a5,'r9':a6}


def argument_rows():
    def render(out):
        return {k:(hex(v) if isinstance(v,int) else v) for k,v in out.items()}
    rows=[{'inputs':['a1','a2','a3','a4','a5','a6'],
           'outputs':render(transform('a1','a2','a3','a4','a5','a6'))}]
    marks=[0x1111111111111111,0x2222222222222222,0x3333333333333333,
           0x4444444444444444,0x5555555555555555,0x6666666666666666]
    rows.append({'inputs':[hex(m) for m in marks],
                 'outputs':render(transform(*marks))})
    return rows


def direct_refs(data,opcode):
    text=next(s for s in sections(data) if s['name']=='.text')
    body=data[text['offset']:text['offset']+text['size']];base=text['address']
    count=0;index=body.find(bytes([opcode]))
    while index!=-1:
        if base+index+5+struct.unpack_from('<i',body,index+1)[0]==OWNER[0]:
            count+=1
        index=body.find(bytes([opcode]),index+1)
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
        raise ValueError('shim raw reference changed')
    return len(hits)


def analyze(data):
    _,fs,_=fde_extents(data);fdes={(f['start'],f['end']):f for f in fs}
    if (OWNER[0],OWNER[1]) not in fdes:
        raise ValueError('shim FDE changed')
    offset,body=read(data,OWNER[0],OWNER[1]-OWNER[0])
    shim_constants(body)
    if hashlib.sha256(body).hexdigest()!=OWNER[2]:
        raise ValueError('shim body changed')
    by_offset,by_addend,addend_field=relocations(data)
    for slot,target in SLOTS.items():
        if by_offset.get(TABLE+slot)!=[(8,target)]:
            raise ValueError('adapter table relocation changed')
    if by_offset.get(TAIL_SLOT)!=[(8,TAIL_TARGET)]:
        raise ValueError('shim tail slot relocation changed')
    header=struct.unpack_from('<3Q',read(data,TABLE,24)[1],0)
    if tuple(header)!=HEADER_WORDS:
        raise ValueError('adapter table header changed')
    if struct.unpack_from('<3Q',read(data,TABLE+24,24)[1],0)!=(0,0,0):
        raise ValueError('adapter table inline pointer changed')
    if direct_refs(data,0xe8)!=0:
        raise ValueError('shim direct caller appeared')
    if direct_refs(data,0xe9)!=0:
        raise ValueError('shim direct jump appeared')
    refs=by_addend.get(OWNER[0],[])
    if refs!=[TABLE+40]:
        raise ValueError('shim relocation reference changed')
    occurrences=raw_va_occurrences(data,addend_field[TABLE+40])
    frames={}
    for kind in ['fde','cie']:
        va=fdes[(OWNER[0],OWNER[1])][kind];n=struct.unpack('<I',read(data,va,4)[1])[0]+4
        frames[kind]={'va':hex(va),'bytes_hex':read(data,va,n)[1].hex()}
    owner={'role':'adapter_table_shim','start':hex(OWNER[0]),'end':hex(OWNER[1]),
           'file_offset':hex(offset),'bytes':OWNER[1]-OWNER[0],'sha256':OWNER[2],'frames':frames}
    table={'va':hex(TABLE),'header_words':[hex(w) for w in HEADER_WORDS],
           'slots':[{'offset':slot,'slot':hex(TABLE+slot),'target':hex(SLOTS[slot]),
                     'status':SLOT_ROLES[slot]} for slot in sorted(SLOTS)]}
    transformation={'moves':[{'site':'0x168aa10','bytes':'4889d1',
                              'from':'rdx (argument 3)','to':'rcx (argument 4)'},
                             {'site':'0x168aa13','bytes':'4889f2',
                              'from':'rsi (argument 2)','to':'rdx (argument 3)'}],
                    'insertion':{'site':'0x168aa16','bytes':'488d35dbced704',
                                 'register':'rsi (argument 2)','value':hex(TABLE),
                                 'identity':'the adapter table that holds this shim at +40'},
                    'forwarded_unchanged':['rdi (argument 1)','r8 (argument 5)','r9 (argument 6)'],
                    'overwritten':['rcx: the entry argument 4 value is replaced by argument 3 '
                                   'and reaches no register at the tail jump'],
                    'stack':'rsp unchanged; no stack slot is read or written; stack-passed '
                            'arguments keep their entry offsets for the tail target',
                    'flags':'mov, lea and the indirect jmp modify no flags; the tail target '
                            'inherits the shim entry flag state'}
    tail={'jump_site':'0x168aa1d','bytes':'ff25cd4ce504','slot':hex(TAIL_SLOT),
          'target':hex(TAIL_TARGET),'relocation_type':8,
          'note':'the target body is the next link and is not qualified by this packet'}
    return {'target_sha256':SHA,'owner':owner,'adapter_table':table,
            'transformation':transformation,'argument_rows':argument_rows(),'tail':tail,
            'census':{'direct_callers':0,'direct_jumps':0,
                      'relocation_references':[hex(TABLE+40)],
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
            raise ValueError('native shim FDE disagreement')
        asm=subprocess.check_output(['objdump','-d','-M','intel','--insn-width=16',
            f'--start-address={OWNER[0]:#x}',f'--stop-address={OWNER[1]:#x}',str(snapshot)],text=True)
        ins=decode_export(asm,OWNER[0],OWNER[1],read(data,OWNER[0],OWNER[1]-OWNER[0])[1])
        required=[0x168aa10,0x168aa13,0x168aa16,0x168aa1d]
        if not set(required)<=set(ins):
            raise ValueError('shim evidence site not native instruction start')
        (output/'shim.objdump.txt').write_bytes(asm.replace(str(snapshot),'<authenticated-node115>').encode('utf-8'))
        (output/'frames.txt').write_bytes((rows[0]+'\n').encode('utf-8'))
    (output/'records.json').write_bytes((json.dumps(report,indent=2)+'\n').encode('utf-8'))
    return report


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary',type=Path,default=TARGET)
    p.add_argument('--output',type=Path,default=ROOT/'work/field-adapter-table-shim')
    args=p.parse_args();report=generate(args.binary,args.output)
    print(json.dumps({'functions':1,'bytes':report['owner']['bytes'],'executed':False}))
