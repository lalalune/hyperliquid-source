#!/usr/bin/env python3
"""RE-015: digest-bound node115 flag-group first-byte writer trace.

The flag group is the four-byte stack block at [rsp+0x14] in the large
consumer 0x15a3b90..0x15a6509, passed by pointer (rcx) to the
derived-byte callee 0x15ae430 at exactly four direct call sites.  This
packet establishes who writes the group's first byte (offset +0x0,
stack offset +0x14) and what values it can hold when a callee call --
and so, downstream, the pointer formatter 0x15eadd0 -- reads it:

- A direct rsp-relative store census over the whole consumer body
  shows exactly one store site per group byte: +0x16 (the cached flag
  byte, #2317) at 0x15a3c55, +0x15 (the derived byte, #2396) at
  0x15a3c5e, +0x17 (the loop counter byte) at 0x15a3d14, and +0x14
  (the first byte) at exactly two sites, both immediate stores:
  0x15a3f10 writes 1 and 0x15a420c writes 0.
- Each first-byte write is the entry instruction of a field segment.
  Segment A (0x15a3f10..0x15a4023, callee calls 0x15a3f5f/0x15a401e) is
  entered only by the jne at 0x15a3ee2 on the segment gate
  (r14 != sentinel, r14 loaded from [rsp+0xc0]); the instruction
  before the write is an unconditional jump away, so there is no
  fall-through entry.  Segment B (0x15a420c..0x15a4321, callee calls
  0x15a4263/0x15a431c) is entered by the jne at 0x15a4161 on its gate
  (r14 != sentinel, r14 loaded from [rsp+0x68]) or by fall-through
  past the je at 0x15a4206 on the repeated gate; both gates compare
  the same loaded word against the sentinel.  Every direct branch
  into a segment interior originates inside that segment, and inside
  each segment window there is no indirect store, no push/pop, and
  no store to the group byte other than the segment's own write.
- Composed with the pointer formatter's established selection table
  (#2440), the chain call therefore selects "Warn" for field block A
  (byte 1) and "Error" for field block B (byte 0).  Bytes 2 ("Info")
  and 3 ("Debug") cannot be written by this consumer, and no
  out-of-range byte can reach the formatter's unchecked index
  through this chain: the only values ever stored are the two
  immediates 0 and 1.

The two store instruction bytes were already pinned as sites by the
derived-byte-callee packet (#2396, as its block A / block B tag
stores); that packet records the group offsets but does not record
the values in its records, does not prove the stores are the only
writes, does not prove the segment gating, and does not compose the
values with the formatter's selection table.  Those four facts are
this packet's claim.
"""
import argparse
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
PACKET=ROOT/'research/work-items/RE-015-node115-flag-group-first-byte'
SHA='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
OWNERS={
 'consumer_large':(0x15a3b90,0x15a6509,'7995f7af57e2be27ca6ed1e307d9bcce9d6140f72b0ff0cf0804d7f09e5505fb')}
BOUNDARIES={
 'callee':(0x15ae430,0x15ae5ae,'4cfb1633d772df3d0e75abf5864ea242a85e7732e479b5351ae80c97842d7acf'),
 'pointer_formatter':(0x15eadd0,0x15eadff,'4e4d3a1a67401cbceb6f4bdb72d100eca0676a13fa66f9c82f73f1a6d8d8aec3')}
CONSUMER=0x15a3b90
CALLEE=0x15ae430
SENTINEL=0x8000000000000000
GROUP_BASE=0x14
CALL_SITES=[0x15a3f5f,0x15a401e,0x15a4263,0x15a431c]
LEA_SITES=[0x15a3f52,0x15a400a,0x15a4256,0x15a4308]
WRITE_A=0x15a3f10
WRITE_B=0x15a420c
SEGMENTS={
 'A':{'write':WRITE_A,'range':(WRITE_A,0x15a4023),'value':1,
      'calls':[0x15a3f5f,0x15a401e],
      'entry_branches':[0x15a3ee2],'fallthrough_entry':False},
 'B':{'write':WRITE_B,'range':(WRITE_B,0x15a4321),'value':0,
      'calls':[0x15a4263,0x15a431c],
      'entry_branches':[0x15a4161],'fallthrough_entry':True}}
LENGTH_TABLE=0x457fc0
POINTER_TABLE=0x46a838
SELECTIONS={
 0:(0x46a5c4,5,b'Error'),
 1:(0x459e50,4,b'Warn'),
 2:(0x45a19c,4,b'Info'),
 3:(0x46a5c9,5,b'Debug')}
FIRST_BYTE={'A':1,'B':0}
WINDOWS={
 'population_window_15a3b90_15a3e07_objdump.txt':(0x15a3b90,0x15a3e07),
 'gate_a_window_15a3dbf_15a3f10_objdump.txt':(0x15a3dbf,0x15a3f10),
 'segment_a_window_15a3f10_15a4023_objdump.txt':(0x15a3f10,0x15a4023),
 'gate_b_window_15a4150_15a420c_objdump.txt':(0x15a4150,0x15a420c),
 'segment_b_window_15a420c_15a4321_objdump.txt':(0x15a420c,0x15a4321)}
LIMITS=('Flag-group first byte only, in the large consumer '
 '0x15a3b90..0x15a6509: the direct rsp-relative store census over the '
 'whole body (exactly one store site per group byte; exactly two '
 'immediate stores for the first byte, values 1 and 0), the two field '
 'segment gates and their entry modes, the branch/store scans of the '
 'two segment windows, and the composition of the two values with '
 'the pointer formatter\'s established selection table. The store '
 'census covers direct rsp-relative stores over the whole body and '
 'all stores (direct or indirect) inside the two segment windows; '
 'the 81 indirect stores elsewhere in the body write through heap, '
 'map and allocation pointers outside the segment windows and are '
 'not claimed alias-free in general -- the group address itself is '
 'materialised only at the four lea sites inside the segments, each '
 'after its segment\'s write, and is passed only as the callee\'s '
 'rcx argument. Downstream, no function before the pointer '
 'formatter dereferences the group pointer at all (pointer '
 'formatter packet, #2440), so no downstream write through the '
 'pointer can intervene. The callee\'s entry split (its format path '
 'requires the consumer\'s rsi argument to be nonzero) is owned by '
 'the derived-byte-callee packet (#2396) and cited, not re-derived: '
 'this packet\'s selection claim holds for every callee call, and '
 'reaches the formatter exactly on those calls where the callee '
 'takes its format path. What the two field blocks mean, what the '
 'gate words at [rsp+0xc0] and [rsp+0x68] represent beyond the '
 'sentinel comparison, and what the table method at descriptor '
 '+0x18 computes with the selected name are NOT established. No '
 'captured code executed, no runtime value, indirect-call recovery, '
 '#94 correspondence, or reconstruction gate is claimed.')


def read(data,va,n):
    matches=[s for s in sections(data) if s['type']!=8 and s['address']<=va and va+n<=s['address']+s['size']]
    if len(matches)!=1:
        raise ValueError('expected one file-backed mapping')
    s=matches[0];o=s['offset']+va-s['address']
    return o,bytes(data[o:o+n])


def _pin(body,base,va,hexbytes,what):
    off=va-base;want=bytes.fromhex(hexbytes)
    if body[off:off+len(want)]!=want:
        raise ValueError(f'flag group {what} changed')


def _rip(body,base,va,insn_len,disp_at):
    return va+insn_len+struct.unpack_from('<i',body,disp_at-base)[0]


def _rip8(body,base,va,insn_len,disp_at):
    return va+insn_len+struct.unpack_from('<b',body,disp_at-base)[0]


def direct_call_sites(data):
    text=next(s for s in sections(data) if s['name']=='.text')
    body=data[text['offset']:text['offset']+text['size']];base=text['address']
    sites=[];index=body.find(b'\xe8')
    while index!=-1:
        if base+index+5+struct.unpack_from('<i',body,index+1)[0]==CALLEE:
            sites.append(base+index)
        index=body.find(b'\xe8',index+1)
    return sites


def parse_asm(asm):
    insns=[]
    for line in asm.splitlines():
        parts=line.split('\t')
        if len(parts)<3 or not parts[0].strip().endswith(':'):
            continue
        try:
            va=int(parts[0].strip()[:-1],16)
        except ValueError:
            continue
        text=parts[2].strip()
        mnemonic=text.split(' ')[0]
        ops=text[len(mnemonic):].strip()
        insns.append((va,mnemonic,ops))
    return insns


def split_ops(ops):
    out,depth,cur=[],0,''
    for ch in ops:
        if ch=='[': depth+=1
        if ch==']': depth-=1
        if ch==',' and depth==0:
            out.append(cur.strip());cur=''
        else:
            cur+=ch
    if cur.strip():
        out.append(cur.strip())
    return out


_WRITE_MNEMONICS={'mov','movups','movaps','movdqa','movdqu','movq',
                  'add','sub','and','or','xor','inc','dec','xadd','cmpxchg'}
_SIZES={'BYTE':1,'WORD':2,'DWORD':4,'QWORD':8,'XMMWORD':16,'YMMWORD':32}


def dest_store(mnemonic,ops):
    """(kind, disp, size, source) if the instruction stores to memory.

    kind is 'rsp' for a pure [rsp+disp] destination, 'indirect' for
    any other memory destination, None for no memory store."""
    if mnemonic not in _WRITE_MNEMONICS or not ops:
        return None
    opl=split_ops(ops)
    if not opl or '[' not in opl[0]:
        return None
    dest=opl[0]
    size=None
    for name,n in _SIZES.items():
        if dest.startswith(name):
            size=n;break
    expr=dest[dest.index('[')+1:dest.index(']')]
    tokens=[t for t in re.split(r'[^a-z0-9]',expr) if t]
    if 'rsp' in tokens:
        if tokens!=['rsp'] and not (len(tokens)==2 and tokens[0]=='rsp'):
            raise ValueError('store census changed: rsp-indexed store')
        m=re.search(r'rsp(?:\+(0x[0-9a-f]+)|-(0x[0-9a-f]+))?',expr)
        disp=0
        if m and m.group(1): disp=int(m.group(1),16)
        if m and m.group(2): disp=-int(m.group(2),16)
        if size is None:
            raise ValueError('store census changed: unsized rsp store')
        return ('rsp',disp,size,opl[1] if len(opl)>1 else None)
    return ('indirect',None,size,opl[1] if len(opl)>1 else None)


def group_store_census(insns):
    """Every direct rsp-relative store whose byte range covers a
    flag-group byte, grouped by group offset, plus store totals."""
    group={0x14:[],0x15:[],0x16:[],0x17:[]}
    rsp_stores=0;indirect_stores=[]
    for va,mnemonic,ops in insns:
        st=dest_store(mnemonic,ops)
        if st is None:
            continue
        kind,disp,size,source=st
        if kind=='indirect':
            indirect_stores.append(va);continue
        rsp_stores+=1
        for g in group:
            if disp<=g<disp+size:
                group[g].append((va,source))
    return {'group':{hex(g):[[hex(va),src] for va,src in sorted(v)]
                     for g,v in group.items()},
            'rsp_store_count':rsp_stores,
            'indirect_store_sites':[hex(v) for v in sorted(indirect_stores)]}


def branch_target(mnemonic,ops):
    if mnemonic.startswith('j') or mnemonic=='call':
        first=split_ops(ops)[0] if ops else ''
        m=re.match(r'^([0-9a-f]+)\s',first+' ')
        if m:
            return int(m.group(1),16)
    return None


def segment_scan(insns,rows,name):
    seg=SEGMENTS[name];lo,hi=seg['range']
    branches=[]
    for va,mnemonic,ops in insns:
        t=branch_target(mnemonic,ops)
        if t is not None:
            branches.append((va,t))
    entry=sorted(va for va,t in branches if t==lo)
    interior=sorted((va,t) for va,t in branches if lo<t<=hi)
    window=[(va,mn,ops) for va,mn,ops in insns if lo<=va<hi]
    stores=[];indirect=[]
    for va,mn,ops in window:
        st=dest_store(mn,ops)
        if st is not None:
            stores.append(va)
            if st[0]=='indirect':
                indirect.append(va)
    pushes=[va for va,mn,ops in window if mn in ('push','pop')]
    # Predecessor instruction (the one ending exactly at lo).
    pred=None
    for va,mn,ops in insns:
        if va<lo and va+len(rows[va])==lo:
            pred=(va,mn,ops);break
    fallthrough=False
    if pred is not None:
        t=branch_target(pred[1],pred[2])
        # Fall-through entry iff the predecessor is a conditional
        # branch whose target leaves the segment (the not-taken path
        # is the write itself).
        fallthrough=(pred[1].startswith('j') and pred[1] not in ('jmp',)
                     and t is not None and not (lo<=t<hi))
    return {'entry_branches':[hex(v) for v in entry],
            'interior_branches':[[hex(v),hex(t)] for v,t in interior],
            'interior_origins_inside':all(lo<=v<hi for v,t in interior),
            'window_store_sites':[hex(v) for v in sorted(stores)],
            'window_indirect_stores':[hex(v) for v in sorted(indirect)],
            'window_push_pop':[hex(v) for v in sorted(pushes)],
            'predecessor':{'site':hex(pred[0]),'mnemonic':pred[1],
                           'target':(hex(branch_target(pred[1],pred[2]))
                                     if branch_target(pred[1],pred[2]) else None)},
            'fallthrough_entry':fallthrough}


def validate_scans(insns,rows):
    census=group_store_census(insns)
    expected_group={'0x14':[[hex(WRITE_A),'0x1'],[hex(WRITE_B),'0x0']],
                    '0x15':[['0x15a3c5e','al']],
                    '0x16':[['0x15a3c55','al']],
                    '0x17':[['0x15a3d14','cl']]}
    if census['group']!=expected_group:
        raise ValueError('store census changed')
    scans={}
    for name,seg in SEGMENTS.items():
        scan=segment_scan(insns,rows,name)
        if scan['entry_branches']!=[hex(v) for v in seg['entry_branches']]:
            raise ValueError(f'segment {name} gating changed')
        if scan['fallthrough_entry']!=seg['fallthrough_entry']:
            raise ValueError(f'segment {name} gating changed')
        if not scan['interior_origins_inside']:
            raise ValueError(f'segment {name} gating changed')
        if scan['window_indirect_stores'] or scan['window_push_pop']:
            raise ValueError(f'segment {name} window store changed')
        scans[name]=scan
    return census,scans


def decoded_consumer(data):
    """Decode the consumer body from a private snapshot of `data` and
    return (insns, rows) with native instruction starts validated."""
    start,end,_=OWNERS['consumer_large']
    _,body=read(data,start,end-start)
    with tempfile.TemporaryDirectory() as directory:
        snapshot=Path(directory)/'node115.elf';snapshot.write_bytes(data)
        asm=subprocess.check_output(['objdump','-d','-M','intel','--insn-width=16',
            f'--start-address={start:#x}',f'--stop-address={end:#x}',
            str(snapshot)],text=True)
    rows=decode_export(asm,start,end,body)
    return parse_asm(asm),rows


def first_byte_value(block):
    """The immediate the segment's entry store writes to the flag
    group's first byte: block A stores 1, block B stores 0."""
    if block not in FIRST_BYTE:
        raise ValueError('unknown field block')
    return FIRST_BYTE[block]


def formatter_selection(flag_byte):
    """The established (pointer, length, bytes) the pointer
    formatter's two tables assign to a flag byte (#2440)."""
    if flag_byte not in SELECTIONS:
        raise ValueError('table index not pinned')
    return SELECTIONS[flag_byte]


def selection_for_block(block):
    """The level name the chain call from a field block selects:
    block A -> byte 1 -> 'Warn'; block B -> byte 0 -> 'Error'."""
    pointer,length,text=formatter_selection(first_byte_value(block))
    return {'block':block,'flag_byte':FIRST_BYTE[block],
            'pointer':hex(pointer),'length':length,'text':text.decode('ascii')}


def consumer_trace(data):
    start,end,_=OWNERS['consumer_large']
    _,body=read(data,start,end-start)
    def pin(va,hx,what): _pin(body,start,va,hx,what)
    def rip(va,ln,at): return _rip(body,start,va,ln,at)
    def rip8(va,ln,at): return _rip8(body,start,va,ln,at)
    # Sentinel constant (rbp for the whole consumer).
    pin(0x15a3bd5,'48bd0000000000000080','sentinel load')
    # Group byte +0x16 (cached flag byte): load pair, store.
    pin(0x15a3bc5,'803d','flag load cmp opcode')
    if rip(0x15a3bc5,7,0x15a3bc5+2)!=0x64f01b0:
        raise ValueError('flag group flag load target changed')
    pin(0x15a3bcc,'0f95c0','flag load setne')
    pin(0x15a3bcf,'2205','flag load and opcode')
    if rip(0x15a3bcf,6,0x15a3bcf+2)!=0x64f01b1:
        raise ValueError('flag group flag load target changed')
    pin(0x15a3c55,'88442416','flag byte store')
    # Group byte +0x15 (derived byte): negate, OR input byte, store.
    pin(0x15a3c59,'3401','derived negate')
    pin(0x15a3c5b,'0a464d','derived or')
    pin(0x15a3c5e,'88442415','derived byte store')
    # Group byte +0x17 (loop counter byte): counter reload/increment
    # at the loop head and the store at the loop top.
    pin(0x15a3cc4,'31c9','counter initial zero')
    pin(0x15a3cf0,'488b8c24c8020000','counter reload')
    pin(0x15a3cf8,'488d4101','counter increment')
    pin(0x15a3d14,'884c2417','counter byte store')
    pin(0x15a3d1c,'48898424c8020000','counter store back')
    # The two first-byte writes (immediate stores, segment entries).
    pin(WRITE_A,'c644241401','first-byte write A')
    pin(WRITE_B,'c644241400','first-byte write B')
    # Segment A gate: r14 = [rsp+0xc0]; cmp r14,rbp; jne write.
    pin(0x15a3dbf,'4c8bb424c0000000','segment A gate load')
    pin(0x15a3edf,'4939ee','segment A gate cmp')
    pin(0x15a3ee2,'752c','segment A gate jne')
    if rip8(0x15a3ee2,2,0x15a3ee2+1)!=WRITE_A:
        raise ValueError('segment A gate target changed')
    pin(0x15a3ef8,'0f84e2050000','segment A gate exit je')
    if rip(0x15a3ef8,6,0x15a3ef8+2)!=0x15a44e0:
        raise ValueError('segment A gate exit target changed')
    pin(0x15a3f0b,'e9d0050000','segment A predecessor jmp')
    if rip(0x15a3f0b,5,0x15a3f0b+1)!=0x15a44e0:
        raise ValueError('segment A predecessor target changed')
    # Segment B gates: both blocks load r14 = [rsp+0x68] and compare
    # against the sentinel; gate A jumps to the write on !=, gate B
    # falls through to it on != (its je exits on ==).
    pin(0x15a4150,'48c744242002000000','segment B gate A mark')
    pin(0x15a4159,'4c8b742468','segment B gate A load')
    pin(0x15a415e,'4939ee','segment B gate A cmp')
    pin(0x15a4161,'0f85a5000000','segment B gate A jne')
    if rip(0x15a4161,6,0x15a4161+2)!=WRITE_B:
        raise ValueError('segment B gate target changed')
    pin(0x15a41f5,'48c744242002000000','segment B gate B mark')
    pin(0x15a41fe,'4c8b742468','segment B gate B load')
    pin(0x15a4203,'4939ee','segment B gate B cmp')
    pin(0x15a4206,'0f84d4020000','segment B gate B exit je')
    if rip(0x15a4206,6,0x15a4206+2)!=0x15a44e0:
        raise ValueError('segment B gate exit target changed')
    # Segment-internal field gates (sentinel field check + derived
    # test), showing both callee-call variants share the segment write.
    pin(0x15a3f15,'4839ac24a0020000','segment A field cmp')
    pin(0x15a3f1d,'7561','segment A field jne')
    if rip8(0x15a3f1d,2,0x15a3f1d+1)!=0x15a3f80:
        raise ValueError('segment A field target changed')
    pin(0x15a3f1f,'f644241501','segment A derived test')
    pin(0x15a3f24,'0f84a8000000','segment A derived je')
    if rip(0x15a3f24,6,0x15a3f24+2)!=0x15a3fd2:
        raise ValueError('segment A derived target changed')
    pin(0x15a4216,'4839ac2498020000','segment B field cmp')
    pin(0x15a421e,'7556','segment B field jne')
    if rip8(0x15a421e,2,0x15a421e+1)!=0x15a4276:
        raise ValueError('segment B field target changed')
    pin(0x15a4220,'f644241501','segment B derived test')
    pin(0x15a4225,'0f849d000000','segment B derived je')
    if rip(0x15a4225,6,0x15a4225+2)!=0x15a42c8:
        raise ValueError('segment B derived target changed')
    # Group pointer materialisation + callee calls.
    for lea,call in zip(LEA_SITES,CALL_SITES):
        pin(lea,'488d4c2414','group lea')
        pin(call,'e8','callee call opcode')
        if rip(call,5,call+1)!=CALLEE:
            raise ValueError('consumer callee call target changed')
    return {'group':{'stack_base':'0x14','bytes':{
                '+0x0':{'stack_offset':'0x14','role':'first byte (formatter index)'},
                '+0x1':{'stack_offset':'0x15','role':'derived byte (#2396)'},
                '+0x2':{'stack_offset':'0x16','role':'cached flag byte (#2317)'},
                '+0x3':{'stack_offset':'0x17','role':'loop counter byte'}}},
            'population':{
                'flag_byte':{'store':'0x15a3c55','loads':['0x15a3bc5','0x15a3bcc','0x15a3bcf']},
                'derived_byte':{'store':'0x15a3c5e','negate':'0x15a3c59','or':'0x15a3c5b'},
                'counter_byte':{'store':'0x15a3d14','reload':'0x15a3cf0',
                                'increment':'0x15a3cf8','store_back':'0x15a3d1c',
                                'initial':'0x15a3cc4'}},
            'first_byte_writes':{
                'A':{'site':hex(WRITE_A),'instruction':'mov BYTE PTR [rsp+0x14],0x1','value':1},
                'B':{'site':hex(WRITE_B),'instruction':'mov BYTE PTR [rsp+0x14],0x0','value':0}},
            'segment_gates':{
                'A':{'load':'0x15a3dbf','loads_from':'[rsp+0xc0]',
                     'cmp':'0x15a3edf','entry_jne':'0x15a3ee2',
                     'entry':'branch on r14 != sentinel (rbp)',
                     'skip_exit_je':'0x15a3ef8','predecessor_jmp':'0x15a3f0b',
                     'skip_target':'0x15a44e0'},
                'B':{'load':'0x15a4159','load_again':'0x15a41fe',
                     'loads_from':'[rsp+0x68]',
                     'cmp':'0x15a415e','cmp_again':'0x15a4203',
                     'entry_jne':'0x15a4161',
                     'entry':'branch on r14 != sentinel (rbp), or '
                             'fall-through past the repeated gate\'s je '
                             'at 0x15a4206 on r14 != sentinel',
                     'skip_exit_je':'0x15a4206','skip_target':'0x15a44e0'}},
            'segment_internals':{
                'A':{'field_cmp':'0x15a3f15','field_jne':'0x15a3f1d',
                     'derived_test':'0x15a3f1f','derived_je':'0x15a3f24'},
                'B':{'field_cmp':'0x15a4216','field_jne':'0x15a421e',
                     'derived_test':'0x15a4220','derived_je':'0x15a4225'}},
            'group_lea_sites':[hex(v) for v in LEA_SITES],
            'callee_call_sites':[hex(v) for v in CALL_SITES]}


def selection_table(data):
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
    return selections


def analyze(data):
    if direct_call_sites(data)!=CALL_SITES:
        raise ValueError('direct call census changed')
    trace=consumer_trace(data)
    insns,rows=decoded_consumer(data)
    census,scans=validate_scans(insns,rows)
    _,fs,_=fde_extents(data);fdes={(f['start'],f['end']):f for f in fs}
    owners=[]
    for role,(a,b,sha) in list(OWNERS.items())+list(BOUNDARIES.items()):
        if (a,b) not in fdes:
            raise ValueError('flag group scope FDE changed')
        offset,raw=read(data,a,b-a)
        if hashlib.sha256(raw).hexdigest()!=sha:
            raise ValueError(f'{role} body changed')
        records={}
        for kind in ['fde','cie']:
            va=fdes[(a,b)][kind];n=struct.unpack('<I',read(data,va,4)[1])[0]+4
            records[kind]={'va':hex(va),'bytes_hex':read(data,va,n)[1].hex()}
        entry={'role':role,'start':hex(a),'end':hex(b),'file_offset':hex(offset),
               'bytes':b-a,'sha256':sha,'frames':records}
        owners.append(entry)
    # Callee boundary pin: the callee stores the group pointer value
    # into its own frame pair block; it does not store through it.
    cs,ce,_=BOUNDARIES['callee']
    _,cbody=read(data,cs,ce-cs)
    _pin(cbody,cs,0x15ae454,'48894c2410','callee pair store')
    selections=selection_table(data)
    return {'target_sha256':SHA,
            'owners':[o for o in owners if o['role'] in OWNERS],
            'boundaries':[o for o in owners if o['role'] in BOUNDARIES],
            'consumer':trace,
            'store_census':census,
            'segments':scans,
            'callee_call_census':{'direct_e8_sites':[hex(v) for v in CALL_SITES],
                                  'all_inside_consumer':True,
                                  'binary_wide':True},
            'formatter_selections':selections,
            'chain_selections':[selection_for_block('A'),selection_for_block('B')],
            'chain_verdict':'The flag group\'s first byte is written by '
                            'the large consumer itself, at exactly two '
                            'immediate store sites, and every callee call '
                            'is gated behind one of them: field block A '
                            'stores 1 before its two callee calls and '
                            'field block B stores 0 before its two. No '
                            'other direct store in the body touches the '
                            'byte, and no store inside either segment '
                            'window overwrites it. Composed with the '
                            'pointer formatter\'s established table, a '
                            'chain call from block A selects "Warn" and '
                            'a chain call from block B selects "Error"; '
                            '"Info" (2) and "Debug" (3) are unreachable '
                            'through this chain, and the formatter\'s '
                            'unchecked index is provably in range for '
                            'this chain because the only stored values '
                            'are 0 and 1.',
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
                raise ValueError('native flag group FDE disagreement')
            lines.extend(rows)
        for fname,(a,b) in WINDOWS.items():
            asm=subprocess.check_output(['objdump','-d','-M','intel','--insn-width=16',f'--start-address={a:#x}',f'--stop-address={b:#x}',str(snapshot)],text=True)
            ins=decode_export(asm,a,b,read(data,a,b-a)[1])
            required=[va for va in ins if a<=va<b]
            if not required:
                raise ValueError('flag group window empty')
            (output/fname).write_bytes(asm.replace(str(snapshot),'<authenticated-node115>').encode('utf-8'))
    (output/'frames.txt').write_bytes(('\n'.join(lines)+'\n').encode('utf-8'))
    (output/'records.json').write_bytes((json.dumps(report,indent=2)+'\n').encode('utf-8'))
    return report


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary',type=Path,default=TARGET)
    p.add_argument('--output',type=Path,default=ROOT/'work/flag-group-first-byte115')
    args=p.parse_args();report=generate(args.binary,args.output)
    print(json.dumps({'functions':len(report['owners']),'bytes':sum(x['bytes'] for x in report['owners']),'executed':False}))
