#!/usr/bin/env python3
"""RE-015: digest-bound node115 callee 0x15ae430 of the derived flag byte."""
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
PACKET=ROOT/'research/work-items/RE-015-node115-derived-byte-callee'
SHA='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
OWNERS={
 'callee':(0x15ae430,0x15ae5ae,'4cfb1633d772df3d0e75abf5864ea242a85e7732e479b5351ae80c97842d7acf'),
 'consumer_large':(0x15a3b90,0x15a6509,'7995f7af57e2be27ca6ed1e307d9bcce9d6140f72b0ff0cf0804d7f09e5505fb')}
CALLEE=0x15ae430
CONSUMER=0x15a3b90
SENTINEL=0x8000000000000000
CALL_SITES=[0x15a3f5f,0x15a401e,0x15a4263,0x15a431c]
SLOT_CALL_A=0x64df6e8
CALL_A_TARGET=0x141e3a0
SLOT_CALL_B=0x64df650
CALL_B_TARGET=0x141cc40
SLOT_DEALLOC=0x64df4a0
DEALLOC_TARGET=0x635de30
GLOBAL_PAIR=0x64e1490
GLOBAL_PAIR_VALUE=0x16035e0
GLOBAL_RECORD=0x64e0b68
GLOBAL_RECORD_VALUE=0x150ce90
RECORD_FN_1=0x1500960
RECORD_FN_2=0x1598e40
ARG_VALUE_1=0x43b857
ARG_VALUE_2=0x440e47
UNWIND_RESUME=0x63f0a50
LIMITS=('Callee behaviour for the derived-byte-selected record only: the entry split on the '
 'rsi argument (zero copies the record to the output, nonzero builds the output and drops '
 'the record under the pinned guard), the consumer-side selection of that record by bit 0 '
 'of the derived byte at its two field blocks, and the four direct call sites. What the two '
 'calls through slot 0x64df6e8 compute with the flag-group pointer, what the pair and the '
 'constructed record fields mean, and the record contents beyond the first qword\'s guard '
 'role are NOT established by these bytes. The flag and derived bytes\' construction is '
 'owned by the RE-015 scratch-name-pair packet and is cited here, not re-derived. '
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
    callee_hits = []
    for a, i, v in struct.iter_unpack('<QQq', data[sec['offset']:sec['offset'] + sec['size']]):
        by_offset.setdefault(a,[]).append((i,v))
        if v==CALLEE:
            callee_hits.append(a)
    return by_offset,callee_hits


def slot_bindings(data):
    by_offset,_=relocations(data)
    expected={SLOT_CALL_A:CALL_A_TARGET,SLOT_CALL_B:CALL_B_TARGET,SLOT_DEALLOC:DEALLOC_TARGET,
              GLOBAL_PAIR:GLOBAL_PAIR_VALUE,GLOBAL_RECORD:GLOBAL_RECORD_VALUE}
    out={}
    for slot,target in expected.items():
        if by_offset.get(slot)!=[(8,target)]:
            raise ValueError('slot binding changed')
        out[hex(slot)]=hex(target)
    return out


def drop_guard_fires(first_qword):
    """Model of the callee record-drop guard at 0x15ae524: the dealloc call
    runs iff the record's first qword is neither 0 (neg clears CF) nor the
    sentinel 0x8000000000000000 (neg overflows)."""
    return first_qword not in (0,SENTINEL)


def record_variant(derived_byte):
    """Model of the consumer selection at 0x15a3f1f/0x15a4220: bit 0 of the
    derived byte selects the record whose first qword is the sentinel."""
    return 'sentinel' if derived_byte & 1 else 'register'


def address_as_data_count(data):
    """Occurrences of the callee VA as an 8-byte little-endian value outside
    the .rela.dyn byte range (relocation addends are counted separately)."""
    sec = next((s for s in sections(data) if s['name'] == '.rela.dyn'), None)
    if sec is None:
        raise ValueError('missing.rela.dyn section')
    needle=struct.pack('<Q',CALLEE);count=0;index=data.find(needle)
    while index!=-1:
        if not (sec['offset']<=index<sec['offset']+sec['size']):
            count+=1
        index=data.find(needle,index+1)
    return count


def direct_call_sites(data):
    text = next((s for s in sections(data) if s['name'] == '.text'), None)
    if text is None:
        raise ValueError('missing.text section')
    body=data[text['offset']:text['offset']+text['size']];base=text['address']
    sites=[];index=body.find(b'\xe8')
    while index!=-1:
        if base+index+5+struct.unpack_from('<i',body,index+1)[0]==CALLEE:
            sites.append(base+index)
        index=body.find(b'\xe8',index+1)
    return sites


def _pin(body,base,va,hexbytes,what,who):
    off=va-base;want=bytes.fromhex(hexbytes)
    if body[off:off+len(want)]!=want:
        raise ValueError(f'{who} {what} changed')


def _rip(body,base,va,insn_len,disp_at):
    return va+insn_len+struct.unpack_from('<i',body,disp_at-base)[0]


def _rip8(body,base,va,insn_len,disp_at):
    return va+insn_len+struct.unpack_from('<b',body,disp_at-base)[0]


def callee_trace(data):
    start,end,_=OWNERS['callee']
    _,body=read(data,start,end-start)
    def pin(va,hx,what): _pin(body,start,va,hx,what,'callee')
    def rip(va,ln,at): return _rip(body,start,va,ln,at)
    def rip8(va,ln,at): return _rip8(body,start,va,ln,at)
    # Entry: rdx (record) saved to rbx, rdi (output) to r14, rsi tested.
    pin(0x15ae43d,'4889d3','record save')
    pin(0x15ae440,'4989fe','output save')
    pin(0x15ae443,'4885f6','entry test')
    pin(0x15ae446,'0f84','entry branch opcode')
    if rip(0x15ae446,6,0x15ae446+2)!=0x15ae53f:
        raise ValueError('callee entry branch target changed')
    pin(0x15ae44c,'4d89c7','aux save')
    # Pair store: (rsi, rcx flag-group pointer, global) at [rsp+0x8..0x20].
    pin(0x15ae44f,'4889742408','pair first store')
    pin(0x15ae454,'48894c2410','pair group-pointer store')
    pin(0x15ae459,'488b05','pair global load opcode')
    if rip(0x15ae459,7,0x15ae459+3)!=GLOBAL_PAIR:
        raise ValueError('callee pair global slot changed')
    pin(0x15ae460,'4889442418','pair global store')
    # Call A #1: rsi=value 1, rdi=&[rsp+0x28], rdx=&[rsp+0x10].
    pin(0x15ae465,'488d35','call A1 value opcode')
    if rip(0x15ae465,7,0x15ae465+3)!=ARG_VALUE_1:
        raise ValueError('callee call A1 value changed')
    pin(0x15ae46c,'488d7c2428','call A1 out')
    pin(0x15ae471,'488d542410','call A1 argument')
    pin(0x15ae476,'ff15','call A1 opcode')
    if rip(0x15ae476,6,0x15ae476+2)!=SLOT_CALL_A:
        raise ValueError('callee call A1 slot changed')
    # Call B: rdi=&[rsp+0x58], rsi=call-A1 result word.
    pin(0x15ae47c,'4c8b642430','call B input load')
    pin(0x15ae481,'488b542438','call B input load 2')
    pin(0x15ae486,'4c8d6c2458','call B out')
    pin(0x15ae491,'ff15','call B opcode')
    if rip(0x15ae491,6,0x15ae491+2)!=SLOT_CALL_B:
        raise ValueError('callee call B slot changed')
    # Drop #1: call-A1 result word, if nonzero, through the dealloc slot.
    pin(0x15ae497,'488b742428','drop 1 test load')
    pin(0x15ae49c,'4885f6','drop 1 test')
    pin(0x15ae49f,'740b','drop 1 branch')
    if rip8(0x15ae49f,2,0x15ae49f+1)!=0x15ae4ac:
        raise ValueError('callee drop 1 branch target changed')
    pin(0x15ae4a1,'4c89e7','drop 1 argument')
    pin(0x15ae4a4,'31d2','drop 1 zero')
    pin(0x15ae4a6,'ff15','drop 1 opcode')
    if rip(0x15ae4a6,6,0x15ae4a6+2)!=SLOT_DEALLOC:
        raise ValueError('callee drop 1 slot changed')
    # Constructed record at [rsp+0x28]: {&pair, fn1, &call-B out, fn2, r8 aux, global}.
    pin(0x15ae4ac,'488d442408','record pair pointer')
    pin(0x15ae4b1,'4889442428','record pair store')
    pin(0x15ae4b6,'488d05','record fn 1 opcode')
    if rip(0x15ae4b6,7,0x15ae4b6+3)!=RECORD_FN_1:
        raise ValueError('callee record fn 1 changed')
    pin(0x15ae4bd,'4889442430','record fn 1 store')
    pin(0x15ae4c2,'4c896c2438','record third store')
    pin(0x15ae4c7,'488d05','record fn 2 opcode')
    if rip(0x15ae4c7,7,0x15ae4c7+3)!=RECORD_FN_2:
        raise ValueError('callee record fn 2 changed')
    pin(0x15ae4ce,'4889442440','record fn 2 store')
    pin(0x15ae4d3,'4c897c2448','record aux store')
    pin(0x15ae4d8,'488b05','record global load opcode')
    if rip(0x15ae4d8,7,0x15ae4d8+3)!=GLOBAL_RECORD:
        raise ValueError('callee record global slot changed')
    pin(0x15ae4df,'4889442450','record global store')
    # Call A #2: rsi=value 2, rdi=&[rsp+0x10], rdx=&record.
    pin(0x15ae4e4,'488d35','call A2 value opcode')
    if rip(0x15ae4e4,7,0x15ae4e4+3)!=ARG_VALUE_2:
        raise ValueError('callee call A2 value changed')
    pin(0x15ae4eb,'488d7c2410','call A2 out')
    pin(0x15ae4f0,'488d542428','call A2 argument')
    pin(0x15ae4f5,'ff15','call A2 opcode')
    if rip(0x15ae4f5,6,0x15ae4f5+2)!=SLOT_CALL_A:
        raise ValueError('callee call A2 slot changed')
    # Output store: 24 bytes from [rsp+0x10] to r14.
    pin(0x15ae4fb,'488b442420','output third load')
    pin(0x15ae500,'49894610','output third store')
    pin(0x15ae504,'0f10442410','output copy load')
    pin(0x15ae509,'410f1106','output copy store')
    # Drop #2: call-B result word, if nonzero, through the dealloc slot.
    pin(0x15ae50d,'488b742458','drop 2 test load')
    pin(0x15ae512,'4885f6','drop 2 test')
    pin(0x15ae515,'740d','drop 2 branch')
    if rip8(0x15ae515,2,0x15ae515+1)!=0x15ae524:
        raise ValueError('callee drop 2 branch target changed')
    pin(0x15ae517,'488b7c2460','drop 2 argument')
    pin(0x15ae51c,'31d2','drop 2 zero')
    pin(0x15ae51e,'ff15','drop 2 opcode')
    if rip(0x15ae51e,6,0x15ae51e+2)!=SLOT_DEALLOC:
        raise ValueError('callee drop 2 slot changed')
    # Record drop guard: c=[rbx]; jo on neg overflow (sentinel), jae on
    # neg carry-clear (zero); otherwise dealloc (rdi=[rbx+8], edx=0).
    pin(0x15ae524,'488b33','guard load')
    pin(0x15ae527,'4889f0','guard copy')
    pin(0x15ae52a,'48f7d8','guard neg')
    pin(0x15ae52d,'701f','guard jo')
    if rip8(0x15ae52d,2,0x15ae52d+1)!=0x15ae54e:
        raise ValueError('callee guard jo target changed')
    pin(0x15ae52f,'731d','guard jae')
    if rip8(0x15ae52f,2,0x15ae52f+1)!=0x15ae54e:
        raise ValueError('callee guard jae target changed')
    pin(0x15ae531,'488b7b08','record drop argument')
    pin(0x15ae535,'31d2','record drop zero')
    pin(0x15ae537,'ff15','record drop opcode')
    if rip(0x15ae537,6,0x15ae537+2)!=SLOT_DEALLOC:
        raise ValueError('callee record drop slot changed')
    pin(0x15ae53d,'eb0f','record drop jump')
    # Copy path (rsi == 0): the 24-byte record is copied verbatim to r14.
    pin(0x15ae53f,'488b4310','copy third load')
    pin(0x15ae543,'49894610','copy third store')
    pin(0x15ae547,'0f1003','copy load')
    pin(0x15ae54a,'410f1106','copy store')
    pin(0x15ae54e,'4883c470','epilogue')
    # Unwind pads and the mirrored guard before _Unwind_Resume.
    for pad in (0x15ae55c,0x15ae570,0x15ae58a):
        pin(pad,'4989c6','unwind pad save')
    pin(0x15ae58d,'488b33','unwind guard load')
    pin(0x15ae593,'48f7d8','unwind guard neg')
    pin(0x15ae596,'700e','unwind guard jo')
    if rip8(0x15ae596,2,0x15ae596+1)!=0x15ae5a6:
        raise ValueError('callee unwind guard jo target changed')
    pin(0x15ae598,'730c','unwind guard jae')
    if rip8(0x15ae598,2,0x15ae598+1)!=0x15ae5a6:
        raise ValueError('callee unwind guard jae target changed')
    pin(0x15ae59a,'488b7b08','unwind drop argument')
    pin(0x15ae5a0,'ff15','unwind drop opcode')
    if rip(0x15ae5a0,6,0x15ae5a0+2)!=SLOT_DEALLOC:
        raise ValueError('callee unwind drop slot changed')
    pin(0x15ae5a9,'e8','unwind resume opcode')
    if rip(0x15ae5a9,5,0x15ae5a9+1)!=UNWIND_RESUME:
        raise ValueError('callee unwind resume target changed')
    return {'entry_split':{'test':'0x15ae443','branch':'0x15ae446','zero_path':'0x15ae53f'},
            'pair_store':{'offsets':['0x8','0x10','0x18'],'group_pointer_word':'0x10',
                          'global_slot':hex(GLOBAL_PAIR)},
            'calls':[{'site':'0x15ae476','slot':hex(SLOT_CALL_A),'value':'0x43b857'},
                     {'site':'0x15ae491','slot':hex(SLOT_CALL_B)},
                     {'site':'0x15ae4f5','slot':hex(SLOT_CALL_A),'value':'0x440e47'}],
            'record_fields':{'pair_pointer':'&[rsp+0x8]','fn_1':hex(RECORD_FN_1),
                             'third':'&[rsp+0x58]','fn_2':hex(RECORD_FN_2),
                             'aux':'r8 argument','global_slot':hex(GLOBAL_RECORD)},
            'conditional_drops':[{'site':'0x15ae4a6','word':'[rsp+0x28]'},
                                  {'site':'0x15ae51e','word':'[rsp+0x58]'}],
            'record_drop_guard':{'load':'0x15ae524','neg':'0x15ae52a','jo':'0x15ae52d',
                                  'jae':'0x15ae52f','call':'0x15ae537',
                                  'slot':hex(SLOT_DEALLOC),
                                  'fires_iff':'first qword not in {0, 0x8000000000000000}'},
            'copy_path':{'loads':['0x15ae53f','0x15ae547'],'stores':['0x15ae543','0x15ae54a']},
            'unwind_guard':{'load':'0x15ae58d','call':'0x15ae5a0','resume':'0x15ae5a9'}}


def consumer_derived_trace(data):
    start,end,_=OWNERS['consumer_large']
    _,body=read(data,start,end-start)
    def pin(va,hx,what): _pin(body,start,va,hx,what,'consumer')
    def rip(va,ln,at): return _rip(body,start,va,ln,at)
    # Sentinel constant for the whole consumer.
    pin(0x15a3bd5,'48bd0000000000000080','sentinel load')
    # rsi argument provenance: lea rdx,[rsi+0x30]; xor edi,edi;
    # cmp rdi,[rsi+0x30] (flags of 0 - field: overflow iff field == sentinel);
    # cmovo rdx,rdi; store to [rsp+0x1a8], the rsi of all four calls.
    pin(0x15a3c34,'488d5630','rsi provenance lea')
    pin(0x15a3c38,'31ff','rsi provenance zero')
    pin(0x15a3c3a,'483b7e30','rsi provenance cmp')
    pin(0x15a3c3e,'480f40d7','rsi provenance cmovo')
    pin(0x15a3c42,'48899424a8010000','rsi provenance store')
    # Group byte +0 (tag): 1 in field block A, 0 in field block B.
    pin(0x15a3f10,'c644241401','block A tag store')
    pin(0x15a420c,'c644241400','block B tag store')
    # Derived-byte tests: bit 0 selects the record variant per block.
    tests=[]
    for site,je,reg in [(0x15a3f1f,0x15a3f24,0x15a3fd2),(0x15a4220,0x15a4225,0x15a42c8)]:
        pin(site,'f644241501','derived byte test')
        pin(je,'0f84','derived byte branch opcode')
        if rip(je,6,je+2)!=reg:
            raise ValueError('consumer derived byte branch target changed')
        tests.append({'site':hex(site),'register_variant':hex(reg),
                      'sentinel_variant':hex(je+6)})
    # Sentinel record variant: only the first qword is stored (the sentinel).
    for site in (0x15a3f2a,0x15a422b):
        pin(site,'4889ac24c0000000','sentinel record store')
    # Register record variant A: {r14, r15, rbx}.
    pin(0x15a3fd2,'4c89b424c0000000','register record A first')
    pin(0x15a3fda,'4c89bc24c8000000','register record A second')
    pin(0x15a3fe2,'48899c24d0000000','register record A third')
    # Register record variant B: {r14, r15, [rsp+0x78]}.
    pin(0x15a42c8,'488b442478','register record B third load')
    pin(0x15a42cd,'4c89b424c0000000','register record B first')
    pin(0x15a42d5,'4c89bc24c8000000','register record B second')
    pin(0x15a42dd,'48898424d0000000','register record B third')
    # Shared call setup per site and the call itself.
    setups=[]
    for lea_rdi,mov_rsi,lea_rdx,lea_rcx,lea_r8,call in [
            (0x15a3f3a,0x15a3f42,0x15a3f4a,0x15a3f52,0x15a3f57,0x15a3f5f),
            (0x15a3ff2,0x15a3ffa,0x15a4002,0x15a400a,0x15a400f,0x15a401e),
            (0x15a423e,0x15a4246,0x15a424e,0x15a4256,0x15a425b,0x15a4263),
            (0x15a42f0,0x15a42f8,0x15a4300,0x15a4308,0x15a430d,0x15a431c)]:
        pin(lea_rdi,'488dbc2458010000','call out lea')
        pin(mov_rsi,'488bb424a8010000','call rsi load')
        pin(lea_rdx,'488d9424c0000000','call record lea')
        pin(lea_rcx,'488d4c2414','call group lea')
        pin(lea_r8,'4c8d84243c010000','call aux lea')
        pin(call,'e8','call opcode')
        if rip(call,5,call+1)!=CALLEE:
            raise ValueError('consumer call target changed')
        setups.append({'call':hex(call),'out':'[rsp+0x158]','record':'[rsp+0xc0]',
                       'group':'[rsp+0x14]','aux':'[rsp+0x13c]'})
    return {'sentinel':'0x8000000000000000',
            'rsi_provenance':{'lea':'0x15a3c34','cmp':'0x15a3c3a','cmovo':'0x15a3c3e',
                              'store':'0x15a3c42','stack_offset':'0x1a8',
                              'rule':'rsi = 0 iff input qword at +0x30 == sentinel, else &input+0x30'},
            'group':{'stack_base':'0x14','tag_offset':'0x14','derived_offset':'0x15',
                     'flag_offset':'0x16'},
            'derived_tests':tests,
            'sentinel_record_stores':['0x15a3f2a','0x15a422b'],
            'register_record_stores':{'A':['0x15a3fd2','0x15a3fda','0x15a3fe2'],
                                      'B':['0x15a42cd','0x15a42d5','0x15a42dd']},
            'call_setups':setups}


def analyze(data):
    _,fs,_=fde_extents(data);fdes={(f['start'],f['end']):f for f in fs}
    by_offset,callee_hits=relocations(data)
    if callee_hits:
        raise ValueError('callee relocation reference appeared')
    bindings=slot_bindings(data)
    sites=direct_call_sites(data)
    if sites!=CALL_SITES:
        raise ValueError('direct call census changed')
    if address_as_data_count(data)!=0:
        raise ValueError('callee address-as-data reference appeared')
    cs,ce,_=OWNERS['consumer_large']
    if any(not (cs<=s<ce) for s in sites):
        raise ValueError('direct call census changed')
    owners=[]
    for role,(a,b,sha) in OWNERS.items():
        if (a,b) not in fdes:
            raise ValueError('derived-byte scope FDE changed')
        offset,raw=read(data,a,b-a)
        if hashlib.sha256(raw).hexdigest()!=sha:
            raise ValueError(f'{role} body changed')
        records={}
        for kind in ['fde','cie']:
            va=fdes[(a,b)][kind];n=struct.unpack('<I',read(data,va,4)[1])[0]+4
            records[kind]={'va':hex(va),'bytes_hex':read(data,va,n)[1].hex()}
        owners.append({'role':role,'start':hex(a),'end':hex(b),'file_offset':hex(offset),'bytes':b-a,'sha256':sha,'frames':records})
    return {'target_sha256':SHA,'owners':owners,
            'callee':callee_trace(data),
            'consumer_derived':consumer_derived_trace(data),
            'slot_bindings':bindings,
            'direct_callers':{'count':len(sites),'sites':[hex(s) for s in sites],
                              'containing_fde':'consumer_large',
                              'relocation_references':0,'address_as_data':0},
            'guard_model':{'fires_iff':'first qword not in {0, 0x8000000000000000}',
                           'sentinel_record':'never fires (neg overflow)',
                           'zero_record':'never fires (neg carry clear)'},
            'variant_model':{'rule':'derived byte bit 0 == 1 -> sentinel record; == 0 -> register record',
                              'scratch_names':'derived byte is odd for every input byte, so both field blocks always take the sentinel record'},
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
                raise ValueError('native derived-byte FDE disagreement')
            lines.extend(rows)
            asm=subprocess.check_output(['objdump','-d','-M','intel','--insn-width=16',f'--start-address={a:#x}',f'--stop-address={b:#x}',str(snapshot)],text=True)
            ins=decode_export(asm,a,b,read(data,a,b-a)[1])
            if role=='callee':
                required=[0x15ae430,0x15ae43d,0x15ae443,0x15ae446,0x15ae44f,0x15ae454,0x15ae459,
                          0x15ae465,0x15ae476,0x15ae491,0x15ae4a6,0x15ae4b6,0x15ae4c7,0x15ae4d8,
                          0x15ae4f5,0x15ae500,0x15ae51e,0x15ae524,0x15ae52a,0x15ae52d,0x15ae52f,
                          0x15ae537,0x15ae53f,0x15ae543,0x15ae547,0x15ae54e,0x15ae58d,0x15ae5a9]
                if not set(required)<=set(ins):
                    raise ValueError('callee evidence site not native instruction start')
                (output/'callee.objdump.txt').write_bytes(asm.replace(str(snapshot),'<authenticated-node115>').encode('utf-8'))
            else:
                # No 10,617-byte consumer export is retained; its derived-byte
                # sites are validated as native instruction starts instead.
                required=[0x15a3bd5,0x15a3c34,0x15a3c3a,0x15a3c3e,0x15a3c42,0x15a3f10,0x15a3f1f,
                          0x15a3f24,0x15a3f2a,0x15a3f3a,0x15a3f42,0x15a3f4a,0x15a3f52,0x15a3f57,
                          0x15a3f5f,0x15a3fd2,0x15a3fda,0x15a3fe2,0x15a3ff2,0x15a3ffa,0x15a4002,
                          0x15a400a,0x15a400f,0x15a401e,0x15a420c,0x15a4220,0x15a4225,0x15a422b,
                          0x15a423e,0x15a4246,0x15a424e,0x15a4256,0x15a425b,0x15a4263,0x15a42c8,
                          0x15a42cd,0x15a42d5,0x15a42dd,0x15a42f0,0x15a42f8,0x15a4300,0x15a4308,
                          0x15a430d,0x15a431c]
                if not set(required)<=set(ins):
                    raise ValueError('consumer derived-byte site not native instruction start')
    (output/'frames.txt').write_bytes(('\n'.join(lines)+'\n').encode('utf-8'))
    (output/'records.json').write_bytes((json.dumps(report,indent=2)+'\n').encode('utf-8'))
    return report


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary',type=Path,default=TARGET)
    p.add_argument('--output',type=Path,default=ROOT/'work/derived-byte-callee115')
    args=p.parse_args();report=generate(args.binary,args.output)
    print(json.dumps({'functions':len(report['owners']),'bytes':sum(x['bytes'] for x in report['owners']),'executed':False}))
