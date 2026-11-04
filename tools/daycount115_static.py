"""Authenticated node115 raw-day constructor, inert original ELF only."""
from pathlib import Path
import hashlib,json,struct
from evm_amount_scale import Image
from fde_extents import eh_frame_records
ROOT=Path(__file__).resolve().parents[1]
TARGET=ROOT/'artifacts/node/115/hl-node'
SHA256='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
START,END=0x1628f50,0x16290ca
BODY_SHA256='3e1c87803439d929d85b9ff77ea4ba6fca238fe6584dfdcea4ea56e4a353581d'
TABLE1_VA,TABLE2_VA=0x46bcaa,0x46be3b
Reader=Image

def require(ok,message):
    if not ok:raise ValueError(message)

def days_from_civil(year,month,day):
    """Mathematical proleptic Gregorian days since1970; astronomical years.

    Python // is floor division: no additional negative-year truncation repair.
    This is an independently written calendar cross-check, not captured code.
    """
    require(type(year) is int and type(month) is int and type(day) is int,'Integer date required')
    require(1<=month<=12 and 1<=day<=31,'Bounded calendar fields required')
    year-=int(month<=2);era=year//400;y=year-era*400
    doy=(153*(month+(-3 if month>2 else 9))+2)//5+day-1
    return era*146097+y*365+y//4-y//100+doy-719468

def analyze(data,strict=True):
    if strict:require(len(data)==105896032 and hashlib.sha256(data).hexdigest()==SHA256,'Wrong captured target')
    im=Image(data);_,frames=eh_frame_records(data);found=[f for f in frames if f['start']==START]
    require(len(found)==1 and found[0]['end']==END,'Native constructor FDE changed')
    require(not any(f['start']<END and f['end']>START and f!=found[0] for f in frames),'Overlapping native FDE')
    body=im.read(START,END-START)
    if strict:require(hashlib.sha256(body).hexdigest()==BODY_SHA256,'Native constructor body changed')
    from capstone import Cs,CS_ARCH_X86,CS_MODE_64,CS_OP_MEM
    cs=Cs(CS_ARCH_X86,CS_MODE_64);cs.detail=True;instructions=list(cs.disasm(body,START))
    require(sum(i.size for i in instructions)==len(body),'Incomplete native export')
    rips=[]
    for i in instructions:
        for op in i.operands:
            if op.type==CS_OP_MEM and i.reg_name(op.mem.base)=='rip':rips.append(dict(site=hex(i.address),target=hex(i.address+i.size+op.mem.disp),mnemonic=i.mnemonic,bytes=i.bytes.hex()))
    expected=[(0x1628fb5,TABLE1_VA),(0x162905b,TABLE2_VA),(0x1629089,0x64053c0),(0x1629090,0x64df848),(0x1629096,0x6405420),(0x16290a2,0x64df620),(0x16290a8,0x64053d8),(0x16290b7,0x64df620),(0x16290bd,0x64053f0),(0x16290c4,0x64df520)]
    require([(int(r['site'],16),int(r['target'],16)) for r in rips]==expected,'Native RIP/call mapping changed')
    tables=[]
    for va,size,digest in [(TABLE1_VA,401,'25aaa39a8eb1ce46f7d87855944e78f393cc34f6077d322918ad212015ad9f46'),(TABLE2_VA,400,'d4998d79b18634a4227880dc249c5744dc4e028a3829363494a6a3a2e1cc82f4')]:
        b=im.read(va,size)
        if strict:require(hashlib.sha256(b).hexdigest()==digest,'Native date table changed')
        tables.append(dict(va=hex(va),bytes=size,sha256=hashlib.sha256(b).hexdigest(),bytes_hex=b.hex()))
    if strict:
        def leap(y):return y%4==0 and (y%100!=0 or y%400==0)
        generated_leaps=bytes(sum(leap(y) for y in range(i)) for i in range(401))
        generated_flags=bytes((0 if leap(y) else 8)|((days_from_civil(y,1,1)-days_from_civil(0,1,1)+3)%7+1) for y in range(400))
        require(im.read(TABLE1_VA,401)==generated_leaps,'Gregorian leap-table cross-check failed')
        require(im.read(TABLE2_VA,400)==generated_flags,'Gregorian flag-table cross-check failed')
    _,ro,rs=im.section('.rela.dyn');require(rs%24==0 and ro+rs<=len(data),'Truncated relocations')
    reloc=list(struct.iter_unpack('<QQq',data[ro:ro+rs]))
    def relative(slot):
        rows=[r for r in reloc if r[0]==slot];require(len(rows)==1 and rows[0][1]==8 and rows[0][2]>=0,'Unique RELATIVE relocation required');return rows[0]
    locations=[]
    for va,path,line,column in [(0x64053c0,'date/mod.rs',2325,9),(0x6405420,'internals.rs',80,9),(0x64053d8,'date/mod.rs',2326,27),(0x64053f0,'date/mod.rs',2326,9)]:
        raw=im.read(va,24);zero,length,l,c=struct.unpack('<QQII',raw);rr=relative(va);name=im.read(rr[2],length).decode('utf8')
        require(zero==0 and name=='/home/ubuntu/hl/code_Mainnet/z_vendor/chrono/src/naive/'+path and (l,c)==(line,column),'Vendored native Location changed')
        locations.append(dict(va=hex(va),raw=raw.hex(),path=name,line=l,column=c,relocation=list(rr)))
    panics=[]
    for slot,address in [(0x64df848,0x1681e40),(0x64df620,0x1680cbf),(0x64df520,0x1681da0)]:
        rr=relative(slot);require(rr[2]==address,'Panic relocation target changed');fs=[f for f in frames if f['start']==address];require(len(fs)==1,'Panic FDE not unique')
        panics.append(dict(slot=hex(slot),address=hex(address),fde=fs[0],body_sha256=hashlib.sha256(im.read(address,fs[0]['end']-address)).hexdigest(),relocation=list(rr)))
    f=found[0];raw_frames={}
    for kind in ('fde','cie'):
        va=f[kind];length=int.from_bytes(im.read(va,4),'little')+4;raw_frames[kind]=dict(va=hex(va),bytes_hex=im.read(va,length).hex())
    return dict(target_sha256=SHA256,owner=dict(start=hex(START),end=hex(END),bytes=len(body),instructions=len(instructions),sha256=hashlib.sha256(body).hexdigest(),frames=raw_frames),rips=rips,tables=tables,locations=locations,panic_boundaries=panics,original_instruction_export=[f'{i.address:x}: {i.bytes.hex()} {i.mnemonic} {i.op_str}'.rstrip() for i in instructions],limits='Raw i32-to-packed-u32 constructor only. Vendored path is observed, source version not established. Panic helpers, callers, typed ABI and full node remain unclosed. No captured execution.')
