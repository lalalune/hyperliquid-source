"""Interpret only our compiled Rust scalar body, never the captured target."""
from pathlib import Path
import sys

import evm_amount_scale as engine
import daycount115_static as target

class NoExternalMemory:
    def in_rodata(self,*args): return False
    def read(self,*args): raise engine.Unmodelled('Own Rust scalar cannot read external memory')

class DateMachine(engine.Machine):
    # Only own compiled scalar instructions enter this scoped extension.
    def i_movsxd(self,ops):
        if ops[0][0]!='r' or self.size(ops[0])!=8 or ops[1][0]!='r' or self.size(ops[1])!=4:raise engine.Unmodelled('Only observed own-code movsxd32to64')
        self.wr(ops[0],engine.signed(self.rd(ops[1]),32))
    def i_ror(self,ops):
        if self.size(ops[0])!=4 or ops[1][0]!='i' or self.rd(ops[1])!=2:
            raise engine.Unmodelled('Only observed own-code ror32 by2 is modeled')
        value=self.rd(ops[0]);result=((value>>2)|(value<<30))&0xffffffff
        self.wr(ops[0],result);self.cf=bool(result&(1<<31));self.of=None

def own_machine(path,machine_type=DateMachine):
    data=Path(path).read_bytes()
    if len(data)<64:raise ValueError("Truncated own Rust object")
    if data[:6]!=b'\x7fELF\x02\x01' or int.from_bytes(data[16:18],'little')!=1 or int.from_bytes(data[18:20],'little')!=62:
        raise ValueError('Expected our Linux x86-64 relocatable Rust object')
    image=engine.Image(data)
    if any(name.startswith(('.rela.text','.rel.text')) for name in image.sec):
        raise ValueError('External code relocations are not supported')
    text=[(name,section) for name,section in image.sec.items() if name.startswith('.text') and section[2]]
    if len(text)!=1 or text[0][0]!='.text.node115_date_from_ce_days':
        raise ValueError('Exactly one known Rust scalar section required')
    _,(_,offset,size)=text[0];body=data[offset:offset+size]
    from capstone import Cs,CS_ARCH_X86,CS_MODE_64,CS_OP_REG,CS_OP_IMM,CS_OP_MEM
    cs=Cs(CS_ARCH_X86,CS_MODE_64);cs.detail=True
    instructions=list(cs.disasm(body,0x100000));rows=[]
    if sum(i.size for i in instructions)!=len(body):raise ValueError('Incomplete own-object decoding')
    for ins in instructions:
        operands=[]
        for op in ins.operands:
            if op.type==CS_OP_REG:
                register,width=engine.REGS[ins.reg_name(op.reg)]
                operands.append(('r',register,width))
            elif op.type==CS_OP_IMM:operands.append(('i',op.imm))
            elif op.type==CS_OP_MEM:
                if ins.reg_name(op.mem.base)=='rip':raise ValueError('External data reference')
                base=engine.REGS[ins.reg_name(op.mem.base)][0] if op.mem.base else None
                index=engine.REGS[ins.reg_name(op.mem.index)][0] if op.mem.index else None
                operands.append(('m',op.size,base,index,op.mem.scale,op.mem.disp))
            else:raise ValueError('Unsupported operand')
        if ins.mnemonic=='call':raise ValueError('Opaque compiled helper call')
        rows.append((ins.address,ins.mnemonic,tuple(operands),ins.address+ins.size))
    return machine_type(rows,NoExternalMemory(),{}),body,instructions

def evaluate_day(machine,day):
    if type(day) is not int or not -(1<<31)<=day<(1<<31):raise ValueError('raw i32 day required')
    machine.reset();machine.setreg(engine.RSP,engine.STACK_TOP)
    machine.store(engine.STACK_TOP,8,engine.RET_MAGIC);machine.setreg(engine.RDI,day&0xffffffff)
    saved={r:0x1122334400000000+r for r in (engine.RBX,engine.RBP,engine.R12,engine.R13,engine.R14,engine.R15)}
    for r,v in saved.items():machine.setreg(r,v)
    if machine.run(0x100000,limit=5000)!=engine.RET_MAGIC:raise ValueError('Own scalar did not return')
    if machine.known[engine.RAX]&0xffffffff!=0xffffffff:raise ValueError('Unset raw date result')
    for r,v in saved.items():
        if machine.known[r]!=engine.MASK or machine.regs[r]!=v:raise ValueError('Own callee-saved register changed')
    return machine.regs[engine.RAX]&0xffffffff

class NativeDateOracle:
    """Lower original integer transfers and read original tables; no target run."""
    def __init__(self,data,strict=True):
        import hashlib
        if strict and hashlib.sha256(data).hexdigest()!=target.SHA256:raise ValueError('Wrong captured target')
        self.records=target.analyze(data,strict=strict);self.reader=target.Reader(data)
        self.leaps=list(self.reader.read(target.TABLE1_VA,401))
        self.flags=list(self.reader.read(target.TABLE2_VA,400))
    def imm(self,va,signed=False):return int.from_bytes(self.reader.read(va,4),'little',signed=signed)
    def date(self,raw):
        if type(raw) is not int or not -(1<<31)<=raw<(1<<31):raise ValueError('raw i32 day required')
        n=raw+self.imm(0x1628f55)
        if not -(1<<31)<=n<(1<<31):return 0
        product=n*self.imm(0x1628f65,signed=True)
        bits=product&((1<<64)-1)
        quotient=(engine.signed(bits>>32,32)>>15)+(bits>>63)
        cycle_length=self.imm(0x1628f7b)
        remainder=n-quotient*cycle_length
        correction=-1 if remainder<0 else 0
        cycle_day=remainder+(correction&cycle_length)
        hi=(cycle_day*self.imm(0x1628f93))>>32
        year_in_cycle=(((cycle_day-hi)>>1)+hi)>>8
        partial=cycle_day-self.imm(0x1628fab)*year_in_cycle
        raw_ordinal=partial-self.leaps[year_in_cycle]
        if raw_ordinal>=0:
            if cycle_day>self.imm(0x1629021):raise ValueError('Native ordinal panic condition')
            ordinal=raw_ordinal+1
        else:
            if cycle_day<365:raise ValueError('Native borrow panic condition')
            year_in_cycle-=1
            if not 0<=year_in_cycle<401:raise ValueError('Native leap-index panic condition')
            ordinal=partial-self.leaps[year_in_cycle]+366
        if not 1<=ordinal<=366:return 0
        year=(quotient+correction)*400+year_in_cycle
        gate=(year+self.imm(0x162904d,signed=True))&0xffffffff
        if gate<self.imm(0x1629053):return 0
        packed=((year<<13)|(ordinal<<4)|self.flags[year_in_cycle])&0xffffffff
        return packed if packed&self.imm(0x1629077)<self.imm(0x162907f) else 0


ROOT=Path(__file__).resolve().parents[1]
PACKET=ROOT/"research/work-items/RE-014-daycount-date-115"
CRATE=ROOT/"src/node115-daycount-date"

def beginning(year):
    cycle,y=divmod(year,400)
    return cycle*146097+365*y+(y+3)//4-(y+99)//100+(y+399)//400-365

def fixtures():
    # Fixed integer generator: the fixture set is independent of Python RNG versions.
    values=set(range(-146097-365,146097-365))
    for year in (-262144,-262143,-262142,-401,-400,-1,0,1,399,400,1600,1900,1970,2000,2400,262141,262142,262143):
        values.update(beginning(year)+delta for delta in (-2,-1,0,1,2))
    values.update(range(-(1<<31),-(1<<31)+367))
    values.update(range((1<<31)-367,(1<<31)))
    state=0x1628f50
    def next_word():
        nonlocal state
        state=(state*6364136223846793005+1442695040888963407)&((1<<64)-1)
        return state
    for _ in range(16384):values.add(engine.signed(next_word()>>32,32))
    low,high=beginning(-262143),beginning(262143)
    for _ in range(32768):values.add(low+next_word()%(high-low))
    for year in (-262143,-401,-400,-399,-4,-1,0,1,1970,262142):values.add(target.days_from_civil(year,1,1)+719163)
    return sorted(values)

def verify(rustc,output):
    """Compile source, interpret own code, and compare with original static transfers."""
    import hashlib,json,subprocess,time,struct
    from fde_extents import eh_frame_records
    rustc=Path(rustc).resolve();output=Path(output).resolve()
    if rustc.is_relative_to(ROOT/'artifacts') or hashlib.sha256(rustc.read_bytes()).hexdigest() in {target.SHA256,'3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f','89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31'}:raise ValueError('Captured artifact cannot be a compiler')
    version=subprocess.run([str(rustc),'-Vv'],check=True,text=True,capture_output=True).stdout
    if not version.startswith('rustc 1.94.1 '):raise ValueError('Direct pinned rustc 1.94.1 required')
    output.mkdir(parents=True,exist_ok=False)
    source=(CRATE/'src/lib.rs').read_text(encoding='utf8')
    flags=['--crate-name','node115_daycount_date','--edition=2024','--crate-type=lib',
           '--target=x86_64-unknown-linux-gnu','-C','opt-level=3','-C','panic=abort',
           '-C','codegen-units=1','-C','debuginfo=0','-C','lto=off','--emit=obj']
    def build(name,text):
        folder=output/name;folder.mkdir();path=folder/'lib.rs';path.write_text(text,encoding='utf8',newline='\n')
        obj=folder/'daycount-date.o'
        subprocess.run([str(rustc),*flags,'-o',str(obj),str(path)],check=True,capture_output=True)
        return obj
    first=build('first',source);second=build('independent',source)
    machine,body,instructions=own_machine(first);_,other,_=own_machine(second)
    if body!=other:raise ValueError('Independent own-code builds differ')
    data=target.TARGET.read_bytes();oracle=NativeDateOracle(data)
    blockers=[]
    class SignOnly(engine.Machine):i_movsxd=DateMachine.i_movsxd
    for name,model_type,expected_mnemonic,input_day in [('shared',engine.Machine,'movsxd',719163),('movsxd_only',SignOnly,'ror',beginning(4))]:
        original,_,_=own_machine(first,model_type)
        try:evaluate_day(original,input_day)
        except engine.Unmodelled as e:
            if expected_mnemonic not in str(e):raise ValueError('Different evaluator blocker') from e
            blockers.append(dict(profile=name,input_day=input_day,error=str(e)))
        else:raise ValueError('Expected evaluator blocker did not reproduce')
    # Bound the signed reciprocal division over the complete i32 magnitude range.
    multiplier=oracle.imm(0x1628f65);divisor=oracle.imm(0x1628f7b);scale=1<<47
    error=multiplier*divisor-scale;quotient_bound=(1<<31)//divisor
    maximum=quotient_bound*error+(divisor-1)*multiplier
    if not 0<error or maximum>=scale:raise ValueError('Signed reciprocal proof bound changed')
    started=time.monotonic();vectors=fixtures();max_steps=0
    for ordinal,day in enumerate(vectors,1):
        expected=oracle.date(day);actual=evaluate_day(machine,day)
        if expected!=actual:raise ValueError(f'Rust date mismatch for raw day {day}')
        max_steps=max(max_steps,machine.steps)
        if ordinal%32768==0:print(f'Own Rust date: {ordinal}/{len(vectors)} cases pass',flush=True)
    controls=[]
    for name,old,new,day in (('offset','checked_add(365)','checked_add(364)',719163),
                             ('leap','(year + 3) / 4','(year + 2) / 4',0),
                             ('flag','(start + 3) % 7','(start + 4) % 7',719163)):
        if source.count(old)!=1:raise ValueError('Review changed source and corruption controls')
        obj=build(name,source.replace(old,new));model,mutant,_=own_machine(obj)
        expected=oracle.date(day);actual=evaluate_day(model,day)
        if actual==expected:raise ValueError('Source corruption was not detected')
        controls.append(dict(control=name,day=day,target_expected=hex(expected),mutant_actual=hex(actual),
                             rejected=True,mutant_code_sha256=hashlib.sha256(mutant).hexdigest()))
    native_controls=[]
    for name,va,new,raw in [('offset',0x1628f55,(364).to_bytes(4,'little'),719163),('cycle',0x1628f7b,(146096).to_bytes(4,'little'),145732),('year_bias',0x162904d,(-262144).to_bytes(4,'little',signed=True),beginning(-262143)),('year_flag',target.TABLE2_VA+370,bytes([oracle.flags[370]^1]),719163)]:
        patched=bytearray(data);offset=oracle.reader.off(va,len(new));patched[offset:offset+len(new)]=new
        try:NativeDateOracle(bytes(patched))
        except ValueError:pass
        else:raise ValueError('Mutated native target accepted')
        expected=oracle.date(raw);actual=NativeDateOracle(bytes(patched),strict=False).date(raw)
        if expected==actual:raise ValueError('Inactive native operand counterexample '+name)
        native_controls.append(dict(control=name,va=hex(va),raw_day=raw,expected=expected,changed=actual,rejected=True))
    _,fdes=eh_frame_records(data);owner=[f for f in fdes if f['start']==target.START]
    if len(owner)!=1 or owner[0]['end']!=target.END:raise ValueError('Original constructor FDE changed')
    reader=oracle.reader;native_owner=dict(start=hex(target.START),end_exclusive=hex(target.END),
                                        sha256=hashlib.sha256(reader.read(target.START,target.END-target.START)).hexdigest())
    for kind in ('fde','cie'):
        va=owner[0][kind];size=struct.unpack('<I',reader.read(va,4))[0]+4
        native_owner[kind]=hex(va);native_owner[kind+'_raw']=reader.read(va,size).hex()
    record=dict(target_sha256=target.SHA256,native_owner=native_owner,
                source_sha256={name:hashlib.sha256((CRATE/name).read_bytes()).hexdigest() for name in ('Cargo.toml','Cargo.lock','src/lib.rs')},
                checker_source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                native_binder_sha256=hashlib.sha256(Path(target.__file__).read_bytes()).hexdigest(),
                evaluator_source_sha256=hashlib.sha256(Path(engine.__file__).read_bytes()).hexdigest(),
                compiler_version=version.strip().splitlines(),compiler_flags=flags,
                compiler_executable_sha256=hashlib.sha256(rustc.read_bytes()).hexdigest(),
                own_compiled_bytes=len(body),own_compiled_instructions=len(instructions),
                own_code_sha256=hashlib.sha256(body).hexdigest(),own_object_sha256=hashlib.sha256(first.read_bytes()).hexdigest(),
                own_object_reproducible=first.read_bytes()==second.read_bytes(),
                native_bindings=oracle.records,evaluator_blockers=blockers,native_operand_controls=native_controls,
                cases=len(vectors),complete_cycle_cases=292194,mismatches=0,max_steps=max_steps,
                seconds=round(time.monotonic()-started,3),source_controls=controls,
                signed_division_bound=dict(multiplier=multiplier,divisor=divisor,scale=scale,error=error,
                                           quotient_bound=quotient_bound,worst_case=maximum,holds=maximum<scale),
                captured_binary_executed=False,target_code_identity_measured=False,
                scope='Raw integer/date contract. Only freshly compiled own Rust code is interpreted; original panic policy, typed caller ABI, compiler provenance and whole-ELF identity are not claimed.')
    (output/'rust-validation.json').write_text(json.dumps(record,indent=2)+'\n',encoding='utf8',newline='\n')
    lines=['Own compiled Rust object, not captured target code. Function-relative offsets.',
           'rustc1.94.1, Linux x86-64; no text relocations or helper calls; SHA-256 '+record['own_code_sha256']]
    lines.extend(f'{i.address-0x100000:#x} {i.bytes.hex():30} {i.mnemonic} {i.op_str}'.rstrip() for i in instructions)
    (output/'own-rust.capstone.txt').write_text('\n'.join(lines)+'\n',encoding='utf8',newline='\n')
    return record

if __name__=='__main__':
    import argparse,json
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rustc',type=Path,required=True)
    parser.add_argument('--out-dir',type=Path,required=True,help='New WORK output directory; no previous evidence is removed')
    args=parser.parse_args();record=verify(args.rustc,args.out_dir)
    print(json.dumps(dict(cases=record['cases'],mismatches=record['mismatches'],
                         own_object_reproducible=record['own_object_reproducible'],
                         controls_rejected=all(c['rejected'] for c in record['source_controls']))))
