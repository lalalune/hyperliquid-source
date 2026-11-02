"""Compare only independently compiled Rust with the native nonce-ring relation."""
from pathlib import Path
import hashlib,itertools,json,random,subprocess,time
import evm_amount_scale as engine
import nonce_ordering_static as native
ROOT=Path(__file__).resolve().parents[1]
CRATE=ROOT/'src/node115-nonce-ring'
PACKET=ROOT/'research/work-items/RE-001-node115-nonce-ring-rust'
class NoExternalMemory:
    def in_rodata(self,*args): return False
    def read(self,*args): raise engine.Unmodelled('Only initialized own RAM is permitted')
def own_machine(path):
    data=Path(path).read_bytes()
    if len(data)<64:raise ValueError("Truncated own Rust object")
    if data[:6]!=b'\x7fELF\x02\x01' or int.from_bytes(data[16:18],'little')!=1 or int.from_bytes(data[18:20],'little')!=62:
        raise ValueError('Expected our Linux x86-64 relocatable Rust object')
    image=engine.Image(data)
    if any(name.startswith(('.rela.text','.rel.text')) for name in image.sec):
        raise ValueError('External code relocations are not supported')
    text=[(name,section) for name,section in image.sec.items() if name.startswith('.text') and section[2]]
    if len(text)!=1 or text[0][0]!='.text.node115_nonce_ring_is_ordered':
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
    return engine.Machine(rows,NoExternalMemory(),{}),body,instructions


def evaluate(machine,values,head,count,offset=0):
    capacity=len(values)
    if type(offset) is not int or not 0<=offset<8:raise ValueError('Synthetic alignment offset must be0..7')
    if any(type(v) is not int or not 0<=v<1<<64 for v in values):raise ValueError('Raw u64 storage values required')
    if type(head) is not int or type(count) is not int:raise ValueError('Raw integer metadata required')
    native.obligations(capacity,head,count)
    machine.reset();machine.setreg(engine.RSP,engine.STACK_TOP)
    machine.store(engine.STACK_TOP,8,engine.RET_MAGIC)
    pointer=engine.BUFFER+offset
    for i,value in enumerate(values):machine.store(pointer+8*i,8,value)
    for r,v in ((engine.RDI,pointer),(engine.RSI,capacity),(engine.RDX,head),(engine.RCX,count)):
        machine.setreg(r,v)
    if machine.run(0x100000,limit=20000)!=engine.RET_MAGIC:raise ValueError('Own Rust failed to return')
    if machine.known[engine.RAX]&255!=255:raise ValueError('Unset own result')
    value=machine.regs[engine.RAX]&255
    if value not in (0,1):raise ValueError('Nonboolean own result')
    return bool(value)

def bind_native(data):
    if len(data)!=105896032 or hashlib.sha256(data).hexdigest()!=native.SHA:
        raise ValueError('Expected captured node115 identity')
    record=native.analyze(data)
    parameters=[native.parameters(data,a) for a in native.BRANCHES]
    if any(p!=[0x72,0x72] for p in parameters):
        raise ValueError('Native strict unsigned predicates changed')
    return record,parameters[0]

def fixtures():
    edges=(0,1,0x7fffffffffffffff,0x8000000000000000,0xffffffffffffffff)
    for capacity in range(5):
        for values in itertools.product(edges,repeat=capacity):
            for head in range(capacity or 1):
                for count in range(capacity+1):
                    yield 'exhaustive',values,head,count
    # Stable, explicitly specified generator, independent of Python RNG versions.
    state=115
    for capacity in range(1,33):
        for head in range(capacity):
            for count in range(capacity+1):
                random_values=[]
                for _ in range(count):
                    state=(state*6364136223846793005+1442695040888963407)&((1<<64)-1)
                    random_values.append(state)
                for logical in (list(range(count)),[0]*count,list(reversed(range(count))),random_values):
                    physical=[(1<<64)-1]*capacity
                    for i,value in enumerate(logical):physical[(head+i)%capacity]=value
                    yield 'layouts',physical,head,count

def verify(rustc,output):
    rustc=Path(rustc).resolve();output=Path(output).resolve()
    # A captured image must never be launched as a mistaken compiler path.
    captured={'3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f',
              'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301',
              '89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31'}
    if rustc.is_relative_to(native.ROOT/'artifacts') or hashlib.sha256(rustc.read_bytes()).hexdigest() in captured:
        raise ValueError('Captured artifact cannot be a compiler')
    version=subprocess.run([str(rustc),'-Vv'],check=True,capture_output=True,text=True).stdout
    if not version.startswith('rustc 1.94.1 '):raise ValueError('Direct Rust 1.94.1 required')
    output.mkdir(parents=True,exist_ok=False)
    source=(CRATE/'src/lib.rs').read_text(encoding='utf8')
    flags=['--crate-name','node115_nonce_ring','--edition=2024','--crate-type=lib','--emit=obj',
           '--target=x86_64-unknown-linux-gnu','-C','opt-level=2','-C','panic=abort',
           '-C','codegen-units=1','-C','debuginfo=0','-C','lto=off']
    def build(name,text):
        folder=output/name;folder.mkdir();path=folder/'lib.rs'
        path.write_text(text,encoding='utf8',newline='\n');obj=folder/'nonce-ring.o'
        subprocess.run([str(rustc),*flags,str(path),'-o',str(obj)],check=True,capture_output=True)
        return obj
    first=build('first',source);second=build('independent',source)
    if first.read_bytes()!=second.read_bytes():raise ValueError('Repeated own objects differ')
    machine,body,instructions=own_machine(first)
    original,params=bind_native(native.TARGET.read_bytes())
    started=time.monotonic();counts={'exhaustive':0,'layouts':0};max_steps=0
    for group,values,head,count in fixtures():
        expected=native.ordered(params,values,head,count)
        actual=evaluate(machine,values,head,count)
        if actual!=expected:raise ValueError('Compiled Rust ring predicate mismatch')
        counts[group]+=1;max_steps=max(max_steps,machine.steps)
    unaligned=0
    for capacity in range(9):
        for head in range(capacity or 1):
            for count in range(capacity+1):
                for logical in (list(range(count)),[1]*count,list(reversed(range(count)))):
                    values=[(1<<64)-1]*capacity
                    for i,value in enumerate(logical):values[(head+i)%capacity]=value
                    expected=native.ordered(params,values,head,count)
                    for offset in range(8):
                        if evaluate(machine,values,head,count,offset)!=expected:
                            raise ValueError('Unaligned own Rust ring mismatch')
                        max_steps=max(max_steps,machine.steps);unaligned+=1
    counts['unaligned']=unaligned
    controls=[]
    for name,old,new,values,head,count in (
        ('equal','previous >= current','previous > current',[1,1],0,2),
        ('wrap','previous >= current','index != 0 && previous >= current',[0,1],1,2),
        ('first_pair','count - 1','count - 2',[2,1],0,2)):
        if source.count(old)!=1:raise ValueError('Review changed source and controls')
        changed=source.replace(old,new);obj=build(name,changed);mutant,_,_=own_machine(obj)
        expected=native.ordered(params,values,head,count);actual=evaluate(mutant,values,head,count)
        if expected==actual:raise ValueError('Compiled source control was not detected')
        controls.append(dict(control=name,source_sha256=hashlib.sha256(changed.encode()).hexdigest(),
                             object_sha256=hashlib.sha256(obj.read_bytes()).hexdigest(),
                             values=values,head=head,count=count,expected=expected,actual=actual,rejected=True))
    # The checker must not silently fill missing synthetic storage with zero.
    machine.reset();machine.setreg(engine.RSP,engine.STACK_TOP)
    machine.store(engine.STACK_TOP,8,engine.RET_MAGIC)
    for register,value in ((engine.RDI,engine.BUFFER),(engine.RSI,2),(engine.RDX,0),(engine.RCX,2)):
        machine.setreg(register,value)
    try:machine.run(0x100000)
    except engine.Unmodelled as error:
        if 'unset memory' not in str(error):raise
    else:raise ValueError('Uninitialized synthetic storage was accepted')
    record=dict(target_sha256=native.SHA,native_record=original,
                source_sha256={n:hashlib.sha256((CRATE/n).read_bytes()).hexdigest()
                               for n in ('Cargo.toml','Cargo.lock','src/lib.rs')},
                checker_source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                native_binder_sha256=hashlib.sha256(Path(native.__file__).read_bytes()).hexdigest(),
                native_spec_sha256=native.SPEC_SHA,
                evaluator_source_sha256=hashlib.sha256(Path(engine.__file__).read_bytes()).hexdigest(),
                compiler_version=version.strip().splitlines(),compiler_flags=flags,
                compiler_executable_sha256=hashlib.sha256(rustc.read_bytes()).hexdigest(),
                own_bytes=len(body),own_instructions=len(instructions),own_code_sha256=hashlib.sha256(body).hexdigest(),
                own_object_sha256=hashlib.sha256(first.read_bytes()).hexdigest(),own_object_reproducible=True,
                evaluation_counts=counts,mismatches=0,max_steps=max_steps,
                seconds=round(time.monotonic()-started,3),compiled_source_controls=controls,
                unset_storage_rejected=True,captured_binary_executed=False,target_code_identity_measured=False,
                scope='Conditional strict adjacent-u64 invariant under valid ring metadata/storage only. Original providers, layouts, output/error ABI, replay policy and full component recovery remain open.')
    (output/'rust-validation.json').write_text(json.dumps(record,indent=2)+'\n',encoding='utf8',newline='\n')
    lines=['Own compiled Rust, function-relative offsets; not captured target code.']
    lines.extend(f'{i.address-0x100000:#x} {i.bytes.hex():30} {i.mnemonic} {i.op_str}'.rstrip() for i in instructions)
    (output/'own-rust.capstone.txt').write_text('\n'.join(lines)+'\n',encoding='utf8',newline='\n')
    return record

if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rustc',type=Path,required=True)
    parser.add_argument('--out-dir',type=Path,required=True)
    args=parser.parse_args();record=verify(args.rustc,args.out_dir)
    print(json.dumps({k:record[k] for k in ('evaluation_counts','mismatches','own_object_reproducible')}))
