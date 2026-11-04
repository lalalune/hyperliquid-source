"""Static checksum bindings and interpretation of only newly compiled own Rust."""
from pathlib import Path
import hashlib,json,struct,subprocess,time
import evm_amount_scale as engine
from fde_extents import eh_frame_records
ROOT=Path(__file__).resolve().parents[1]
BINARY='artifacts/node/115/hl-node'
SHA256='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
def check_target(data):
    if len(data)!=105896032 or hashlib.sha256(data).hexdigest()!=SHA256:raise ValueError('Expected node115 captured identity')
CRATE=ROOT/'src/node115-buffer-hash32'
PACKET=ROOT/'research/work-items/RE-014-checksum-selector2-115'
class NoExternalMemory:
    def in_rodata(self,*args):return False
    def read(self,*args):raise engine.Unmodelled('Only initialized synthetic RAM allowed')
class HashMachine(engine.Machine):
    # Scoped to actual own-code 32-bit immediate rotations; shared engine intact.
    def i_rol(self,ops):
        if self.size(ops[0])!=4 or ops[1][0]!='i' or self.rd(ops[1]) not in (1,7,11,12,13,17,18):
            raise engine.Unmodelled('Outside observed own-code rol32 subset')
        count=self.rd(ops[1]);value=self.rd(ops[0])
        result=((value<<count)|(value>>(32-count)))&0xffffffff
        self.wr(ops[0],result);self.cf=bool(result&1)
        self.of=bool((result>>31)^int(self.cf)) if count==1 else None

MASK32=(1<<32)-1
def rol(value,count):
    count &= 31;value &= MASK32
    return ((value<<count)|(value>>((32-count)&31)))&MASK32

class NativeFormula:
    START=0x61da8b0;END=0x61daa52
    BODY_SHA='b2d5ccf56d670650affce9c0efa1fe0ce5eaaf92543d3b3658fd03350f9675b8'
    def __init__(self,data,strict=True):
        if strict:check_target(data)
        self.image=engine.Image(data)
        if strict:
            if hashlib.sha256(self.image.read(self.START,self.END-self.START)).hexdigest()!=self.BODY_SHA:
                raise ValueError('Native hash body changed')
            _,frames=eh_frame_records(data)
            selected=[f for f in frames if f['start']==self.START]
            if len(selected)!=1 or selected[0]['end']!=self.END:raise ValueError('Native full FDE changed')
            self.frame=selected[0]
            wrapper=[f for f in frames if f['start']==0x616bca0]
            if len(wrapper)!=1 or wrapper[0]['end']!=0x616bd51:
                raise ValueError('Selector wrapper FDE changed')
            self.wrapper_frame=wrapper[0]
        self.initial=self.imm(0x61da8b5,'8d82')
        self.initial_lanes=[self.imm(0x61da8dd,'8d92'),self.imm(0x61da8e6,'8d9e'),0,self.imm(0x61da8ec,'448d9e')]
        self.p2=[self.imm(a,p) for a,p in ((0x61da8f8,'6908'),(0x61da904,'6948f4'),(0x61da91f,'6948f8'),(0x61da931,'6948fc'))]
        self.p1=[self.imm(a,p) for a,p in ((0x61da90e,'69d2'),(0x61da919,'69d9'),(0x61da92b,'69f1'),(0x61da93e,'4469d9'))]
        self.rotations=[self.byte(a,p) for a,p in ((0x61da90b,'c1c2'),(0x61da916,'c1c1'),(0x61da928,'c1c1'),(0x61da93b,'c1c1'))]
        if self.image.read(0x61da966,2)!=bytes.fromhex('d1c2'):raise ValueError('First combination rotate changed')
        self.combine=[1,self.byte(0x61da96c,'c1c3'),self.byte(0x61da96f,'c1c6'),32-self.byte(0x61da978,'41c1cb')]
        self.threshold=self.byte(0x61da8cc,'4883fe')
        gate=self.image.read(0x61da8be,6)
        if gate[:2] not in (b'\x0f\x84',b'\x0f\x85') or 0x61da8c4+struct.unpack_from('<i',gate,2)[0]!=0x61daa2f:
            raise ValueError('Native null gate or target changed')
        self.null_when_equal=gate[1]==0x84
        self.word_p3=[self.imm(a,p) for a,p in ((0x61da98a,'6917'),(0x61da9a5,'694f04'),(0x61da9c1,'694f08'))]
        self.word_rot=[32-self.byte(a,'c1c8') for a in (0x61da996,0x61da9b2,0x61da9ca)]
        self.word_p4=[self.imm(a,'69c0') for a in (0x61da999,0x61da9b5,0x61da9cd)]
        self.byte_p5=[self.imm(a,'69d2') for a in (0x61da9e8,0x61daa03,0x61daa1e)]
        self.byte_rot=[self.byte(a,'c1c0') for a in (0x61da9f0,0x61daa0b,0x61daa26)]
        self.byte_p1=[self.imm(a,'69c0') for a in (0x61da9f3,0x61daa0e,0x61daa29)]
        self.shifts=[self.byte(a,'c1ea') for a in (0x61daa32,0x61daa3f,0x61daa4c)]
        self.avalanche=[self.imm(0x61daa37,'69c0'),self.imm(0x61daa44,'69c0')]

    def imm(self,va,prefix):
        prefix=bytes.fromhex(prefix);raw=self.image.read(va,len(prefix)+4)
        if raw[:len(prefix)]!=prefix:raise ValueError('Native immediate form changed')
        return int.from_bytes(raw[len(prefix):],'little')

    def byte(self,va,prefix):
        prefix=bytes.fromhex(prefix);raw=self.image.read(va,len(prefix)+1)
        if raw[:len(prefix)]!=prefix:raise ValueError('Native byte operand form changed')
        return raw[-1]

    def finish(self,value):
        for shift,multiplier in zip(self.shifts[:2],self.avalanche):
            value=((value^(value>>(shift&31)))*multiplier)&MASK32
        return (value^(value>>(self.shifts[2]&31)))&MASK32

    def hash(self,payload,seed,null_length=0):
        if type(seed) is not int or not 0<=seed<1<<32:raise ValueError('Raw u32 seed required')
        if payload is not None and not isinstance(payload,bytes):raise ValueError('Synthetic bytes or null required')
        if type(null_length) is not int or not 0<=null_length<1<<64:raise ValueError('Raw null length required')
        initial=(seed+self.initial)&MASK32
        if (payload is None)==self.null_when_equal:return self.finish(initial)
        data=b'' if payload is None else payload
        size=null_length if payload is None else len(data)
        def word(at):
            if at<0 or at+4>len(data):raise ValueError('Native lowering requests outside supplied storage')
            return int.from_bytes(data[at:at+4],'little')
        pos=0;value=(initial+size)&MASK32
        if size>self.threshold:
            lanes=[(seed+x)&MASK32 for x in self.initial_lanes]
            while size-pos>=16:
                for lane in range(4):
                    lanes[lane]=(rol((lanes[lane]+word(pos+4*lane)*self.p2[lane])&MASK32,self.rotations[lane])*self.p1[lane])&MASK32
                pos+=16
            if pos==0:raise ValueError('Changed threshold enters an unsupported no-stripe path')
            value=(sum(rol(v,n) for v,n in zip(lanes,self.combine))+size)&MASK32
        remaining=size-pos
        # Preserve the actual native unrolled three-word limit, including for
        # operative changed-threshold controls that violate the usual <16 tail.
        for lane in range(min(remaining//4,3)):
            value=(rol((value+word(pos+4*lane)*self.word_p3[lane])&MASK32,self.word_rot[lane])*self.word_p4[lane])&MASK32
        pos+=remaining//4*4
        for lane in range(remaining&3):
            if pos+lane>=len(data):raise ValueError('Native lowering requests an absent byte')
            value=(rol((value+data[pos+lane]*self.byte_p5[lane])&MASK32,self.byte_rot[lane])*self.byte_p1[lane])&MASK32
        return self.finish(value)

def own_machine(path):
    data=Path(path).read_bytes()
    if len(data)<64:raise ValueError("Truncated own Rust object")
    if data[:6]!=b'\x7fELF\x02\x01' or int.from_bytes(data[16:18],'little')!=1 or int.from_bytes(data[18:20],'little')!=62:
        raise ValueError('Expected our Linux x86-64 relocatable Rust object')
    image=engine.Image(data)
    if any(name.startswith(('.rela.text','.rel.text')) for name in image.sec):
        raise ValueError('External code relocations are not supported')
    text=[(name,section) for name,section in image.sec.items() if name.startswith('.text') and section[2]]
    if len(text)!=1 or text[0][0]!='.text.node115_buffer_hash32':
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
    return HashMachine(rows,NoExternalMemory(),{}),body,instructions



def evaluate(machine,payload,seed,null_length=0,offset=0):
    if type(seed) is not int or not 0<=seed<1<<32:raise ValueError('Raw u32 seed required')
    if type(offset) is not int or not 0<=offset<8:raise ValueError('Byte alignment0..7 required')
    if payload is not None and (not isinstance(payload,bytes) or len(payload)>32768):raise ValueError('Bounded synthetic bytes required')
    if type(null_length) is not int or not 0<=null_length<1<<64:raise ValueError('Raw u64 null length required')
    machine.reset();machine.setreg(engine.RSP,engine.STACK_TOP);machine.store(engine.STACK_TOP,8,engine.RET_MAGIC)
    saved={r:0x1122334400000000+r for r in (engine.RBX,engine.RBP,engine.R12,engine.R13,engine.R14,engine.R15)}
    for r,v in saved.items():machine.setreg(r,v)
    pointer=0 if payload is None else engine.BUFFER+offset
    length=null_length if payload is None else len(payload)
    if payload:machine.store(pointer,len(payload),int.from_bytes(payload,'little'))
    for r,v in ((engine.RDI,pointer),(engine.RSI,length),(engine.RDX,seed)):machine.setreg(r,v)
    if machine.run(0x100000,limit=200000)!=engine.RET_MAGIC:raise ValueError('Own checksum did not return')
    if machine.known[engine.RAX]!=engine.MASK:raise ValueError('Unset return bits')
    if machine.regs[engine.RAX]>>32:raise ValueError('Own raw RAX was not zero-extended')
    for r,v in saved.items():
        if machine.known[r]!=engine.MASK or machine.regs[r]!=v:raise ValueError('Callee-saved register changed')
    return machine.regs[engine.RAX]

def native_record(data,listing=None):
    oracle=NativeFormula(data)
    im=oracle.image
    wrapper=im.read(0x616bca0,177)
    if hashlib.sha256(wrapper).hexdigest()!='be940db36c40290321b93a1c386040a55c14fd0beab8a1c5de9688c1ad3674f2':
        raise ValueError('Selector wrapper body changed')
    # These are the actual register transfers for the raw DIL2 route. The
    # complete body identity above also binds its preceding JE/JG conditions.
    selected={0x616bcbe:'4080ff02',0x616bcc8:'4883c408',0x616bccc:'4889de',
              0x616bccf:'4889ef',0x616bcd2:'31d2',0x616bcd4:'5b5d'}
    for va,text in selected.items():
        raw=bytes.fromhex(text)
        if im.read(va,len(raw))!=raw:raise ValueError('Selected wrapper transfer changed')
    jump=im.read(0x616bcd6,5)
    if jump[0]!=0xe9 or 0x616bcdb+struct.unpack_from('<i',jump,1)[0]!=oracle.START:
        raise ValueError('Selected tail target changed')
    owners=[]
    for frame in (oracle.frame,oracle.wrapper_frame):
        start,end=frame['start'],frame['end'];body=im.read(start,end-start);raw_frames={}
        for kind in ('fde','cie'):
            va=frame[kind];length=int.from_bytes(im.read(va,4),'little')+4
            raw_frames[kind]=dict(va=hex(va),bytes_hex=im.read(va,length).hex())
        owners.append(dict(start=hex(start),end=hex(end),bytes=end-start,
                           sha256=hashlib.sha256(body).hexdigest(),frames=raw_frames))
    if listing is not None:
        from capstone import Cs,CS_ARCH_X86,CS_MODE_64
        cs=Cs(CS_ARCH_X86,CS_MODE_64)
        lines=['Original node115 static evidence. ELF VAs, no masks; captured code is never run.',
               'SHA-256 '+SHA256,'Complete checksum leaf plus wrapper context; only selector2 is closed.']
        for row in owners:
            start,end=int(row['start'],16),int(row['end'],16)
            ins=list(cs.disasm(im.read(start,end-start),start))
            if sum(i.size for i in ins)!=end-start:raise ValueError('Incomplete original decoding')
            if any(a.address+a.size!=b.address for a,b in zip(ins,ins[1:])):raise ValueError('Original decoding gap')
            row['instructions']=len(ins)
            if start==oracle.START and any(i.mnemonic in ('call','jmp') and i.op_str.startswith('qword') for i in ins):
                raise ValueError('Unclosed checksum import')
            if start==oracle.START and any(i.mnemonic=='call' for i in ins):raise ValueError('Unclosed checksum helper')
            lines.append(f"\n{start:#x}..{end:#x}; {end-start} bytes/{len(ins)} instructions; SHA-256 "+row['sha256'])
            for kind,raw in row['frames'].items():lines.append(kind+' '+raw['va']+' '+raw['bytes_hex'])
            lines.extend(f'{i.address:#x} {i.bytes.hex():30} {i.mnemonic} {i.op_str}'.rstrip() for i in ins)
        Path(listing).write_text('\n'.join(lines)+'\n',encoding='utf8',newline='\n')
    parameters=dict(initial=oracle.initial,initial_lanes=oracle.initial_lanes,
                    lane_p2=oracle.p2,lane_p1=oracle.p1,lane_rotations=oracle.rotations,
                    combine_rotations=oracle.combine,word_p3=oracle.word_p3,
                    word_rotations=oracle.word_rot,word_p4=oracle.word_p4,
                    byte_p5=oracle.byte_p5,byte_rotations=oracle.byte_rot,byte_p1=oracle.byte_p1,
                    avalanche_multipliers=oracle.avalanche,avalanche_shifts=oracle.shifts,
                    stripe_threshold=oracle.threshold)
    certificates=dict(initial_sum=oracle.initial_lanes[0]==(oracle.p1[0]+oracle.p2[0])&MASK32,
                      initial_second=oracle.initial_lanes[1]==oracle.p2[0],
                      initial_third=oracle.initial_lanes[2]==0,
                      initial_fourth=oracle.initial_lanes[3]==(-oracle.p1[0])&MASK32,
                      p1_copies=len(set(oracle.p1+oracle.byte_p1))==1,
                      p2_copies=len(set(oracle.p2+[oracle.avalanche[0]]))==1,
                      p3_copies=len(set(oracle.word_p3+[oracle.avalanche[1]]))==1,
                      p4_copies=len(set(oracle.word_p4))==1,
                      p5_copies=len(set(oracle.byte_p5+[oracle.initial]))==1,
                      stripe_shape=oracle.threshold==15 and oracle.rotations==[13]*4,
                      combine_shape=oracle.combine==[1,7,12,18],
                      tail_shape=oracle.word_rot==[17]*3 and oracle.byte_rot==[11]*3,
                      avalanche_shape=oracle.shifts==[15,13,16])
    if not all(certificates.values()):raise ValueError('Native algebraic correspondence changed')
    return oracle,dict(target_sha256=SHA256,owners=owners,parameters=parameters,certificates=certificates,selected_raw_tag=2,
                       selected_tail_site='0x616bcd6',selected_tail_target=hex(oracle.START),selected_seed=0,
                       scope='Complete leaf value contract; wrapper context proves selected tag2 forwarding. Other selectors, source provenance and indirect/caller reachability remain unclosed.')

def fixtures():
    seeds=(0,1,0x9e3779b1,0x80000000,0xffffffff)
    lengths=list(range(66))+[127,128,129,255,256,257,511,512,513,1023,1024,1025,4095,4096,4097]
    for size in lengths:
        payload=bytes((i*73+19)&255 for i in range(size))
        for seed in seeds:
            for alignment in (0,1,3,7):yield 'boundaries',payload,seed,0,alignment
    for value in range(256):
        for seed in (0,0xffffffff):
            for alignment in (0,7):yield 'one_byte',bytes([value]),seed,0,alignment
    for seed in seeds:
        for length in (0,1,15,16,0xffffffff,1<<32,1<<63,(1<<64)-1):yield 'null',None,seed,length,0

def verify(rustc,output):
    rustc=Path(rustc).resolve();output=Path(output).resolve()
    captured={SHA256,'3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f',
              '89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31'}
    if rustc.is_relative_to(ROOT/'artifacts') or hashlib.sha256(rustc.read_bytes()).hexdigest() in captured:
        raise ValueError('Captured artifact cannot be a compiler')
    version=subprocess.run([str(rustc),'-Vv'],capture_output=True,text=True,check=True).stdout
    if not version.startswith('rustc 1.94.1 '):raise ValueError('Direct pinned Rust1.94.1 required')
    output.mkdir(parents=True,exist_ok=False)
    data=(ROOT/BINARY).read_bytes()
    native,original=native_record(data,output/'original.capstone.txt')
    flags=['--crate-name','node115_buffer_hash32','--edition=2024','--crate-type=lib','--emit=obj',
           '--target=x86_64-unknown-linux-gnu','-C','opt-level=2','-C','panic=abort',
           '-C','codegen-units=1','-C','debuginfo=0','-C','lto=off',
           '-C','no-vectorize-loops','-C','no-vectorize-slp']
    source=(CRATE/'src/lib.rs').read_text(encoding='utf8')
    def build(name,text):
        folder=output/name;folder.mkdir();path=folder/'lib.rs';path.write_text(text,encoding='utf8',newline='\n')
        obj=folder/'checksum.o'
        subprocess.run([str(rustc),*flags,str(path),'-o',str(obj)],check=True,capture_output=True)
        return obj
    first=build('first',source);second=build('independent',source)
    if first.read_bytes()!=second.read_bytes():raise ValueError('Repeated own objects differ')
    model,body,instructions=own_machine(first)
    started=time.monotonic();counts={'boundaries':0,'one_byte':0,'null':0};max_steps=0
    for group,payload,seed,length,alignment in fixtures():
        expected=native.hash(payload,seed,length)
        actual=evaluate(model,payload,seed,length,alignment)
        if expected!=actual:raise ValueError('Own Rust differs from original integer lowering')
        counts[group]+=1;max_steps=max(max_steps,model.steps)
    controls=[]
    for name,old,new,payload,seed in (
        ('null','if input.is_null() { return finish(seed.wrapping_add(P5)); }','if input.is_null() { return 0; }',None,0),
        ('word_prime','0xc2b2ae3d','0xc2b2ae3c',b'abcd',1),
        ('stripe_boundary','if len >= 16','if len >= 17',bytes(range(16)),0),
        ('lane_rotate','rotate_left(13)','rotate_left(12)',bytes(range(16)),0),
        ('byte_rotate','rotate_left(11)','rotate_left(12)',b'a',0),
        ('length','value = value.wrapping_add(len as u32);','value = value;',b'abc',0)):
        if source.count(old)!=1:raise ValueError('Review changed Rust corruption controls')
        changed=source.replace(old,new);obj=build(name,changed);mutant,_,_=own_machine(obj)
        expected=native.hash(payload,seed);actual=evaluate(mutant,payload,seed)
        if actual==expected:raise ValueError('Compiled source mutation was not detected')
        controls.append(dict(control=name,source_sha256=hashlib.sha256(changed.encode()).hexdigest(),
                             object_sha256=hashlib.sha256(obj.read_bytes()).hexdigest(),
                             expected=expected,changed=actual,rejected=True))
    counterexamples=[]
    for name,va,width,value,payload,seed in (
        ('initial',0x61da8b7,4,native.initial^1,None,0),
        ('lane2_prime',0x61da907,4,native.p2[1]^1,bytes(range(16)),0),
        ('combine_rotate',0x61da96e,1,6,bytes(range(16)),0),
        ('word_prime',0x61da98c,4,native.word_p3[0]^1,b'abcd',0),
        ('word_rotate',0x61da998,1,14,b'abcd',0),
        ('third_byte_prime',0x61daa20,4,native.byte_p5[2]^1,b'abc',0),
        ('avalanche',0x61daa46,4,native.avalanche[1]^1,b'',0),
        ('null_branch',0x61da8bf,1,0x85,b'abc',0)):
        changed=bytearray(data);offset=native.image.off(va,width)
        changed[offset:offset+width]=value.to_bytes(width,'little')
        expected=native.hash(payload,seed);actual=NativeFormula(changed,strict=False).hash(payload,seed)
        if actual==expected:raise ValueError('Operative original operand did not change the result')
        try:NativeFormula(changed)
        except ValueError:pass
        else:raise ValueError('Changed capture passed the original digest gate')
        counterexamples.append(dict(control=name,va=hex(va),expected=expected,changed=actual,rejected=True))
    # Original load helpers, standard library and shared evaluator stay pinned.
    import fde_extents,elf_index
    record=dict(target_sha256=SHA256,native=original,
                source_sha256={n:hashlib.sha256((CRATE/n).read_bytes()).hexdigest()
                               for n in ('Cargo.toml','Cargo.lock','src/lib.rs')},
                checker_source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                dependencies_sha256={Path(m.__file__).name:hashlib.sha256(Path(m.__file__).read_bytes()).hexdigest()
                                     for m in (engine,fde_extents,elf_index)},
                compiler_version=version.strip().splitlines(),compiler_flags=flags,
                compiler_executable_sha256=hashlib.sha256(rustc.read_bytes()).hexdigest(),
                own_code_sha256=hashlib.sha256(body).hexdigest(),own_object_sha256=hashlib.sha256(first.read_bytes()).hexdigest(),
                own_bytes=len(body),own_instructions=len(instructions),own_object_reproducible=True,
                evaluation_counts=counts,mismatches=0,max_steps=max_steps,seconds=round(time.monotonic()-started,3),
                compiled_source_controls=controls,native_operand_controls=counterexamples,
                captured_binary_executed=False,target_code_identity_measured=False,
                scope='Only newly compiled own Rust is interpreted. Original leaf and selected dispatcher2 forwarding; finite valid-buffer/null comparisons. No streaming API, other selectors, source/compiler provenance or whole-node equivalence claimed.')
    (output/'rust-validation.json').write_text(json.dumps(record,indent=2)+'\n',encoding='utf8',newline='\n')
    lines=['Own compiled Rust checksum, function-relative offsets; not original target code.']
    lines.extend(f'{i.address-0x100000:#x} {i.bytes.hex():30} {i.mnemonic} {i.op_str}'.rstrip() for i in instructions)
    (output/'own-rust.capstone.txt').write_text('\n'.join(lines)+'\n',encoding='utf8',newline='\n')
    return record

if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rustc',type=Path,required=True)
    parser.add_argument('--out-dir',type=Path,required=True)
    args=parser.parse_args();r=verify(args.rustc,args.out_dir)
    print(json.dumps({n:r[n] for n in ('evaluation_counts','mismatches','own_object_reproducible')}))
