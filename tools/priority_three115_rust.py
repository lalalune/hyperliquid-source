"""Node115 defined three-byte normal projection, not original ABI or decoder."""
from pathlib import Path
import hashlib,itertools,json,struct,subprocess
import evm_amount_scale as engine
import priority_prefix_static as native
from fde_extents import eh_frame_records
ROOT=Path(__file__).resolve().parents[1]
BINARY='artifacts/node/115/hl-node'
SHA256='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
CRATE=ROOT/'src/node115-priority-three'
PACKET=ROOT/'research/work-items/RE-014-priority-three-115'
def require(ok,message):
    if not ok:raise ValueError(message)
class NoExternalMemory:
    def in_rodata(self,*args):return False
    def read(self,*args):raise engine.Unmodelled('Only initialized synthetic own-code RAM')

def own_machine(path):
    data = Path(path).read_bytes()
    if len(data) < 64:
        raise ValueError('Truncated own Rust object')
    if data[:6] != b'\x7fELF\x02\x01' or int.from_bytes(data[16:18], 'little') != 1 or int.from_bytes(data[18:20], 'little') != 62:
        raise ValueError('Expected our Linux x86-64 relocatable Rust object')
    image = engine.Image(data)
    if any((name.startswith(('.rela.text', '.rel.text')) for name in image.sec)):
        raise ValueError('External code relocations are not supported')
    text = [(name, section) for name, section in image.sec.items() if name == '.text.node115_priority_probe' and section[2]]
    if len(text) != 1 or text[0][0] != '.text.node115_priority_probe':
        raise ValueError('Exactly one known Rust scalar section required')
    _, (_, offset, size) = text[0]
    body = data[offset:offset + size]
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_OP_REG, CS_OP_IMM, CS_OP_MEM
    cs = Cs(CS_ARCH_X86, CS_MODE_64)
    cs.detail = True
    instructions = list(cs.disasm(body, 1048576))
    rows = []
    if sum((i.size for i in instructions)) != len(body):
        raise ValueError('Incomplete own-object decoding')
    for ins in instructions:
        operands = []
        for op in ins.operands:
            if op.type == CS_OP_REG:
                register, width = engine.REGS[ins.reg_name(op.reg)]
                operands.append(('r', register, width))
            elif op.type == CS_OP_IMM:
                operands.append(('i', op.imm))
            elif op.type == CS_OP_MEM:
                if ins.reg_name(op.mem.base) == 'rip':
                    raise ValueError('External data reference')
                base = engine.REGS[ins.reg_name(op.mem.base)][0] if op.mem.base else None
                index = engine.REGS[ins.reg_name(op.mem.index)][0] if op.mem.index else None
                operands.append(('m', op.size, base, index, op.mem.scale, op.mem.disp))
            else:
                raise ValueError('Unsupported operand')
        if ins.mnemonic == 'call':
            raise ValueError('Opaque compiled helper call')
        rows.append((ins.address, ins.mnemonic, tuple(operands), ins.address + ins.size))
    return (engine.Machine(rows, NoExternalMemory(), {}), body, instructions)

def evaluate(m,cursor,count,values):
    m.reset();m.setreg(engine.RSP,engine.STACK_TOP);m.store(engine.STACK_TOP,8,engine.RET_MAGIC)
    saved={r:0x1122334400000000+r for r in (engine.RBX,engine.RBP,engine.R12,engine.R13,engine.R14,engine.R15)}
    for r,v in saved.items():m.setreg(r,v)
    for r,v in zip((engine.RDI,engine.RSI,engine.RDX,engine.RCX,engine.R8,engine.R9),(engine.BUFFER,cursor,count,*values)):m.setreg(r,v)
    require(m.run(0x100000,limit=5000)==engine.RET_MAGIC,'Own code return failed')
    for r,v in saved.items():require(m.known[r]==engine.MASK and m.regs[r]==v,'Saved register changed')
    flag=m.load(engine.BUFFER,8)
    return [m.load(engine.BUFFER+8*i,8) for i in range(9)] if flag else [0]

def own_expected(cursor,count,values):
    if cursor==0 or cursor>engine.MASK-3 or count>engine.MASK-3:return [0]
    bits=[int.from_bytes(struct.pack('<d',value),'little') for value in values]
    return [1,cursor+3,count+3,0,0,*bits,0]


def corpus():
    seen=set();rows=[]
    def add(t):
        if t not in seen:seen.add(t);rows.append(t)
    for t in [(0,0,0),(7,11,13),(255,255,255)]:add(t)
    for v in range(256):
        for channel in range(3):add(tuple(v if i==channel else 0 for i in range(3)))
        add((v,v,v));add((v,255-v,v^85))
    state=0x1839480
    for _ in range(8192):
        values=[]
        for _ in range(3):state=(state*6364136223846793005+1442695040888963407)&engine.MASK;values.append((state>>32)&255)
        add(tuple(values))
    return rows

def native_projection(prefix,cursor,count,values):
    """Selected literal/dataflow equations, no captured-PC or register stepping."""
    require(cursor!=0 and cursor<=engine.MASK-3 and 0<=count<=engine.MASK-3,'Outside native qualified state cut')
    require(len(values)==3 and all(type(v)is int and 0<=v<256 for v in values),'Three raw u8 values required')
    for at,h in [(0xdb,'498d46'),(0xf1,'4d8d67'),(0x102,'b9'),(0x10e,'41be'),(0x114,'4c0f45f1'),(0x12d,'b8'),(0x136,'31c9'),(0x13c,'480f45c8'),(0x140,'4c8937'),(0x148,'48894f10'),(0x151,'f20f115720'),(0x156,'f20f115f28'),(0x15b,'f20f114f30'),(0x160,'44887f38')]:
        b=bytes.fromhex(h);require(prefix[at:at+len(b)]==b,'Qualified dataflow opcode changed')
    gates=native.numeric_certificate(prefix)
    if values[0] not in gates[0]['accepted_u8'] or values[1] not in gates[1]['accepted_u8']:return dict(selected_path=False,reason='numeric-gate')
    cursor_step=prefix[0xde];count_step=prefix[0xf4]
    if cursor_step!=3:return dict(selected_path=False,reason='cursor/end mismatch')
    first_status=int.from_bytes(prefix[0x103:0x107],'little');initial=int.from_bytes(prefix[0x110:0x114],'little');first_bound=prefix[0x10d]
    second_status=int.from_bytes(prefix[0x12e:0x132],'little');second_bound=prefix[0x13b]
    control_a=first_status if first_status!=first_bound else initial
    control_b=second_status if second_status!=second_bound else 0
    bits=[int.from_bytes(struct.pack('<d',v),'little') for v in values]
    return dict(selected_path=True,probe_words=[1,cursor+cursor_step,count+count_step,control_a,control_b,*bits,0])

def native_record(data):
    require(len(data)==105896032 and hashlib.sha256(data).hexdigest()==SHA256,'Wrong node115 target')
    report=native.analyze(data);retained=json.loads((native.PACKET/'records.json').read_bytes());require(report==retained,'Retained native certificate changed')
    image=engine.Image(data);_,frames=eh_frame_records(data)
    from capstone import Cs,CS_ARCH_X86,CS_MODE_64
    cs=Cs(CS_ARCH_X86,CS_MODE_64);owners=[]
    _,ro,rs=image.section('.rela.dyn');require(rs%24==0 and ro+rs<=len(data),'Truncated relocations');relocs=list(struct.iter_unpack('<QQq',data[ro:ro+rs]))
    for start,end,slot in native.OWNERS:
        fs=[f for f in frames if f['start']==start];require(len(fs)==1 and fs[0]['end']==end,'Unique complete owner FDE required')
        require(not any(f['start']<end and f['end']>start and f!=fs[0] for f in frames),'Overlapping native FDE')
        prefix=image.read(start,native.PREFIX_SIZE);epilogue=image.read(start+0x25e,15);body=image.read(start,end-start);ins=list(cs.disasm(body,start))
        require(sum(i.size for i in ins)==len(body) and len(ins)==267,'Complete native export changed')
        rows=[r for r in relocs if r[0]==slot];require(len(rows)==1 and rows[0][1]==8,'Unique diagnostic relocation writer required')
        selected=[i for i in ins if i.address<start+native.PREFIX_SIZE or start+0x25e<=i.address<start+0x26d]
        require(not any(i.mnemonic=='call' for i in selected),'Call on qualified cut')
        expected={start+x for x in native.BRANCHES}|{start+0x164}
        require({i.address for i in ins if i.address<start+native.PREFIX_SIZE and i.mnemonic.startswith(('j','loop','ret','call'))}==expected,'Qualified transfer set changed')
        for x in (0,1,255):require(native_projection(prefix,4096,7,(x,x,x))['selected_path'],'Normal-path witness failed')
        owners.append(dict(start=hex(start),end=hex(end),bytes=len(body),instructions=len(ins),body_sha256=hashlib.sha256(body).hexdigest(),prefix_sha256=hashlib.sha256(prefix).hexdigest(),epilogue_sha256=hashlib.sha256(epilogue).hexdigest(),export=[f'{i.address:x}: {i.bytes.hex()} {i.mnemonic} {i.op_str}'.rstrip() for i in ins]))
    return dict(target_sha256=SHA256,existing_certificate=report,owners=owners,normal_combination_domain=256**3,normal_path_helpers=0,defined_projection_only=True,unqualified_native_bytes=['output+8..15 incoming XMM4','output+24..31 incoming XMM0','padding/other bytes'],limits='Exactly three readable byte values, nonnull/nonwrapping cursor/end=p+3, count<=MAX-3 and valid nonaliasing stack/state/output. Original type/ABI, other lengths, errors/helpers, callers, protocol and full component remain unclosed.')

def verify(rustc,output):
    rustc=Path(rustc).resolve();output=Path(output)
    if rustc.is_relative_to(ROOT/'artifacts') or hashlib.sha256(rustc.read_bytes()).hexdigest() in {SHA256,'3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f','89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31'}:raise ValueError('Captured artifact cannot be a compiler')
    version=subprocess.run([str(rustc),'-Vv'],check=True,capture_output=True,text=True).stdout;require(version.startswith('rustc 1.94.1 '),'Pinned Rust1.94.1 required')
    data=(ROOT/BINARY).read_bytes();original=native_record(data);prefix=engine.Image(data).read(native.OWNERS[0][0],native.PREFIX_SIZE)
    output.mkdir(parents=True,exist_ok=False);source=(CRATE/'src/lib.rs').read_text(encoding='utf8')
    flags=['--crate-name','node115_priority_three','--edition=2024','--crate-type=lib','--emit=obj','--target=x86_64-unknown-linux-gnu','-C','opt-level=3','-C','panic=abort','-C','codegen-units=1','-C','debuginfo=0','-C','lto=off','-C','no-vectorize-loops','-C','no-vectorize-slp']
    def build(name,text):
        d=output/name;d.mkdir();s=d/'lib.rs';s.write_text(text,encoding='utf8',newline='\n');obj=d/'own.o';subprocess.run([str(rustc),*flags,str(s),'-o',str(obj)],check=True,capture_output=True);return obj
    first=build('first',source);second=build('repeat',source);require(first.read_bytes()==second.read_bytes(),'Repeated own objects differ');machine,body,instructions=own_machine(first)
    values=corpus();evaluations=0
    for triple in values:
        for cursor in (4096,4097,1<<40):
            for count in (0,1,engine.MASK-3):
                expected=native_projection(prefix,cursor,count,triple);require(expected['selected_path'],'Outside certified path')
                require(evaluate(machine,cursor,count,triple)==expected['probe_words'],'Own defined projection mismatch');evaluations+=1
    refusals=[]
    for cursor,count in [(0,0),(engine.MASK-2,0),(4096,engine.MASK-2),(engine.MASK,engine.MASK)]:
        require(evaluate(machine,cursor,count,(0,0,0))==[0],'Own API domain refusal changed');refusals.append(dict(cursor=cursor,count=count,scope='Own API refusal only; native behavior unqualified'))
    changes=[('exponent','1023 + exponent','1022 + exponent'),('cursor','cursor.checked_add(3)','cursor.checked_add(2)'),('counter','count.checked_add(3)','count.checked_add(2)'),('control','control_words: [0, 0]','control_words: [1, 0]'),('marker','marker: 0','marker: 1'),('first_value','integer_binary64(input[0])','integer_binary64(input[0].wrapping_add(1))'),('order','integer_binary64(input[1])','integer_binary64(input[0])')]
    controls=[]
    for name,before,after in changes:
        require(source.count(before)==1,'Mutation anchor changed');obj=build(name,source.replace(before,after));m,b,_=own_machine(obj);witness=None
        for triple in values[:3]:
            a=evaluate(m,4096,7,triple);e=native_projection(prefix,4096,7,triple)['probe_words']
            if a!=e:witness=dict(values=list(triple),expected=e,changed=a);break
        require(witness is not None,'Compiled source mutation survived');controls.append(dict(name=name,rejected=True,own_body_sha256=hashlib.sha256(b).hexdigest(),**witness))
    native_controls=[]
    patches=[('first_gate',0x65,(512).to_bytes(4,'little')),('second_gate',0xb8,(512).to_bytes(4,'little')),('count_step',0xf4,b'\x02'),('cursor_step',0xde,b'\x02'),('control_init',0x110,(1).to_bytes(4,'little')),('second_status',0x12e,(3).to_bytes(4,'little'))]
    base=native.OWNERS[0][0];image=engine.Image(data)
    for name,offset,value in patches:
        changed=bytearray(data);off=image.off(base+offset,len(value));changed[off:off+len(value)]=value
        try:native_record(bytes(changed))
        except ValueError:pass
        else:raise ValueError('Mutated native admitted')
        cp=bytes(changed[image.off(base,native.PREFIX_SIZE):image.off(base,native.PREFIX_SIZE)+native.PREFIX_SIZE]);a=native_projection(cp,4096,7,(7,11,13));e=native_projection(prefix,4096,7,(7,11,13));require(a!=e,'Native dataflow mutation inactive')
        native_controls.append(dict(name=name,va=hex(base+offset),values=[7,11,13],expected=e,changed=a,rejected=True))
    result=dict(target_sha256=SHA256,native=original,source_sha256={n:hashlib.sha256((CRATE/n).read_bytes()).hexdigest() for n in ('Cargo.toml','Cargo.lock','src/lib.rs')},checker_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),native_model_sha256=hashlib.sha256(Path(native.__file__).read_bytes()).hexdigest(),shared_engine_sha256=hashlib.sha256(Path(engine.__file__).read_bytes()).hexdigest(),compiler_version=version,compiler_sha256=hashlib.sha256(rustc.read_bytes()).hexdigest(),flags=flags,unique_triples=len(values),state_pairs=9,evaluations=evaluations,mismatches=0,own_api_refusals=refusals,compiled_source_controls=controls,native_operand_controls=native_controls,own_code_bytes=len(body),own_code_instructions=len(instructions),own_code_sha256=hashlib.sha256(body).hexdigest(),own_objects_reproducible=True,captured_executed=False,target_code_identity_measured=False,scope='New logical defined-word/state projection of the helper-free exact-three-u8 normal cut. Original incoming XMM payloads/padding, result ABI, other lengths/errors, callers and protocol are excluded; own out-of-cut refusals are not native error claims. The16777216 domain is algebraic/separable, not executed count.')
    (output/'rust-validation.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf8',newline='\n')
    (output/'own-rust.capstone.txt').write_text('\n'.join(f'{i.address-0x100000:x}: {i.bytes.hex()} {i.mnemonic} {i.op_str}'.rstrip() for i in instructions)+'\n',encoding='utf8',newline='\n')
    for row in original['owners']:(output/(row['start']+'.capstone.txt')).write_text('\n'.join(row['export'])+'\n',encoding='utf8',newline='\n')
    return result

if __name__=='__main__':
    import argparse
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--rustc',required=True);p.add_argument('--out',required=True);a=p.parse_args();r=verify(a.rustc,a.out);print(json.dumps(dict(unique_triples=r['unique_triples'],evaluations=r['evaluations'],mismatches=r['mismatches'],compiled_controls=len(r['compiled_source_controls']),native_controls=len(r['native_operand_controls']))))
