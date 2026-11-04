"""Node115 normal-return numeric-byte policy; original stays inert."""
from pathlib import Path
import hashlib,itertools,json,struct,subprocess
import evm_amount_scale as engine
import numeric_selector_static as native
from fde_extents import eh_frame_records
ROOT=Path(__file__).resolve().parents[1]
BINARY='artifacts/node/115/hl-node'
SHA256='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
CRATE=ROOT/'src/node115-numeric-selector'
PACKET=ROOT/'research/work-items/RE-014-numeric-byte-policy-115'
FROZEN_EXPECTED_SHA256='1196742a5801a2c392ec494e60eb029876db02ef1f6d62359f1e5f25cb14685e'
def require(ok,message):
    if not ok:raise ValueError(message)
class NoExternalMemory:
    def in_rodata(self,*args):return False
    def read(self,*args):raise engine.Unmodelled('Only initialized synthetic RAM')

def corpus():
    seen=set();out=[]
    def add(b):
        if b not in seen:seen.add(b);out.append(b)
    for b in (b'PURR/USDC',b'',b'#0',b'@0',b'#01',b'@100000000',b'#18446744073709551615',b'#18446744073709551616',b'#1',b'@1',b'PURR/USDD',b'#',b'@',b'#+1',b'@+1'):
        add(b)
    numbers={0,1,2,9,10,99,100,999,1000,9999,10000,99999999,100000000,100000001,(1<<64)-1,(1<<64)-1-100000000,(1<<64)-100000000}
    for i in range(21):
        numbers.update(n for n in (10**i-1,10**i,10**i+1) if 0<=n<1<<64)
    numbers.update(range(1025));state=0x46aa760
    for _ in range(2048):state=(state*6364136223846793005+1442695040888963407)&((1<<64)-1);numbers.add(state)
    for n in sorted(numbers):
        for p in (b'#',b'@'):
            b=str(n).encode();add(p+b);add(p+b'0'+b);add(p+b'+'+b)
    alphabet=(0,43,45,48,49,57,120,255)
    for length in range(5):
        for digits in itertools.product(alphabet,repeat=length):
            for p in (b'#',b'@',b'!'):add(p+bytes(digits))
    for b in range(256):add(bytes([b]));add(b'#'+bytes([b]));add(b'@'+bytes([b]))
    for b in (b'\xc3\xa9',b'\xe2\x82\xac',b'\xff'*32,b'#'+b'0'*256,b'@'+b'9'*256,b'PURR/USDC\x00'):add(b)
    return out

def own_machine(path):
    data = Path(path).read_bytes()
    if len(data) < 64:
        raise ValueError('Truncated own Rust object')
    if data[:6] != b'\x7fELF\x02\x01' or int.from_bytes(data[16:18], 'little') != 1 or int.from_bytes(data[18:20], 'little') != 62:
        raise ValueError('Expected our Linux x86-64 relocatable Rust object')
    image = engine.Image(data)
    if any((name.startswith(('.rela.text', '.rel.text')) for name in image.sec)):
        raise ValueError('External code relocations are not supported')
    text = [(name, section) for name, section in image.sec.items() if name == '.text.node115_selector_probe' and section[2]]
    if len(text) != 1 or text[0][0] != '.text.node115_selector_probe':
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

def evaluate(m,payload,offset=0):
    m.reset();m.setreg(engine.RSP,engine.STACK_TOP);m.store(engine.STACK_TOP,8,engine.RET_MAGIC)
    saved={r:0x1122334400000000+r for r in (engine.RBX,engine.RBP,engine.R12,engine.R13,engine.R14,engine.R15)}
    for r,v in saved.items():m.setreg(r,v)
    pointer=engine.BUFFER+offset;out=engine.BUFFER+0x1000
    if payload:m.store(pointer,len(payload),int.from_bytes(payload,'little'))
    for r,v in [(engine.RDI,out),(engine.RSI,pointer),(engine.RDX,len(payload))]:m.setreg(r,v)
    require(m.run(0x100000,limit=10000)==engine.RET_MAGIC,'Own code failed to return')
    for r,v in saved.items():require(m.known[r]==engine.MASK and m.regs[r]==v,'Saved register changed')
    return [m.load(out+8*i,8) for i in range(4)]

def expected(payload,p,table,offset=0):
    r=native.numeric_projection(payload,p,table)
    if 'value' in r:return [r['tag'],r['value'],0,0]
    require(bytes.fromhex(r['copied_bytes_hex'])==payload,'Native copied payload changed')
    return [r['tag'],0,engine.BUFFER+offset,len(payload)]


def native_record(data,strict=True):
    if strict:require(len(data)==105896032 and hashlib.sha256(data).hexdigest()==SHA256,'Wrong node115 target')
    image=engine.Image(data);spec=native.specification();owner=spec['functions'][0]
    start,end=owner['start'],owner['end'];require((start,end)==(0x46aa760,0x46aab78),'Parser scope changed')
    _,frames=eh_frame_records(data);f=[r for r in frames if r['start']==start]
    require(len(f)==1 and f[0]['end']==end,'Parser FDE changed');f=f[0]
    require(not any(r['start']<end and r['end']>start and r!=f for r in frames),'Overlapping parser FDE')
    va,_,size=image.section('.text');require(va<=start<end<=va+size,'Parser outside .text')
    body=image.read(start,end-start)
    if strict:require(hashlib.sha256(body).hexdigest()==owner['body_sha256'],'Parser body changed')
    from capstone import Cs,CS_ARCH_X86,CS_MODE_64,CS_OP_MEM,CS_OP_IMM
    cs=Cs(CS_ARCH_X86,CS_MODE_64);cs.detail=True;instructions=list(cs.disasm(body,start))
    require(sum(i.size for i in instructions)==len(body) and len(instructions)==owner['instructions'],'Parser export partition changed')
    rips={};calls={}
    for i in instructions:
        if i.mnemonic=='call' and i.operands[0].type==CS_OP_IMM:calls[str(i.address)]=i.operands[0].imm
        for op in i.operands:
            if op.type==CS_OP_MEM and i.reg_name(op.mem.base)=='rip':rips[str(i.address)]=i.address+i.size+op.mem.disp
    require(rips==owner['rip_bindings'] and calls==owner['direct_calls'],'Parser references changed')
    raw_frames={}
    for kind in ('fde','cie'):
        require(f[kind]==owner[kind],'Frame coordinate changed');a=f[kind];n=int.from_bytes(image.read(a,4),'little')+4;b=image.read(a,n)
        require(b.hex()==owner[kind+'_bytes_hex'],'Frame bytes changed');raw_frames[kind]=dict(va=hex(a),bytes_hex=b.hex())
    p=native.parameters(data)
    if strict:require(p==spec['parameters'],'Native policy constants changed')
    table=image.read(0x46ea12,200)
    if strict:require(table==b''.join(f'{i:02d}'.encode() for i in range(100)),'Decimal pair table changed')
    certificates=[r for r in native.division_certificates(p) if r['name']!='lookup']
    _,ro,rs=image.section('.rela.dyn');require(rs%24==0 and ro+rs<=len(data),'Relocation table truncated')
    reloc=list(struct.iter_unpack('<QQq',data[ro:ro+rs]));_,so,ss=image.section('.dynsym');_,st,sts=image.section('.dynstr');bindings={}
    for slot in sorted(set(rips.values())):
        if str(slot) not in spec['relocations']:continue
        rows=[r for r in reloc if r[0]==slot];require(len(rows)==1,'Unique parser relocation writer required')
        _,info,addend=rows[0];index=info>>32;name=None
        if index:
            require(index*24+24<=ss,'Dynamic symbol outside table');off=struct.unpack_from('<I',data,so+index*24)[0]
            require(off<sts,'Dynamic name outside table');stop=data.find(b'\0',st+off,st+sts);require(stop>=0,'Unterminated dynamic name');name=data[st+off:stop].decode('utf8')
        row=dict(kind=info&0xffffffff,symbol_index=index,addend=addend,symbol=name)
        require(row==spec['relocations'][str(slot)],'Parser helper relocation changed');bindings[str(slot)]=row
    record=dict(target_sha256=SHA256,owner=dict(start=hex(start),end=hex(end),bytes=len(body),instructions=len(instructions),sha256=hashlib.sha256(body).hexdigest(),frames=raw_frames),rip_bindings=rips,direct_calls=calls,relocations=bindings,parser_parameters={k:v for k,v in p.items() if not k.startswith(('lookup_','caller_'))},decimal_pair_table=dict(va='0x46ea12',bytes_hex=table.hex(),sha256=hashlib.sha256(table).hexdigest()),formatter_division_certificates=certificates,original_export=[f'{i.address:x}: {i.bytes.hex()} {i.mnemonic} {i.op_str}'.rstrip() for i in instructions],limits='Conditional normal-return raw-byte/value projection. Allocation/copy/compare helpers, native object ABI, lifecycle, caller/context lookup and protocol meaning remain unclosed. No captured execution.')
    return p,table,record

def verify(rustc,output):
    rustc=Path(rustc).resolve();output=Path(output)
    captured={SHA256,'3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f','89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31'}
    if rustc.is_relative_to(ROOT/'artifacts') or hashlib.sha256(rustc.read_bytes()).hexdigest() in captured:raise ValueError('Captured artifact cannot be a compiler')
    version=subprocess.run([str(rustc),'-Vv'],capture_output=True,text=True,check=True).stdout
    require(version.startswith('rustc 1.94.1 '),'Pinned direct Rust1.94.1 required')
    data=(ROOT/BINARY).read_bytes();p,table,original=native_record(data);cases=corpus()
    stream=('\n'.join(json.dumps(dict(input_hex=b.hex(),expected=native.numeric_projection(b,p,table)),sort_keys=True) for b in cases)+'\n').encode()
    require(hashlib.sha256(stream).hexdigest()==FROZEN_EXPECTED_SHA256,'Frozen expectations changed')
    output.mkdir(parents=True,exist_ok=False)
    flags=['--crate-name','node115_numeric_selector','--edition=2024','--crate-type=lib','--emit=obj','--target=x86_64-unknown-linux-gnu','-C','opt-level=3','-C','panic=abort','-C','codegen-units=1','-C','debuginfo=0','-C','lto=off','-C','no-vectorize-loops','-C','no-vectorize-slp']
    source=(CRATE/'src/lib.rs').read_text(encoding='utf8')
    def build(name,text):
        d=output/name;d.mkdir();s=d/'lib.rs';s.write_text(text,encoding='utf8',newline='\n');obj=d/'own.o'
        subprocess.run([str(rustc),*flags,str(s),'-o',str(obj)],check=True,capture_output=True);return obj
    first=build('first',source);second=build('repeat',source);require(first.read_bytes()==second.read_bytes(),'Repeated objects differ');machine,body,instructions=own_machine(first)
    evaluations=0
    for b in cases:
        for offset in range(8):
            require(evaluate(machine,b,offset)==expected(b,p,table,offset),'Own selector mismatch');evaluations+=1
    source_controls=[]
    changes=[('builtin',"input[8] == b'C'","input[8] == b'D'"),('leading_zero','digits.len() > 1','digits.len() > 2'),('at_zero','n == 0 || n >= 100_000_000','n >= 100_000_000'),('at_bound','n >= 100_000_000','n > 100_000_000'),('saturation','n.saturating_add(100_000_000)','n.wrapping_add(100_000_000)'),('checked_parse','n.checked_mul(10).and_then(|v| v.checked_add(digit as u64))','Some(n.wrapping_mul(10).wrapping_add(digit as u64))'),('fallback_payload','Selector::CopySource(input);','Selector::CopySource(if input.is_empty() { input } else { &input[1..] });')]
    for name,before,after in changes:
        require(source.count(before)==1,'Source mutation anchor changed');obj=build(name,source.replace(before,after));m,code,_=own_machine(obj);witness=None
        for b in cases[:15]:
            actual=evaluate(m,b);e=expected(b,p,table)
            if actual!=e:witness=dict(input_hex=b.hex(),expected=e,changed=actual);break
        require(witness is not None,'Compiled mutant survived');source_controls.append(dict(name=name,rejected=True,own_body_sha256=hashlib.sha256(code).hexdigest(),**witness))
    native_controls=[]
    changes=[('prefix',[(0x46aa7a9,b'$')],b'#1'),('at_bound',[(0x46aab07,(100000001).to_bytes(4,'little',signed=True))],b'@100000000'),('hash_offset',[(0x46aab18,(-100000001).to_bytes(4,'little',signed=True)),(0x46aab21,(100000001).to_bytes(4,'little',signed=True))],b'#1'),('numeric_tag',[(0x46aa875,(419).to_bytes(2,'little'))],b'#1'),('builtin_last',[(0x46aa79a,b'D')],b'PURR/USDC'),('decimal_pair',[(0x46ea15,b'2')],b'#1')]
    image=engine.Image(data)
    for name,patches,b in changes:
        changed=bytearray(data)
        for va,value in patches:
            off=image.off(va,len(value));changed[off:off+len(value)]=value
        try:native_record(bytes(changed))
        except ValueError:pass
        else:raise ValueError('Changed target admitted')
        cp,ct,_=native_record(bytes(changed),strict=False);a=expected(b,cp,ct);e=expected(b,p,table)
        require(a!=e,'Native counterexample inactive');native_controls.append(dict(name=name,addresses=[hex(a) for a,_ in patches],input_hex=b.hex(),expected=e,changed=a,rejected=True))
    result=dict(target_sha256=SHA256,native=original,source_sha256={n:hashlib.sha256((CRATE/n).read_bytes()).hexdigest() for n in ('Cargo.toml','Cargo.lock','src/lib.rs')},checker_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),native_model_sha256=hashlib.sha256(Path(native.__file__).read_bytes()).hexdigest(),shared_engine_sha256=hashlib.sha256(Path(engine.__file__).read_bytes()).hexdigest(),compiler_version=version,compiler_sha256=hashlib.sha256(rustc.read_bytes()).hexdigest(),compiler_flags=flags,raw_corpus_cases=len(cases),alignments=8,evaluations=evaluations,mismatches=0,frozen_expected_sha256=FROZEN_EXPECTED_SHA256,own_code_bytes=len(body),own_code_instructions=len(instructions),own_code_sha256=hashlib.sha256(body).hexdigest(),own_objects_reproducible=True,compiled_source_controls=source_controls,native_operand_controls=native_controls,captured_executed=False,target_code_identity_measured=False,limits='New enum and synthetic probe ABI only. CopySource borrows the input bytes; it does not reproduce native allocation/ownership. Native numeric/copied-byte policy assumes normal opaque helpers. Callers, namespace lookup, full ABI and component gates remain open.')
    (output/'rust-validation.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf8',newline='\n')
    (output/'original.capstone.txt').write_text('\n'.join(original['original_export'])+'\n',encoding='utf8',newline='\n')
    (output/'own-rust.capstone.txt').write_text('\n'.join(f'{i.address-0x100000:x}: {i.bytes.hex()} {i.mnemonic} {i.op_str}'.rstrip() for i in instructions)+'\n',encoding='utf8',newline='\n')
    return result

if __name__=='__main__':
    import argparse
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--rustc',required=True);p.add_argument('--out',required=True);a=p.parse_args();r=verify(a.rustc,a.out)
    print(json.dumps(dict(raw_cases=r['raw_corpus_cases'],evaluations=r['evaluations'],mismatches=r['mismatches'],source_controls=len(r['compiled_source_controls']),native_controls=len(r['native_operand_controls']))))
