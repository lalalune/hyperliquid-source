"""Bounded #115 write-progress reconstruction: static original, own Rust only."""
from pathlib import Path
import hashlib, itertools, json, subprocess, time, struct
import evm_amount_scale as engine
from fde_extents import eh_frame_records
ROOT = Path(__file__).resolve().parents[1]
BINARY = 'artifacts/node/115/hl-node'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
CRATE = ROOT / 'src/node115-write-progress'
PACKET = ROOT / 'research/work-items/RE-012-write-progress-115'

def require(ok, message):
    if not ok:
        raise ValueError(message)

class NoExternalMemory:

    def in_rodata(self, *args):
        return False

    def read(self, *args):
        raise engine.Unmodelled('No external data in own-code adapter')

def native_record(D):
    require(len(D) == 105896032 and hashlib.sha256(D).hexdigest() == SHA256, 'Wrong node115 target')
    im = engine.Image(D)

    def exact(pc, h):
        b = bytes.fromhex(h)
        require(im.read(pc, len(b)) == b, 'Native binding changed')
        return {'va': hex(pc), 'bytes': h}
    checks = [exact(pc, h) for pc, h in [(45592464, 'f048014a10'), (45592584, '4829d1'), (45592593, '4801d0'), (45592626, '41c6042403'), (45592669, '41c6042401')]]
    branches = []
    for pc, size, target in [(45592515, 6, 45592652), (45592546, 2, 45592617), (45592587, 6, 45593475), (45592613, 2, 45592512), (45592624, 2, 45592639)]:
        b = im.read(pc, size)
        width = 4 if size == 6 else 1
        actual = pc + size + int.from_bytes(b[-width:], 'little', signed=True)
        require(actual == target, 'Native binding changed')
        branches.append(dict(va=hex(pc), bytes=b.hex(), target=hex(target)))
    tables = []
    for pc, targets in [(45592325, [45592341, 45593559, 45593544, 45592399]), (45592416, [45592432, 45593574, 45593589, 45593370])]:
        b = im.read(pc, 7)
        require(b[:3] == bytes.fromhex('488d0d'), 'Native binding changed')
        va = pc + 7 + int.from_bytes(b[3:], 'little', signed=True)
        raw = im.read(va, 16)
        actual = [va + struct.unpack_from('<i', raw, i * 4)[0] for i in range(4)]
        require(actual == targets, 'Native binding changed')
        tables.append(dict(lea=hex(pc), table=hex(va), raw=raw.hex(), targets=[hex(t) for t in targets]))
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    cs = Cs(CS_ARCH_X86, CS_MODE_64)
    resume = list(cs.disasm(im.read(45593370, 12), 45593370))
    exact(0x2b7b31a, '488b8b38020000e98bfcffff')
    calls = []
    for pc, target in [(45592538, 97385616), (45592642, 44050128)]:
        b = im.read(pc, 5)
        require(b[0] == 232 and pc + 5 + int.from_bytes(b[1:], 'little', signed=True) == target, 'Native binding changed')
        calls.append(dict(va=hex(pc), bytes=b.hex(), target=hex(target)))
    _, ro, rs = im.section('.rela.dyn')
    _, so, ss = im.section('.dynsym')
    _, st, sts = im.section('.dynstr')
    imports = []
    for pc in [97385790, 97385802]:
        b = im.read(pc, 6)
        require(b[:2] == bytes.fromhex('ff15'), 'Native binding changed')
        slot = pc + 6 + int.from_bytes(b[2:], 'little', signed=True)
        rr = [(s, info, addend) for s, info, addend in struct.iter_unpack('<QQq', D[ro:ro + rs]) if s == slot]
        require(len(rr) == 1, 'Native binding changed')
        _, info, addend = rr[0]
        require(info & 4294967295 == 6 and (info >> 32) * 24 + 24 <= ss, 'Native binding changed')
        nameoff = struct.unpack_from('<I', D, so + (info >> 32) * 24)[0]
        require(nameoff < sts, 'Native binding changed')
        end = D.find(b'\x00', st + nameoff, st + sts)
        require(end >= 0, 'Native binding changed')
        name = D[st + nameoff:end].decode('ascii')
        imports.append(dict(va=hex(pc), slot=hex(slot), relocation_type=6, symbol=name, addend=addend))
    require([i['symbol'] for i in imports] == ['send', '__errno_location'], 'Native binding changed')
    record = dict(target_sha256=hashlib.sha256(D).hexdigest(), checks=checks, branches=branches, tables=tables, calls=calls, imports=imports, resume_dump=[f'{i.address:x}: {i.bytes.hex()} {i.mnemonic} {i.op_str}' for i in resume], limit='Conditional raw helper outputs only; send/readiness/CAS behavior, error conversion, alias interference and scheduler remain unclosed. Shared owner with PR2068 and2117 retained as context, not claimed as newly recovered whole function.')
    return record

def own_machine(path):
    data = Path(path).read_bytes()
    if len(data) < 64:
        raise ValueError('Truncated own Rust object')
    if data[:6] != b'\x7fELF\x02\x01' or int.from_bytes(data[16:18], 'little') != 1 or int.from_bytes(data[18:20], 'little') != 62:
        raise ValueError('Expected our Linux x86-64 relocatable Rust object')
    image = engine.Image(data)
    if any((name.startswith(('.rela.text', '.rel.text')) for name in image.sec)):
        raise ValueError('External code relocations are not supported')
    text = [(name, section) for name, section in image.sec.items() if name == '.text.node115_progress_probe' and section[2]]
    if len(text) != 1 or text[0][0] != '.text.node115_progress_probe':
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

class NativeStep:

    def __init__(self, data=None, strict=True):
        if data is None:
            data = (ROOT / BINARY).read_bytes()
        if strict:
            native_record(data)
        self.im = engine.Image(data)
        _, fs = eh_frame_records(data)
        for start, end, digest in [(45589136, 45593891, '2bf6ed624f7fb94712c9834aff1dabd860f718c380e11ab5812642eba3ce09cb'), (97385616, 97386059, 'df885a621985a5dae8f50e02efbadea04d1cd6036db2a7408b74eb4b7b22e807')]:
            found = [f for f in fs if f['start'] == start]
            require(len(found) == 1 and found[0]['end'] == end, 'Native or own-code qualification failed')
            if strict:
                require(hashlib.sha256(self.im.read(start, end - start)).hexdigest() == digest, 'Native body changed')
        for va, h in [(45592512, '4885c9'), (45592543, '4885c0'), (45592584, '4829d1'), (45592593, '4801d0'), (45592610, '4885d2'), (45592464, 'f048014a10')]:
            require(self.im.read(va, len(bytes.fromhex(h))) == bytes.fromhex(h), 'Native or own-code qualification failed')
        require(self.im.read(45592620, 3) == bytes.fromhex('4883f8'), 'Native or own-code qualification failed')
        self.pending = self.im.read(45592623, 1)[0]
        require(self.im.read(45592497, 2) == bytes.fromhex('49be'), 'Native or own-code qualification failed')
        self.zero = int.from_bytes(self.im.read(45592499, 8), 'little')
        require(self.im.read(45592626, 4) == bytes.fromhex('41c60424'), 'Native or own-code qualification failed')
        require(self.im.read(45592669, 4) == bytes.fromhex('41c60424'), 'Native or own-code qualification failed')
        self.pending_state = self.im.read(45592630, 1)[0]
        self.done_state = self.im.read(45592673, 1)[0]

    def step(self, p, r, s, n, c):
        charge = c + r & engine.MASK
        if r == 0:
            return [p, r, 1, 0, self.done_state, charge]
        if s:
            if s == self.pending:
                return [p, r, 2, 0, self.pending_state, charge]
            return [p, r, 3, n, self.done_state, charge]
        if n > r:
            return [1, 0, 4, 0, 0, charge]
        p = p + n & engine.MASK
        r -= n
        if n:
            return [p, r, 0, 0, 0, charge]
        return [p, r, 3, self.zero, self.done_state, charge]

def evaluate(m, args):
    m.reset()
    m.setreg(engine.RSP, engine.STACK_TOP)
    m.store(engine.STACK_TOP, 8, engine.RET_MAGIC)
    saved = {r: 1234605615003729920 + r for r in (engine.RBX, engine.RBP, engine.R12, engine.R13, engine.R14, engine.R15)}
    for r, v in saved.items():
        m.setreg(r, v)
    for r, v in zip((engine.RDI, engine.RSI, engine.RDX, engine.RCX, engine.R8, engine.R9), (engine.BUFFER, *args)):
        m.setreg(r, v)
    require(m.run(1048576, limit=2000) == engine.RET_MAGIC, 'Native or own-code qualification failed')
    for r, v in saved.items():
        require(m.known[r] == engine.MASK and m.regs[r] == v, 'Own saved register changed')
    return [m.load(engine.BUFFER + 8 * i, 8) for i in range(6)]

def corpus():
    return itertools.product([0,1,4096,engine.MASK],[0,1,2,3,16,1<<63,engine.MASK],[0,1,2,3,4,1<<63,engine.MASK],[0,1,2,3,15,16,1<<63,engine.MASK],[0,engine.MASK])

def verify(rustc,output):
    rustc=Path(rustc).resolve();output=Path(output)
    captured={SHA256,'3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f','89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31'}
    if rustc.is_relative_to(ROOT/'artifacts') or hashlib.sha256(rustc.read_bytes()).hexdigest() in captured:
        raise ValueError('Captured artifact cannot be a compiler')
    version=subprocess.run([str(rustc),'-Vv'],check=True,capture_output=True,text=True).stdout
    require(version.startswith('rustc 1.94.1 '),'Pinned Rust1.94.1 required')
    output.mkdir(parents=True,exist_ok=False)
    data=(ROOT/BINARY).read_bytes();native=NativeStep(data);record=native_record(data)
    flags=['--crate-name','node115_write_progress','--edition=2024','--crate-type=lib','--emit=obj','--target=x86_64-unknown-linux-gnu','-C','opt-level=2','-C','panic=abort','-C','codegen-units=1','-C','debuginfo=0','-C','lto=off','-C','no-vectorize-loops','-C','no-vectorize-slp']
    source=(CRATE/'src/lib.rs').read_text(encoding='utf8')
    def build(name,text):
        d=output/name;d.mkdir();p=d/'lib.rs';p.write_text(text,encoding='utf8',newline='\n');obj=d/'own.o'
        subprocess.run([str(rustc),*flags,str(p),'-o',str(obj)],check=True,capture_output=True)
        return obj
    first=build('first',source);second=build('repeat',source)
    require(first.read_bytes()==second.read_bytes(),'Repeated objects differ')
    machine,body,ins=own_machine(first);count=0
    for args in corpus():
        require(evaluate(machine,args)==native.step(*args),'Compiled transition mismatch');count+=1
    controls=[]
    for name,before,after in [('empty','if remaining == 0 {','if remaining == 1 {'),('pending','if status == 2 {','if status == 3 {'),('borrow','if value > remaining {','if value >= remaining {'),('pointer','pointer.wrapping_add(value)','pointer.wrapping_sub(value)'),('zero','argument: 0x1700000003','argument: 0x1700000004'),('charge','counter.wrapping_add(length)','counter.wrapping_sub(length)')]:
        require(source.count(before)==1,'Mutant anchor changed');obj=build(name,source.replace(before,after));m,_,_=own_machine(obj);witness=None
        for args in corpus():
            actual=evaluate(m,args);expected=native.step(*args)
            if actual!=expected:witness=dict(inputs=list(args),expected=expected,changed=actual);break
        require(witness is not None,'Compiled mutant survived')
        controls.append(dict(name=name,object_sha256=hashlib.sha256(obj.read_bytes()).hexdigest(),rejected=True,**witness))
    counterexamples=[]
    for name,va,value,args in [('pending_tag',0x2b7b02f,3,(0,1,2,0,0)),('zero_error',0x2b7afb3,4,(0,1,0,0,0)),('pending_state',0x2b7b036,2,(0,1,2,0,0)),('done_state',0x2b7b061,2,(0,0,0,0,0))]:
        patched=bytearray(data);patched[engine.Image(data).off(va,1)]=value
        rejected=False
        try:NativeStep(bytes(patched))
        except ValueError:rejected=True
        require(rejected,'Changed captured target accepted')
        changed=NativeStep(bytes(patched),strict=False).step(*args);expected=native.step(*args)
        require(changed!=expected,'Native immediate counterexample inactive')
        counterexamples.append(dict(name=name,va=hex(va),inputs=list(args),expected=expected,changed=changed,rejected=True))
    owners=[];_,frames=eh_frame_records(data);image=engine.Image(data)
    for va in [0x2b7a290,0x5cdfc90]:
        f=[x for x in frames if x['start']==va][0];raw=image.read(va,f['end']-va)
        from capstone import Cs,CS_ARCH_X86,CS_MODE_64
        rows=list(Cs(CS_ARCH_X86,CS_MODE_64).disasm(raw,va));require(sum(i.size for i in rows)==len(raw),'Incomplete original export')
        raw_frames={kind:dict(va=hex(f[kind]),bytes_hex=image.read(f[kind],int.from_bytes(image.read(f[kind],4),'little')+4).hex()) for kind in ('fde','cie')}
        owners.append(dict(frames=raw_frames,start=hex(va),end=hex(f['end']),fde=hex(f['fde']),cie=hex(f['cie']),bytes=len(raw),instructions=len(rows),sha256=hashlib.sha256(raw).hexdigest()))
        (output/(hex(va)+'.capstone.txt')).write_text('\n'.join(f'{i.address:x}: {i.bytes.hex()} {i.mnemonic} {i.op_str}' for i in rows)+'\n',encoding='utf8')
    result=dict(target_sha256=SHA256,native=record,owners=owners,cases=count,mismatches=0,source_sha256={name:hashlib.sha256((CRATE/name).read_bytes()).hexdigest() for name in ['Cargo.toml','Cargo.lock','src/lib.rs']},checker_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),compiler_version=version,compiler_sha256=hashlib.sha256(rustc.read_bytes()).hexdigest(),flags=flags,own_body_sha256=hashlib.sha256(body).hexdigest(),own_body_bytes=len(body),own_instruction_count=len(ins),repeated_objects_equal=True,compiled_source_controls=controls,native_operand_controls=counterexamples,captured_binary_executed=False,target_code_identity_measured=False,limits='Conditional single raw-helper transition and separate wrapping charge only. Unknown helper readiness/retry/CAS, scheduling, cancellation, error transformation, alias preservation, full future ABI and network delivery. Synthetic probe layout is not native ABI. Shared owner is contextual, not whole-function implementation credit.')
    (output/'rust-validation.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf8')
    (output/'own-rust.capstone.txt').write_text('\n'.join(f'{i.address-0x100000:x}: {i.bytes.hex()} {i.mnemonic} {i.op_str}' for i in ins)+'\n',encoding='utf8')
    return result

if __name__=='__main__':
    import argparse
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--rustc',required=True);p.add_argument('--out',required=True);a=p.parse_args()
    r=verify(a.rustc,a.out);print(json.dumps({'cases':r['cases'],'mismatches':r['mismatches'],'compiled_controls':len(r['compiled_source_controls']),'native_controls':len(r['native_operand_controls'])}))
