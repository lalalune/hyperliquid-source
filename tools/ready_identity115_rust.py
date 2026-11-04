"""Node115 qualified ready-vector identity relation; captured artifacts stay inert."""
from pathlib import Path
import hashlib,json,random,struct,subprocess
import evm_amount_scale as engine
import tls_lock_id_static as native
from fde_extents import eh_frame_records
ROOT=Path(__file__).resolve().parents[1]
BINARY='artifacts/node/115/hl-node'
SHA256='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
CRATE=ROOT/'src/node115-ready-identity'
PACKET=ROOT/'research/work-items/RE-001-ready-identity-rust-115'
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
    text = [(name, section) for name, section in image.sec.items() if name == '.text.node115_identity_probe' and section[2]]
    if len(text) != 1 or text[0][0] != '.text.node115_identity_probe':
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


def evaluate(m,rows,key,counter,enabled,offset=0):
 m.reset();m.setreg(engine.RSP,engine.STACK_TOP);m.store(engine.STACK_TOP,8,engine.RET_MAGIC)
 saved={r:0x1122334400000000+r for r in (engine.RBX,engine.RBP,engine.R12,engine.R13,engine.R14,engine.R15)}
 for r,v in saved.items():m.setreg(r,v)
 rp=engine.BUFFER+4096+offset;kp=engine.BUFFER+8192+offset;bp=engine.BUFFER+12288+offset
 def raw(address,blob):
  for i,b in enumerate(blob):m.store(address+i,1,b)
 raw(kp,bytes([0xa5])*40);m.store(kp,8,bp);m.store(kp+8,8,len(key[0]));m.store(kp+16,4,key[1]);m.store(kp+24,8,key[2]);raw(bp,key[0])
 for i,row in enumerate(rows):
  at=rp+56*i;data=bp+256*(i+1);raw(at,bytes([0x5a+i])*56);m.store(at,8,data);m.store(at+8,8,len(row[0]));m.store(at+16,4,row[1]);m.store(at+24,8,row[2]);raw(data,row[0])
 for r,v in zip((engine.RDI,engine.RSI,engine.RDX,engine.RCX,engine.R8,engine.R9),(engine.BUFFER,rp,len(rows),kp,counter,enabled)):m.setreg(r,v)
 require(m.run(0x100000,limit=20000)==engine.RET_MAGIC,'Own return failed')
 for r,v in saved.items():require(m.known[r]==engine.MASK and m.regs[r]==v,'Saved register changed')
 flag=m.load(engine.BUFFER,8);return [m.load(engine.BUFFER+8*i,8) for i in range(3)] if flag else [0]

def raw_record(blob,word,token,fill):
 r=bytearray([fill]*56);struct.pack_into('<QQI',r,0,0x100000+fill*256,len(blob),word);struct.pack_into('<Q',r,24,token);return bytes(r)
def project(code,rows,key,counter,enabled):
 p=native.probe_layout(code)
 if enabled!=p['enabled_value']:return dict(selected_path=True,value=False,counter=counter)
 if counter>=p['borrow_limit']:return dict(selected_path=False,reason='borrow-failure route unqualified')
 assert p['stride_multiply']==p['stride_increment']==56
 input_offsets=[code[0xa1],code[0xa5],code[0xb1]]
 kp=raw_record(*key,0xa5)
 for row in rows:
  rp=raw_record(*row,0x5a)
  if all(rp[f['record_offset']:f['record_offset']+f['width']]==kp[i:i+f['width']] for f,i in zip(p['fields'],input_offsets)) and row[0]==key[0]:return dict(selected_path=True,value=True,counter=counter)
 return dict(selected_path=True,value=False,counter=counter)

def native_record(data):
 require(len(data)==105896032 and hashlib.sha256(data).hexdigest()==SHA256,'Wrong node115 target')
 report=native.analyze(data);require(report==json.loads((native.PACKET/'records.json').read_bytes()),'Retained native certificate changed')
 image=engine.Image(data);_,frames=eh_frame_records(data)
 _,off,size=image.section('.rela.dyn');require(off+size<=len(data) and size%24==0,'Truncated relocation table');relocs=list(struct.iter_unpack('<QQq',data[off:off+size]))
 slots=set(native.BINDINGS)|set(native.LOCATIONS)|{0x64df9f8}
 for slot in slots:require(len([r for r in relocs if r[0]==slot])==1,'Duplicate/missing selected relocation writer')
 from capstone import Cs,CS_ARCH_X86,CS_MODE_64
 cs=Cs(CS_ARCH_X86,CS_MODE_64);owners=[]
 for name,(start,end,sha) in native.OWNERS.items():
  fs=[f for f in frames if f['start']==start];require(len(fs)==1 and fs[0]['end']==end,'Unique full owner FDE required')
  require(not any(f['start']<end and f['end']>start and f!=fs[0] for f in frames),'Overlapping native FDE')
  body=image.read(start,end-start);ins=list(cs.disasm(body,start));require(sum(i.size for i in ins)==len(body),'Incomplete native export')
  owners.append(dict(role=name,start=hex(start),end=hex(end),bytes=len(body),instructions=len(ins),sha256=hashlib.sha256(body).hexdigest(),export=[f'{i.address:x}: {i.bytes.hex()} {i.mnemonic} {i.op_str}'.rstrip() for i in ins]))
 code=image.read(0x154cd10,299)
 for at,h in [(0xe,'807f2001'),(0x21,'83f801'),(0x67,'64498b0e'),(0x75,'4839c1'),(0x7e,'488d4101'),(0x82,'64498906'),(0x9e,'4c8b7f18'),(0xa2,'448b6710'),(0xae,'4c8b7708'),(0xe8,'4c89f2'),(0xf1,'85c0'),(0x10b,'6449890e')]:
  require(code[at:at+len(bytes.fromhex(h))]==bytes.fromhex(h),'Ready scan/state opcode changed')
 return dict(target_sha256=SHA256,existing_certificate=report,owners=owners,normal_helper='GLOB_DAT symbol11 bcmp via0x64df9f8; ordinary ABI-preserving return/equality contract is a premise, runtime implementation/interposition excluded',projection='Enabled input!=1 returns false; ready TLS counter<2^63-1 admits finite56B vector scan, three scalar equalities then bytes equal; both local returning outcomes restore original counter',limits='New logical API/adapter, no original Rust type/ABI/TLS lifecycle/panic/unwind/actual counter mutation/ordering/caller effects or byte identity. All encoded slices valid<=isizeMAX, stricter than native deferred bcmp reads.')

def corpus():
 rows=[];seen=set()
 def add(records,key):
  signature=(tuple(records),key)
  if signature not in seen:seen.add(signature);rows.append((records,key))
 for length in (0,1,7,8,15,16,31,32,63,64,65,127,128):
  payload=bytes((i*37+length)&255 for i in range(length));key=(payload,0x89abcdef,0xfedcba9876543210)
  other=payload[:-1]+bytes([payload[-1]^1]) if payload else b'x'
  mismatch=(other,key[1],key[2]);word=(payload,key[1]^1,key[2]);token=(payload,key[1],key[2]^1)
  for r in ([],[key],[mismatch],[word],[token],[mismatch,key],[word,token,key],[key,key],[key,mismatch],[key,word,key]):add(r,key)
  add([(payload+b'x',key[1],key[2])],key)
  if payload:add([(payload[:-1],key[1],key[2])],key)
  for position in sorted({0,length//2,length-1}) if length else []:
   changed=bytearray(payload);changed[position]^=1;add([(bytes(changed),key[1],key[2])],key)
 for word in (0,1,0x7fffffff,0x80000000,0xffffffff):
  for token in (0,1,0x7fffffffffffffff,0x8000000000000000,0xffffffffffffffff):
   key=(b'\x00\xff',word,token);add([key],key);add([(key[0],word^1,token)],key)
 rng=random.Random(0x154cd10)
 for i in range(512):
  key=(rng.randbytes(rng.randrange(129)),rng.getrandbits(32),rng.getrandbits(64));records=[]
  for j in range(i%13):records.append(key if j==i%7 else (rng.randbytes(len(key[0])),key[1]^(j%3==0),key[2]^(j%3==1)))
  add(records,key)
 return rows

def verify(rustc,output):
 rustc=Path(rustc).resolve();output=Path(output)
 if rustc.is_relative_to(ROOT/'artifacts') or hashlib.sha256(rustc.read_bytes()).hexdigest() in {SHA256,'3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f','89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31'}:raise ValueError('Captured artifact cannot be a compiler')
 version=subprocess.run([str(rustc),'-Vv'],check=True,capture_output=True,text=True).stdout;require(version.startswith('rustc 1.94.1 '),'Pinned Rust1.94.1 required')
 data=(ROOT/BINARY).read_bytes();original=native_record(data);code=engine.Image(data).read(0x154cd10,299)
 output.mkdir(parents=True,exist_ok=False);source=(CRATE/'src/lib.rs').read_text(encoding='utf8')
 flags=['--crate-name','node115_ready_identity','--edition=2024','--crate-type=lib','--emit=obj','--target=x86_64-unknown-linux-gnu','-C','opt-level=3','-C','panic=abort','-C','codegen-units=1','-C','debuginfo=0','-C','lto=off','-C','no-vectorize-loops','-C','no-vectorize-slp']
 def build(name,text):
  d=output/name;d.mkdir();s=d/'lib.rs';s.write_text(text,encoding='utf8',newline='\n');obj=d/'own.o';subprocess.run([str(rustc),*flags,str(s),'-o',str(obj)],check=True,capture_output=True);return obj
 first=build('first',source);second=build('repeat',source);require(first.read_bytes()==second.read_bytes(),'Repeated own objects differ');m,body,ins=own_machine(first)
 fixtures=corpus();evaluations=0;stream=[]
 for records,key in fixtures:
  row=dict(rows=[dict(bytes_hex=x[0].hex(),word=x[1],token=x[2]) for x in records],key=dict(bytes_hex=key[0].hex(),word=key[1],token=key[2]));stream.append(row)
  for counter,enabled in ((0,1),((1<<63)-2,1),(engine.MASK,0),(engine.MASK,2)):
   expected=project(code,records,key,counter,enabled);require(expected['selected_path'],'Outside native cut')
   words=[1,int(expected['value']),counter]
   for offset in range(8):require(evaluate(m,records,key,counter,enabled,offset)==words,'Own scan/state projection mismatch');evaluations+=1
 refusals=[]
 for counter in ((1<<63)-1,engine.MASK):
  require(evaluate(m,[],(b'',0,0),counter,1)==[0],'Own domain refusal changed');refusals.append(dict(counter=counter,scope='Own API refusal only; native failure route unqualified'))
 k=(b'abc',0x89abcdef,0xfedcba9876543210);no=(b'abx',k[1],k[2]);wrongword=(b'abc',k[1]^1,k[2]);wrongtag=(b'abc',k[1],k[2]^1)
 cases=[([],k,0,1),([k],k,0,1),([no,k],k,(1<<63)-2,1),([no],k,0,1),([wrongword],k,0,1),([wrongtag],k,0,1),([k],k,(1<<63)-1,1),([k],k,0,0)]
 changes=[('enabled','enabled != 1','enabled == 1'),('borrow_bound','counter >= (1u64 << 63) - 1','counter > (1u64 << 63) - 1'),('token','row.token != key.token','row.token == key.token'),('word','row.word != key.word','row.word == key.word'),('byte_equality','read_volatile() != key.bytes','read_volatile() == key.bytes'),('match_result','if equal { return Some(true); }','if equal { return Some(false); }'),('raw_word_offset','(row.add(16) as *const u32)','(row.add(20) as *const u32)')]
 controls=[]
 for name,before,after in changes:
  require(source.count(before)==1,'Mutation anchor changed');obj=build(name,source.replace(before,after));cm,cb,_=own_machine(obj);witness=None
  for records,key,counter,enabled in cases:
   expected=project(code,records,key,counter,enabled);words=[1,int(expected['value']),counter] if expected['selected_path'] else [0];a=evaluate(cm,records,key,counter,enabled)
   if a!=words:witness=dict(counter=counter,enabled=enabled,expected=words,changed=a);break
  require(witness is not None,'Compiled source corruption survived');controls.append(dict(name=name,rejected=True,own_code_sha256=hashlib.sha256(cb).hexdigest(),**witness))
 native_controls=[];image=engine.Image(data);expected=project(code,[k],k,7,1)
 for name,offset,value in [('enabled_value',0x11,b'\x02'),('record_token_offset',0xcd,b'\x20'),('record_word_offset',0xd4,b'\x14'),('record_length_offset',0xdb,b'\x00'),('input_token_offset',0xa1,b'\x10'),('borrow_limit',0x6d,(0).to_bytes(8,'little'))]:
  cp=bytearray(code);cp[offset:offset+len(value)]=value;changed=project(cp,[k],k,7,1);require(changed!=expected,'Native operand control inactive');mut=bytearray(data);off=image.off(0x154cd10+offset,len(value));mut[off:off+len(value)]=value
  try:native_record(bytes(mut))
  except ValueError:pass
  else:raise ValueError('Mutated native admitted')
  native_controls.append(dict(name=name,va=hex(0x154cd10+offset),rejected=True,expected=expected,changed=changed))
 corpus_bytes=('\n'.join(json.dumps(x,sort_keys=True) for x in stream)+'\n').encode()
 result=dict(target_sha256=SHA256,native=original,source_sha256={n:hashlib.sha256((CRATE/n).read_bytes()).hexdigest() for n in ('Cargo.toml','Cargo.lock','src/lib.rs')},checker_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),native_model_sha256=hashlib.sha256(Path(native.__file__).read_bytes()).hexdigest(),shared_engine_sha256=hashlib.sha256(Path(engine.__file__).read_bytes()).hexdigest(),compiler_version=version,compiler_sha256=hashlib.sha256(rustc.read_bytes()).hexdigest(),flags=flags,fixtures=len(fixtures),corpus_sha256=hashlib.sha256(corpus_bytes).hexdigest(),state_pairs=4,alignments=8,evaluations=evaluations,mismatches=0,own_api_refusals=refusals,compiled_source_controls=controls,native_operand_controls=native_controls,own_code_bytes=len(body),own_code_instructions=len(ins),own_code_sha256=hashlib.sha256(body).hexdigest(),own_objects_reproducible=True,captured_executed=False,target_code_identity_measured=False,limits=original['limits'])
 (output/'rust-validation.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf8',newline='\n')
 (output/'corpus.jsonl').write_bytes(corpus_bytes)
 (output/'own-rust.capstone.txt').write_text('\n'.join(f'{i.address-0x100000:x}: {i.bytes.hex()} {i.mnemonic} {i.op_str}'.rstrip() for i in ins)+'\n',encoding='utf8',newline='\n')
 for row in original['owners']:(output/(row['role']+'.capstone.txt')).write_text('\n'.join(row['export'])+'\n',encoding='utf8',newline='\n')
 return result

if __name__=='__main__':
 import argparse
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--rustc',required=True);p.add_argument('--out',required=True);a=p.parse_args();r=verify(a.rustc,a.out);print(json.dumps(dict(fixtures=r['fixtures'],evaluations=r['evaluations'],mismatches=r['mismatches'])))
