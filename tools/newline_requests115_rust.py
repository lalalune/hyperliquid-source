"""Node115 newline request/state protocol; only newly compiled own code is interpreted."""
from pathlib import Path
import copy,gzip,hashlib,importlib.util,itertools,json,struct,subprocess,sys
import evm_amount_scale as engine
from fde_extents import eh_frame_records
ROOT=Path(__file__).resolve().parents[1]
BINARY='artifacts/node/115/hl-node'
SHA256='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
CRATE=ROOT/'src/node115-newline-requests'
PACKET=ROOT/'research/work-items/RE-014-newline-requests-rust-115'
NATIVE_PACKET=ROOT/'research/work-items/RE-014-node115-newline-protocol'
ORACLE_PATH=ROOT/'tests/test_node_padadapter_semantic_comparison.py'
def require(ok,message):
 if not ok:raise ValueError(message)
def load_module(name,path):
 spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
native=load_module('licensed_newline_collect115',NATIVE_PACKET/'collect.py')
oracle=load_module('licensed_pad_trace115',ORACLE_PATH)
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
    text = [(name, section) for name, section in image.sec.items() if name == '.text.node115_newline_probe' and section[2]]
    if len(text) != 1 or text[0][0] != '.text.node115_newline_probe':
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


def evaluate(m,data,initial,actions,offset=0):
 m.reset();m.setreg(engine.RSP,engine.STACK_TOP);m.store(engine.STACK_TOP,8,engine.RET_MAGIC)
 saved={r:0x1122334400000000+r for r in (engine.RBX,engine.RBP,engine.R12,engine.R13,engine.R14,engine.R15)}
 for r,v in saved.items():m.setreg(r,v)
 buf=engine.BUFFER+24576+offset;script=engine.BUFFER+28672
 for i,b in enumerate(data):m.store(buf+i,1,b)
 for i,a in enumerate(actions):
  for j,v in enumerate((*a,0)):m.store(script+4*i+j,1,v)
 for r,v in zip((engine.RDI,engine.RSI,engine.RDX,engine.RCX,engine.R8,engine.R9),(engine.BUFFER,buf,len(data),initial,script,len(actions))):m.setreg(r,v)
 require(m.run(0x100000,limit=200000)==engine.RET_MAGIC,'Own return failed')
 for r,v in saved.items():require(m.known[r]==engine.MASK and m.regs[r]==v,'Saved register changed')
 head=[m.load(engine.BUFFER+8*i,8) for i in range(3)];require(head[2]<=2*len(data),'Own callback count exceeds qualified bound')
 return head+[[m.load(engine.BUFFER+24+32*i+8*j,8) for j in range(4)] for i in range(head[2])]


def short_projection(image,data,initial,actions):
 require(len(data)<=15,'Only the scalar short scan is parameterized for changed targets')
 scan=image.at(0x1686cd3,1)[0];owned=image.at(0x1686c34,1)[0];skip=image.at(0x1686dff,1)[0];length=int.from_bytes(image.at(0x1686e03,4),'little');literal=int.from_bytes(image.at(0x45a128,4),'little');failure=image.at(0x1686e36,1)[0]
 state=initial;events=[];start=0
 def call(kind,value,length):
  nonlocal state
  i=len(events);events.append([kind,value,length,state]);a=actions[i] if i<len(actions) else (0,0,0)
  if a[1]:state=a[2]
  return a[0]
 while start<len(data):
  pos=data.find(bytes([scan]),start);end=pos+1 if pos>=0 else len(data)
  if state!=skip:
   if call(1,literal,length):return [failure,state,len(events),*events]
  state=int(data[end-1]==owned)
  if call(0,start,end-start):return [failure,state,len(events),*events]
  start=end
 return [0,state,len(events),*events]

def native_record(data):
 require(len(data)==105896032 and hashlib.sha256(data).hexdigest()==SHA256,'Wrong node115 target')
 image=native.Image('115',data);_,frames=eh_frame_records(data);retained=json.loads((NATIVE_PACKET/'observed/records.json').read_bytes())
 from capstone import Cs,CS_ARCH_X86,CS_MODE_64
 cs=Cs(CS_ARCH_X86,CS_MODE_64);owners=[]
 for name,(_,start,end,_) in native.RANGES.items():
  fs=[f for f in frames if f['start']==start];require(len(fs)==1 and fs[0]['end']==end,'Unique complete owner FDE required')
  require(not any(f['start']<end and f['end']>start and f!=fs[0] for f in frames),'Overlapping owner FDE')
  body=image.at(start,end-start);ins=list(cs.disasm(body,start));require(sum(i.size for i in ins)==len(body),'Incomplete native export')
  old=native.partition(image,(NATIVE_PACKET/'observed'/(name+'.gnu.txt')).read_text(encoding='utf8'),start,end)
  require([(i.address,bytes(i.bytes)) for i in ins]==[(a,b) for a,b,_ in old],'Fresh Capstone/retained GNU raw partition differs')
  record=retained['ranges'][name];require(hashlib.sha256(body).hexdigest()==record['bodySha256'],'Retained native body differs')
  require(fs[0]['fde']==image.named['.eh_frame'][3]+int(record['fde']['sectionOffset'],16),'Actual FDE/retained coordinates differ')
  require(fs[0]['cie']==image.named['.eh_frame'][3]+int(record['fde']['cie']['sectionOffset'],16),'Actual CIE/retained coordinates differ')
  for which in ('fde','cie'):
   f=record['fde'] if which=='fde' else record['fde']['cie'];off=int(f['fileOffset'],16);raw=bytes.fromhex(f['raw']);require(data[off:off+len(raw)]==raw,'Retained raw frame/CIE differs')
  if name=='adapter115':require(native.bind(image,old)==record['bindings'],'Retained complete native operand binding differs')
  owners.append(dict(role=name,start=hex(start),end=hex(end),bytes=len(body),instructions=len(ins),sha256=hashlib.sha256(body).hexdigest(),frames=record['fde'],export=[f'{i.address:x}: {i.bytes.hex()} {i.mnemonic} {i.op_str}'.rstrip() for i in ins]))
 return dict(target_sha256=SHA256,owners=owners,bindings=retained['ranges']['adapter115']['bindings'],retained_reference_source_base=retained['sourceBase'],scope='630B helper request/state protocol under immutable nonaliasing input, protected storage and normally returning preserving callbacks;390B parent context only. No original Rust type/ABI, physical callback identity/vtable, rendered output, arbitrary aliases, unwind/concurrency or whole-node closure. Empty safe API still requires a valid flag reference, stricter than original empty B mapping requirement.')

def reference(data,initial,actions,alignment):
 fail=next((i for i,a in enumerate(actions) if a[0]),None);mutations={str(i):a[2] for i,a in enumerate(actions) if a[1]}
 calls,final,status,flags=oracle.abstract_trace(data,initial,fail,alignment,mutations);result=[status,final,len(calls)]
 for call,flag in zip(calls,flags):
  if call=='indent':result.append([1,0x20202020,4,flag])
  else:
   _,start,end=call.split(':');result.append([0,int(start),int(end)-int(start),flag])
 return result

def corpus():
 cases={};vectors=json.loads(oracle.VECTORS.read_bytes())
 def add(data,initial,actions,label):
  key=(bytes(data),initial,tuple(tuple(a) for a in actions))
  if key not in cases:cases[key]=dict(data=key[0],initial=initial,actions=key[2],origins=[])
  cases[key]['origins'].append(label)
 scripts=[[],[(1,0,0)],[(128,0,0)],[(0,1,0),(0,1,255)],[(0,1,255),(0,1,0),(255,1,2)]]
 for length in (0,1,7,8,15,16,17,31,32,33,63,64,65,127,128,129):
  samples={b'a'*length,bytes([10])*length,bytes((i*31)&255 for i in range(length))}
  for at in {0,length//2,length-1,7,8,15,16,31,32,63,64}:
   if 0<=at<length:samples.add(b'a'*at+b'\n'+b'a'*(length-at-1))
  for data in sorted(samples):
   for initial in (0,1,2,128,255):
    for actions in scripts:add(data,initial,actions,'boundary/script matrix')
 for case in vectors['cases']:
  data=bytearray(b'a'*case['length'])
  for i in case['lf']:data[i]=10
  for i in case.get('high',[]):data[i]=0x80 if i%2 else 0xff
  index=max([case['fail_at'] if case['fail_at'] is not None else -1,*map(int,case.get('mutations',{}))]);actions=[(int(i==case['fail_at']),int(str(i) in case.get('mutations',{})),case.get('mutations',{}).get(str(i),0)) for i in range(index+1)]
  for alignment in vectors['alignments']:
   trace=oracle.abstract_trace(bytes(data),case['initial'],case['fail_at'],alignment,case.get('mutations',{}));require(trace[:3]==(case['calls'],case['final'],case['return']),'Existing frozen trace changed')
   if 'entry_flags' in case:require(trace[3]==case['entry_flags'],'Existing frozen entry flags changed')
  add(data,case['initial'],actions,'frozen:'+case['name'])
 return list(cases.values()),len(vectors['cases'])

def verify(rustc,output):
 rustc=Path(rustc).resolve();output=Path(output)
 if rustc.is_relative_to(ROOT/'artifacts') or hashlib.sha256(rustc.read_bytes()).hexdigest() in {SHA256,'3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f','89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31'}:raise ValueError('Captured artifact cannot be a compiler')
 version=subprocess.run([str(rustc),'-Vv'],check=True,capture_output=True,text=True).stdout;require(version.startswith('rustc 1.94.1 '),'Pinned Rust1.94.1 required')
 data=(ROOT/BINARY).read_bytes();original=native_record(data);output.mkdir(parents=True,exist_ok=False);source=(CRATE/'src/lib.rs').read_text(encoding='utf8')
 flags=['--crate-name','node115_newline_requests','--edition=2024','--crate-type=lib','--emit=obj','--target=x86_64-unknown-linux-gnu','-C','opt-level=3','-C','panic=abort','-C','codegen-units=1','-C','debuginfo=0','-C','lto=off','-C','no-vectorize-loops','-C','no-vectorize-slp']
 def build(name,text):
  d=output/name;d.mkdir();s=d/'lib.rs';s.write_text(text,encoding='utf8',newline='\n');obj=d/'own.o';subprocess.run([str(rustc),*flags,str(s),'-o',str(obj)],check=True,capture_output=True);return obj
 first=build('first',source);repeat=build('repeat',source);require(first.read_bytes()==repeat.read_bytes(),'Repeated own objects differ');m,body,ins=own_machine(first)
 fixtures,frozen_cases=corpus();evaluations=0;stream=[];raw=output/'comparisons.jsonl.gz'
 with raw.open('wb') as file:
  with gzip.GzipFile(filename='',mode='wb',fileobj=file,mtime=0) as tracefile:
   for index,case in enumerate(fixtures):
    blob=case['data'];initial=case['initial'];actions=case['actions'];stream.append(dict(input_hex=blob.hex(),initial=initial,actions=actions,origins=case['origins']))
    for alignment in range(8):
     expected=reference(blob,initial,actions,alignment);actual=evaluate(m,blob,initial,actions,alignment);require(actual==expected,'Own request/state trace mismatch');evaluations+=1
     tracefile.write((json.dumps(dict(case=index,alignment=alignment,expected=expected,actual=actual),sort_keys=True)+'\n').encode())
 changes=[('linefeed','read_volatile() } != 10','read_volatile() } != 13'),('indent_bytes','write_volatile(32)','write_volatile(9)'),('nonzero_flag','if *flag != 0','if *flag == 1'),('owned_flag','*flag = has_lf as u8','*flag = (!has_lf) as u8'),('normalize_payload','if callback(flag,piece) != 0 { return 1; }','let raw = callback(flag,piece); if raw != 0 { return raw; }'),('next_cursor','start = end;','start = end + 1;'),('indent_failure','if callback(flag,&indent) != 0','if callback(flag,&indent) == 0')]
 scripts=[[],[(128,0,0)],[(0,1,255),(0,1,0),(255,1,2)]];witnesses=list(itertools.product((b'a',b'\na',b'a\nb\n',b'\n'),(0,1,2,255),scripts));controls=[]
 for name,before,after in changes:
  require(source.count(before)==1,'Mutation anchor changed');obj=build(name,source.replace(before,after));cm,cb,_=own_machine(obj);witness=None
  for blob,initial,actions in witnesses:
   expected=reference(blob,initial,actions,0);actual=evaluate(cm,blob,initial,actions)
   if actual!=expected:witness=dict(input_hex=blob.hex(),initial=initial,actions=actions,expected=expected,changed=actual);break
  require(witness is not None,'Compiled source corruption survived');controls.append(dict(name=name,rejected=True,own_code_sha256=hashlib.sha256(cb).hexdigest(),**witness))
 native_controls=[];image=native.Image('115',data);rows=native.partition(image,(NATIVE_PACKET/'observed/adapter115.gnu.txt').read_text(encoding='utf8'),0x1686bd0,0x1686e46)
 for name,va,value,blob,initial,actions in [('short_scan_lf',0x1686cd3,b'\x0b',b'\na',0,[]),('payload_last_lf',0x1686c34,b'\x0b',b'\n',0,[]),('indent_literal',0x45a128,b'\x09',b'a',1,[]),('indent_length',0x1686e03,(3).to_bytes(4,'little'),b'a',1,[]),('current_flag_test',0x1686dff,b'\x01',b'a',1,[]),('failure_result',0x1686e36,b'\x02',b'a',0,[(128,0,0)])]:
  mut=bytearray(data);off=image.offset(va,len(value));mut[off:off+len(value)]=value;changed=copy.copy(image);changed.data=bytes(mut);expected=short_projection(image,blob,initial,actions);actual=short_projection(changed,blob,initial,actions);require(actual!=expected,'Native short-path operand control inactive')
  try:native.bind(changed,rows)
  except ValueError as error:binding=str(error)
  else:raise ValueError('Below-identity binding admitted changed operand')
  native_controls.append(dict(name=name,va=hex(va),replacement_hex=value.hex(),input_hex=blob.hex(),initial=initial,actions=actions,expected=expected,changed=actual,rejected=True,below_identity_binding_error=binding))
 corpus_bytes=('\n'.join(json.dumps(x,sort_keys=True) for x in stream)+'\n').encode()
 result=dict(target_sha256=SHA256,native=original,source_sha256={n:hashlib.sha256((CRATE/n).read_bytes()).hexdigest() for n in ('Cargo.toml','Cargo.lock','src/lib.rs')},checker_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),oracle_sha256=hashlib.sha256(ORACLE_PATH.read_bytes()).hexdigest(),native_collector_sha256=hashlib.sha256((NATIVE_PACKET/'collect.py').read_bytes()).hexdigest(),frozen_vectors_sha256=hashlib.sha256(oracle.VECTORS.read_bytes()).hexdigest(),shared_engine_sha256=hashlib.sha256(Path(engine.__file__).read_bytes()).hexdigest(),compiler_version=version,compiler_sha256=hashlib.sha256(rustc.read_bytes()).hexdigest(),flags=flags,unique_cases=len(fixtures),frozen_vectors_included=frozen_cases,alignments=8,evaluations=evaluations,mismatches=0,corpus_sha256=hashlib.sha256(corpus_bytes).hexdigest(),raw_comparisons_sha256=hashlib.sha256(raw.read_bytes()).hexdigest(),compiled_source_controls=controls,native_operand_controls=native_controls,own_code_bytes=len(body),own_code_instructions=len(ins),own_code_sha256=hashlib.sha256(body).hexdigest(),own_objects_reproducible=True,captured_executed=False,target_code_identity_measured=False,scope=original['scope'])
 (output/'rust-validation.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf8',newline='\n');(output/'corpus.jsonl').write_bytes(corpus_bytes)
 (output/'own-rust.capstone.txt').write_text('\n'.join(f'{i.address-0x100000:x}: {i.bytes.hex()} {i.mnemonic} {i.op_str}'.rstrip() for i in ins)+'\n',encoding='utf8',newline='\n')
 for row in original['owners']:(output/(row['role']+'.capstone.txt')).write_text('\n'.join(row['export'])+'\n',encoding='utf8',newline='\n')
 return result

if __name__=='__main__':
 import argparse
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--rustc',required=True);p.add_argument('--out',required=True);a=p.parse_args();r=verify(a.rustc,a.out);print(json.dumps(dict(unique_cases=r['unique_cases'],evaluations=r['evaluations'],mismatches=r['mismatches'])))
