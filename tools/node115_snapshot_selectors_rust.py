"""Compare node115 selected worker/wrapper/mode/exit routes with real Rust."""
import argparse
import hashlib
import json
import struct
from pathlib import Path
import subprocess
import decimal_scaled_u64 as cpu
import snapshot_selection_static as native
from elf_index import sections

ROOT=Path(__file__).resolve().parents[1]
TARGET=ROOT/'artifacts/node/115/hl-node'
COMPONENT=ROOT/'src/node115-snapshot-selectors'
PACKET=ROOT/'research/work-items/RE-014-node115-snapshot-selectors-rust'

def need(ok,message):
 if not ok:raise ValueError(message)

def sha(raw):return hashlib.sha256(raw).hexdigest()

class Image:
 file_offset=cpu.Image.file_offset
 _fdes=cpu.Image._fdes
 _slots=cpu.Image._slots
 fde_of=cpu.Image.fde_of
 fetch=cpu.Image.fetch
 read_only=cpu.Image.read_only
 def __init__(self,data):
  self.data=data
  self.sections={s['name']:(s['address'],s['offset'],s['size']) for s in sections(data) if s['type']!=8}
  self.text_va,self.text_off,self.text_size=self.sections['.text']
  self.rodata=self.sections['.rodata']
  self.fdes=self._fdes();self.starts=[r[0] for r in self.fdes]
  self.slots=self._slots();self.cache={}

CTX=cpu.INPUT+0x1000
class Machine(cpu.Machine):
 def bounds(self,at,size,write=False):
  roles=[(cpu.STACK,0x100)]
  if not write:roles.extend([(cpu.INPUT,64),(CTX,64)])
  if not any(lo<=at and at+size<=lo+n for lo,n in roles):raise ValueError('memory outside qualified roles')
 def load(self,at,size):
  self.bounds(at,size);return super().load(at,size)
 def store(self,at,size,value):
  self.bounds(at,size,True);return super().store(at,size,value)
 def spill(self,at,reg,size):
  self.bounds(at,size,True);return super().spill(at,reg,size)
 def reload(self,reg,at,size):
  self.bounds(at,size);return super().reload(reg,at,size)
 def call(self,target,where):
  raise ValueError('call outside selected projection')

def put(m,at,size,value):
 for i,b in enumerate(value.to_bytes(size,'little')):m.mem[at+i]=b

def drive(m,stops,allowed):
 for _ in range(64):
  if m.pc in stops:return stops[m.pc],m.seen
  if not any(lo<=m.pc<hi for lo,hi in allowed):raise ValueError('control escaped selected regions')
  m.step()
 raise ValueError('selected instruction bound')

def worker(image,which,word,count):
 a=native.MAINS[which];m=Machine(image);m.set_reg(cpu.RSI,cpu.INPUT)
 put(m,cpu.INPUT,8,word);put(m,cpu.INPUT+16,8,count)
 m.pc=a+0x19
 return drive(m,{a+0x28:'A',a+0x5da:'L',a+0x482:'E'},
              [(a+0x19,a+0x28),(a+0x474,a+0x482)])

def wrapper(image,which,word,byte,mode):
 a=native.WRAPPERS[which];m=Machine(image)
 m.set_reg(cpu.RDI,cpu.INPUT);m.set_reg(cpu.RSI,CTX);m.set_reg(cpu.RSP,cpu.STACK);m.set_reg(cpu.R8,mode)
 for i in range(32):m.mem[cpu.INPUT+i]=0
 put(m,cpu.INPUT,8,word);put(m,cpu.INPUT+0x1a,1,byte);put(m,CTX+0x28,8,0x55)
 m.pc=a+0x14
 path,seen=drive(m,{a+0xa2:4,a+0x58:(0 if which==0 else 3),a+0x119:(2 if which==0 else 1)},
                 [(a+0x14,a+0x58),(a+0x8d,a+0xa2)])
 normalized=m.get(cpu.R12,64)
 if normalized not in (0,1):raise ValueError('undefined normalized mode')
 return f'{path}\t{normalized}',seen

def mode_gate(image,which,mode):
 a=native.MAINS[which];m=Machine(image);m.set_reg(cpu.RSP,cpu.STACK)
 put(m,cpu.STACK+0x38,8,0x115);put(m,cpu.STACK+0x40,8,mode)
 m.pc=a+0x43b
 return drive(m,{a+0x44c:'1',a+0x530:'0'},[(a+0x43b,a+0x44c)])

def exit_gate(image,tag):
 m=Machine(image);m.set_reg(cpu.RDI,cpu.INPUT);put(m,cpu.INPUT,2,tag)
 m.pc=0x2308124
 return drive(m,{0x230812e:'U',0x23081b6:'U',0x2308171:'U',0x2308274:'K'},
              [(0x2308124,0x230812e),(0x230815c,0x2308171)])

def inspect(binary):
 data=Path(binary).read_bytes()
 if len(data)!=105896032 or sha(data)!=native.SHA:raise ValueError('pinned node115 identity mismatch')
 record=native.analyze(data)
 if record!=json.loads((native.PACKET/'records.json').read_text()):raise ValueError('accepted static records changed')
 try:
  cpu.Image(data)
 except KeyError as error:
  blocker={'existing_image_constructor':'KeyError','node94_specific_missing_slot':hex(error.args[0]),
           'remedy':'local adapter parses only actual node115 sections/FDEs/relocations; no fake slots; all calls rejected'}
 else:
  blocker={'existing_image_constructor':'not used: binds node94-specific diagnostic slots',
           'remedy':'local real-map adapter only; all calls rejected'}
 image=Image(data)
 for owner in record['owners']:
  if image.fde_of(int(owner['start'],16))!=(int(owner['start'],16),int(owner['end'],16)):
   raise ValueError('independent FDE mapping differs')
 return data,image,record,blocker


def oracle(binary=TARGET):
 data,image,record,blocker=inspect(binary)

 words=sorted(set(range(64))|{(1<<63)+i for i in range(-64,65)}|{((1<<64)-1)-i for i in range(64)})
 counts=list(range(103))+[(1<<63)-1,1<<63,(1<<64)-1]
 flags=(0,1,0xffffffff,1<<32,1<<63,(1<<64)-1)
 bytes_=(0,1,2,128,255)
 inputs=[];expected=[];seen=set();parts={}
 for which in range(4):
  for word in words:
   for count in counts:
    result,trace=worker(image,which,word,count)
    model='A' if word==1<<63 else 'L' if count>=101 else 'E'
    if result!=model:raise ValueError('worker model differs')
    inputs.append(f'W\t{which}\t{word}\t{count}\n');expected.append(result+'\n');seen.update(trace)
 parts['worker']=len(inputs)
 for which in range(2):
  for word in words:
   for byte in bytes_:
    for flag in flags:
     result,trace=wrapper(image,which,word,byte,flag)
     path=4 if word==(1<<63)+1 else ((0 if byte else 2) if which==0 else (3 if byte else 1))
     model=f'{path}\t{int(bool(flag&0xffffffff))}'
     if result!=model:raise ValueError('wrapper model differs')
     inputs.append(f'O\t{which}\t{word}\t{byte}\t{flag}\n');expected.append(result+'\n');seen.update(trace)
 parts['wrapper']=len(inputs)-parts['worker']
 modes=(0,1,2,255,1<<32,1<<63,(1<<64)-1)
 for which in range(4):
  for mode in modes:
   result,trace=mode_gate(image,which,mode)
   if result!=str(int(mode==1)):raise ValueError('mode model differs')
   inputs.append(f'M\t{which}\t{mode}\n');expected.append(result+'\n');seen.update(trace)
 parts['mode']=len(inputs)-sum(parts.values())
 for tag in range(65536):
  result,trace=exit_gate(image,tag)
  if result!=('K' if 266<=tag<=351 else 'U'):raise ValueError('exit prefix differs')
  inputs.append(f'X\t{tag}\n');expected.append(result+'\n');seen.update(trace)
 parts['exit']=len(inputs)-sum(parts.values())
 controls=[]
 cases=[
 ('worker-overflow-condition',native.MAINS[0]+0x23,0x80,'worker',(0,1<<63,101)),
 ('count-threshold',native.MAINS[0]+0x47b,102,'worker',(0,0,101)),
 ('wrapper-input-width',native.WRAPPERS[0]+0x14,0x4d,'wrapper',(0,1<<63,128,1<<32)),
 ('wrapper-byte-equality',native.WRAPPERS[0]+0x51,1,'wrapper',(0,0,1,0)),
 ('exact-mode',native.MAINS[0]+0x440,2,'mode',(0,1)),
 ('exit-range',0x230816a,26,'exit',(266,))]
 functions={'worker':worker,'wrapper':wrapper,'mode':mode_gate,'exit':exit_gate}
 for name,va,byte,kind,args in cases:
  original=image.data[image.file_offset(va)]
  changed=bytearray(data);changed[image.file_offset(va)]=byte
  private=Image(bytes(changed))
  before=functions[kind](image,*args)[0];after=functions[kind](private,*args)[0]
  if before==after:raise ValueError('actual byte control escaped: '+name)
  try:native.analyze(changed)
  except ValueError as error:rejected=str(error)
  else:raise ValueError('static binding accepted private mutation')
  controls.append({'name':name,'va':hex(va),'old':original,'new':byte,'kind':kind,
                   'inputs':args,'before':before,'after':after,'binding_rejected':rejected})
 import capstone
 decoder=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);instruction_rows=[]
 for va in sorted(seen):
  ins=image.fetch(va);raw=data[ins.off:ins.off+ins.size];other=list(decoder.disasm(raw,va))
  if len(other)!=1 or other[0].size!=ins.size:raise ValueError('independent raw decode differs')
  instruction_rows.append({'va':hex(va),'size':ins.size,'raw_hex':raw.hex()})

 rawin=''.join(inputs).encode();rawout=''.join(expected).encode()
 return {'inputs':rawin,'expected':rawout,'count':len(inputs),'distinct_inputs':len(set(inputs)),
         'record':record,'controls':controls,'parts':parts,'selected_instructions':instruction_rows,'blocker':blocker}


def build(binary,rustc,output):
    output=Path(output)
    need(not output.exists(),'output must be new')
    result=oracle(binary)
    freeze=json.loads((PACKET/'FREEZE.json').read_text())
    need(sha(result['inputs'])==freeze['input_sha256'] and sha(result['expected'])==freeze['expected_sha256'],
         'frozen expectations differ before compiler')
    version=subprocess.check_output([str(rustc),'-Vv'],text=True)
    need(version.startswith('rustc 1.94.1 ('),'pinned rustc1.94.1 required')
    output.mkdir(parents=True)
    (output/'inputs.tsv').write_bytes(result['inputs']);(output/'expected.tsv').write_bytes(result['expected'])
    commands=[]
    def run(argv,**kwargs):
        argv=list(map(str,argv));commands.append(argv)
        return subprocess.run(argv,text=True,capture_output=True,**kwargs)
    def library(source,folder,opt):
        folder.mkdir()
        lib=folder/'libnode115_snapshot_selectors.rlib'
        args=[rustc,'--edition=2021','--crate-name','node115_snapshot_selectors','--crate-type','rlib',
              '-C',f'opt-level={opt}','-C','codegen-units=1','-C','overflow-checks=on',
              '-C','metadata=node115_snapshot_selectors','-D','warnings',source,'-o',lib]
        p=run(args);need(p.returncode==0,p.stderr)
        exe=folder/'driver'
        p=run([rustc,'--edition=2021','-C',f'opt-level={opt}','-D','warnings',
               COMPONENT/'input_only_driver.rs','--extern',f'node115_snapshot_selectors={lib}','-o',exe])
        need(p.returncode==0,p.stderr)
        return lib,exe
    profiles={}
    for opt in (0,3):
        _,exe=library(COMPONENT/'lib.rs',output/f'o{opt}',opt)
        p=run([exe],input=result['inputs'].decode())
        need(p.returncode==0 and p.stdout.encode()==result['expected'],'compiled Rust differs')
        (output/f'output-o{opt}.tsv').write_text(p.stdout)
        profiles[str(opt)]={'rows':result['count'],'match':True,'stdout_sha256':sha(p.stdout.encode())}
    def test(source,folder):
        exe=folder/'smoke-test'
        p=run([rustc,'--edition=2021','--test',source,'-o',exe]);need(p.returncode==0,p.stderr)
        return run([exe])
    p=test(COMPONENT/'lib.rs',output);need(p.returncode==0,p.stdout+p.stderr)
    (output/'unit-test-output.txt').write_text(p.stdout)
    source=(COMPONENT/'lib.rs').read_text();mutants=[]
    for name,old,new in [('worker-sentinel','selector == ALL','selector == SPECIAL'),
                         ('count','count >= 101','count > 101'),
                         ('normalization-width','raw_mode as u32','raw_mode'),
                         ('selector-byte','selector_byte != 0','selector_byte & 1 != 0'),
                         ('mode','mode == 1','mode != 0'),
                         ('exit','266..=351','267..=351')]:
        need(source.count(old)==1,'compiled mutation binding changed')
        folder=output/('mutant-'+name);folder.mkdir()
        changed=folder/'lib.rs';changed.write_text(source.replace(old,new))
        (folder/'target-smoke.tsv').write_bytes((COMPONENT/'target-smoke.tsv').read_bytes())
        _,exe=library(changed,folder/'build',3)
        p=run([exe],input=result['inputs'].decode())
        need(p.returncode==0,'mutant must emit comparison rows')
        actual=p.stdout.splitlines();expected=result['expected'].decode().splitlines()
        mismatch=sum(a!=b for a,b in zip(actual,expected))
        need(len(actual)==len(expected) and mismatch>0,'compiled mutation escaped')
        smoke=test(changed,folder)
        need(smoke.returncode!=0,'mutant passed compiled target-smoke assertions')
        mutants.append({'name':name,'rows':len(actual),'mismatches':mismatch,'compiled_smoke_exit':smoke.returncode})
    repeat,_=library(COMPONENT/'lib.rs',output/'o3-repeat',3)
    original=(output/'o3/libnode115_snapshot_selectors.rlib').read_bytes()
    need(original==repeat.read_bytes(),'raw own-rust archive not reproducible')
    report={'rows':result['count'],'distinct_inputs':result['distinct_inputs'],'profiles':profiles,
            'compiled_mutants':mutants,'raw_own_rlib_equal':True,'rlib_sha256':sha(original),
            'source_sha256':sha(source.encode()),'rustc':version,'commands':commands,
            'authorized_offline_python_instruction_evaluation':True,'native_capture_executed':False}
    (output/'build-result.json').write_text(json.dumps(report,indent=2)+'\n')
    return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary',type=Path,default=TARGET)
    parser.add_argument('--rustc',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    report=build(args.binary,args.rustc,args.output)
    print(json.dumps({k:report[k] for k in ('rows','distinct_inputs','profiles','compiled_mutants','raw_own_rlib_equal')}))
