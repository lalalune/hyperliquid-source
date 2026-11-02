"""Offline, authorized evaluation of node94 varint size-counter state.
No captured process or callee is executed. Panic is a pre-call boundary only.
"""
import sys,hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import decimal_scaled_u64 as cpu
SITES=[(0x27ab280,0x27ab2f5,32,0x56c2e78),(0x27ab5b0,0x27ab64b,64,0x56c2e78),(0x4aaa230,0x4aaa2cb,64,0x5737ce8)]
class Machine(cpu.Machine):
 def bounds(self,a,n):
  if not any(lo<=a and a+n<=lo+size for lo,size in [(cpu.INPUT,8),(cpu.OUT,8),(cpu.STACK+64,96)]):raise ValueError('unqualified memory')
 def load(self,a,n):self.bounds(a,n);return super().load(a,n)
 def store(self,a,n,v):self.bounds(a,n);return super().store(a,n,v)
 def spill(self,a,r,n):self.bounds(a,n);return super().spill(a,r,n)
 def reload(self,r,a,n):self.bounds(a,n);return super().reload(r,a,n)
 def call(self,t,w):raise ValueError('all calls forbidden')
def evaluate(image,which,value,count,flag):
 a,b,width,loc=SITES[which];m=Machine(image)
 for r,v in [(cpu.RAX,0x1234),(cpu.RSP,cpu.STACK+128),(cpu.RDI,cpu.OUT),(cpu.RSI,cpu.INPUT),(cpu.RDX,flag),(cpu.RCX,value)]:m.set_reg(r,v)
 m.store(cpu.STACK+128,8,cpu.RETURN_MARK);m.store(cpu.INPUT,8,count);m.store(cpu.OUT,8,0x55)
 m.pc=a
 for _ in range(64):
  if not a<=m.pc<b:raise ValueError('escaped owner')
  if m.pc==b-6:
   if m.get(cpu.RDI,64)!=loc:raise ValueError('wrong panic Location')
   return f'P\t{m.load(cpu.INPUT,8)}\t{m.load(cpu.OUT,8)}',m.seen
  try:m.step()
  except cpu.Done as end:
   if end.how!='ret' or m.get(cpu.RAX,64)!=cpu.OUT or m.get(cpu.RSP,64)!=cpu.STACK+136:raise ValueError('bad return')
   return f'O\t{m.load(cpu.INPUT,8)}\t{m.load(cpu.OUT,8)}',m.seen
 raise ValueError('step bound')
def model(value,count):
 length=1 if value<251 else 3 if value<65536 else 5 if value<1<<32 else 9
 if count==cpu.U64:return f'P\t{count}\t85'
 if count>cpu.U64-length:return f'P\t{count+1}\t85'
 return f'O\t{count+length}\t8'

import capstone
import bincode_varint as prior

def oracle(binary=cpu.TARGET):
 data=Path(binary).read_bytes()
 if len(data)!=91774280 or hashlib.sha256(data).hexdigest()!=cpu.SHA256:raise ValueError('pinned node94 identity mismatch')
 if prior.scan(data)!=json.loads((ROOT/'research/work-items/RE-005-bincode-varint/varint-sites.json').read_text()):raise ValueError('original static records differ')
 image=cpu.Image(data)
 words32=sorted(set(range(260))|{65535+i for i in range(-8,9)}|{(1<<32)-1-i for i in range(8)})
 words64=sorted(set(words32)|{(1<<32)+i for i in range(-8,9)}|{(1<<63)+i for i in range(-4,5)}|{cpu.U64-i for i in range(12)})
 counts=list(range(12))+[cpu.U64-i for i in range(16)]+[(1<<63)-1,1<<63]
 flags=[0,1,2,128,255]
 inputs=[];expected=[];seen=set();parts=[];owners=[]
 cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
 for which,(a,b,width,loc) in enumerate(SITES):
  assert image.fde_of(a)==(a,b)
  start=image.file_offset(a);raw=data[start:start+b-a];ins=list(cs.disasm(raw,a));assert sum(i.size for i in ins)==b-a
  slots=[image.slots[0x576e118]]
  owner={'va':hex(a),'end':hex(b),'body_sha256':hashlib.sha256(raw).hexdigest(),'raw_hex':raw.hex(),'instructions':[{'va':hex(i.address),'bytes':i.bytes.hex(),'op':i.mnemonic,'args':i.op_str} for i in ins],'panic_location':hex(loc),'panic_target':hex(slots[0])}
  owners.append(owner)
  before=len(inputs)
  for value in words32 if width==32 else words64:
   for count in counts:
    for flag in flags:
     answer,trace=evaluate(image,which,value,count,flag);assert answer==model(value,count),(which,value,count,flag,answer)
     inputs.append(f'{which}\t{value}\t{count}\t{flag}\n');expected.append(answer+'\n');seen.update(trace)
  parts.append(len(inputs)-before)
 controls=[]
 for name,va,value,args in [('u32-threshold',0x27ab283,252,(0,251,0,0)),('u64-threshold',0x27ab5b4,252,(1,251,0,0)),('precommit-u32',0x27ab2ab,2,(0,251,cpu.U64-1,0)),('overflow-u64',0x27ab5ea,0xfc,(1,251,cpu.U64-3,0))]:
  changed=bytearray(data);old=changed[image.file_offset(va)];changed[image.file_offset(va)]=value
  private=cpu.Image(bytes(changed));before,_=evaluate(image,*args);after,_=evaluate(private,*args);assert before!=after,(name,before,after)
  controls.append({'name':name,'va':hex(va),'old':old,'new':value,'inputs':args,'before':before,'after':after})
 rawin=''.join(inputs).encode();rawout=''.join(expected).encode()
 return {'inputs':rawin,'expected':rawout,'rows':len(inputs),'rows_per_owner':parts,'owners':owners,'controls':controls,'visited_instructions':len(seen),'words_u32':len(words32),'words_u64':len(words64),'counts':len(counts),'flags':flags}

PACKET=ROOT/'research/work-items/RE-005-bincode-size-state-rust-94'
SOURCE=ROOT/'src/bincode-varint/src/lib.rs'
def need(ok,message):
 if not ok:raise ValueError(message)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def build(binary,rustc,output):
 import subprocess
 output=Path(output);need(not output.exists(),'output must be new')
 result=oracle(binary);freeze=json.loads((PACKET/'FREEZE.json').read_text())
 need(sha(result['inputs'])==freeze['inputs_sha256'] and sha(result['expected'])==freeze['expected_sha256'],'frozen expectations differ before compiler')
 need(result['owners']==json.loads((PACKET/'owners.json').read_text()),'native owner records differ')
 need(json.loads(json.dumps(result['controls']))==json.loads((PACKET/'native-controls.json').read_text()),'native controls differ')
 version=subprocess.check_output([str(rustc),'-Vv'],text=True);need(version.startswith('rustc 1.94.1 ('),'pinned rustc1.94.1 required')
 output.mkdir(parents=True);(output/'inputs.tsv').write_bytes(result['inputs']);(output/'expected.tsv').write_bytes(result['expected'])
 commands=[]
 def run(args,**kw):
  args=list(map(str,args));commands.append(args);return subprocess.run(args,capture_output=True,text=True,**kw)
 def library(source,folder,opt):
  folder.mkdir();lib=folder/'libhl_bincode_varint.rlib'
  p=run([rustc,'--edition=2024','--crate-name','hl_bincode_varint','--crate-type','rlib','-C',f'opt-level={opt}','-C','overflow-checks=on','-C','codegen-units=1','-C','metadata=bincode_size_state','-D','warnings',source,'-o',lib]);need(p.returncode==0,p.stderr)
  exe=folder/'driver';p=run([rustc,'--edition=2024','-C',f'opt-level={opt}',PACKET/'driver.rs','--extern',f'hl_bincode_varint={lib}','-D','warnings','-o',exe]);need(p.returncode==0,p.stderr)
  return lib,exe
 def test(lib,source,out):
  p=run([rustc,'--edition=2024','--test',source,'--extern',f'hl_bincode_varint={lib}','-D','warnings','-o',out]);need(p.returncode==0,p.stderr)
  return run([out])
 profiles={}
 for opt in (0,3):
  folder=output/f'o{opt}';lib,exe=library(SOURCE,folder,opt)
  p=run([exe],input=result['inputs'].decode());need(p.returncode==0 and p.stdout.encode()==result['expected'],'compiled Rust differs')
  (output/f'output-o{opt}.tsv').write_text(p.stdout)
  stdout_sha=sha(p.stdout.encode())
  tests={}
  for source in sorted((ROOT/'src/bincode-varint/tests').glob('*.rs')):
   p=test(lib,source,folder/source.stem);need(p.returncode==0,p.stdout+p.stderr);tests[source.name]=p.stdout
  profiles[str(opt)]={'rows':result['rows'],'match':True,'stdout_sha256':stdout_sha,'integration_tests':tests}
 source=SOURCE.read_text();mutants=[]
 for name,old,new in [('atomic-counter','    *counter = marked;','    // omitted precommit'),('payload-charge','marked.checked_add(length - 1)','marked.checked_add(length)'),('marker-charge','counter.checked_add(1)','counter.checked_add(0)')]:
  need(source.count(old)==1,'mutation binding changed');folder=output/('mutant-'+name);folder.mkdir();changed=folder/'lib.rs';changed.write_text(source.replace(old,new))
  lib,exe=library(changed,folder/'build',3);p=run([exe],input=result['inputs'].decode());need(p.returncode==0,'mutant must emit rows')
  actual=p.stdout.splitlines();expected=result['expected'].decode().splitlines();mismatch=sum(a!=b for a,b in zip(actual,expected));need(len(actual)==len(expected) and mismatch>0,'mutant escaped')
  smoke=test(lib,ROOT/'src/bincode-varint/tests/size_counter.rs',folder/'smoke');need(smoke.returncode!=0,'mutant passed target fixture')
  mutants.append({'name':name,'mismatches':mismatch,'rows':len(actual),'compiled_smoke_exit':smoke.returncode})
 repeat,_=library(SOURCE,output/'o3-repeat',3);original=(output/'o3/libhl_bincode_varint.rlib').read_bytes();need(original==repeat.read_bytes(),'raw own archive differs')
 report={'rows':result['rows'],'profiles':profiles,'compiled_mutants':mutants,'raw_own_rlib_equal':True,'rlib_sha256':sha(original),'source_sha256':sha(source.encode()),'compiler':version,'commands':commands,'captured_process_executed':False,'offline_python_instruction_evaluation_authorized':True}
 (output/'build-result.json').write_text(json.dumps(report,indent=2)+'\n');return report

if __name__=='__main__':
 import argparse
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--binary',type=Path,default=cpu.TARGET);p.add_argument('--rustc',type=Path,required=True);p.add_argument('--output',type=Path,required=True);args=p.parse_args()
 r=build(args.binary,args.rustc,args.output);print(json.dumps({k:r[k] for k in ('rows','compiled_mutants','raw_own_rlib_equal')}))
