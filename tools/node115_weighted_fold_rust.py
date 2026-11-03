"""Authorized offline instruction comparison for node115 two-span checked weights.
First provider result is an explicit register boundary; no helper is substituted.
"""
import sys,hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import weighted_comparison_static as native
import decimal_scaled_u64 as cpu
import gas_auction_price as generic
class Image:
 file_offset=cpu.Image.file_offset
 fetch=cpu.Image.fetch
 fde_of=cpu.Image.fde_of
 read_only=cpu.Image.read_only
 def __init__(self,data):
  parsed=generic.Image(data);self.data=data
  self.sections={s['name']:(s['address'],s['offset'],s['size']) for s in parsed.sections if s['type']!=8}
  for name in ('.text','.rodata'):
   if name not in self.sections:raise ValueError('missing required section '+name)
  self.text_va,self.text_off,self.text_size=self.sections['.text'];self.rodata=self.sections['.rodata']
  self.fdes=sorted(parsed.fde_ends.items());self.starts=[a for a,b in self.fdes];self.slots=parsed.relative();self.cache={}
SECOND=cpu.INPUT+0x1000
class Machine(cpu.Machine):
 def __init__(self,image,n1,n2):super().__init__(image);self.n1=n1;self.n2=n2
 def bounds(self,a,n,write=False):
  roles=[(cpu.STACK+8,32)]
  if not write:roles.extend([(cpu.INPUT,32*self.n1),(SECOND,32*self.n2)])
  if not any(lo<=a and a+n<=lo+size for lo,size in roles):raise ValueError('unqualified fold memory')
 def load(self,a,n):self.bounds(a,n);return super().load(a,n)
 def store(self,a,n,v):self.bounds(a,n,True);return super().store(a,n,v)
 def spill(self,a,r,n):self.bounds(a,n,True);return super().spill(a,r,n)
 def reload(self,r,a,n):self.bounds(a,n);return super().reload(r,a,n)
 def call(self,*args):raise ValueError('all calls forbidden')
def put(m,a,n,value):
 for i,b in enumerate(value.to_bytes(n,'little')):m.mem[a+i]=b

def evaluate(image,status,basis,first,second):
 m=Machine(image,len(first),len(second))
 for r,v in [(cpu.RSP,cpu.STACK),(cpu.R13,cpu.STACK+8),(cpu.R14,status),(cpu.RBX,basis)]:m.set_reg(r,v)
 for at,val in [(8,cpu.INPUT),(16,cpu.INPUT+32*len(first)),(24,SECOND),(32,SECOND+32*len(second))]:put(m,cpu.STACK+at,8,val)
 for start,values in [(cpu.INPUT,first),(SECOND,second)]:
  for i,value in enumerate(values):put(m,start+32*i+24,8,value)
 m.pc=0x422e2d9
 for _ in range(1024):
  if m.pc==0x422e3f5:return str(m.get(cpu.RAX,8)),m.seen
  if not (0x422e2d9<=m.pc<0x422e352 or 0x422e3cd<=m.pc<0x422e3f5):raise ValueError('escaped closed fastfold')
  m.step()
 raise ValueError('step bound')
def model(status,basis,first,second):
 total=sum(first)+sum(second)
 return str(int(total<=cpu.U64 and status==1 and 2*total<3*basis))

import itertools,capstone

def oracle(binary=native.TARGET):
 blob=Path(binary).read_bytes()
 if len(blob)!=105896032 or hashlib.sha256(blob).hexdigest()!=native.SHA:raise ValueError('pinned node115 identity mismatch')
 record=native.analyze(blob);assert record==json.loads((native.PACKET/'records.json').read_text())
 image=Image(blob)
 for a,b,_,_ in native.OWNERS.values():assert image.fde_of(a)==(a,b)
 stimuli=set();alphabet=[0,1,(1<<63)-1,cpu.U64];bases=[0,1,2,3,1<<62,(1<<63)-1,1<<63,cpu.U64-1,cpu.U64];statuses=[0,1,2,cpu.U64]
 for size in range(4):
  for values in itertools.product(alphabet,repeat=size):
   for split in range(size+1):
    for status in statuses:
     for basis in bases:stimuli.add((status,basis,split,values))
 state=0x115f01d
 for i in range(64):
  values=[]
  for _ in range(4+i%7):state=(state*6364136223846793005+1442695040888963407)&cpu.U64;values.append(state)
  for split in [0,len(values)//2,len(values)]:
   for status in statuses:
    for basis in [1,cpu.U64]:stimuli.add((status,basis,split,tuple(values)))
 inputs=[];expected=[];seen=set()
 for status,basis,split,values in sorted(stimuli):
  first,second=values[:split],values[split:];result,trace=evaluate(image,status,basis,first,second)
  assert result==model(status,basis,first,second),(status,basis,split,values,result)
  inputs.append(f'{status}\t{basis}\t{split}\t'+(','.join(map(str,values)) or '-')+'\n');expected.append(result+'\n');seen.update(trace)
 controls=[]
 for name,va,new,args in [('carry-bypass',0x422e2f9,0,(1,1,(cpu.U64,1),())),('right-factor',0x422e3de,2,(1,1,(1,),())),('wide-condition',0x422e3ef,0x93,(1,2,(3,),())),('first-status',0x422e3d0,2,(1,1,(),()))]:
  changed=bytearray(blob);off=image.file_offset(va);old=changed[off];changed[off]=new;private=Image(bytes(changed))
  before,_=evaluate(image,*args);after,_=evaluate(private,*args);assert before!=after,(name,before,after)
  try:native.analyze(changed)
  except ValueError as e:rejected=str(e)
  else:raise ValueError('native binding accepted mutation')
  controls.append({'name':name,'va':hex(va),'old':old,'new':new,'inputs':args,'before':before,'after':after,'binding_rejected':rejected})
 cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);rows=[]
 for va in sorted(seen):
  ins=image.fetch(va);raw=blob[ins.off:ins.off+ins.size];independent=list(cs.disasm(raw,va));assert len(independent)==1 and independent[0].size==ins.size
  rows.append({'va':hex(va),'raw_hex':raw.hex(),'size':ins.size})
 return {'inputs':''.join(inputs).encode(),'expected':''.join(expected).encode(),'record':record,'controls':controls,'selected_instructions':rows,'rows':len(stimuli)}

PACKET=ROOT/'research/work-items/RE-014-node115-weighted-fastfold-rust'
COMPONENT=ROOT/'src/node115-weighted-fastfold'
def need(ok,message):
 if not ok:raise ValueError(message)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def build(binary,rustc,output):
 import subprocess
 output=Path(output);need(not output.exists(),'output must be new')
 result=oracle(binary);freeze=json.loads((PACKET/'FREEZE.json').read_text())
 need(sha(result['inputs'])==freeze['input_sha256'] and sha(result['expected'])==freeze['expected_sha256'],'frozen expectations differ before compiler')
 need(result['record']==json.loads((PACKET/'native-records.json').read_text()),'owner record differs')
 need(json.loads(json.dumps(result['controls']))==json.loads((PACKET/'native-controls.json').read_text()),'native controls differ')
 need(result['selected_instructions']==json.loads((PACKET/'selected-instructions.json').read_text()),'selected instruction rows differ')
 need((COMPONENT/'target-smoke.tsv').read_bytes()==(PACKET/'target-smoke.tsv').read_bytes(),'smoke fixture differs')
 version=subprocess.check_output([str(rustc),'-Vv'],text=True);need(version.startswith('rustc 1.94.1 ('),'pinned Rust1.94.1 required')
 output.mkdir(parents=True);(output/'inputs.tsv').write_bytes(result['inputs']);(output/'expected.tsv').write_bytes(result['expected']);commands=[]
 def run(args,**kw):
  args=list(map(str,args));commands.append(args);return subprocess.run(args,capture_output=True,text=True,**kw)
 def library(source,folder,opt):
  folder.mkdir();lib=folder/'libnode115_weighted_fastfold.rlib'
  p=run([rustc,'--edition=2021','--crate-name','node115_weighted_fastfold','--crate-type','rlib','-C',f'opt-level={opt}','-C','overflow-checks=on','-C','codegen-units=1','-C','metadata=node115_weighted_fastfold','-D','warnings',source,'-o',lib]);need(p.returncode==0,p.stderr)
  exe=folder/'driver';p=run([rustc,'--edition=2021','-C',f'opt-level={opt}',COMPONENT/'input_only_driver.rs','--extern',f'node115_weighted_fastfold={lib}','-D','warnings','-o',exe]);need(p.returncode==0,p.stderr);return lib,exe
 def smoke(source,folder):
  exe=folder/'smoke-test';p=run([rustc,'--edition=2021','--test',source,'-D','warnings','-o',exe]);need(p.returncode==0,p.stderr);return run([exe])
 profiles={}
 for opt in (0,3):
  _,exe=library(COMPONENT/'lib.rs',output/f'o{opt}',opt);p=run([exe],input=result['inputs'].decode());need(p.returncode==0 and p.stdout.encode()==result['expected'],'compiled Rust differs')
  (output/f'output-o{opt}.tsv').write_text(p.stdout);profiles[str(opt)]={'rows':result['rows'],'match':True,'stdout_sha256':sha(p.stdout.encode())}
 p=smoke(COMPONENT/'lib.rs',output);need(p.returncode==0,p.stdout+p.stderr);(output/'smoke-output.txt').write_text(p.stdout)
 source=(COMPONENT/'lib.rs').read_text();mutants=[]
 for name,old,new in [('checked-add','total.checked_add(weight)','Some(total.wrapping_add(weight))'),('wide-product','(total as u128) * 2','u128::from(total.wrapping_mul(2))'),('strictness','* 2 <','* 2 <=')]:
  need(source.count(old)==1,'mutation binding changed');folder=output/('mutant-'+name);folder.mkdir();changed=folder/'lib.rs';changed.write_text(source.replace(old,new));(folder/'target-smoke.tsv').write_bytes((COMPONENT/'target-smoke.tsv').read_bytes())
  _,exe=library(changed,folder/'build',3);p=run([exe],input=result['inputs'].decode());need(p.returncode==0,'mutant must emit rows')
  actual=p.stdout.splitlines();expected=result['expected'].decode().splitlines();mismatch=sum(a!=b for a,b in zip(actual,expected));need(len(actual)==len(expected) and mismatch>0,'mutant escaped')
  p=smoke(changed,folder);need(p.returncode!=0,'mutant passed target-smoke');mutants.append({'name':name,'mismatches':mismatch,'rows':len(actual),'compiled_smoke_exit':p.returncode})
 repeat,_=library(COMPONENT/'lib.rs',output/'o3-repeat',3);raw=(output/'o3/libnode115_weighted_fastfold.rlib').read_bytes();need(raw==repeat.read_bytes(),'raw own archive differs')
 report={'rows':result['rows'],'profiles':profiles,'compiled_mutants':mutants,'raw_own_rlib_equal':True,'rlib_sha256':sha(raw),'source_sha256':sha(source.encode()),'compiler':version,'commands':commands,'captured_process_executed':False,'offline_python_instruction_evaluation_authorized':True}
 (output/'build-result.json').write_text(json.dumps(report,indent=2)+'\n');return report
if __name__=='__main__':
 import argparse
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--binary',type=Path,default=native.TARGET);p.add_argument('--rustc',type=Path,required=True);p.add_argument('--output',type=Path,required=True);args=p.parse_args();r=build(args.binary,args.rustc,args.output);print(json.dumps({k:r[k] for k in ('rows','compiled_mutants','raw_own_rlib_equal')}))
