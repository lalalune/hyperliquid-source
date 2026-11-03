"""Authorized offline node115 signed-pair numeric projections and Rust comparison.
Selected CVTSI2SD widths are corrected locally; no helper or captured process runs.
"""
import sys,json,hashlib,struct
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import latency_projection_static as native
import gas_auction_price as generic
class Memory(generic.Memory):
 def allowed(self,a,n,write=False):
  if generic.STACK_TOP-0x100+0x48<=a and a+n<=generic.STACK_TOP-0x100+0x50:return
  if not write:
   sec=self.image.named.get('.rodata')
   if sec is not None and sec['address']<=a and a+n<=sec['address']+sec['size']:return
  raise ValueError('outside qualified pair projection memory')
 def bytes_at(self,a,n):self.allowed(a,n);return super().bytes_at(a,n)
 def write(self,a,n,v):self.allowed(a,n,True);return super().write(a,n,v)
 def put_bytes(self,a,b):self.allowed(a,len(b),True);return super().put_bytes(a,b)
class Machine(generic.Machine):
 def step(self,row):
  if row.op=='cvtsi2sd':
   raw=bytes(self.read_code(row.va,row.size))
   if raw.startswith(b'\xf2\x48\x0f\x2a'):width=8
   elif raw.startswith(b'\xf2\x0f\x2a'):width=4
   else:raise ValueError('unqualified conversion encoding')
   value=self.get(row.b,width);signed=value-(1<<(width*8)) if value&(1<<(width*8-1)) else value
   self.set_low(row.a[1],generic.to_bits(float(signed)));return row.next
  return super().step(row)
class Engine:
 def __init__(self,image):self.m=Machine(image);self.m.memory=Memory(image)
 def run(self,lane,s,n):
  m=self.m;m.regs=[generic.POISON]*16;m.xmm=[generic.POISON|generic.POISON<<64]*16;m.cf=m.zf=m.sf=m.of=m.pf=False
  m.regs[generic.RAX]=s&generic.MASK[8];m.regs[generic.RDX]=n&0xffffffff;m.regs[generic.RSP]=generic.STACK_TOP-0x100;m.regs[generic.RBX]=0x12340000
  start,stop=(0x51c9b26,0x51c9b75) if lane==0 else (0x51c9b9b,0x51c9c06)
  pc=start;seen=set()
  for _ in range(64):
   if pc==stop:
    first=m.xmm[0]&generic.MASK[8]
    return (str(first) if lane==0 else f'{first}\t{m.memory.read(generic.STACK_TOP-0x100+0x48,8)}'),seen
   if not start<=pc<stop:raise ValueError('escaped pair window')
   row=m.cache.get(pc)
   if row is None:row=generic.decode(m.read_code,pc);m.cache[pc]=row
   if row.op in ('call','calli','ret'):raise ValueError('helper calls forbidden')
   seen.add(pc);pc=m.step(row)
  raise ValueError('step bound')
def model(lane,s,n):
 corrected_s,corrected_n=native.corrected_pair(s,n)
 v=max(0.0,float(corrected_s)+float(corrected_n)/1e9)
 return str(generic.to_bits(v)) if lane==0 else f'{generic.to_bits(min(60.0,v))}\t{generic.to_bits(v)}'

import capstone

def oracle(binary=native.TARGET):
 blob=Path(binary).read_bytes()
 if len(blob)!=105896032 or hashlib.sha256(blob).hexdigest()!=native.SHA:raise ValueError('pinned node115 identity mismatch')
 record=native.analyze(blob);assert record==json.loads((native.PACKET/'records.json').read_text());image=generic.Image(blob);engine=Engine(image)
 swords=[-(1<<63),-(1<<63)+1,-(1<<53)-1,-121,-61,-60,-2,-1,0,1,2,59,60,61,119,120,(1<<53)-1,1<<53,(1<<53)+1,(1<<63)-2,(1<<63)-1]
 nwords=[-(1<<31),-1000000001,-1000000000,-1,0,1,999999999,1000000000,1000000001,(1<<31)-1]
 pairs={(s,n) for s in swords for n in nwords};state=0x1151a7
 for _ in range(1024):
  state=(state*6364136223846793005+1442695040888963407)&generic.MASK[8];s=state-(1<<64) if state>>63 else state
  state=(state*6364136223846793005+1442695040888963407)&generic.MASK[8];n=state&0xffffffff;n=n-(1<<32) if n>>31 else n;pairs.add((s,n))
 inputs=[];expected=[];seen=set()
 for lane in [0,1]:
  for s,n in sorted(pairs):
   answer,trace=engine.run(lane,s,n);assert answer==model(lane,s,n),(lane,s,n,answer,model(lane,s,n))
   inputs.append(f'{lane}\t{s}\t{n}\n');expected.append(answer+'\n');seen.update(trace)
 cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);cs.detail=True;selected=[];conversions=[]
 for va in sorted(seen):
  row=generic.decode(engine.m.read_code,va);raw=bytes(engine.m.read_code(va,row.size));other=list(cs.disasm(raw,va));assert len(other)==1 and other[0].size==row.size
  selected.append({'va':hex(va),'raw_hex':raw.hex(),'size':row.size})
  if row.op=='cvtsi2sd':conversions.append({'va':hex(va),'raw_hex':raw.hex(),'source_bytes':other[0].operands[1].size})
 assert sorted(c['source_bytes'] for c in conversions)==[4,4,8,8]
 controls=[]
 for name,va,newraw,args in [('divisor',0x458d50,struct.pack('<d',1e6),(0,1,500000000)),('cap',0x459718,struct.pack('<d',120.0),(1,120,0)),('correction-sign',0x51c9b2a,b'\x99',(0,-1,1000000001))]:
  changed=bytearray(blob);off=image.offset(va);old=bytes(changed[off:off+len(newraw)]);changed[off:off+len(newraw)]=newraw
  private=Engine(generic.Image(bytes(changed)));before,_=engine.run(*args);after,_=private.run(*args);assert before!=after,(name,before,after)
  try:native.analyze(changed)
  except ValueError as error:rejected=str(error)
  else:raise ValueError('static binding accepted mutation')
  controls.append({'name':name,'va':hex(va),'old_hex':old.hex(),'new_hex':newraw.hex(),'inputs':args,'before':before,'after':after,'binding_rejected':rejected})
 return {'inputs':''.join(inputs).encode(),'expected':''.join(expected).encode(),'record':record,'controls':controls,'selected_instructions':selected,'conversions':conversions,'rows':len(inputs)}

PACKET=ROOT/'research/work-items/RE-014-node115-latency-pair-rust'
COMPONENT=ROOT/'src/node115-latency-pair'
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
 need(result['conversions']==json.loads((PACKET/'conversion-bindings.json').read_text()),'conversion widths differ')
 need((COMPONENT/'target-smoke.tsv').read_bytes()==(PACKET/'target-smoke.tsv').read_bytes(),'smoke fixture differs')
 version=subprocess.check_output([str(rustc),'-Vv'],text=True);need(version.startswith('rustc 1.94.1 ('),'pinned Rust1.94.1 required')
 output.mkdir(parents=True);(output/'inputs.tsv').write_bytes(result['inputs']);(output/'expected.tsv').write_bytes(result['expected']);commands=[]
 def run(args,**kw):
  args=list(map(str,args));commands.append(args);return subprocess.run(args,capture_output=True,text=True,**kw)
 def library(source,folder,opt):
  folder.mkdir();lib=folder/'libnode115_latency_pair.rlib'
  p=run([rustc,'--edition=2021','--crate-name','node115_latency_pair','--crate-type','rlib','-C',f'opt-level={opt}','-C','overflow-checks=on','-C','codegen-units=1','-C','metadata=node115_latency_pair','-D','warnings',source,'-o',lib]);need(p.returncode==0,p.stderr)
  exe=folder/'driver';p=run([rustc,'--edition=2021','-C',f'opt-level={opt}',COMPONENT/'input_only_driver.rs','--extern',f'node115_latency_pair={lib}','-D','warnings','-o',exe]);need(p.returncode==0,p.stderr);return lib,exe
 def smoke(source,folder):
  exe=folder/'smoke-test';p=run([rustc,'--edition=2021','--test',source,'-D','warnings','-o',exe]);need(p.returncode==0,p.stderr);return run([exe])
 profiles={}
 for opt in (0,3):
  _,exe=library(COMPONENT/'lib.rs',output/f'o{opt}',opt);p=run([exe],input=result['inputs'].decode());need(p.returncode==0 and p.stdout.encode()==result['expected'],'compiled Rust differs')
  (output/f'output-o{opt}.tsv').write_text(p.stdout);profiles[str(opt)]={'rows':result['rows'],'match':True,'stdout_sha256':sha(p.stdout.encode())}
 p=smoke(COMPONENT/'lib.rs',output);need(p.returncode==0,p.stdout+p.stderr);(output/'smoke-output.txt').write_text(p.stdout)
 source=(COMPONENT/'lib.rs').read_text();mutants=[]
 for name,old,new in [('divisor','1_000_000_000.0','1_000_000.0'),('cap','value.min(60.0)','value.min(120.0)'),('correction','wide < 0','wide < -1'),('saved-value','saved_value: value,','saved_value: value.min(60.0),')]:
  need(source.count(old)==1,'mutation binding changed');folder=output/('mutant-'+name);folder.mkdir();changed=folder/'lib.rs';changed.write_text(source.replace(old,new));(folder/'target-smoke.tsv').write_bytes((COMPONENT/'target-smoke.tsv').read_bytes())
  _,exe=library(changed,folder/'build',3);p=run([exe],input=result['inputs'].decode());need(p.returncode==0,'mutant must emit rows')
  actual=p.stdout.splitlines();expected=result['expected'].decode().splitlines();mismatch=sum(a!=b for a,b in zip(actual,expected));need(len(actual)==len(expected) and mismatch>0,'mutant escaped')
  p=smoke(changed,folder);need(p.returncode!=0,'mutant passed target-smoke');mutants.append({'name':name,'mismatches':mismatch,'rows':len(actual),'compiled_smoke_exit':p.returncode})
 repeat,_=library(COMPONENT/'lib.rs',output/'o3-repeat',3);raw=(output/'o3/libnode115_latency_pair.rlib').read_bytes();need(raw==repeat.read_bytes(),'raw own archive differs')
 report={'rows':result['rows'],'profiles':profiles,'compiled_mutants':mutants,'raw_own_rlib_equal':True,'rlib_sha256':sha(raw),'source_sha256':sha(source.encode()),'compiler':version,'commands':commands,'captured_process_executed':False,'offline_python_instruction_evaluation_authorized':True}
 (output/'build-result.json').write_text(json.dumps(report,indent=2)+'\n');return report
if __name__=='__main__':
 import argparse
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--binary',type=Path,default=native.TARGET);p.add_argument('--rustc',type=Path,required=True);p.add_argument('--output',type=Path,required=True);args=p.parse_args();r=build(args.binary,args.rustc,args.output);print(json.dumps({k:r[k] for k in ('rows','compiled_mutants','raw_own_rlib_equal')}))
