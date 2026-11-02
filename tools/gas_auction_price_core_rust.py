"""Rust comparison for the helper-free, post-round node94 auction-price core.
Authorized offline Python instruction evaluation; no captured process or helper execution.
"""
import sys,struct,math,json,hashlib
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import gas_auction_price as native
class Memory(native.Memory):
 def permitted(self,a,n,write=False):
  if native.OUT<=a and a+n<=native.OUT+16:return
  if not write:
   if native.AUCTION<=a and a+n<=native.AUCTION+64:return
   sec=self.image.named['.rodata']
   if sec['address']<=a and a+n<=sec['address']+sec['size']:return
  raise ValueError('outside selected memory')
 def bytes_at(self,a,n):self.permitted(a,n);return super().bytes_at(a,n)
 def write(self,a,n,v):self.permitted(a,n,True);return super().write(a,n,v)
 def put_bytes(self,a,b):self.permitted(a,len(b),True);return super().put_bytes(a,b)
class Engine:
 def __init__(self,image,patches=None):
  self.m=native.Machine(image,patches);self.m.memory=Memory(image)
 def run(self,bits,bucket,start,floor):
  m=self.m;m.regs=[native.POISON]*16;m.xmm=[native.POISON|native.POISON<<64]*16
  m.regs[native.RBX]=native.OUT;m.regs[native.R15]=native.AUCTION;m.regs[native.R14]=native.AUCTION+16;m.xmm[0]=bits|native.POISON<<64
  m.cf=m.zf=m.sf=m.of=m.pf=False
  # Initialization through the base implementation is outside instruction evaluation.
  native.Memory.put_bytes(m.memory,native.AUCTION,native.Auction(millis=bucket,start=start,floor=floor).data())
  native.Memory.put_bytes(m.memory,native.OUT,bytes([0xa5])*16)
  pc=0x325cd8b;seen=set()
  for _ in range(160):
   if pc==0x325cccd:
    tag=m.memory.read(native.OUT,2)
    if tag not in (native.TAG_SUB,native.TAG_OK):raise ValueError('unknown result tag')
    return ('E' if tag==native.TAG_SUB else 'O')+'\t'+str(m.memory.read(native.OUT+8,8)),seen
   if not (0x325cd8b<=pc<0x325cf3c or pc==0x325ccca):raise ValueError('escaped core')
   row=m.cache.get(pc)
   if row is None:row=native.decode(m.read_code,pc);m.cache[pc]=row
   if row.op in ('call','calli','ret'):raise ValueError('calls/returns forbidden')
   seen.add(pc);pc=m.step(row)
  raise ValueError('step bound')
def model(bits,bucket,start,floor):
 if start<floor:return 'E\t'+str(0xa5a5a5a5a5a5a5a5)
 elapsed=native.saturate(native.to_float(bits))
 factor=1.0-native.fdiv(float(elapsed),float(bucket));factor=factor if factor>0 else 0.0
 value=native.saturate(factor*float(start-floor))+floor
 if value>native.MASK[8]:value=floor
 return 'O\t'+str(value)

import capstone

def oracle(binary=native.BINARY):
 image=native.load_image(binary);engine=Engine(image)
 lo,hi=image.exact_fde(native.PRICE);raw=image.blob[image.offset(lo):image.offset(lo)+hi-lo]
 cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);rows=list(cs.disasm(raw,lo));assert sum(x.size for x in rows)==len(raw)
 bits={0,1,(1<<63),(1<<63)+1,0x7fefffffffffffff,0xffefffffffffffff,0x7ff0000000000000,0xfff0000000000000,0x7ff8000000000001,0xfff8000000000042}
 for value in [0.5,1.0,999.0,15000.0,59999.0,60000.0,60001.0,float(1<<53),float(1<<63),float(1<<64)]:
  b=native.to_bits(value);bits.update(b+i for i in [-2,-1,0,1,2])
 bits=sorted(bits)
 buckets=[0,1,2,1000,60000,(1<<32)-1,1<<32,(1<<53)+3,(1<<63),native.MASK[8]]
 pairs=[(0,0),(1,0),(1,1),(99,100),(100,100),(1000,100),((1<<53)+1,0),((1<<53)+3,0),(native.MASK[8],0),(native.MASK[8],1),(native.MASK[8],2048),(native.MASK[8],native.MASK[8]-1000),(1<<63,1<<40)]
 stimuli=[(b,k,s,f) for b in bits for k in buckets for s,f in pairs]
 state=0x94a0c710
 for _ in range(512):
  vals=[]
  for _ in range(4):state=(state*6364136223846793005+1442695040888963407)&native.MASK[8];vals.append(state)
  b,k,s,f=vals
  if b&0x7ff0000000000000==0x7ff0000000000000:b|=1<<51
  stimuli.append((b,k,s,f))
 stimuli=sorted(set(stimuli));inputs=[];expected=[];seen=set()
 for b,k,s,f in stimuli:
  answer,trace=engine.run(b,k,s,f);assert answer==model(b,k,s,f),(hex(b),k,s,f,answer,model(b,k,s,f))
  inputs.append(f'{b}\t{k}\t{s}\t{f}\n');expected.append(answer+'\n');seen.update(trace)
 controls=[]
 # Change the actual subtract-borrow branch and wrapped-add fallback branch.
 for name,va,value,args in [('subtract-gate',0x325cde8,0x83,(0,60000,99,100)),('wrapped-add',0x325cf2a,0x83,(0,60000,native.MASK[8],1))]:
  old=image.blob[image.offset(va)];private=Engine(image,{va:value});before,_=engine.run(*args);after,_=private.run(*args);assert before!=after,(name,before,after)
  controls.append({'name':name,'va':hex(va),'old':old,'new':value,'inputs':args,'before':before,'after':after})
 rawin=''.join(inputs).encode();rawout=''.join(expected).encode()
 owner={'va':hex(lo),'end':hex(hi),'bytes':len(raw),'instructions':len(rows),'body_sha256':hashlib.sha256(raw).hexdigest(),'visited_instructions':len(seen),'selected_rows':[{'va':hex(x.address),'raw_hex':x.bytes.hex(),'mnemonic':x.mnemonic,'operands':x.op_str} for x in rows if x.address in seen]}
 return {'inputs':rawin,'expected':rawout,'owner':owner,'controls':controls,'rows':len(stimuli)}

PACKET=ROOT/'research/work-items/RE-004-gas-auction-price-core-rust-94'
COMPONENT=ROOT/'src/node94-gas-auction-price-core'
def need(ok,message):
 if not ok:raise ValueError(message)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def build(binary,rustc,output):
 import subprocess
 output=Path(output);need(not output.exists(),'output must be new')
 result=oracle(binary);freeze=json.loads((PACKET/'FREEZE.json').read_text())
 need(sha(result['inputs'])==freeze['input_sha256'] and sha(result['expected'])==freeze['expected_sha256'],'frozen expectations differ before compiler')
 need(result['owner']==json.loads((PACKET/'owner.json').read_text()),'owner record differs')
 need(json.loads(json.dumps(result['controls']))==json.loads((PACKET/'native-controls.json').read_text()),'native controls differ')
 need((COMPONENT/'target-smoke.tsv').read_bytes()==(PACKET/'target-smoke.tsv').read_bytes(),'smoke fixture differs')
 version=subprocess.check_output([str(rustc),'-Vv'],text=True);need(version.startswith('rustc 1.94.1 ('),'pinned Rust1.94.1 required')
 output.mkdir(parents=True);(output/'inputs.tsv').write_bytes(result['inputs']);(output/'expected.tsv').write_bytes(result['expected']);commands=[]
 def run(args,**kw):
  args=list(map(str,args));commands.append(args);return subprocess.run(args,capture_output=True,text=True,**kw)
 def library(source,folder,opt):
  folder.mkdir();lib=folder/'libnode94_gas_auction_price_core.rlib'
  p=run([rustc,'--edition=2021','--crate-name','node94_gas_auction_price_core','--crate-type','rlib','-C',f'opt-level={opt}','-C','overflow-checks=on','-C','codegen-units=1','-C','metadata=gas_auction_price_core','-D','warnings',source,'-o',lib]);need(p.returncode==0,p.stderr)
  exe=folder/'driver';p=run([rustc,'--edition=2021','-C',f'opt-level={opt}',COMPONENT/'input_only_driver.rs','--extern',f'node94_gas_auction_price_core={lib}','-D','warnings','-o',exe]);need(p.returncode==0,p.stderr);return lib,exe
 def smoke(source,folder):
  exe=folder/'smoke-test';p=run([rustc,'--edition=2021','--test',source,'-D','warnings','-o',exe]);need(p.returncode==0,p.stderr);return run([exe])
 profiles={}
 for opt in (0,3):
  _,exe=library(COMPONENT/'lib.rs',output/f'o{opt}',opt);p=run([exe],input=result['inputs'].decode());need(p.returncode==0 and p.stdout.encode()==result['expected'],'compiled Rust differs')
  (output/f'output-o{opt}.tsv').write_text(p.stdout);profiles[str(opt)]={'rows':result['rows'],'match':True,'stdout_sha256':sha(p.stdout.encode())}
 p=smoke(COMPONENT/'lib.rs',output);need(p.returncode==0,p.stdout+p.stderr);(output/'smoke-output.txt').write_text(p.stdout)
 source=(COMPONENT/'lib.rs').read_text();mutants=[]
 for name,old,new in [('infinity','!value.is_finite()','value.is_nan()'),('wrapped-add','unwrap_or(floor)','unwrap_or(u64::MAX)'),('span-rounding','(start - floor) as f64','start as f64 - floor as f64')]:
  need(source.count(old)==1,'mutation binding changed');folder=output/('mutant-'+name);folder.mkdir();changed=folder/'lib.rs';changed.write_text(source.replace(old,new));(folder/'target-smoke.tsv').write_bytes((COMPONENT/'target-smoke.tsv').read_bytes())
  _,exe=library(changed,folder/'build',3);p=run([exe],input=result['inputs'].decode());need(p.returncode==0,'mutant must emit rows')
  actual=p.stdout.splitlines();expected=result['expected'].decode().splitlines();mismatch=sum(a!=b for a,b in zip(actual,expected));need(len(actual)==len(expected) and mismatch>0,'mutant escaped')
  p=smoke(changed,folder);need(p.returncode!=0,'mutant passed target-smoke');mutants.append({'name':name,'mismatches':mismatch,'rows':len(actual),'compiled_smoke_exit':p.returncode})
 repeat,_=library(COMPONENT/'lib.rs',output/'o3-repeat',3);raw=(output/'o3/libnode94_gas_auction_price_core.rlib').read_bytes();need(raw==repeat.read_bytes(),'raw own archive differs')
 report={'rows':result['rows'],'profiles':profiles,'compiled_mutants':mutants,'raw_own_rlib_equal':True,'rlib_sha256':sha(raw),'source_sha256':sha(source.encode()),'compiler':version,'commands':commands,'captured_process_executed':False,'offline_python_instruction_evaluation_authorized':True}
 (output/'build-result.json').write_text(json.dumps(report,indent=2)+'\n');return report
if __name__=='__main__':
 import argparse
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--binary',type=Path,default=native.BINARY);p.add_argument('--rustc',type=Path,required=True);p.add_argument('--output',type=Path,required=True);args=p.parse_args();r=build(args.binary,args.rustc,args.output);print(json.dumps({k:r[k] for k in ('rows','compiled_mutants','raw_own_rlib_equal')}))
