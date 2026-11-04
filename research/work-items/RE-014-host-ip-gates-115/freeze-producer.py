"""One-time pre-Rust caller-boundary freeze. No original helper/command runs."""
from native import *
import hashlib,json,mmap,capstone
if (ROOT/'src/node115-host-ip-gates/lib.rs').exists():raise RuntimeError('freeze refuses existing Rust component')
image=Image()
if hashlib.sha256(image.data).hexdigest()!=SHA:raise ValueError('wrong115 target')
if image.view.fde(START)!=(START,END):raise ValueError('owner FDE changed')
inputs,expected,seen=corpus(image);controls=[]
specs=[('length-bound',0x1562bf8,14,'M',(15,1,0)),('length-unsigned',0x1562bfa,0x8f,'M',(cpu.U64,1,0)),('remaining-zero',0x1562c21,1,'M',(15,1,0)),('parser-low-bit',0x1562c26,0xc9,'M',(15,0,0)),('post-parser-branch',0x1562c28,0x85,'M',(15,1,0)),('override-sentinel',0x15627f1,0x40,'O',(1<<63,)),('override-branch',0x15627fb,0x84,'O',(0,))]
for name,va,byte,op,args in specs:
 class Mutant(Image):
  def __init__(self):
   super().__init__();self.data=mmap.mmap(self.view.file.fileno(),0,access=mmap.ACCESS_COPY);self.data[self.view.offset(va)]=byte
 mutant=Mutant();fn=admission if op=='M' else override;before,_=fn(image,*args);after,_=fn(mutant,*args)
 if before==after:raise ValueError(('non-distinguishing corruption',name,before,after))
 controls.append({'name':name,'va':hex(va),'original_byte':image.view.read(va,1).hex(),'mutant_byte':hex(byte),'operation':op,'inputs':args,'before':before,'after':after})
cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);raw=image.view.read(START,END-START);rows=list(cs.disasm(raw,START))
if sum(x.size for x in rows)!=len(raw):raise ValueError('incomplete owner decode')
owner={'start':hex(START),'end':hex(END),'file_offset':image.view.offset(START),'bytes':len(raw),'instructions':len(rows),'sha256':hashlib.sha256(raw).hexdigest(),'selected_rows':[{'va':hex(x.address),'raw_hex':x.bytes.hex(),'mnemonic':x.mnemonic,'operands':x.op_str} for x in rows if x.address in seen]}
freeze={'target_sha256':SHA,'base':'8fd8db680ec4bfef40996e5616bce3d5156d0b86','rows':len(expected.splitlines()),'admission_rows':sum(x[0]=='M' for x in stimuli()),'override_rows':sum(x[0]=='O' for x in stimuli()),'input_sha256':hashlib.sha256(inputs).hexdigest(),'expected_sha256':hashlib.sha256(expected).hexdigest(),'visited_addresses':sorted(seen),'new115_rust_source_exists':False,'historical_MIT_gate_policy_preexisted':True,'helper_calls':0,'captured_process_executed':False,'scope':'separate pre-parser and post-normal-parser-return boundaries plus post-reader override branch; actual parser/reader/commands/services/collection/final result unclosed'}
if hashlib.sha256(image.data).hexdigest()!=SHA:raise ValueError('original input changed')
for name,obj in [('FREEZE.json',freeze),('owner.json',owner),('native-controls.json',controls)]: (PACKET/name).write_text(json.dumps(obj,indent=2)+'\n')
# Full streams remain in ignored work. Expectations are fixed before Rust exists.
out=ROOT/'work/host-ip-115-frozen';out.mkdir(parents=True,exist_ok=False);(out/'inputs.tsv').write_bytes(inputs);(out/'expected.tsv').write_bytes(expected)
lookup={a:b for a,b in zip(inputs.decode().splitlines(),expected.decode().splitlines())}
keys=['M\t0\t1\t0','M\t15\t1\t0','M\t16\t1\t0','M\t15\t2\t0','M\t15\t255\t0','M\t15\t1\t1',f'M\t{cpu.U64}\t1\t0','O\t0',f'O\t{1<<63}',f'O\t{(1<<63)-1}',f'O\t{(1<<63)+1}',f'O\t{cpu.U64}']
(PACKET/'target-smoke.tsv').write_text(''.join(k+'\t'+lookup[k]+'\n' for k in keys));print(json.dumps(freeze))
