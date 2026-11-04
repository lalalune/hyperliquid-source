"""Freeze the three115 selected routes before authoring the Rust component."""
from native import *
import hashlib,json,capstone,mmap
SHA='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
if (ROOT/'src/node115-liquidity-bucket/lib.rs').exists():raise RuntimeError('freeze refuses existing Rust component')
image=Image()
if hashlib.sha256(image.data).hexdigest()!=SHA:raise ValueError('wrong115 target')
raws=sorted({0,1,2,59,60,61,999,1000,1001,cpu.U64}|{(1<<32)+j for j in range(-3,4)}|{(1<<63)+j for j in range(-3,4)}|{cpu.U64-j for j in range(4)})
divisors=sorted({0,1,2,59,60,1000,cpu.U64}|{(1<<32)+j for j in range(-2,3)}|{(1<<63)+j for j in range(-1,2)})
cases=set()
for raw in raws:
 for d in divisors:
  old_values={0,1,2,1<<63,cpu.U64}
  if d:
   q=(raw if raw<1<<63 else 0)//d;old_values|={q,max(0,q-1),min(cpu.U64,q+1)}
  for old in old_values:cases.add((raw,d,old))
state=0x115b0c
for _ in range(512):
 values=[]
 for _ in range(3):state=(state*6364136223846793005+1442695040888963407)&cpu.U64;values.append(state)
 cases.add(tuple(values))
inputs=[];expected=[];semantic=[];owners=[];seen=set();cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
ordered=sorted(cases);bypass_cases=ordered[::max(1,len(ordered)//32)]
for which,a in enumerate(SITES):
 lo,hi=image.view.fde(a)
 if (lo,hi)!=(a,a+630):raise ValueError('owner FDE mismatch')
 rows=list(cs.disasm(image.view.read(a,630),a))
 if sum(x.size for x in rows)!=630:raise ValueError('incomplete disassembly')
 owners.append({'start':hex(a),'end':hex(hi),'bytes':630,'instructions':len(rows),'sha256':hashlib.sha256(image.view.read(a,630)).hexdigest(),'rows':[{'va':hex(x.address),'raw_hex':x.bytes.hex(),'mnemonic':x.mnemonic,'operands':x.op_str} for x in rows]})
 stimuli=[(0,*args) for args in ordered]+[(flag,*args) for flag in [1,2,127,128,254,255] for args in bypass_cases]
 for flag,raw,d,old in stimuli:
  actual,trace=select(image,which,flag,raw,d,old);clamped=raw if raw<1<<63 else 0;width=32 if (clamped|d)<1<<32 else 64
  if flag:model=('D',)
  elif not d:model=('Z',width)
  else:q=clamped//d;model=('T',q,max(q,old),int(q>old),width)
  if actual!=model:raise ValueError(('native/model mismatch',which,flag,raw,d,old,actual,model))
  inputs.append(f'{which}\t{flag}\t{raw}\t{d}\t{old}\n');expected.append('\t'.join(map(str,actual))+'\n');semantic.append('\t'.join(map(str,actual[:4] if actual[0]=='T' else actual[:1]))+'\n');seen|=trace
controls=[]
for which,a in enumerate(SITES):
 specs=[('signed-clamp',0x19f,0x47,(0,cpu.U64,2,0)),('state-store-source',0x1c3,0x4c,(0,100,2,1)),('flag-signedness',0x1df,0x9d,(0,0,1,cpu.U64)),('division-width',0x1af,31,(0,(1<<32)-1,1,0)),('bypass-branch',0xde,0x75,(1,100,2,1)),('independent-divisor-field',0x1a5,0x28,(0,100,0,1))]
 for name,offset,byte,args in specs:
  class Mutant(Image):
   def __init__(self):
    super().__init__();self.data=mmap.mmap(self.view.file.fileno(),0,access=mmap.ACCESS_COPY);self.data[self.view.offset(a+offset)]=byte
  mutant=Mutant();before,_=select(image,which,*args);after,_=select(mutant,which,*args)
  if before==after:raise ValueError(('non-distinguishing corruption',name,which,before,after))
  controls.append({'owner':which,'name':name,'va':hex(a+offset),'original_byte':image.view.read(a+offset,1).hex(),'mutant_byte':hex(byte),'inputs':args,'before':before,'after':after})
if hashlib.sha256(image.data).hexdigest()!=SHA:raise ValueError('original capture changed')
rawin=''.join(inputs).encode();rawout=''.join(expected).encode();projection=''.join(semantic).encode();out=Path(__file__).resolve().parent/'frozen';out.mkdir(exist_ok=False)
(out/'inputs.tsv').write_bytes(rawin);(out/'expected.tsv').write_bytes(rawout);(out/'semantic-expected.tsv').write_bytes(projection)
freeze={'target_sha256':SHA,'base':'8fd8db680ec4bfef40996e5616bce3d5156d0b86','rows':len(inputs),'timed_logical_inputs':len(cases),'bypass_logical_inputs':6*len(bypass_cases),'physical_owners':3,'visited_addresses':sorted(seen),'input_sha256':hashlib.sha256(rawin).hexdigest(),'expected_sha256':hashlib.sha256(rawout).hexdigest(),'semantic_projection_sha256':hashlib.sha256(projection).hexdigest(),'native_width_field':'retained as separate metadata; Rust comparison excludes width','new115_rust_source_exists':False,'helper_calls':0,'captured_process_executed':False,'zero_divisor':'actual decoded operand checked at actual DIV; stop before fault, own Z is a boundary classification','scope':'supplied post-helper bypass byte; local route supplies post-calendar-conversion raw word and field snapshot; handoffs/FP or clock conversion/original ABI remain unclosed'}
for name,obj in [('FREEZE.json',freeze),('owners.json',owners),('native-controls.json',controls)]: (out/name).write_text(json.dumps(obj,indent=2)+'\n')
print(json.dumps(freeze))
