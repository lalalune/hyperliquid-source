"""One-time native producer; refuses an existing node115 Rust component."""
from native import *
import hashlib,json,capstone,itertools
if (ROOT/'src/node115-price-core/lib.rs').exists():
 raise RuntimeError('freeze refuses existing Rust component')
image=Image()
if hashlib.sha256(image.blob).hexdigest()!=SHA:raise ValueError('wrong node115 capture')
bits={0,1,1<<63,(1<<63)+1,0x7fefffffffffffff,0xffefffffffffffff,0x7ff0000000000000,0xfff0000000000000,0x7ff8000000000001,0xfff8000000000042}
for x in [0.5,1.0,999.0,15000.0,59999.0,60000.0,60001.0,float(1<<53),float(1<<63),float(1<<64)]:
 word=cpu.to_bits(x);bits.update(word+d for d in [-2,-1,0,1,2])
buckets=[0,1,2,1000,60000,(1<<32)-1,1<<32,(1<<53)+3,1<<63,U64]
pairs=[(0,0),(1,0),(1,1),(99,100),(100,100),(1000,100),((1<<53)+1,0),((1<<53)+3,0),(U64,0),(U64,1),(U64,2048),(U64,U64-1000),(1<<63,1<<40)]
stimuli=list((b,k,s,f) for b in sorted(bits) for k in buckets for s,f in pairs);state=0x115ac710
for _ in range(512):
 values=[]
 for _ in range(4):state=(state*6364136223846793005+1442695040888963407)&U64;values.append(state)
 b,k,s,f=values
 if b&0x7ff0000000000000==0x7ff0000000000000:b|=1<<51
 stimuli.append((b,k,s,f))
stimuli=sorted(set(stimuli));inputs=[];expected=[];seen=set()
for b,k,s,f in stimuli:
 actual,trace=evaluate(image,b,k,s,f);assert actual==model(b,k,s,f),(b,k,s,f,actual,model(b,k,s,f));seen|=trace
 inputs.append(f'{b}\t{k}\t{s}\t{f}\n');expected.append(actual+'\n')
controls=[]
for name,va,value,args in [('subtract-borrow',0x3be58a5,0x83,(0,60000,99,100)),('wrapped-add',0x3be59e7,0x83,(0,60000,U64,1)),('nonfinite-clamp',0x3be587d,0x75,(0x7ff0000000000000,60000,1000,100)),('factor-fallback',0x3be5950,0x72,(0,60000,1000,100))]:
 before,_=evaluate(image,*args);after,_=evaluate(image,*args,patch={va:value});assert before!=after,(name,before,after)
 controls.append({'name':name,'va':hex(va),'before_byte':image.view.read(va,1).hex(),'after_byte':hex(value),'inputs':args,'before':before,'after':after})
lo,hi=image.view.fde(0x3be5790);raw=image.view.read(lo,hi-lo);cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);rows=list(cs.disasm(raw,lo));assert sum(x.size for x in rows)==len(raw)
out=Path(__file__).resolve().parent/'frozen';out.mkdir(exist_ok=False);rawin=''.join(inputs).encode();rawout=''.join(expected).encode();(out/'inputs.tsv').write_bytes(rawin);(out/'expected.tsv').write_bytes(rawout)
freeze={'target_sha256':hashlib.sha256(image.blob).hexdigest(),'rows':len(stimuli),'input_sha256':hashlib.sha256(rawin).hexdigest(),'expected_sha256':hashlib.sha256(rawout).hexdigest(),'visited_instructions':len(seen),'visited_addresses':sorted(seen),'new115_rust_source_exists':False,'historical_MIT_price_policy_preexisted':True,'helper_calls':0,'unknown_GPR_or_vector_lane_reads':0,'quiet_nan_only':True,'captured_process_executed':False,'normalization':'native error payload excluded; error tag mapped to own E, success tag to own O/value; not original result ABI'}
for name,obj in [('FREEZE.json',freeze),('native-controls.json',controls),('owner.json',{'start':hex(lo),'end':hex(hi),'bytes':len(raw),'instructions':len(rows),'sha256':hashlib.sha256(raw).hexdigest(),'selected_rows':[{'va':hex(x.address),'raw_hex':x.bytes.hex(),'mnemonic':x.mnemonic,'operands':x.op_str} for x in rows if x.address in seen]})]: (out/name).write_text(json.dumps(obj,indent=2)+'\n')
print(json.dumps(freeze))
