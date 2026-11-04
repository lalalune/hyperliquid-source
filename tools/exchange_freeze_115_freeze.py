from exchange_freeze_115 import *
import capstone,struct
b=TARGET.read_bytes();assert len(b)==105896032 and hashlib.sha256(b).hexdigest()==SHA;i=cpu.Image(b);cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);cs.detail=True
owners=[];starts={}
for which,c in enumerate(CASES):
 a,end=c['start'],c['end'];assert i.fde_of(c['entry'])==(a,end);body=b[i.file_offset(a):i.file_offset(end)];decoded=list(cs.disasm(body,a));assert sum(x.size for x in decoded)==end-a
 starts.update({x.address:x for x in decoded});assert b[i.file_offset(c['entry']-4):i.file_offset(c['entry'])]==bytes.fromhex('4c8b7e28')
 cold=[]
 for va in c['cold']:
  rows=list(cs.disasm(b[i.file_offset(va):i.file_offset(va)+25],va));lea=rows[1];assert lea.mnemonic=='lea' and lea.operands[0].reg==capstone.x86.X86_REG_RDX
  location=lea.address+lea.size+lea.operands[1].mem.disp;raw,n,line,col=struct.unpack_from('<QQII',b,i.file_offset(location));ptr=i.slots[location];path=b[i.file_offset(ptr):i.file_offset(ptr)+n].decode();assert (path,line,col)==('l1/src/exchange/exchange.rs',607,17)
  call=rows[3];slot=call.address+call.size+call.operands[0].mem.disp
  cold.append({'entry':hex(va),'location':hex(location),'raw_pointer':raw,'relative_addend':hex(ptr),'path':path,'length':n,'line':line,'column':col,'call_site':hex(call.address),'slot':hex(slot),'target':hex(i.slots[slot]),'helper_execution':False})
 call=starts[c['prepare']];assert call.mnemonic=='call' and call.operands[0].type==capstone.x86.X86_OP_IMM
 owners.append({'start':hex(a),'end':hex(end),'bytes':len(body),'sha256':hashlib.sha256(body).hexdigest(),'instructions':len(decoded),'file_offset':i.file_offset(a),'selected_entry':hex(c['entry']),'tag_offset':hex(c['tag']),'target_offset':hex(c['tag']+8),'secondary_offset':None if c['extra'] is None else hex(c['extra']),'height_qualification':'preloaded R15, source loads qword at context+0x28; context comes from outer+0x450','cold_boundaries':cold,'prepare_call':{'site':hex(call.address),'direct_target':hex(call.operands[0].imm),'executed':False},'sentinel_word_stop':hex(c['sentinel']),'skip_continuation':hex(c['skip'])})
last=(cpu.U64//10000)*10000;heights=sorted({0,1,9999,10000,10001,19999,20000,20001,(1<<32)-1,1<<32,(1<<63)-1,1<<63,cpu.U64,cpu.U64-1,last,last-1});cadences=[1,2,1000,9999,10000,(1<<32)-1,1<<32,cpu.U64]
rows=set()
for which in range(3):
 for h in range(20001):rows.add((which,0,0,h,cpu.U64,0 if which==0 else 1000))
 for h in heights:
  for target in {0,max(0,h-1),h,min(cpu.U64,h+1),cpu.U64}:
   for outer in [0,2,3,0xffffffff]:
    for tag in [0,1,2,0xffffffff]:
     for cadence in [0] if which==0 else cadences:rows.add((which,outer,tag,h,target,cadence))
state=0x115f22
for _ in range(512):
 vals=[]
 for _ in range(3):state=(state*6364136223846793005+1442695040888963407)&cpu.U64;vals.append(state)
 for which in range(3):rows.add((which,[0,2,0xffffffff][vals[0]%3],[0,1,0xffffffff][vals[1]%3],vals[0],vals[1],0 if which==0 else vals[2] or 1))
inputs=[];outputs=[];seen=set();counts=[0,0,0];logical=set()
for row in sorted(rows):
 result,trace=evaluate(i,*row);assert result==model(*row),(row,result,model(*row));seen.update(trace);inputs.append('\t'.join(map(str,row))+'\n');outputs.append(result+'\n');counts[row[0]]+=1;logical.add((0 if row[0]==0 else 1,*row[1:]))
for which in range(3):assert evaluate(i,which,2,None,10000,None,1)[0]=='R'
selected=[]
for va in sorted(seen):
 ins=i.fetch(va);other=starts[va];assert ins.size==other.size
 selected.append({'va':hex(va),'raw_hex':other.bytes.hex(),'mnemonic':other.mnemonic,'operands':other.op_str})
controls=[]
for name,va,new,args in [('periodic-before-target',0x2d25661,0x73,(0,2,1,10000,9999,0)),('outer-tag',0x5a07f20,3,(1,2,1,1,cpu.U64,cpu.U64)),('second-target-gate',0x5a087b9,0x83,(2,0,1,10000,9999,7)),('secondary64-remainder',0x5a07fa4,0x84,(1,0,0,1<<32,cpu.U64,1<<32)),('secondary32-remainder',0x5a08816,0x84,(2,0,0,1,cpu.U64,1)),('rotate-periodic',0x5a08753,3,(2,0,0,last,cpu.U64,cpu.U64))]:
 private=bytearray(b);off=i.file_offset(va);old=private[off];private[off]=new;before,_=evaluate(i,*args);after,_=evaluate(cpu.Image(bytes(private)),*args);assert before!=after,(name,before,after)
 controls.append({'name':name,'va':hex(va),'old':old,'new':new,'inputs':args,'before':before,'after':after})
rawin=''.join(inputs).encode();rawout=''.join(outputs).encode();out=Path(sys.argv[1]);out.mkdir()
f={'base':'8fd8db680ec4bfef40996e5616bce3d5156d0b86','target_sha256':SHA,'rows':len(rows),'rows_per_lane':counts,'distinct_two_class_inputs':len(logical),'input_sha256':hashlib.sha256(rawin).hexdigest(),'expected_sha256':hashlib.sha256(rawout).hexdigest(),'visited_instructions':len(seen),'new115_source_exists':(ROOT/'src/node115-exchange-freeze-prelude/lib.rs').exists(),'historical94_admission_preexisted':True,'captured_process_executed':False,'helper_calls':0,'secondary_domain':'strictly positive u64; zero/trap/caller reachability unclosed','active_flags':'one byte each; upper temporary padding excluded from scalar projection','missing_freeze_fields_periodic_outer2':'all three lanes reach sentinel word without those fields'}
(out/'inputs.tsv').write_bytes(rawin);(out/'expected.tsv').write_bytes(rawout)
for name,obj in [('FREEZE.json',f),('owners.json',owners),('native-controls.json',controls),('selected-instructions.json',selected)]: (out/name).write_text(json.dumps(obj,indent=2)+'\n')
print(json.dumps(f))
