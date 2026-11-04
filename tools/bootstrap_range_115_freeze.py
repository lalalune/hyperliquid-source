from bootstrap_range_115 import *
import capstone
b=TARGET.read_bytes();assert len(b)==105896032 and hashlib.sha256(b).hexdigest()==SHA;i=cpu.Image(b)
start,end=0x5a82670,0x5a89535;assert i.fde_of(0x5a88391)==(start,end)
body=b[i.file_offset(start):i.file_offset(end)];cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);decoded=list(cs.disasm(body,start));assert sum(x.size for x in decoded)==end-start and decoded[-1].address+decoded[-1].size==end
location=0x64b92e8;raw,n,line,col=struct.unpack_from('<QQII',b,i.file_offset(location));ptr=i.slots[location];path=b[i.file_offset(ptr):i.file_offset(ptr)+n].decode()
context={'owner':{'start':hex(start),'end':hex(end),'bytes':len(body),'instructions':len(decoded),'sha256':hashlib.sha256(body).hexdigest()},'entry':'0x5a88391','span_exit':'0x5a88d17','reversed_continuation':'0x5a883c4','window_join':'0x5a83026','window_stop':'0x5a83054','input_roles':{'r14':'pointer to raw inclusive lower','r15':'pointer to raw target','rbx':'qualified state pointer'},'output_fields':{'lower':'rbx+0x288','last':'rbx+0x290'},'location':{'va':hex(location),'raw_pointer':raw,'relative_addend':hex(ptr),'length':n,'path':path,'line':line,'column':col},'cold_call':{'site':'0x5a88d2f','slot':'0x64df6b8','target':hex(i.slots[0x64df6b8]),'esi_raw':53,'string_interpretation':'not established; raw arguments only'}}
values=list(range(0,111))+[29999,30000,30001,30002,(1<<63)-1,1<<63]+[cpu.U64-j for j in range(0,111)]
rows={(l,t) for l in values for t in values};state=0x115b007
for _ in range(1024):
 state=(state*6364136223846793005+1442695040888963407)&cpu.U64;l=state
 state=(state*6364136223846793005+1442695040888963407)&cpu.U64;rows.add((l,state))
for l in [0,1,100,1<<63,cpu.U64-30001,cpu.U64-30000,cpu.U64]:
 for d in [-1,0,1,98,99,100,29999,30000,30001]:
  if 0<=l+d<=cpu.U64:rows.add((l,l+d))
inputs=[];outputs=[];seen=set()
for l,t in sorted(rows):
 a,trace=evaluate(i,l,t);assert a==model(l,t),(l,t,a);inputs.append(f'{l}\t{t}\n');outputs.append(a+'\n');seen.update(trace)
controls=[]
for name,va,new,args in [('strict-span',0x5a883a4,0x30,(0,30000)),('borrow',0x5a8839f,0x92,(100,50)),('inclusive-lower',0x5a883bf,0x82,(1,1)),('window99',0x5a83031,0x9e,(0,100)),('overflow-branch',0x5a83032,0x73,(cpu.U64-98,cpu.U64))]:
 changed=bytearray(b);off=i.file_offset(va);old=changed[off];changed[off]=new;answer,_=evaluate(cpu.Image(bytes(changed)),*args);original,_=evaluate(i,*args);assert answer!=original,(name,original,answer)
 controls.append({'name':name,'va':hex(va),'old':old,'new':new,'inputs':args,'before':original,'after':answer,'full_body_binding_rejects':hashlib.sha256(changed[i.file_offset(start):i.file_offset(end)]).hexdigest()!=context['owner']['sha256']})
selected=[]
for va in sorted(seen):
 ins=i.fetch(va);raw=b[ins.off:ins.off+ins.size];check=list(cs.disasm(raw,va));assert len(check)==1 and check[0].size==ins.size
 selected.append({'va':hex(va),'raw_hex':raw.hex(),'mnemonic':check[0].mnemonic,'operands':check[0].op_str})
rawin=''.join(inputs).encode();rawout=''.join(outputs).encode();out=Path(sys.argv[1]);out.mkdir()
freeze={'base':'8fd8db680ec4bfef40996e5616bce3d5156d0b86','target_sha256':SHA,'input_sha256':hashlib.sha256(rawin).hexdigest(),'expected_sha256':hashlib.sha256(rawout).hexdigest(),'rows':len(rows),'selected_instructions':len(selected),'node115_production_source_exists':(ROOT/'src/node115-bootstrap-range/lib.rs').exists(),'retired94_logic_preexisted':True,'native_process_executed':False,'helper_calls':0}
(out/'inputs.tsv').write_bytes(rawin);(out/'expected.tsv').write_bytes(rawout)
for name,value in [('FREEZE.json',freeze),('native-context.json',context),('native-controls.json',controls),('selected-instructions.json',selected)]: (out/name).write_text(json.dumps(value,indent=2)+'\n')
print(json.dumps(freeze));print(json.dumps(context))
