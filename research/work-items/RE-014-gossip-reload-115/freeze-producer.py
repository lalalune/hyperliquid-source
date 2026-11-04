from pathlib import Path
import sys,hashlib,json,struct,subprocess
P=Path('research/work-items/RE-014-gossip-reload-115').resolve();sys.path.insert(0,str(P));import native
import capstone
b=native.TARGET.read_bytes();i=native.authenticate(b);cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);cs.detail=True
inputs,expected,visited=native.corpus(i)
rows=list(cs.disasm(b[i.file_offset(native.START):i.file_offset(native.END)],native.START));assert sum(x.size for x in rows)==native.END-native.START
owner={'start':hex(native.START),'end_exclusive':hex(native.END),'sha256':hashlib.sha256(b[i.file_offset(native.START):i.file_offset(native.END)]).hexdigest(),'file_offset':i.file_offset(native.START),'bytes':native.END-native.START,'instruction_count':len(rows)}
exports=[];calls=[]
for x in rows:
 exports.append(f'{x.address:#x}\t{x.bytes.hex()}\t{x.mnemonic}\t{x.op_str}'.rstrip()+'\n')
 if x.mnemonic=='call':
  row={'site':hex(x.address),'raw':x.bytes.hex(),'operand':x.op_str,'executed':False}
  if x.op_str.startswith('0x'):row['target']=x.op_str
  elif x.bytes[:2]==b'\xff\x15':
   slot=x.address+x.size+struct.unpack_from('<i',x.bytes,2)[0];row.update(slot=hex(slot),relative_addend=hex(i.slots[slot]))
  else:row['closure']='dynamic vtable call unresolved'
  calls.append(row)
locations=[]
for site,call,loc in [(0x5a6291e,0x5a62925,0x64aaee0),(0x5a84adf,0x5a84ae9,0x64aaee0)]:
 raw=b[i.file_offset(site):i.file_offset(site)+7];assert raw[:3]==b'\x48\x8d\x35' and site+7+struct.unpack_from('<i',raw,3)[0]==loc
 co=i.file_offset(call);rawcall=b[co:co+5];assert rawcall[0]==0xe8 and call+5+struct.unpack_from('<i',rawcall,1)[0]==native.START
 off=i.file_offset(loc);_,n,line,col=struct.unpack_from('<QQII',b,off);path=b[i.file_offset(i.slots[loc]):i.file_offset(i.slots[loc])+n].decode();assert path=='node/src/gossip_config.rs' and (line,col)==(103,32)
 locations.append({'lea':hex(site),'lea_raw':raw.hex(),'call':hex(call),'call_raw':rawcall.hex(),'caller_fde':[hex(x) for x in i.fde_of(call)],'location':hex(loc),'location_raw':b[off:off+24].hex(),'relative_path_addend':hex(i.slots[loc]),'path':path,'length':n,'line':line,'column':col})
controls=[]
for name,va,value,new,old in [('first-signedness',0x57d3010,0x97,(0x80000000,0,0),(0,0,0)),('cached-field-independent',0x57d300b,0x84,(3,10,0),(1,5,0)),('second-signedness',0x57d301f,0x9f,(0,0x80000000,0),(0,0,0)),('third-strictness',0x57d302d,0x82,(0,0,1),(0,0,1))]:
 data=bytearray(b);off=i.file_offset(va);previous=data[off];data[off]=value;ci=native.cpu.Image(bytes(data));before,_=native.evaluate(i,new,old);after,_=native.evaluate(ci,new,old);assert before!=after,(name,before,after)
 controls.append({'name':name,'va':hex(va),'before_byte':previous,'after_byte':value,'new':new,'cached':old,'original':before,'mutant':after})
record={'target_sha256':native.SHA,'base':'8fd8db680ec4bfef40996e5616bce3d5156d0b86','rows':len(expected.splitlines()),'input_sha256':hashlib.sha256(inputs).hexdigest(),'expected_sha256':hashlib.sha256(expected).hexdigest(),'visited_addresses':sorted(visited),'new115_rust_source_exists':Path('src/node115-gossip-reload/lib.rs').exists(),'historical_MIT_metadata_function_preexisted':True,'captured_process_executed':False,'helper_calls_in_interpretation':0,'scope':'gate only; post-normal metadata helper success, pre-parser handoff; no helper stubs'}
assert not record['new115_rust_source_exists']
for name,obj in [('FREEZE.json',record),('owner.json',owner),('calls.json',calls),('caller-locations.json',locations),('native-controls.json',controls)]: (P/name).write_text(json.dumps(obj,indent=2)+'\n')
(P/'owner.capstone.tsv').write_text(''.join(exports))
out=Path('../low-cpu-drafts/gossip-reload-115');out.mkdir(exist_ok=True);(out/'inputs.tsv').write_bytes(inputs);(out/'expected.tsv').write_bytes(expected)
# Every selected smoke expectation is frozen before the component is authored.
smoke=[]
for line,result in zip(inputs.decode().splitlines(),expected.decode().splitlines()):
 vals=list(map(int,line.split('\t')))
 if vals[:3] in ([0,0,0],[0x80000000,0,0],[0,0x80000000,0],[0,0,0xffffffff]) and vals[3:] in ([0,0,0],[1,0,0],[0,0x80000000,0],[0,0,0xffffffff]):smoke.append(line+'\t'+result+'\n')
(P/'target-smoke.tsv').write_text(''.join(smoke));print(json.dumps(record));print('native-controls',len(controls),'smoke',len(smoke))
