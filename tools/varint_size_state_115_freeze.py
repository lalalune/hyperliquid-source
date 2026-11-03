from varint_size_state_115 import *
import capstone
blob=TARGET.read_bytes();assert len(blob)==105896032 and hashlib.sha256(blob).hexdigest()==SHA
image=cpu.Image(blob);cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
words32=sorted(set(range(260))|{65535+j for j in range(-8,9)}|{(1<<32)-1-j for j in range(8)})
words64=sorted(set(words32)|{(1<<32)+j for j in range(-8,9)}|{(1<<63)+j for j in range(-4,5)}|{cpu.U64-j for j in range(12)})
counts=list(range(12))+[cpu.U64-j for j in range(16)]+[(1<<63)-1,1<<63]
inputs=[];outputs=[];owners=[];parts=[];logical=set();seen=set()
for which,(a,b,width,abi) in enumerate(SITES):
 assert image.fde_of(a)==(a,b);raw=blob[image.file_offset(a):image.file_offset(b)];decoded=list(cs.disasm(raw,a));assert sum(x.size for x in decoded)==b-a
 for x in decoded:assert image.fetch(x.address).size==x.size
 lea=blob[image.file_offset(b-13):image.file_offset(b-13)+7];assert lea[:3]==bytes.fromhex('488d3d');location=b-6+struct.unpack_from('<i',lea,3)[0]
 ptr_raw,n,line,col=struct.unpack_from('<QQII',blob,image.file_offset(location));ptr=image.slots[location];path=blob[image.file_offset(ptr):image.file_offset(ptr)+n].decode();assert path=='z_forks/bincode-fork/src/enc/write.rs' and (line,col)==(78,9)
 call=blob[image.file_offset(b-6):image.file_offset(b-6)+6];assert call[:2]==b'\xff\x15';slot=b+struct.unpack_from('<i',call,2)[0]
 owners.append({'va':hex(a),'end':hex(b),'file_offset':image.file_offset(a),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'width':width,'abi_qualification':abi,'raw_hex':raw.hex(),'instructions':[{'va':hex(x.address),'raw_hex':x.bytes.hex(),'mnemonic':x.mnemonic,'operands':x.op_str} for x in decoded],'location':{'va':hex(location),'raw_pointer':ptr_raw,'relative_addend':hex(ptr),'length':n,'path':path,'line':line,'column':col},'overflow_boundary':{'site':hex(b-6),'slot':hex(slot),'target':hex(image.slots[slot]),'executed':False}})
 before=len(inputs)
 for value in words32 if width==32 else words64:
  for count in counts:
   for flag in [0,1,2,128,255] if abi=='direct-rcx' else [0]:
    result,trace=evaluate(image,which,value,count,flag);assert result==model(value,count),(which,value,count,flag,result);seen.update(trace);logical.add((width,value,count));inputs.append(f'{which}\t{value}\t{count}\t{flag}\n');outputs.append(result+'\n')
 parts.append(len(inputs)-before)
assert seen=={int(x['va'],16) for o in owners for x in o['instructions']} - {b-6 for a,b,w,abi in SITES}
controls=[]
for name,va,new,args in [('u64-threshold',0x29360e4,252,(0,251,0,0)),('inline-u32-precommit',0x582210d,2,(1,251,cpu.U64-1,0)),('indirect-u32-threshold',0x5822169,252,(2,251,0,0)),('u64-overflow',0x58228e4,0xf8,(3,1<<32,cpu.U64-8,0)),('u64-sibling-precommit',0x5822bcf+3,0xfe,(4,251,cpu.U64-2,0))]:
 private=bytearray(blob);off=image.file_offset(va);old=private[off];private[off]=new;original,_=evaluate(image,*args);changed,_=evaluate(cpu.Image(bytes(private)),*args);assert changed!=original,(name,original,changed)
 controls.append({'name':name,'va':hex(va),'old':old,'new':new,'inputs':args,'before':original,'after':changed})
rawin=''.join(inputs).encode();rawout=''.join(outputs).encode();out=Path(sys.argv[1]);out.mkdir()
freeze={'base':'8fd8db680ec4bfef40996e5616bce3d5156d0b86','target_sha256':SHA,'rows':len(inputs),'rows_per_owner':parts,'distinct_logical_width_value_count':len(logical),'input_sha256':hashlib.sha256(rawin).hexdigest(),'expected_sha256':hashlib.sha256(rawout).hexdigest(),'visited_instructions':len(seen),'new115_source_exists':(ROOT/'src/node115-varint-size-state/lib.rs').exists(),'retired_mit_counter_logic_preexisted':True,'captured_process_executed':False,'helper_calls':0,'out_tags_and_return_registers':'qualified natively; not asserted as Rust ABI'}
(out/'inputs.tsv').write_bytes(rawin);(out/'expected.tsv').write_bytes(rawout)
for name,obj in [('FREEZE.json',freeze),('owners.json',owners),('native-controls.json',controls)]: (out/name).write_text(json.dumps(obj,indent=2)+'\n')
print(json.dumps(freeze))
