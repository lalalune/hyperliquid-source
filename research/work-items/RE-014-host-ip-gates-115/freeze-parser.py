"""Second pre-Rust freeze: full leaf plus authentic caller CALL/RET."""
from parser import *
import hashlib,json,mmap,capstone,subprocess
if (ROOT/'src/node115-host-ip-gates/lib.rs').exists():raise RuntimeError('freeze refuses existing Rust component')
image=Image()
if hashlib.sha256(image.data).hexdigest()!=SHA:raise ValueError('wrong target')
if image.view.fde(LEAF)!=(LEAF,LEAF_END):raise ValueError('leaf FDE mismatch')
inputs,expected,seen=corpus(image)
controls=[]
specs=[('octet-bound',0x167cd6b,1,b'256.0.0.0'),('separator',0x167cd9a,0x3a,b'1:2.3.4'),('leading-zero',0x167cd64,0x31,b'01.2.3.4'),('payload',0x167d014,0xc1,b'1.2.3.4'),('cursor-pointer',0x167d05f,7,b'1.2.3.4'),('remaining-store',0x167d062,0x57,b'1.2.3.4')]
for name,va,byte,data in specs:
 mutant=Image();mutant.data=mmap.mmap(mutant.view.file.fileno(),0,access=mmap.ACCESS_COPY);mutant.data[mutant.view.offset(va)]=byte
 before,_=evaluate(image,data);after,_=evaluate(mutant,data)
 if before==after:raise ValueError(('non-distinguishing',name,before,after))
 controls.append(dict(name=name,va=hex(va),original_byte=image.view.read(va,1).hex(),mutant_byte=hex(byte),input_hex=data.hex(),before=before,after=after))
cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);owners=[];export=[];gnu=[]
for start,end in [(START,END),(LEAF,LEAF_END)]:
 raw=image.view.read(start,end-start);rows=list(cs.disasm(raw,start))
 if sum(x.size for x in rows)!=len(raw):raise ValueError('decode incomplete')
 owners.append(dict(start=hex(start),end=hex(end),bytes=len(raw),instructions=len(rows),sha256=hashlib.sha256(raw).hexdigest(),visited=sum(x.address in seen for x in rows)))
 export.extend(f'{x.address:x}\t{x.bytes.hex()}\t{x.mnemonic}\t{x.op_str}\n' for x in rows)
 gnu.append(subprocess.check_output([str(ROOT.parent/'host-tools/bin/objdump'),'-d',f'--start-address={start}',f'--stop-address={end}',str(TARGET)],text=True))
record=dict(target_sha256=SHA,rows=len(expected.splitlines()),byte_cases=len(byte_stimuli()),input_sha256=hashlib.sha256(inputs).hexdigest(),expected_sha256=hashlib.sha256(expected).hexdigest(),visited_addresses=sorted(seen),owners=owners,new115_rust_source_exists=False,parser_stub=False,captured_process_executed=False,normalization='Failure payload ignored; success bits8..39 as little-endian IPv4. Cursor pointer normalized to buffer offset; remaining is independently read. B means length bypass before parser. A/R caller collection handoff/rejection boundaries, not whole-function return.')
for name,obj in [('PARSER-FREEZE.json',record),('parser-controls.json',controls)]: (PACKET/name).write_text(json.dumps(obj,indent=2)+'\n')
(PACKET/'owners.capstone.tsv').write_text(''.join(export));(PACKET/'owners.gnu.txt').write_text('\n'.join(gnu))
out=ROOT/'work/host-ip-parser-115-frozen-v2';out.mkdir(parents=True,exist_ok=False);(out/'inputs.tsv').write_bytes(inputs);(out/'expected.tsv').write_bytes(expected)
lookup=dict(zip(inputs.decode().splitlines(),expected.decode().splitlines()));keys=[]
for data in [b'',b'1.2.3.4',b'0.0.0.0',b'255.255.255.255',b'256.0.0.0',b'01.2.3.4',b'1.2.3.4x',b'1.2.3.4\n',b'1234567890123456']:
 for op in ('P','C'):keys.append(op+'\t'+data.hex())
(PACKET/'parser-smoke.tsv').write_text(''.join(k+'\t'+lookup[k]+'\n' for k in keys))
if hashlib.sha256(image.data).hexdigest()!=SHA:raise ValueError('input altered')
print(json.dumps(record))
