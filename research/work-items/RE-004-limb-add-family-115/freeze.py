"""Freeze original whole-leaf observations before adding new Rust."""
import argparse,hashlib,json,mmap,re,subprocess
from pathlib import Path
import native,capstone
from fde_extents import eh_frame_records

def collect(out,objdump):
 if (native.ROOT/'src/node115-limb-add-family/lib.rs').exists():raise ValueError('freeze refuses existing new Rust')
 if out.exists():raise ValueError('new output required')
 im=native.Image()
 try:
  if hashlib.sha256(im.data).hexdigest()!=native.SHA:raise ValueError('wrong115target')
  inputs,expected,seen=native.corpus(im)
  _,fdes=eh_frame_records(im.data);cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
  owners=[];exports=[];gnu=[];instructions=[]
  for mode,(start,end) in enumerate(native.RANGES):
   raw=im.view.read(start,end-start);rows=list(cs.disasm(raw,start));instructions.append(rows)
   selected=[f for f in fdes if (f['start'],f['end'])==(start,end)]
   if len(selected)!=1 or sum(x.size for x in rows)!=end-start:raise ValueError('bad FDE/decode')
   unwind={}
   for name,address in [('fde',selected[0]['fde']),('cie',selected[0]['cie'])]:
    length=4+int.from_bytes(im.view.read(address,4),'little');unwind[name]={'va':hex(address),'raw_hex':im.view.read(address,length).hex()}
   text=subprocess.check_output([str(objdump),'-d','--wide','-M','intel',f'--start-address={start:#x}',f'--stop-address={end:#x}',str(native.TARGET)],text=True).replace(str(native.TARGET),'artifacts/node/115/hl-node')
   parsed=[]
   for line in text.splitlines():
    match=re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s)+)',line)
    if match:parsed.append((int(match[1],16),bytes.fromhex(match[2])))
   if parsed!=[(x.address,bytes(x.bytes)) for x in rows]:raise ValueError('GNU/Capstone mismatch')
   owners.append({'mode':mode,'start':hex(start),'end':hex(end),'bytes':end-start,'instructions':len(rows),'visited':sum(x.address in seen for x in rows),'sha256':hashlib.sha256(raw).hexdigest(),'unwind':unwind,'scope':'whole guarded last-two addition' if mode==0 else 'whole carry-output leaf; identical body aliases covered together'})
   exports.extend(f'{x.address:x}\t{x.bytes.hex()}\t{x.mnemonic}\t{x.op_str}'.rstrip()+'\n' for x in rows);gnu.append(text)
  U=native.cpu.U64;left=(U,U,U,U);right=(1,0,0,0);specs=[]
  guard=next(i for i in instructions[0] if i.mnemonic=='cmp');short=next(i for i in instructions[0] if i.mnemonic=='mov' and i.op_str=='al, 0x2c')
  specs.extend([('guard-threshold',guard.address+guard.size-1,3,0,2,left,right),('short-status',short.address+short.size-1,45,0,1,left,right)])
  for mode,rows in enumerate(instructions):
   for ordinal,i in enumerate([i for i in rows if i.mnemonic=='adc']):
    opcode=1 if i.bytes[0]&0xf0==0x40 else 0
    if i.bytes[opcode]!=0x11:raise ValueError('unexpected ADC encoding')
    specs.append((f'carry-chain-{mode}-{ordinal}',i.address+opcode,1,mode,2,left,right))
   if mode:
    flag=next(i for i in rows if i.mnemonic=='setb');copy=next(i for i in rows if i.mnemonic=='movups' and i.op_str.startswith('xmmword ptr [rdi + 0x10]'))
    if flag.bytes[0]!=0x0f or flag.bytes[1]!=0x92 or copy.bytes[-1]!=0x10:raise ValueError('unexpected carry/copy encoding')
    specs.extend([(f'carry-flag-{mode}',flag.address+1,0x93,mode,2,left,right),(f'copy-offset-{mode}',copy.address+copy.size-1,0,mode,2,left,right)])
  controls=[]
  for name,address,byte,mode,count,a,b in specs:
   changed=native.Image();changed.data=mmap.mmap(changed.view.file.fileno(),0,access=mmap.ACCESS_COPY)
   try:
    changed.data[changed.view.offset(address)]=byte
    before=native.evaluate(im,mode,count,a,b)[0];after=native.evaluate(changed,mode,count,a,b)[0]
    if before==after:raise ValueError('ineffective native control '+name)
    controls.append({'name':name,'va':hex(address),'original_byte':im.view.read(address,1).hex(),'changed_byte':hex(byte),'input':[mode,count,*a,*b],'original':before,'changed':after})
   finally:changed.close()
  if hashlib.sha256(im.data).hexdigest()!=native.SHA:raise ValueError('capture changed')
  record={'target_sha256':native.SHA,'base':'05bc2de303c05525b71e7e257426e741bc66a390','rows':len(expected.splitlines()),'guarded_count_operand_cases':len(native.stimuli()),'unique_operand_pairs':len({(a,b) for _,a,b in native.stimuli()}),'input_sha256':hashlib.sha256(inputs).hexdigest(),'expected_sha256':hashlib.sha256(expected).hexdigest(),'owners':owners,'visited_addresses':sorted(seen),'new_rust_exists':False,'captured_process_executed':False,'normalization':'all424fixturebytes retained; raw RAX only on guarded leaf; undefined carry-leaf RAX, flags and register side-effects excluded; no ABI/type claim','gnu_version':subprocess.check_output([str(objdump),'--version'],text=True).splitlines()[0]}
  out.mkdir(parents=True);(out/'inputs.tsv').write_bytes(inputs);(out/'expected.tsv').write_bytes(expected)
  p=native.PACKET;(p/'FREEZE.json').write_text(json.dumps(record,indent=2)+'\n');(p/'native-controls.json').write_text(json.dumps(controls,indent=2)+'\n');(p/'owners.capstone.tsv').write_text(''.join(exports));(p/'owners.gnu.txt').write_text(''.join(gnu))
  pairs=list(zip(inputs.decode().splitlines(),expected.decode().splitlines()));sample=pairs[::max(1,len(pairs)//40)]+[('\t'.join(map(str,c['input'])),c['original']) for c in controls]
  (p/'target-smoke.tsv').write_text(''.join(a+'\t'+b+'\n' for a,b in sample));print('FREEZE PASS',record['rows'],'rows',record['guarded_count_operand_cases'],'guarded fixtures',record['unique_operand_pairs'],'operandpairs',len(seen),'visited',len(controls),'nativecontrols',len(sample),'smokes')
 finally:im.close()
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('--objdump',type=Path,required=True);a=p.parse_args();collect(a.output.resolve(),a.objdump.resolve())
