"""Freeze original quantity-change points results BEFORE any new Rust authorship."""
import argparse,hashlib,json,mmap,re,subprocess
from collections import Counter
from pathlib import Path
import native,capstone
from fde_extents import eh_frame_records
def freeze(out,objdump):
 if (native.ROOT/'src/node115-quantity-change/lib.rs').exists():raise ValueError('new Rust already exists')
 if out.exists():raise ValueError('new output required')
 im=native.Image()
 try:
  if hashlib.sha256(im.data).hexdigest()!=native.SHA:raise ValueError('wrong115target')
  inputs,expected,seen=native.corpus(im)
  start,end=0x4206f70,0x4207104;raw=im.view.read(start,end-start)
  _,fdes=eh_frame_records(im.data);fs=[f for f in fdes if (f['start'],f['end'])==(start,end)]
  cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);rows=list(cs.disasm(raw,start))
  if len(fs)!=1 or sum(i.size for i in rows)!=end-start:raise ValueError('FDE/decode mismatch')
  unwind={}
  for name,a in [('fde',fs[0]['fde']),('cie',fs[0]['cie'])]:
   length=4+int.from_bytes(im.view.read(a,4),'little');unwind[name]={'va':hex(a),'raw_hex':im.view.read(a,length).hex()}
  text=subprocess.check_output([str(objdump),'-d','--wide','-M','intel',f'--start-address={start:#x}',f'--stop-address={end:#x}',str(native.TARGET)],text=True).replace(str(native.TARGET),'artifacts/node/115/hl-node')
  parsed=[]
  for line in text.splitlines():
   m=re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s)+)',line)
   if m:parsed.append((int(m[1],16),bytes.fromhex(m[2])))
  if parsed!=[(x.address,bytes(x.bytes)) for x in rows]:raise ValueError('GNU/Capstone mismatch')
  selected=[i for i in rows if any(a<=i.address<b for a,b in native.RANGES)]
  for ins in selected:
   actual=im.fetch(ins.address)
   if actual.size!=ins.size:raise ValueError('evaluator decode mismatch')
  if not seen<={i.address for i in selected}:raise ValueError('visitation outside selected code')
  specs=[('counter-zero-gate',0x4206f98,0x74),('decrement-guard',0x4206fb7,0x75),('decrement',0x4206fbb,0xc0),('increment-saturation',0x4206fcd,0x44),('optional-total',0x4206fd5,0x75),('notification-change',0x420703f,0x94),('notification-gate',0x4207043,0x75),('notification-copy',0x4207048,0x11),('old-absolute-diag',0x4207000,0x89),('subtract',0x420700c,0x01),('subtract-overflow',0x420700e,0x71),('subtract-store',0x4207012,0x20),('new-absolute',0x420701b,0x49),('add',0x420702a,0x29),('add-overflow',0x420702c,0x71),('add-store',0x4207030,0x18)]

  controls=[];fixtures=native.stimuli()
  for name,a,b in specs:
   changed=native.Image();changed.data=mmap.mmap(changed.view.file.fileno(),0,access=mmap.ACCESS_COPY)
   try:
    changed.data[changed.view.offset(a)]=b
    for raw_input in fixtures:
     before=native.evaluate(im,raw_input)[0]
     try:after=native.evaluate(changed,raw_input)[0]
     except (ValueError,native.cpu.ToolError):continue
     if before!=after:
      controls.append(dict(name=name,va=hex(a),original_byte=im.view.read(a,1).hex(),changed_byte=hex(b),input_tsv='\t'.join(map(str,raw_input)),original=before,changed=after));break
    else:raise ValueError('ineffective control '+name)
   finally:changed.close()
  if hashlib.sha256(im.data).hexdigest()!=native.SHA:raise ValueError('capture changed')
  record=dict(target_sha256=native.SHA,base='05bc2de303c05525b71e7e257426e741bc66a390',rows=len(expected.splitlines()),outcomes=dict(Counter(s.split(b':')[3].decode() for s in expected.splitlines())),input_sha256=hashlib.sha256(inputs).hexdigest(),expected_sha256=hashlib.sha256(expected).hexdigest(),owner=dict(start=hex(start),end=hex(end),bytes=end-start,instructions=len(rows),sha256=hashlib.sha256(raw).hexdigest(),unwind=unwind),selected_bytes=sum(b-a for a,b in native.RANGES),selected_instructions=len(selected),spans=[[hex(a),hex(b)] for a,b in native.RANGES],visited_addresses=sorted(seen),unvisited_addresses=sorted({i.address for i in selected}-seen),new_rust_exists=False,captured_process_executed=False,normalization='two entry modes and independent fresh postlookup point; ordered actual counter/total stores and memory snapshot; actual RET/RSP or BEFORE lookup/notification/diagnostic call. No returned lookup/logger/callback result or composed trace; original numeric return type unknown and excluded',gnu_version=subprocess.check_output([str(objdump),'--version'],text=True).splitlines()[0])
  out.mkdir(parents=True);(out/'inputs.tsv').write_bytes(inputs);(out/'expected.tsv').write_bytes(expected)
  p=native.PACKET
  (p/'FREEZE.json').write_text(json.dumps(record,indent=2)+'\n');(p/'native-controls.json').write_text(json.dumps(controls,indent=2)+'\n');(p/'change-hook.gnu.txt').write_text(text)
  (p/'owner.capstone.tsv').write_text(''.join(f'{i.address:x}\t{i.bytes.hex()}\t{i.mnemonic}\t{i.op_str}'.rstrip()+'\n' for i in rows))
  pairs=list(zip(inputs.decode().splitlines(),expected.decode().splitlines()));lookup=dict(pairs);chosen=dict(pairs[::max(1,len(pairs)//45)])
  for c in controls:chosen[c['input_tsv']]=lookup[c['input_tsv']]
  for row in [(0,0,1,0,0,90),(0,0,1,native.cpu.U64,1,90),(1,1,0,0,0,90),(2,1,1,1<<63,0,90),(2,0,1,(1<<63)-1,0,90),(2,1,1<<63,0,0,90),(2,1<<63,0,0,0,90)]:
   key='\t'.join(map(str,row));chosen[key]=lookup[key]
  (p/'target-smoke.tsv').write_text(''.join(a+'\t'+b+'\n' for a,b in chosen.items()))
  print('FREEZE PASS',record['rows'],record['outcomes'],'selected',record['selected_bytes'],record['selected_instructions'],'visited',len(seen),'controls',len(controls),'smokes',len(chosen))
 finally:im.close()
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('--objdump',type=Path,required=True);a=p.parse_args();freeze(a.output.resolve(),a.objdump.resolve())
