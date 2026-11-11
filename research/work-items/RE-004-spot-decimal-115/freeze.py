"""Seal actual original observations before writing new Rust."""
import argparse,hashlib,json,mmap,re,subprocess
from collections import Counter
from pathlib import Path
import native,capstone
from fde_extents import eh_frame_records
def freeze(out,objdump):
 if (native.ROOT/'src/node115-spot-decimal/lib.rs').exists():raise ValueError('freeze refuses existing new Rust')
 if out.exists():raise ValueError('new output required')
 im=native.Image()
 try:
  if hashlib.sha256(im.data).hexdigest()!=native.SHA:raise ValueError('wrong115target')
  inputs,expected,seen=native.corpus(im);start,end=0x29aea00,0x29aeaf2
  _,fdes=eh_frame_records(im.data);fs=[f for f in fdes if (f['start'],f['end'])==(start,end)]
  cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);raw=im.view.read(start,end-start);rows=list(cs.disasm(raw,start))
  if len(fs)!=1 or sum(i.size for i in rows)!=end-start:raise ValueError('FDE/decode mismatch')
  unwind={}
  for name,address in [('fde',fs[0]['fde']),('cie',fs[0]['cie'])]:
   length=4+int.from_bytes(im.view.read(address,4),'little');unwind[name]={'va':hex(address),'raw_hex':im.view.read(address,length).hex()}
  text=subprocess.check_output([str(objdump),'-d','--wide','-M','intel',f'--start-address={start:#x}',f'--stop-address={end:#x}',str(native.TARGET)],text=True).replace(str(native.TARGET),'artifacts/node/115/hl-node')
  parsed=[]
  for line in text.splitlines():
   m=re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s)+)',line)
   if m:parsed.append((int(m[1],16),bytes.fromhex(m[2])))
  if parsed!=[(x.address,bytes(x.bytes)) for x in rows]:raise ValueError('GNU/Capstone mismatch')
  selected=[i for i in rows if any(a<=i.address<b for a,b in native.RANGES)]
  if {i.address for i in selected}!=seen:raise ValueError('selected visitation incomplete')
  specs=[('first-bound',0x29aea09,0x82),('second-bound',0x29aea1f,0x82),('decimal-gate',0x29aea3d,0x76),('power-ten',0x29aea70,0x0b),('power-hundred',0x29aea80,0x65),('power-ten-thousand',0x29aeab7,0x11),('power-hundred-million',0x29aeac6,0x01),('wide-remainder',0x29aea5e,0x75),('narrow-remainder',0x29aeaa2,0x74),('accept-tag',0x29aeaaa,0xa3),('reject-tag',0x29aea38,0x6b),('quotient-offset',0x29aeaa7,0x00),('first-stride',0x29aea15,0x04),('second-stride',0x29aea2b,0x50),('decimal-offset',0x29aea33,0x49)]
  controls=[];fixtures=native.stimuli()
  for name,address,byte in specs:
   changed=native.Image();changed.data=mmap.mmap(changed.view.file.fileno(),0,access=mmap.ACCESS_COPY)
   try:
    changed.data[changed.view.offset(address)]=byte
    for row in fixtures:
     before=native.evaluate(im,row)[0]
     try:after=native.evaluate(changed,row)[0]
     except (ValueError,native.cpu.ToolError):continue
     if before!=after:
      controls.append(dict(name=name,va=hex(address),original_byte=im.view.read(address,1).hex(),changed_byte=hex(byte),input=row,original=before,changed=after));break
    else:raise ValueError('ineffective native control '+name)
   finally:changed.close()
  if hashlib.sha256(im.data).hexdigest()!=native.SHA:raise ValueError('capture changed')
  record=dict(target_sha256=native.SHA,base='05bc2de303c05525b71e7e257426e741bc66a390',rows=len(expected.splitlines()),outcomes=dict(Counter(s.split(b':')[0].decode() for s in expected.splitlines())),input_sha256=hashlib.sha256(inputs).hexdigest(),expected_sha256=hashlib.sha256(expected).hexdigest(),owner=dict(start=hex(start),end=hex(end),bytes=end-start,instructions=len(rows),sha256=hashlib.sha256(raw).hexdigest(),unwind=unwind,scope='complete owner; all ordinary instructions interpreted; diagnostics stop before opaque dispatch'),selected_bytes=sum(b-a for a,b in native.RANGES),selected_instructions=len(selected),spans=[[hex(a),hex(b)] for a,b in native.RANGES],visited_addresses=sorted(seen),new_rust_exists=False,captured_process_executed=False,normalization='actual RET requires output pointer/RSP restoration; observe all16 output bytes including inactive/canary bytes; input bytes unchanged; A/B before diagnostic entries; synthetic disjoint descriptors with actual32/344strides, no recovered original public ABI',gnu_version=subprocess.check_output([str(objdump),'--version'],text=True).splitlines()[0])
  out.mkdir(parents=True);(out/'inputs.tsv').write_bytes(inputs);(out/'expected.tsv').write_bytes(expected);p=native.PACKET
  (p/'FREEZE.json').write_text(json.dumps(record,indent=2)+'\n');(p/'native-controls.json').write_text(json.dumps(controls,indent=2)+'\n');(p/'owner.gnu.txt').write_text(text);(p/'owner.capstone.tsv').write_text(''.join(f'{i.address:x}\t{i.bytes.hex()}\t{i.mnemonic}\t{i.op_str}'.rstrip()+'\n' for i in rows))
  pairs=list(zip(inputs.decode().splitlines(),expected.decode().splitlines()));lookup=dict(pairs);chosen=dict(pairs[::max(1,len(pairs)//24)])
  for c in controls:
   key=native.encode(c['input']);chosen[key]=lookup[key]
  for d in range(9):
   divisor=10**(8-d)
   for amount in [0,divisor-1,divisor,divisor+1]:
    key=native.encode((amount,0,[0],[d],165));chosen[key]=lookup[key]
  for seed in [0,255]:
   for amount in [0,100000001]:
    key=native.encode((amount,0,[0],[0],seed));chosen[key]=lookup[key]
  (p/'target-smoke.tsv').write_text(''.join(a+'\t'+b+'\n' for a,b in chosen.items()));print('FREEZE PASS',record['rows'],record['outcomes'],'selected',record['selected_bytes'],record['selected_instructions'],'controls',len(controls),'smokes',len(chosen))

 finally:im.close()
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('--objdump',type=Path,required=True);a=p.parse_args();freeze(a.output.resolve(),a.objdump.resolve())
