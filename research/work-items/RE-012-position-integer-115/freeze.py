"""Seal actual original observations before writing new Rust."""
import argparse,hashlib,json,mmap,re,subprocess
from collections import Counter
from pathlib import Path
import native,capstone
from fde_extents import eh_frame_records
def freeze(out,objdump):
 if (native.ROOT/'src/node115-position-integer/lib.rs').exists():raise ValueError('freeze refuses existing new Rust')
 if out.exists():raise ValueError('new output required')
 im=native.Image()
 try:
  if hashlib.sha256(im.data).hexdigest()!=native.SHA:raise ValueError('wrong115target')
  inputs,expected,seen=native.corpus(im);start,end=0x2c7fd80,0x2c80666
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
  specs=[('mark-sign',0x2c7ff12,0x89),('product-overflow',0x2c7ff21,0x81),('entry-zero',0x2c7ff3b,0x75),('entry-sign',0x2c7ff3e,0x89),('size-sign',0x2c7ff51,0x4e),('pnl-subtract',0x2c7ff57,0x01),('size-magnitude',0x2c7ff71,0x49),('magnitude-predecessor',0x2c7ff76,0xfe),('price-presence',0x2c7ff85,0x75),('wide-division',0x2c7ffc3,0xf7),('narrow-division',0x2c8007d,0xf7)]
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
  record=dict(target_sha256=native.SHA,base='05bc2de303c05525b71e7e257426e741bc66a390',rows=len(expected.splitlines()),outcomes=dict(Counter(s.split(b':')[0].decode() for s in expected.splitlines())),normal_routes=dict(Counter(s.split(b':')[3].decode() for s in expected.splitlines() if s.startswith(b'V:'))),input_sha256=hashlib.sha256(inputs).hexdigest(),expected_sha256=hashlib.sha256(expected).hexdigest(),owner=dict(start=hex(start),end=hex(end),bytes=end-start,instructions=len(rows),sha256=hashlib.sha256(raw).hexdigest(),unwind=unwind,scope='static containing context; selected integer prefix only'),selected_bytes=sum(b-a for a,b in native.RANGES),selected_instructions=len(selected),spans=[[hex(a),hex(b)] for a,b in native.RANGES],visited_addresses=sorted(seen),new_rust_exists=False,captured_process_executed=False,normalization='post-lookup nonzero-size raw word inputs; V product/pnl and absent or raw quotient/remainder with observed32/64route; M/E/S before opaque diagnostics; no ABI/full response/float conversion or composed helper claim',gnu_version=subprocess.check_output([str(objdump),'--version'],text=True).splitlines()[0])
  out.mkdir(parents=True);(out/'inputs.tsv').write_bytes(inputs);(out/'expected.tsv').write_bytes(expected);p=native.PACKET
  (p/'FREEZE.json').write_text(json.dumps(record,indent=2)+'\n');(p/'native-controls.json').write_text(json.dumps(controls,indent=2)+'\n');(p/'owner.gnu.txt').write_text(text);(p/'owner.capstone.tsv').write_text(''.join(f'{i.address:x}\t{i.bytes.hex()}\t{i.mnemonic}\t{i.op_str}'.rstrip()+'\n' for i in rows))
  pairs=list(zip(inputs.decode().splitlines(),expected.decode().splitlines()));sample=pairs[::max(1,len(pairs)//48)]+[('\t'.join(map(str,c['input'])),c['original']) for c in controls];(p/'target-smoke.tsv').write_text(''.join(a+'\t'+b+'\n' for a,b in sample));print('FREEZE PASS',record['rows'],record['outcomes'],record['normal_routes'],'selected',record['selected_bytes'],record['selected_instructions'],'controls',len(controls),'smokes',len(sample))
 finally:im.close()
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('--objdump',type=Path,required=True);a=p.parse_args();freeze(a.output.resolve(),a.objdump.resolve())
