"""Seal original selected-row margin points before independently authored Rust."""
import argparse,hashlib,json,mmap,re,subprocess
from collections import Counter
from pathlib import Path
import native,capstone
from fde_extents import eh_frame_records
def freeze(out,objdump):
 if (native.ROOT/'src/node115-margin-row/lib.rs').exists():raise ValueError('freeze refuses existing new Rust')
 if out.exists():raise ValueError('new output required')
 im=native.Image()
 try:
  if hashlib.sha256(im.data).hexdigest()!=native.SHA:raise ValueError('wrong115target')
  inputs,expected,seen=native.corpus(im)
  _,fdes=eh_frame_records(im.data);cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
  owners=[];all_rows=[];exports=[]
  for start,end in [(0x38b54b0,0x38b55f3),(0x38b5300,0x38b54a9)]:
   fs=[f for f in fdes if (f['start'],f['end'])==(start,end)];raw=im.view.read(start,end-start);rows=list(cs.disasm(raw,start))
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
   owners.append(dict(start=hex(start),end=hex(end),bytes=end-start,instructions=len(rows),sha256=hashlib.sha256(raw).hexdigest(),unwind=unwind,scope='static full containing body, three qualified arithmetic points only'))
   all_rows+=rows;exports.append((f'{start:x}.gnu.txt',text))
  selected=[i for i in all_rows if any(a<=i.address<b for a,b in native.RANGES)]
  if {i.address for i in selected}!=seen:raise ValueError('selected visitation incomplete')
  specs=[('first-row-byte',0x38b5595,0xf9),('first-wide-divisor',0x38b55a8,0xf3),('first-narrow-divisor',0x38b55cb,0xf3),('first-subtraction',0x38b55aa,0x03),('first-borrow',0x38b55ad,0x72),('doubling-guard',0x38b53e6,0x79),('doubling-operation',0x38b53e9,0x29),('four-b-scale',0x38b53f2,0x4d),('product-row-offset',0x38b53fa,0xf1),('product-overflow',0x38b53fc,0x81),('second-subtraction',0x38b5402,0x01),('six-b-scale',0x38b5421,0x89),('post-doubling-saturation',0x38b5478,0xfe),('product-saturation',0x38b5495,0xfe),('second-narrow-divisor',0x38b5440,0xf3)]
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
  record=dict(target_sha256=native.SHA,base='05bc2de303c05525b71e7e257426e741bc66a390',rows=len(expected.splitlines()),outcomes=dict(Counter(s.split(b':')[0].decode() for s in expected.splitlines())),point_counts=dict(Counter(s.split(b'\t')[0].decode() for s in inputs.splitlines())),input_sha256=hashlib.sha256(inputs).hexdigest(),expected_sha256=hashlib.sha256(expected).hexdigest(),owners=owners,selected_bytes=sum(b-a for a,b in native.RANGES),selected_instructions=len(selected),spans=[[hex(a),hex(b)] for a,b in native.RANGES],visited_addresses=sorted(seen),new_rust_exists=False,captured_process_executed=False,normalization='two fresh post-lookup entries plus independent fresh post-doubling-diagnostic point; nonzero b premise; actual RET RAX and RSP, unchanged input bytes; B/H before opaque diagnostic entry, not native errors or composed handler trace',gnu_version=subprocess.check_output([str(objdump),'--version'],text=True).splitlines()[0])
  out.mkdir(parents=True);(out/'inputs.tsv').write_bytes(inputs);(out/'expected.tsv').write_bytes(expected);p=native.PACKET
  (p/'FREEZE.json').write_text(json.dumps(record,indent=2)+'\n');(p/'native-controls.json').write_text(json.dumps(controls,indent=2)+'\n')
  for name,text in exports:(p/name).write_text(text)
  (p/'owners.capstone.tsv').write_text(''.join(f'{i.address:x}\t{i.bytes.hex()}\t{i.mnemonic}\t{i.op_str}'.rstrip()+'\n' for i in sorted(all_rows,key=lambda x:x.address)))
  pairs=list(zip(inputs.decode().splitlines(),expected.decode().splitlines()));lookup=dict(pairs);chosen=dict(pairs[::max(1,len(pairs)//36)])
  for c in controls:
   key='\t'.join(map(str,c['input']));chosen[key]=lookup[key]
  for row in [(0,0,1,0),(0,5,1,2),(0,5,1,3),(1,6,1,1),(1,5,1,1),(1,0,1,1),(1,(1<<63)-1,1,native.cpu.U64),(1,1<<63,1,0),(2,0,1,0),(2,0,1,native.cpu.U64)]:
   key='\t'.join(map(str,row));chosen[key]=lookup[key]
  (p/'target-smoke.tsv').write_text(''.join(a+'\t'+b+'\n' for a,b in chosen.items()));print('FREEZE PASS',record['rows'],record['outcomes'],record['point_counts'],'selected',record['selected_bytes'],record['selected_instructions'],'controls',len(controls),'smokes',len(chosen))
 finally:im.close()
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('--objdump',type=Path,required=True);a=p.parse_args();freeze(a.output.resolve(),a.objdump.resolve())
