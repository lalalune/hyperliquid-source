"""Regenerate corrected width evidence and actual private byte controls."""
import argparse,hashlib,json,mmap,re,struct,subprocess
from pathlib import Path
import native,capstone
def frame(view,start):
 addr,off,n=view.sections['.eh_frame_hdr'];count=struct.unpack_from('<I',view.b,off+8)[0];lo=0;hi=count
 while lo<hi:
  mid=(lo+hi)//2;value=addr+struct.unpack_from('<i',view.b,off+12+mid*8)[0]
  if value<=start:lo=mid+1
  else:hi=mid
 entry,relative=struct.unpack_from('<ii',view.b,off+12+(lo-1)*8)
 if addr+entry!=start:raise ValueError('not exact FDE start')
 fde=addr+relative;cie=fde+4-int.from_bytes(view.read(fde+4,4),'little');out={}
 for name,a in [('fde',fde),('cie',cie)]:
  size=4+int.from_bytes(view.read(a,4),'little')
  if not 4<size<4096:raise ValueError('unsupported frame record')
  out[name]={'va':hex(a),'raw_hex':view.read(a,size).hex()}
 return out
def generate(objdump):
 im=native.Image()
 try:
  if hashlib.sha256(im.data).hexdigest()!=native.SHA:raise ValueError('wrong115target')
  inputs,expected,seen=native.corpus(im);cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
  owners=[];selected=[];exports=[]
  for s in native.SPECS:
   start,end=im.view.fde(s['owner']);body=im.view.read(start,end-start);rows=list(cs.disasm(body,start))
   if start!=s['owner'] or sum(i.size for i in rows)!=end-start:raise ValueError('owner decode mismatch')
   text=subprocess.check_output([str(objdump),'-d','--wide','-M','intel',f'--start-address={start:#x}',f'--stop-address={end:#x}',str(native.TARGET)],text=True).replace(str(native.TARGET),'artifacts/node/115/hl-node')
   parsed=[]
   for line in text.splitlines():
    m=re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s)+)',line)
    if m:parsed.append((int(m[1],16),bytes.fromhex(m[2])))
   if parsed!=[(i.address,bytes(i.bytes)) for i in rows]:raise ValueError('GNU/Capstone mismatch')
   chosen=[i for i in rows if s['start']<=i.address<s['end']]
   for i in chosen:
    if im.fetch(i.address).size!=i.size:raise ValueError('evaluator decode mismatch')
   selected+=chosen;exports.append((f'{start:x}.gnu.txt',text))
   owners.append(dict(start=hex(start),end=hex(end),bytes=end-start,instructions=len(rows),sha256=hashlib.sha256(body).hexdigest(),unwind=frame(im.view,start)))
  if {i.address for i in selected}!=seen:raise ValueError('selected visitation incomplete')
  controls=[]
  anchors=[('tag2-width',0x2b6a7d9,0x40),('tag1-immediate',0x2b6a7e7,3),('tag1-value',0x2b6a7e1,0x11),('tag2-value',0x2b6a830,0x79),('borrow-gate',0x2b6a7f8,0x73),('scale',0x2b6a809,0x81),('cap-condition',0x2b6a824,0x42),('product-overflow-clamp',0x2b6a82a,0x44)]
  for alias,s in enumerate(native.SPECS):
   delta=s['start']-native.SPECS[0]['start']+(3 if alias else 0)
   for name,va,byte in anchors:
    a=va+delta;changed=native.Image();changed.data=mmap.mmap(changed.view.file.fileno(),0,access=mmap.ACCESS_COPY)
    try:
     changed.data[changed.view.offset(a)]=byte
     for row in native.stimuli():
      if row[0]!=alias:continue
      original=native.evaluate(im,row)[0]
      try:altered=native.evaluate(changed,row)[0]
      except (ValueError,native.cpu.ToolError):continue
      if original!=altered:
       controls.append(dict(name=name,alias=alias,va=hex(a),original_byte=im.view.read(a,1).hex(),changed_byte=hex(byte),input=row,original=original,changed=altered));break
     else:raise ValueError('ineffective control '+name)
    finally:changed.close()
  if hashlib.sha256(im.data).hexdigest()!=native.SHA:raise ValueError('capture changed')
  report=json.loads((native.ROOT/'research/work-items/RE-005-node115-limit-writers/records.json').read_text())
  observed=native.check_declared_source(report)
  for row,line in zip(native.stimuli(),expected.decode().splitlines()):
   if native.declared_prediction(report,*row)!=int(line):raise ValueError('corrected declaration/corpus mismatch')
  record=dict(target_sha256=native.SHA,base='05bc2de303c05525b71e7e257426e741bc66a390',rows=len(expected.splitlines()),input_sha256=hashlib.sha256(inputs).hexdigest(),expected_sha256=hashlib.sha256(expected).hexdigest(),owners=owners,spans=[[hex(s['start']),hex(s['end'])] for s in native.SPECS],selected_bytes=sum(s['end']-s['start'] for s in native.SPECS),selected_instructions=len(selected),visited_addresses=sorted(seen),observations=observed,captured_process_executed=False,normalization='two independently fresh readonly compute points; raw u64 tag/start/end, budget register at following continuation. No original enum/live-validity, whole-dispatcher, actual RET or later constructor/flag trace claimed; corpus collected after metadata correction, no pre-Rust seal or Rust claim')
  p=native.PACKET;(p/'proof.json').write_text(json.dumps(record,indent=2)+'\n');(p/'native-controls.json').write_text(json.dumps(controls,indent=2)+'\n')
  for name,text in exports:(p/name).write_text(text)
  print('PROOF PASS',record['rows'],'inputs',record['selected_bytes'],'bytes',record['selected_instructions'],'starts',len(controls),'actualCOWcontrols; corrected metadata matches all rows')
 finally:im.close()
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--objdump',type=Path,required=True);a=p.parse_args();generate(a.objdump.resolve())
