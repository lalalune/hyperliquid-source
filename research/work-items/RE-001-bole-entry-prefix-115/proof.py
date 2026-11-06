"""Freeze private selector expectations before Rust; no supplied helper results."""
from pathlib import Path
import argparse,capstone,hashlib,json,mmap,re,struct,subprocess
import native
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
  if hashlib.sha256(im.data).hexdigest()!=native.SHA:raise ValueError('wrong node115')
  inputs,expected,seen=native.corpus(im);print('CORPUS COMPLETE',len(expected.splitlines()),flush=True)
  start,end=native.OWNER
  if im.view.fde(start)!=(start,end):raise ValueError('actual FDE mismatch')
  body=im.view.read(start,end-start);cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);rows=list(cs.disasm(body,start))
  if sum(i.size for i in rows)!=len(body):raise ValueError('full decode gap')
  text=subprocess.check_output([str(objdump),'-d','--wide','-M','intel',f'--start-address={start:#x}',f'--stop-address={end:#x}',str(native.TARGET)],text=True).replace(str(native.TARGET),'artifacts/node/115/hl-node');parsed=[]
  for line in text.splitlines():
   m=re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s)+)',line)
   if m:parsed.append((int(m[1],16),bytes.fromhex(m[2])))
  if parsed!=[(i.address,bytes(i.bytes)) for i in rows]:raise ValueError('GNU Capstone mismatch')
  selected=[i for i in rows if any(lo<=i.address<hi for lo,hi in native.SPANS)]
  for i in selected:
   if im.fetch(i.address).size!=i.size:raise ValueError('evaluator length disagreement')
  if seen!={i.address for i in selected}:raise ValueError('selected visitation incomplete')
  relocs={};_,off,n=im.view.sections['.rela.dyn']
  for q in range(off,off+n,24):
   slot,kind,add=struct.unpack_from('<QQq',im.data,q)
   if slot in [0x64df830,0x64df620]:
    if kind!=8:raise ValueError('not RELATIVE')
    relocs[hex(slot)]=hex(add)
  if len(relocs)!=2:raise ValueError('missing diagnostic relocations')
  calls=[]
  for va in native.FRONTIERS:
   ins=next(i for i in rows if i.address==va)
   if va in [0x2c8074b,0x2c80780]:
    target=va+5+int.from_bytes(bytes(ins.bytes)[1:],'little',signed=True)
    if target!={0x2c8074b:0x35bf460,0x2c80780:0x4556410}[va]:raise ValueError('changed actual lookup')
    calls.append(dict(site=hex(va),target=hex(target),bytes=bytes(ins.bytes).hex(),evaluated=False))
   else:
    slot=va+6+int.from_bytes(bytes(ins.bytes)[2:],'little',signed=True)
    calls.append(dict(site=hex(va),slot=hex(slot),target=relocs[hex(slot)],bytes=bytes(ins.bytes).hex(),evaluated=False))
  witnesses=[[1,2,[0,1],[1,0],0,1,17,42],[1,2,[0,1],[1,0],1<<63,1,17,42],[1,2,[0],[0],0,0,17,42]]
  anchors=[('zero-index-gate',0x2c80688,0x85),('primary-guard',0x2c8069c,0x82),('secondary-guard',0x2c806f1,0x82),('skip-occupied',0x2c80707,0x74),('index-advance',0x2c80700,16),('free-word',0x2c80706,1),('representation-gate',0x2c80725,0x70),('selected-map-empty',0x2c80732,0x85),('aux-input-source',0x2c806a4,0)]
  controls=[]
  for name,va,byte in anchors:
   changed=native.Image();changed.data=mmap.mmap(changed.view.file.fileno(),0,access=mmap.ACCESS_COPY)
   try:
    old=changed.data[changed.view.offset(va)];changed.data[changed.view.offset(va)]=byte
    for row in witnesses:
     original=native.evaluate(im,row)[0]
     try:altered=native.evaluate(changed,row)[0]
     except (ValueError,native.cpu.ToolError):continue
     if original!=altered:
      controls.append(dict(name=name,va=hex(va),old=hex(old),new=hex(byte),input=row,original=original,changed=altered));break
    else:raise ValueError('ineffective COW '+name)
   finally:changed.close()
  negatives=[]
  for name,va,byte in [('float-bit-source',0x2c806a9,8),('key-frame-slot',0x2c80717,0x18),('raw-return-tag',0x2c809cd,3),('secondary-stride',0x2c806fc,4)]:
   changed=native.Image();changed.data=mmap.mmap(changed.view.file.fileno(),0,access=mmap.ACCESS_COPY)
   try:
    changed.data[changed.view.offset(va)]=byte
    probes=witnesses+[[0,0,[],[],0,0,17,0]]
    for row in probes:
     try:native.evaluate(changed,row)
     except (ValueError,native.cpu.ToolError) as e:
      negatives.append(dict(name=name,va=hex(va),new=hex(byte),input=row,rejected=str(e)));break
    else:raise ValueError('ineffective rejection '+name)
   finally:changed.close()
  if hashlib.sha256(im.data).hexdigest()!=native.SHA:raise ValueError('capture changed')
  record=dict(target_sha256=native.SHA,base='05bc2de303c05525b71e7e257426e741bc66a390',rows=len(expected.splitlines()),input_sha256=hashlib.sha256(inputs).hexdigest(),expected_sha256=hashlib.sha256(expected).hexdigest(),owner=dict(start=hex(start),end=hex(end),bytes=len(body),instructions=len(rows),sha256=hashlib.sha256(body).hexdigest(),unwind=frame(im.view,start)),spans=[list(map(hex,s)) for s in native.SPANS],selected_bytes=sum(i.size for i in selected),selected_instructions=len(selected),visited_addresses=sorted(seen),actual_calls=calls,captured_process_executed=False,normalization='only returned raw2 is a native return; A/B are exact pre-lookup live selected/key/aux/float-bit frontiers; P/S are pre-diagnostic guards; incoming objects unchanged, no counter/numeric/helper result or composed trace; map header words are raw premises, no original validity/reachability claim')
  p=native.PACKET;(p/'inputs.jsonl').write_bytes(inputs);(p/'expected.jsonl').write_bytes(expected);(p/'proof.json').write_text(json.dumps(record,indent=2)+'\n');(p/'native-controls.json').write_text(json.dumps(dict(output_changes=controls,rejections=negatives),indent=2)+'\n');(p/'2c80670.gnu.txt').write_text(text)
  print('FREEZE PASS',record['rows'],record['selected_bytes'],record['selected_instructions'],len(controls),'outputCOW',len(negatives),'negativeCOW',flush=True)
 finally:im.close()
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--objdump',type=Path,required=True);a=p.parse_args();generate(a.objdump.resolve())
