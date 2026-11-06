"""Bind the entire helper-free entry CFG and its exact first-call frontiers."""
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
  if hashlib.sha256(im.data).hexdigest()!=native.SHA:raise ValueError('wrong target')
  start,end=native.OWNER
  if im.view.fde(start)!=(start,end):raise ValueError('FDE mismatch')
  body=im.view.read(start,end-start);cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);seq=list(cs.disasm(body,start));by={i.address:i for i in seq}
  if sum(i.size for i in seq)!=len(body):raise ValueError('decode gap')
  text=subprocess.check_output([str(objdump),'-d','--wide','-M','intel',f'--start-address={start:#x}',f'--stop-address={end:#x}',str(native.TARGET)],text=True).replace(str(native.TARGET),'artifacts/node/115/hl-node');parsed=[]
  for line in text.splitlines():
   m=re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s)+)',line)
   if m:parsed.append((int(m[1],16),bytes.fromhex(m[2])))
  if parsed!=[(i.address,bytes(i.bytes)) for i in seq]:raise ValueError('GNU/Capstone mismatch')
  for i in seq:
   if im.fetch(i.address).size!=i.size:raise ValueError('machine instruction length')
   if i.mnemonic.startswith('j') and int(i.op_str,0) not in by:raise ValueError('owner branch escape')
  selected=set();boundaries=set();todo=[start]
  while todo:
   a=todo.pop()
   if a in selected or a in boundaries:continue
   i=by[a]
   if a in native.STOPS:
    if i.mnemonic!='call':raise ValueError('not firstCALL')
    boundaries.add(a);continue
   if i.mnemonic=='call':raise ValueError('unlisted call')
   selected.add(a)
   if i.mnemonic=='ret':continue
   if i.mnemonic=='jmp':todo.append(int(i.op_str,0))
   elif i.mnemonic.startswith('j'):todo.extend([int(i.op_str,0),a+i.size])
   else:todo.append(a+i.size)
  if boundaries!=set(native.STOPS):raise ValueError('firstcallset')
  inputs,expected,seen,kinds=native.corpus(im);print('CORPUS',len(expected.splitlines()),kinds,flush=True)
  if seen!=selected:raise ValueError('unvisited '+str(sorted(selected-seen)))
  _,off,n=im.view.sections['.rela.dyn'];bindings={}
  for q in range(off,off+n,24):
   slot,info,add=struct.unpack_from('<QQq',im.data,q)
   if slot in [0x6493610,0x64df830]:bindings[slot]=(info,add)
  if bindings.get(0x64df830)!=(8,0x1680c10):raise ValueError('diagnostic binding')
  info,pathptr=bindings[0x6493610]
  if info!=8:raise ValueError('Location relocation')
  length,line,col=struct.unpack('<QII',im.view.read(0x6493618,16));path=im.view.read(pathptr,length).decode()
  if (path,line,col)!=('l1/src/fees/compute.rs',45,42):raise ValueError('source context')
  calls=[]
  for a,kind in native.STOPS.items():
   i=by[a]
   if a+i.size+int.from_bytes(bytes(i.bytes)[2:],'little',signed=True)!=0x64df830:raise ValueError('callslot')
   lea=by[a-7];lb=bytes(lea.bytes)
   if lb[:3]!=bytes.fromhex('488d3d') or lea.address+lea.size+int.from_bytes(lb[3:],'little',signed=True)!=0x6493610:raise ValueError('Location LEA')
   calls.append(dict(site=hex(a),kind=kind,bytes=bytes(i.bytes).hex(),slot='0x64df830',target='0x1680c10',executed=False))
  changes=[];cases=native.control_inputs()
  anchors=[('scale-first',0x46a6872,101),('scale-second',0x46a6884,101),('scale-outer',0x46a68a8,101),('scale-inner',0x46a68d9,101),('scale-last',0x46a6911,101),('outer-equality',0x46a68a0,2),('outer-branch',0x46a68a1,0x74),('inner-sentinel-present',0x46a68d6,0x71),('inner-sentinel-absent',0x46a690e,0x70),('first-overflow',0x46a687b,0x81),('second-overflow',0x46a688d,0x81),('outer-overflow',0x46a68b0,0x81),('inner-overflow',0x46a68e4,0x81),('last-overflow',0x46a691b,0x71),('outer-tail',0x46a68be,0x0c),('inner-tail',0x46a68f2,0x0c)]
  for label,va,byte in anchors:
   changed=native.Image();changed.data=mmap.mmap(changed.view.file.fileno(),0,access=mmap.ACCESS_COPY)
   try:
    old=changed.data[changed.view.offset(va)];changed.data[changed.view.offset(va)]=byte
    for row in cases:
     original=native.evaluate(im,row)[0]
     try:actual=native.evaluate(changed,row)[0]
     except (ValueError,native.cpu.ToolError):continue
     if original!=actual:changes.append(dict(name=label,va=hex(va),old=hex(old),new=hex(byte),input=row,original=original,changed=actual));break
    else:raise ValueError('ineffective outputCOW '+label)
   finally:changed.close()
  negatives=[]
  for label,va,byte in [('output-origin',0x46a691f,0x4e),('outer-read-bound',0x46a68be,0x78),('inner-read-bound',0x46a68f2,0x78)]:
   changed=native.Image();changed.data=mmap.mmap(changed.view.file.fileno(),0,access=mmap.ACCESS_COPY)
   try:
    changed.data[changed.view.offset(va)]=byte
    for row in cases:
     try:native.evaluate(changed,row)
     except (ValueError,native.cpu.ToolError) as e:negatives.append(dict(name=label,va=hex(va),input=row,new=hex(byte),rejected=str(e)));break
    else:raise ValueError('ineffective rejection '+label)
   finally:changed.close()
  if hashlib.sha256(im.data).hexdigest()!=native.SHA:raise ValueError('capture mutated')
  record=dict(target_sha256=native.SHA,base='05bc2de303c05525b71e7e257426e741bc66a390',rows=len(expected.splitlines()),input_sha256=hashlib.sha256(inputs).hexdigest(),expected_sha256=hashlib.sha256(expected).hexdigest(),owner=dict(start=hex(start),end=hex(end),bytes=len(body),instructions=len(seq),sha256=hashlib.sha256(body).hexdigest(),unwind=frame(im.view,start)),selected_addresses=sorted(selected),visited_addresses=sorted(seen),selected_bytes=sum(by[a].size for a in selected),selected_instructions=len(selected),frontier_counts=kinds,unexecuted_first_calls=calls,qualified_callees=[],source_context=dict(location='0x6493610',path=path,line=line,column=col),captured_process_executed=False,normalization='Entire120B output except explicit inactive payload8..36 when outer!=1 and56..92 when inner==MIN. ?? is excluded, never zero-filled. All remaining known bytes/canary padding compared. Rawinputs and firstdiagnostic callsite distinct, no helperreturns composed.')
  p=native.PACKET;(p/'inputs.jsonl').write_bytes(inputs);(p/'expected.jsonl').write_bytes(expected);(p/'proof.json').write_text(json.dumps(record,indent=2)+'\n');(p/'native-controls.json').write_text(json.dumps(dict(output_changes=changes,rejections=negatives),indent=2)+'\n');(p/'46a6860.gnu.txt').write_text(text);print('FREEZE PASS',record['rows'],record['selected_bytes'],record['selected_instructions'],kinds,len(changes),'outputCOW',len(negatives),'negativeCOW',flush=True)
 finally:im.close()
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--objdump',type=Path,required=True);a=p.parse_args();generate(a.objdump.resolve())
