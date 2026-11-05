"""Freeze real private selector + split-ring CALL/RET before Rust."""
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
  inputs,expected,seen,edges,call_rows=native.corpus(im);print('CORPUS COMPLETE',len(expected.splitlines()),'real-helper rows',call_rows,flush=True)
  if edges!={(0x3c4322c,0x4556c50)} or call_rows==0:raise ValueError('missing genuine call graph')
  cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);allrows=[];owners=[]
  for start,end in [native.OWNER,native.HELPER]:
   if im.view.fde(start)!=(start,end):raise ValueError('FDE mismatch')
   body=im.view.read(start,end-start);rows=list(cs.disasm(body,start));allrows.extend(rows)
   if sum(i.size for i in rows)!=len(body):raise ValueError('decode gap')
   text=subprocess.check_output([str(objdump),'-d','--wide','-M','intel',f'--start-address={start:#x}',f'--stop-address={end:#x}',str(native.TARGET)],text=True).replace(str(native.TARGET),'artifacts/node/115/hl-node');parsed=[]
   for line in text.splitlines():
    m=re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s)+)',line)
    if m:parsed.append((int(m[1],16),bytes.fromhex(m[2])))
   if parsed!=[(i.address,bytes(i.bytes)) for i in rows]:raise ValueError('GNU Capstone disagreement')
   if start==native.HELPER[0]:
    if any(i.mnemonic.startswith('call') for i in rows):raise ValueError('helper has additional calls')
    for i in rows:
     if i.mnemonic.startswith('j') and not start<=int(i.op_str,0)<end:raise ValueError('helper leaves body')
   (native.PACKET/f'{start:x}.gnu.txt').write_text(text)
   owners.append(dict(start=hex(start),end=hex(end),bytes=len(body),instructions=len(rows),sha256=hashlib.sha256(body).hexdigest(),unwind=frame(im.view,start)))
  selected=[i for i in allrows if any(lo<=i.address<hi for lo,hi in native.SPANS)]
  for i in selected:
   if im.fetch(i.address).size!=i.size:raise ValueError('evaluator length disagreement')
  if {i.address for i in selected}!=seen:raise ValueError('selected starts unvisited '+str(sorted({i.address for i in selected}-seen)))
  relocs={};_,off,n=im.view.sections['.rela.dyn']
  for q in range(off,off+n,24):
   slot,kind,add=struct.unpack_from('<QQq',im.data,q)
   if slot in [0x64df9f0,0x64df830,0x64768c0]:
    if kind!=8:raise ValueError('not RELATIVE')
    relocs[slot]=add
  if len(relocs)!=3:raise ValueError('missing actual bindings')
  calls=[]
  for va in [0x3c4322c,*native.FRONTIERS]:
   ins=next(i for i in allrows if i.address==va);raw=bytes(ins.bytes)
   if va==0x3c4322c:
    target=va+5+int.from_bytes(raw[1:],'little',signed=True)
    if target!=0x4556c50:raise ValueError('lookup target changed')
    calls.append(dict(site=hex(va),target=hex(target),bytes=raw.hex(),evaluated=True,actual_call_rows=call_rows))
   else:
    slot=va+6+int.from_bytes(raw[2:],'little',signed=True);target=relocs[slot]
    calls.append(dict(site=hex(va),slot=hex(slot),target=hex(target),bytes=raw.hex(),evaluated=False,target_fde=list(map(hex,im.view.fde(target)))))
  length,line,col=struct.unpack('<QII',im.view.read(0x64768c8,16));location=dict(va='0x64768c0',path_va=hex(relocs[0x64768c0]),path=im.view.read(relocs[0x64768c0],length).decode(),line=line,column=col)
  witnesses=[[49,0,0,17,-1,0,[],native.ring_storage(0,0,[],0)],[49,0,1,17,-1,0,[],native.ring_storage(0,0,[],0)],[50,1<<63,0,17,0,0,native.leaf([50,60],0),None],[60,1<<63,0,17,0,0,native.leaf([50,60],0),None],[1<<31,1<<63,0,17,0,0,native.leaf([(1<<31)-1,1<<31],0),None]]
  tree=native.balanced(1,0);witnesses.append([tree[1][0][0],1<<63,0,17,0,1,tree,None])
  for key in [50,60,70,80,51]:witnesses.append([key,4,0,17,-1,0,[],native.ring_storage(4,3,[50,60,70,80],0)])
  for head,key in [(0,50),(3,1<<31)]:witnesses.append([key,4,0,17,-1,0,[],native.ring_storage(4,head,[50,(1<<31)-1,1<<31,(1<<32)-1],0)])
  witnesses.append([60,5,0,17,-1,0,[],native.ring_storage(5,4,[1,50,60,1<<31,(1<<32)-1],0)])
  anchors=[('threshold',0x3c4315f,49),('global-guard',0x3c43172,0x84),('retained-source',0x3c43165,0x30),('global-stride',0x3c4317a,4),('global-first-word',0x3c43186,2),('global-zero-word',0x3c4318a,0xff),('descriptor-gate',0x3c4319b,0x70),('unsigned-tree-key',0x3c431e1,0x9f),('tree-loop-gate',0x3c431f2,0x75),('tree-match-gate',0x3c431fb,0x75),('tree-height-guard',0x3c43208,0x83),('tree-row-step',0x3c43271,0x80),('row-pointer',0x3c43275,0x20),('word0-source',0x3c4327d,0x10),('word1-source',0x3c43281,0x38),('word3-source',0x3c43279,8),('ring-split-unsigned',0x4556c88,0x9f),('ring-second-span-unsigned',0x4556cc6,0x4f),('ring-first-span-unsigned',0x4556d36,0x4f),('ring-second-found-tag',0x4556ce8,0x94),('ring-first-found-tag',0x4556d4a,0x09),('ring-logical-index',0x4556cec,0xc2),('caller-head-source',0x3c4324c,0x48),('caller-index-guard',0x3c43241,0x82)]
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
  for name,va,byte in [('guard-address',0x3c4316b,0x80),('child-pointer-source',0x3c43211,0xf0),('node-count-source',0x3c431b2,0xf4),('output-pointer-slot',0x3c4328c,0x18),('diagnostic-location',0x3c432ea,0xd1),('caller-wrap-condition',0x3c43254,0x42)]:
   changed=native.Image();changed.data=mmap.mmap(changed.view.file.fileno(),0,access=mmap.ACCESS_COPY)
   try:
    changed.data[changed.view.offset(va)]=byte
    for row in witnesses+[[50,1<<63,0,17,-1,0,[],None]]:
     try:native.evaluate(changed,row)
     except (ValueError,native.cpu.ToolError) as e:
      negatives.append(dict(name=name,va=hex(va),new=hex(byte),input=row,rejected=str(e)));break
    else:raise ValueError('ineffective rejection '+name)
   finally:changed.close()
  if hashlib.sha256(im.data).hexdigest()!=native.SHA:raise ValueError('capture changed')
  record=dict(target_sha256=native.SHA,base='05bc2de303c05525b71e7e257426e741bc66a390',rows=len(expected.splitlines()),input_sha256=hashlib.sha256(inputs).hexdigest(),expected_sha256=hashlib.sha256(expected).hexdigest(),owners=owners,spans=[list(map(hex,s)) for s in native.SPANS],selected_bytes=sum(i.size for i in selected),selected_instructions=len(selected),visited_addresses=sorted(seen),actual_calls=calls,source_location=location,captured_process_executed=False,normalization='four returned words; exact global/tree/ring object-cell-byte-offset pointer identity. Synthetic guard/fields and bounded valid ordered containers are premises, not original data/type/version. Actual split-ring helper CALL/RET, no supplied result. I/M stop before initializer/diagnostic; post-initializer continuation and original ABI/current-network unclaimed. Instruction visitation is not exhaustive branch-state proof.')
  p=native.PACKET;(p/'inputs.jsonl').write_bytes(inputs);(p/'expected.jsonl').write_bytes(expected);(p/'proof.json').write_text(json.dumps(record,indent=2)+'\n');(p/'native-controls.json').write_text(json.dumps(dict(output_changes=controls,rejections=negatives),indent=2)+'\n')
  print('CLOSED FREEZE PASS',record['rows'],record['selected_bytes'],record['selected_instructions'],len(controls),'outputCOW',len(negatives),'negativeCOW',call_rows,'realCALL/RETrows',flush=True)
 finally:im.close()
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--objdump',type=Path,required=True);a=p.parse_args();generate(a.objdump.resolve())
