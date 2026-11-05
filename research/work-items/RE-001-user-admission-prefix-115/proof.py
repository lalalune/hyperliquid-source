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
   if im.fetch(i.address).size!=i.size:raise ValueError('evaluator instruction length')
   if i.mnemonic.startswith('j') and int(i.op_str,0) not in by:raise ValueError('owner branch escape')
  selected=set();boundaries=set();todo=[start]
  while todo:
   a=todo.pop()
   if a in selected or a in boundaries:continue
   i=by[a]
   if a in native.STOPS:
    if i.mnemonic!='call':raise ValueError('frontier not actual CALL')
    boundaries.add(a);continue
   if i.mnemonic=='call':raise ValueError('unlisted first call')
   selected.add(a)
   if i.mnemonic=='ret':continue
   if i.mnemonic=='jmp':todo.append(int(i.op_str,0))
   elif i.mnemonic.startswith('j'):todo.extend([int(i.op_str,0),a+i.size])
   else:todo.append(a+i.size)
  if boundaries!=set(native.STOPS):raise ValueError('frontier CFG set')
  inputs,expected,seen,frontiers=native.corpus(im);print('CORPUS COMPLETE',len(expected.splitlines()),frontiers,flush=True)
  if seen!=selected:raise ValueError('unvisited selected addresses '+str(sorted(selected-seen)))
  _,off,n=im.view.sections['.rela.dyn'];bindings={}
  for q in range(off,off+n,24):
   slot,info,add=struct.unpack_from('<QQq',im.data,q)
   if slot in [0x644d9d8,0x64e4f48,native.IMPORT]:bindings[slot]=(info,add)
  if bindings.get(0x644d9d8)!=(8,0x44c976) or bindings.get(0x64e4f48)!=(8,0x3c3f5a0):raise ValueError('Location/privatecall relocation')
  info,add=bindings[native.IMPORT]
  if info&0xffffffff!=6:raise ValueError('memcmp not GLOB_DAT')
  symbol=info>>32;_,symoff,_=im.view.sections['.dynsym'];_,stroff,_=im.view.sections['.dynstr'];nameoff=struct.unpack_from('<I',im.data,symoff+24*symbol)[0];at=stroff+nameoff;name=im.data[at:im.data.find(b'\0',at)].decode()
  if name!='memcmp':raise ValueError('unresolved import symbol')
  length,line,col=struct.unpack('<QII',im.view.read(0x644d9e0,16));path=im.view.read(0x44c976,length).decode()
  if (path,line,col)!=('l1/src/exchange/impl_user.rs',195,40):raise ValueError('source context')
  lea=by[0x2c77784];lb=bytes(lea.bytes)
  if lb[:3]!=bytes.fromhex('488d0d') or lea.address+lea.size+int.from_bytes(lb[3:],'little',signed=True)!=0x644d9d8:raise ValueError('unselected source LEA binding')
  calls=[]
  for a,kind in native.STOPS.items():
   i=by[a];item=dict(site=hex(a),kind=kind,bytes=bytes(i.bytes).hex(),instruction=i.mnemonic+' '+i.op_str,executed=False)
   if a==0x2c7770d:
    if a+i.size+int.from_bytes(bytes(i.bytes)[2:],'little',signed=True)!=0x64e4f48:raise ValueError('identity slot')
    item.update(slot='0x64e4f48',target='0x3c3f5a0')
   elif a in [0x2c77996,0x2c77a08]:item['target']=i.op_str
   else:item.update(import_slot=hex(native.IMPORT),import_symbol='memcmp',runtime_target='unknown; deliberately not initialized or executed')
   calls.append(item)
  cases=native.control_inputs();changes=[]
  anchors=[('encoded-equality',0x2c7766e,3),('sign-mask-width',0x2c77667,0x3e),('current-selector',0x2c776a7,0x85),('identity-bit',0x2c776ca,2),('operation-bit',0x2c777ba,2),('amount-equality',0x2c778b0,0x87),('amount-unsigned',0x2c778b0,0x8d),('amount-payload-offset',0x2c77972,4),('budget-or',0x2c778c0,1),('descriptor-zero-gate',0x2c778cb,1),('aux-zero-gate',0x2c77987,0x85),('tree-height-step',0x2c77876,2),('node-count-width',0x2c777f3,0xb6),('context-qword-source',0x2c779f1,0x64),('identity-tail-source',0x2c776e9,0x0c),('peer-tail-source',0x2c776d8,0x5b)]
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
  for label,va,byte in [('output-origin',0x2c77675,0x25),('identity-state-origin',0x2c776af,0x80),('identity-out-of-bounds',0x2c776e9,0x14)]:
   changed=native.Image();changed.data=mmap.mmap(changed.view.file.fileno(),0,access=mmap.ACCESS_COPY)
   try:
    changed.data[changed.view.offset(va)]=byte
    for row in cases:
     try:native.evaluate(changed,row)
     except (ValueError,native.cpu.ToolError) as e:negatives.append(dict(name=label,va=hex(va),new=hex(byte),input=row,rejected=str(e)));break
    else:raise ValueError('ineffective rejection '+label)
   finally:changed.close()
  assert hashlib.sha256(im.data).hexdigest()==native.SHA
  record=dict(target_sha256=native.SHA,base='05bc2de303c05525b71e7e257426e741bc66a390',rows=len(expected.splitlines()),input_sha256=hashlib.sha256(inputs).hexdigest(),expected_sha256=hashlib.sha256(expected).hexdigest(),owner=dict(start=hex(start),end=hex(end),bytes=len(body),instructions=len(seq),sha256=hashlib.sha256(body).hexdigest(),unwind=frame(im.view,start)),selected_addresses=sorted(selected),visited_addresses=sorted(seen),selected_bytes=sum(by[a].size for a in selected),selected_instructions=len(selected),frontier_counts=frontiers,unexecuted_first_calls=calls,qualified_callees=[],unresolved_import=dict(slot=hex(native.IMPORT),symbol=name,symbol_index=symbol,relocation_info=info,raw_addend=add,runtime_pointer='unknown; not fabricated from zero rawELF slot'),source_context=dict(location='0x644d9d8',source_lea='0x2c77784',path=path,line=line,column=col,source_lea_selected=False),captured_process_executed=False,normalization='Entire16byte initialcanary/output window and explicitly listed live first-call fields/origins. No helpercalls/returns composed. Descriptor overlapping fields use one99byte envelope; unread/stackpadding/importpointer stayunknown. RET and callfrontier remain distinct; no wholeadmission/ABI/financialpolicy claim.')
  p=native.PACKET;(p/'inputs.jsonl').write_bytes(inputs);(p/'expected.jsonl').write_bytes(expected);(p/'proof.json').write_text(json.dumps(record,indent=2)+'\n');(p/'native-controls.json').write_text(json.dumps(dict(output_changes=changes,rejections=negatives),indent=2)+'\n');(p/'2c77640.gnu.txt').write_text(text);print('FREEZE PASS',record['rows'],record['selected_bytes'],record['selected_instructions'],frontiers,len(changes),'outputCOW',len(negatives),'negativeCOW',flush=True)
 finally:im.close()
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--objdump',type=Path,required=True);a=p.parse_args();generate(a.objdump.resolve())
