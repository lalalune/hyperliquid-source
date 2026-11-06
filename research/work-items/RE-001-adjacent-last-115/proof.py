"""Freeze complete actual compaction state, including inactive backing tail."""
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
  inputs,expected,seen,write_rows=native.corpus(im);print('CORPUS COMPLETE',len(expected.splitlines()),flush=True)
  start,end=native.OWNER
  if im.view.fde(start)!=(start,end):raise ValueError('FDE mismatch')
  body=im.view.read(start,end-start);cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);rows=list(cs.disasm(body,start));starts={i.address for i in rows}
  if sum(i.size for i in rows)!=len(body):raise ValueError('decode gap')
  text=subprocess.check_output([str(objdump),'-d','--wide','-M','intel',f'--start-address={start:#x}',f'--stop-address={end:#x}',str(native.TARGET)],text=True).replace(str(native.TARGET),'artifacts/node/115/hl-node');parsed=[]
  for line in text.splitlines():
   m=re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s)+)',line)
   if m:parsed.append((int(m[1],16),bytes.fromhex(m[2])))
  if parsed!=[(i.address,bytes(i.bytes)) for i in rows]:raise ValueError('GNU Capstone mismatch')
  for i in rows:
   if im.fetch(i.address).size!=i.size:raise ValueError('evaluator length disagreement')
   if i.mnemonic.startswith('call'):raise ValueError('leaf calls')
   if i.mnemonic.startswith('j') and int(i.op_str,0) not in starts:raise ValueError('branch leaves instruction starts')
   if 'rip' in i.op_str:raise ValueError('unexpected RIP data')
  # Only the four-byte alignment NOP after an unconditional JMP is unvisited.
  if starts-seen!={0x5b2d5bc}:raise ValueError('unexpected unvisited starts '+str(sorted(starts-seen)))
  caller=0x4dff15a;raw=im.view.read(caller,5)
  if raw[0]!=0xe8 or caller+5+int.from_bytes(raw[1:],'little',signed=True)!=start:raise ValueError('actual caller binding')
  if im.view.read(0x4dff152,8)!=bytes.fromhex('488dbc2400020000'):raise ValueError('caller RDI object binding')
  pathva=None;_,off,n=im.view.sections['.rela.dyn']
  for q in range(off,off+n,24):
   slot,kind,add=struct.unpack_from('<QQq',im.data,q)
   if slot==0x649ccf8:
    if kind!=8:raise ValueError('Location not RELATIVE')
    pathva=add
  if pathva is None:raise ValueError('missing source Location')
  length,line,col=struct.unpack('<QII',im.view.read(0x649cd00,16));location=dict(va='0x649ccf8',path_va=hex(pathva),path=im.view.read(pathva,length).decode(),line=line,column=col)
  witnesses=[native.records(keys).hex() for keys in [[0,0],[0,0,1],[0,0,0],[0,0,1,2,2],[0,1,1,2,2],[0,1,2,2],[0,0,1,0,0],[0,0,1,1,2,2,3],[0,1,0],[0,1,2]]]
  base=native.records([1,1])
  for at in [0,15,16,19,20,31]:
   row=bytearray(base);row[32+at]^=1;witnesses.append(row.hex())
  anchors=[('short-length',0x5b2d517,3),('initial-equality',0x5b2d56f,0x75),('fragment-next-source',0x5b2d554,0x34),('fragment-prev-source',0x5b2d55a,0x14),('mask-expected',0x5b2d56b,0xfe),('first-kept-low',0x5b2d59a,0x0c),('first-kept-high',0x5b2d5a3,0x4c),('first-length',0x5b2d5a9,0xfe),('remaining-branch',0x5b2d5ae,0x87),('loop-equality',0x5b2d616,0x74),('loop-mask',0x5b2d612,0xfe),('loop-fragment-source',0x5b2d5fa,0x14),('distinct-low',0x5b2d5cf,0x08),('distinct-high',0x5b2d5ca,0x40),('last-kept-low',0x5b2d627,0xc0),('last-kept-high',0x5b2d639,0xe0),('write-stride',0x5b2d5e2,6)]
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
  for name,va,byte in [('length-slot',0x5b2d646,8),('read-stride',0x5b2d5d6,0x40)]:
   changed=native.Image();changed.data=mmap.mmap(changed.view.file.fileno(),0,access=mmap.ACCESS_COPY)
   try:
    changed.data[changed.view.offset(va)]=byte
    for row in witnesses:
     try:native.evaluate(changed,row)
     except (ValueError,native.cpu.ToolError) as e:
      negatives.append(dict(name=name,va=hex(va),new=hex(byte),input=row,rejected=str(e)));break
    else:raise ValueError('ineffective rejection '+name)
   finally:changed.close()
  if hashlib.sha256(im.data).hexdigest()!=native.SHA:raise ValueError('capture changed')
  record=dict(target_sha256=native.SHA,base='05bc2de303c05525b71e7e257426e741bc66a390',rows=len(expected.splitlines()),input_sha256=hashlib.sha256(inputs).hexdigest(),expected_sha256=hashlib.sha256(expected).hexdigest(),owner=dict(start=hex(start),end=hex(end),bytes=len(body),instructions=len(rows),sha256=hashlib.sha256(body).hexdigest(),unwind=frame(im.view,start)),visited_addresses=sorted(seen),visited_bytes=sum(i.size for i in rows if i.address in seen),visited_instructions=len(seen),unvisited_padding='0x5b2d5bc..0x5b2d5c0,4B unreachable after unconditional JMP',write_rows=write_rows,callees=[],actual_caller=dict(site=hex(caller),instruction_hex=raw.hex(),fde=list(map(hex,im.view.fde(caller)))),source_location=location,captured_process_executed=False,normalization='exact stored length and EVERY byte of old-length backing storage, including tail; no byte masks. Native RAX scratch/return type unclaimed. Valid disjoint nonwrapping writable storage and fixed32B records, at most32 in corpus; short/no-equal paths cause no writes. Complete RET, no external helpers/data.')
  p=native.PACKET;(p/'inputs.hex').write_bytes(inputs);(p/'expected.jsonl').write_bytes(expected);(p/'proof.json').write_text(json.dumps(record,indent=2)+'\n');(p/'native-controls.json').write_text(json.dumps(dict(output_changes=controls,rejections=negatives),indent=2)+'\n');(p/'5b2d510.gnu.txt').write_text(text)
  print('FREEZE PASS',record['rows'],record['visited_bytes'],record['visited_instructions'],len(controls),'outputCOW',len(negatives),'negativeCOW',flush=True)
 finally:im.close()
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--objdump',type=Path,required=True);a=p.parse_args();generate(a.objdump.resolve())
