"""Complete ring-search family, no assumed helper returns or initialized padding."""
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
  inputs,expected,seen=native.corpus(im);print('CORPUS COMPLETE',len(expected.splitlines()),flush=True)
  cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);owners=[];allins={};callers=[]
  for family,(start,end,stride) in enumerate(native.FAMILIES):
   if im.view.fde(start)!=(start,end):raise ValueError('FDE mismatch')
   body=im.view.read(start,end-start);seq=list(cs.disasm(body,start));starts={i.address for i in seq}
   if sum(i.size for i in seq)!=len(body):raise ValueError('decode gap')
   text=subprocess.check_output([str(objdump),'-d','--wide','-M','intel',f'--start-address={start:#x}',f'--stop-address={end:#x}',str(native.TARGET)],text=True).replace(str(native.TARGET),'artifacts/node/115/hl-node');parsed=[]
   for line in text.splitlines():
    m=re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s)+)',line)
    if m:parsed.append((int(m[1],16),bytes.fromhex(m[2])))
   if parsed!=[(i.address,bytes(i.bytes)) for i in seq]:raise ValueError('GNU/Capstone mismatch')
   for i in seq:
    if im.fetch(i.address).size!=i.size:raise ValueError('evaluator decode')
    if i.mnemonic.startswith('call') or 'rip' in i.op_str:raise ValueError('unexpected dependency')
    if i.mnemonic.startswith('j') and int(i.op_str,0) not in starts:raise ValueError('CFG escapes')
   if starts!={a for a in seen if start<=a<end}:raise ValueError('unvisited body instructions')
   owners.append(dict(family=family,start=hex(start),end=hex(end),bytes=len(body),instructions=len(seq),stride=stride,sha256=hashlib.sha256(body).hexdigest(),unwind=frame(im.view,start)));allins[family]=seq;(native.PACKET/f'{start:x}.gnu.txt').write_text(text)
  associations=[(49208569,49209249,0x6461510,0x4402cd,'base/src/l1_map/entry.rs',64,17),(57192384,57193269,0x6468b38,0x44e7fd,'l1/src/raw_signature_tracker.rs',231,9)]
  slots={};_,off,n=im.view.sections['.rela.dyn']
  for p in range(off,off+n,24):
   slot,kind,add=struct.unpack_from('<QQq',im.data,p)
   if slot in [a[2] for a in associations]:
    if kind!=8:raise ValueError('Location relocation')
    slots[slot]=add
  for family,(site,lea,loc,pathva,path,line,col) in enumerate(associations):
   raw=im.view.read(site,5);owner=im.view.fde(site)
   if raw[0]!=0xe8 or site+5+int.from_bytes(raw[1:],'little',signed=True)!=native.FAMILIES[family][0]:raise ValueError('actual caller')
   leabytes=im.view.read(lea,7)
   if not owner[0]<=lea<owner[1] or leabytes[:2]!=bytes.fromhex('488d') or leabytes[2]&0xc7!=5 or lea+7+int.from_bytes(leabytes[3:],'little',signed=True)!=loc:raise ValueError('source LEA')
   length,l,c=struct.unpack('<QII',im.view.read(loc+8,16))
   if slots.get(loc)!=pathva or (im.view.read(pathva,length).decode(),l,c)!=(path,line,col):raise ValueError('source Location')
   callers.append(dict(family=family,site=hex(site),bytes=raw.hex(),fde=list(map(hex,owner)),source_lea=hex(lea),source_lea_bytes=leabytes.hex(),location=hex(loc),path=path,line=line,column=col))
  cases=[json.loads(s) for s in inputs.decode().splitlines()];changes=[];negative=[]
  anchors=[[(0x2ee0684,0x85,'seam-equality'),(0x2ee067a,0x9f,'unsigned-pivot'),(0x2ee06b9,0x43,'firstspan-equality'),(0x2ee0729,0x43,'secondspan-equality'),(0x2ee06de,0x94,'status'),(0x2ee073f,0x74,'fallback-equality'),(0x2ee066a,0x72,'wrap-boundary')],[(0x4551853,0x85,'seam-equality'),(0x4551849,0x9f,'unsigned-pivot'),(0x4551886,0x43,'firstspan-equality'),(0x45518f6,0x43,'secondspan-equality'),(0x45518a8,0x94,'status'),(0x4551909,0x74,'fallback-equality'),(0x4551839,0x72,'wrap-boundary')]]
  for family,group in enumerate(anchors):
   for va,byte,name in group:
    changed=native.Image();changed.data=mmap.mmap(changed.view.file.fileno(),0,access=mmap.ACCESS_COPY)
    try:
     old=changed.data[changed.view.offset(va)];changed.data[changed.view.offset(va)]=byte
     for row in cases:
      if row[0]!=family:continue
      original=native.evaluate(im,row)[0]
      try:actual=native.evaluate(changed,row)[0]
      except (ValueError,native.cpu.ToolError):continue
      if original!=actual:changes.append(dict(name=f'family{family}-'+name,va=hex(va),old=hex(old),new=hex(byte),input=row,original=original,changed=actual));break
     else:raise ValueError('ineffective outputCOW '+str(family)+' '+name)
    finally:changed.close()
  for family in [0,1]:
   # Decode-qualified first record-stride arithmetic, not a textual address guess.
   stride=native.FAMILIES[family][2]
   candidate=next(i for i in allins[family] if (i.mnemonic=='shl' and i.op_str.endswith('5')) if family==0) if family==0 else next(i for i in allins[family] if i.mnemonic=='imul' and i.op_str.endswith('0x38'))
   negative_anchors=[('normalization',0x2ee065c if family==0 else 0x455182b,0x42),('stride',candidate.address+candidate.size-1,4 if family==0 else 0x30)]
   for name,va,byte in negative_anchors:
    changed=native.Image();changed.data=mmap.mmap(changed.view.file.fileno(),0,access=mmap.ACCESS_COPY)
    try:
     changed.data[changed.view.offset(va)]=byte
     for row in cases:
      if row[0]!=family:continue
      try:native.evaluate(changed,row)
      except (ValueError,native.cpu.ToolError) as e:negative.append(dict(name=f'family{family}-'+name,va=hex(va),new=hex(byte),input=row,rejected=str(e)));break
     else:raise ValueError('ineffective rejection '+name)
    finally:changed.close()
  assert hashlib.sha256(im.data).hexdigest()==native.SHA
  record=dict(target_sha256=native.SHA,base='05bc2de303c05525b71e7e257426e741bc66a390',rows=len(expected.splitlines()),input_sha256=hashlib.sha256(inputs).hexdigest(),expected_sha256=hashlib.sha256(expected).hexdigest(),owners=owners,visited_addresses=sorted(seen),visited_bytes=sum(o['bytes'] for o in owners),visited_instructions=len(seen),callees=[],actual_callers=callers,captured_process_executed=False,normalization='Exact completeRAX/RDX; valid sorted boundedring; onlylivekey qwordsinitialized, payload/unusedcapacityunknown; emptyquerynotread; nostores; realRET. No ABI/productionpolicy inference.')
  p=native.PACKET;(p/'inputs.jsonl').write_bytes(inputs);(p/'expected.jsonl').write_bytes(expected);(p/'proof.json').write_text(json.dumps(record,indent=2)+'\n');(p/'native-controls.json').write_text(json.dumps(dict(output_changes=changes,rejections=negative),indent=2)+'\n');print('FREEZE PASS',record['rows'],record['visited_bytes'],record['visited_instructions'],len(changes),'outputCOW',len(negative),'negativeCOW',flush=True)
 finally:im.close()
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--objdump',type=Path,required=True);a=p.parse_args();generate(a.objdump.resolve())
