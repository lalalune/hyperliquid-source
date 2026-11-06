"""Freeze complete instruction-backed mixed-sign and saturating selector."""
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
  start,end=native.OWNER
  if im.view.fde(start)!=(start,end):raise ValueError('FDE mismatch')
  body=im.view.read(start,end-start);cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);ins=list(cs.disasm(body,start));starts={i.address for i in ins}
  if sum(i.size for i in ins)!=len(body):raise ValueError('decode gap')
  text=subprocess.check_output([str(objdump),'-d','--wide','-M','intel',f'--start-address={start:#x}',f'--stop-address={end:#x}',str(native.TARGET)],text=True).replace(str(native.TARGET),'artifacts/node/115/hl-node');parsed=[]
  for line in text.splitlines():
   m=re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s)+)',line)
   if m:parsed.append((int(m[1],16),bytes.fromhex(m[2])))
  if parsed!=[(i.address,bytes(i.bytes)) for i in ins]:raise ValueError('GNU/Capstone mismatch')
  for i in ins:
   if im.fetch(i.address).size!=i.size:raise ValueError('evaluator length disagreement')
   if i.mnemonic.startswith('call') or 'rip' in i.op_str:raise ValueError('unexpected external dependency')
   if i.mnemonic.startswith('j') and int(i.op_str,0) not in starts:raise ValueError('branch escapes leaf')
  if starts!={a for a in seen if start<=a<end}:raise ValueError('unvisited selector instructions')
  owners=[]
  for family,(lo,hi,fields) in enumerate(native.FAMILIES):
   b=im.view.read(lo,hi-lo);seq=list(cs.disasm(b,lo))
   if im.view.fde(lo)!=(lo,hi) or sum(i.size for i in seq)!=hi-lo or {i.address for i in seq}!={a for a in seen if lo<=a<hi}:raise ValueError('family body/FDE/visit mismatch')
   for i in seq:
    if im.fetch(i.address).size!=i.size or i.mnemonic.startswith('call') or 'rip' in i.op_str:raise ValueError('family dependency/decode')
    if i.mnemonic.startswith('j') and int(i.op_str,0) not in {x.address for x in seq}:raise ValueError('family CFG')
   export=subprocess.check_output([str(objdump),'-d','--wide','-M','intel',f'--start-address={lo:#x}',f'--stop-address={hi:#x}',str(native.TARGET)],text=True).replace(str(native.TARGET),'artifacts/node/115/hl-node');native.PACKET.joinpath(f'{lo:x}.gnu.txt').write_text(export)
   parsed_family=[]
   for line in export.splitlines():
    m=re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s)+)',line)
    if m:parsed_family.append((int(m[1],16),bytes.fromhex(m[2])))
   if parsed_family!=[(i.address,bytes(i.bytes)) for i in seq]:raise ValueError('family GNU/Capstone mismatch')
   owners.append(dict(family=family,start=hex(lo),end=hex(hi),bytes=len(b),instructions=len(seq),sha256=hashlib.sha256(b).hexdigest(),unwind=frame(im.view,lo),fields=fields))
  census=[];textva,textoff,textsize=im.view.sections['.text']
  for leader in [0x55ff9e0,0x55ff970]:
   needle=im.view.read(leader,100);pos=textoff;matches=[]
   while True:
    pos=im.data.find(needle,pos,textoff+textsize)
    if pos<0:break
    va=textva+pos-textoff
    if im.view.fde(va)!=(va,va+100):raise ValueError('exact bytes outside complete family FDE')
    matches.append(va);pos+=1
   want={lo for lo,hi,_ in native.FAMILIES if im.view.read(lo,100)==needle}
   if set(matches)!=want:raise ValueError('unaccounted exact whole-body alias')
   census.append(dict(encoding_leader=hex(leader),matches=list(map(hex,matches)),scope='every byte offset in.text for exact100B whole encoding; not masked semantic equivalents or indirect callers'))
  caller=0x517adc5;raw=im.view.read(caller,5)
  if raw[0]!=0xe8 or caller+5+int.from_bytes(raw[1:],'little',signed=True)!=start:raise ValueError('caller binding')
  _,off,n=im.view.sections['.rela.dyn'];pathva=None
  for q in range(off,off+n,24):
   slot,kind,add=struct.unpack_from('<QQq',im.data,q)
   if slot==0x64768a8:
    if kind!=8:raise ValueError('sourceLocation relocation')
    pathva=add
  if pathva is None:raise ValueError('missing sourceLocation')
  length,line,col=struct.unpack('<QII',im.view.read(0x64768b0,16));path=im.view.read(pathva,length).decode()
  if (path,line,col)!=('l1/src/perp_meta.rs',163,38):raise ValueError('source association')
  cases=[json.loads(s) for s in inputs.decode().splitlines()];witnesses=cases
  changes=[]
  anchors=[('signed-first',0x55ff9ee,0x92),('unsigned-second',0x55ff9fc,0x9c),('first-branch',0x55ff9f0,0x74),('second-branch',0x55ff9fe,0x74),('third-equality',0x55ffa09,0x77),('primary-equality',0x55ffa1a,0x77),('fallback-equality',0x55ffa41,0x97),('saturation-boundary',0x55ffa26,0x79),('overflow-addend',0x55ffa2e,0),('saturation-selection',0x55ffa3b,0x42),('primary-code',0x55ffa12,3),('tested-word',0x55ff9e6,0x10)]
  for name,va,byte in anchors:
   changed=native.Image();changed.data=mmap.mmap(changed.view.file.fileno(),0,access=mmap.ACCESS_COPY)
   try:
    old=changed.data[changed.view.offset(va)];changed.data[changed.view.offset(va)]=byte
    for row in witnesses:
     original=native.evaluate(im,row)[0]
     try:actual=native.evaluate(changed,row)[0]
     except (ValueError,native.cpu.ToolError):continue
     if original!=actual:changes.append(dict(name=name,va=hex(va),old=hex(old),new=hex(byte),input=row,original=original,changed=actual));break
    else:raise ValueError('ineffective outputCOW '+name)
   finally:changed.close()
  for family in [1,2]:
   lo=native.FAMILIES[family][0]
   for name,relative,byte in [('primary-equality',0x3a,0x77),('fallback-equality',0x61,0x97)]:
    changed=native.Image();changed.data=mmap.mmap(changed.view.file.fileno(),0,access=mmap.ACCESS_COPY);va=lo+relative
    try:
     old=changed.data[changed.view.offset(va)];changed.data[changed.view.offset(va)]=byte
     for row in cases:
      if row[0]!=family:continue
      original=native.evaluate(im,row)[0]
      try:actual=native.evaluate(changed,row)[0]
      except (ValueError,native.cpu.ToolError):continue
      if original!=actual:changes.append(dict(name=f'family{family}-'+name,va=hex(va),old=hex(old),new=hex(byte),input=row,original=original,changed=actual));break
     else:raise ValueError('ineffective family COW '+name)
    finally:changed.close()
  negative=[]
  for name,va,byte in [('uninitialized-object-field',0x55ff9e2,0x5c),('unknown-register',0x55ffa3f,0xd9)]:
   changed=native.Image();changed.data=mmap.mmap(changed.view.file.fileno(),0,access=mmap.ACCESS_COPY)
   try:
    changed.data[changed.view.offset(va)]=byte
    for row in witnesses:
     try:native.evaluate(changed,row)
     except (ValueError,native.cpu.ToolError) as e:negative.append(dict(name=name,va=hex(va),new=hex(byte),input=row,rejected=str(e)));break
    else:raise ValueError('ineffective negativeCOW '+name)
   finally:changed.close()
  assert hashlib.sha256(im.data).hexdigest()==native.SHA
  record=dict(target_sha256=native.SHA,base='05bc2de303c05525b71e7e257426e741bc66a390',rows=len(expected.splitlines()),input_sha256=hashlib.sha256(inputs).hexdigest(),expected_sha256=hashlib.sha256(expected).hexdigest(),owner=dict(start=hex(start),end=hex(end),bytes=len(body),instructions=len(ins),sha256=hashlib.sha256(body).hexdigest(),unwind=frame(im.view,start)),visited_addresses=sorted(seen),owners=owners,exact_body_census=census,visited_bytes=sum(o["bytes"] for o in owners),visited_instructions=len(seen),callees=[],actual_caller=dict(site=hex(caller),instruction_hex=raw.hex(),fde=list(map(hex,im.view.fde(caller)))),source_location=dict(va='0x64768a8',path_va=hex(pathva),path=path,line=line,column=col),captured_process_executed=False,normalization='Only exact raw AL. UpperRAX/unusedregisters not compared. Valid declaredfield memory; no objectpadding read or input write; real RET; three complete bodies300B84starts;two unique encodings. No units/financialpolicy/ABI.')
  p=native.PACKET;(p/'inputs.jsonl').write_bytes(inputs);(p/'expected.jsonl').write_bytes(expected);(p/'proof.json').write_text(json.dumps(record,indent=2)+'\n');(p/'native-controls.json').write_text(json.dumps(dict(output_changes=changes,rejections=negative),indent=2)+'\n');(p/'55ff9e0.gnu.txt').write_text(text)
  print('FREEZE PASS',record['rows'],record['visited_bytes'],len(seen),len(changes),'outputCOW',len(negative),'negativeCOW',flush=True)
 finally:im.close()
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--objdump',type=Path,required=True);a=p.parse_args();generate(a.objdump.resolve())
