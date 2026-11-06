"""Freeze the genuine full decoder CALL graph before Rust authorship."""
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
  if hashlib.sha256(im.data).hexdigest()!=native.SHA:raise ValueError('wrong target')
  inputs,expected,seen,calls=native.corpus(im)
  cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);owners=[];starts=set()
  for start,end in native.RANGES:
   if im.view.fde(start)!=(start,end):raise ValueError('FDE extent')
   body=im.view.read(start,end-start);rows=list(cs.disasm(body,start));starts.update(i.address for i in rows)
   if sum(i.size for i in rows)!=len(body):raise ValueError('incomplete disassembly')
   text=subprocess.check_output([str(objdump),'-d','--wide','-M','intel',f'--start-address={start:#x}',f'--stop-address={end:#x}',str(native.TARGET)],text=True).replace(str(native.TARGET),'artifacts/node/115/hl-node')
   parsed=[]
   for line in text.splitlines():
    m=re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s)+)',line)
    if m:parsed.append((int(m[1],16),bytes.fromhex(m[2])))
   if parsed!=[(i.address,bytes(i.bytes)) for i in rows]:raise ValueError('GNU/Capstone disagreement')
   for i in rows:
    if im.fetch(i.address).size!=i.size:raise ValueError('evaluator decode disagreement')
   (native.PACKET/f'{start:x}.gnu.txt').write_text(text)
   owners.append(dict(start=hex(start),end=hex(end),bytes=len(body),instructions=len(rows),sha256=hashlib.sha256(body).hexdigest(),unwind=frame(im.view,start)))
  if not seen<=starts:raise ValueError('visited non-instruction')
  print('CORPUS COMPLETE',len(expected.splitlines()),flush=True)
  controls=[]
  # Each changed file byte is private COW; same initial state and projection.
  anchors=[('byte-charge',0x2ce17ee,2),('byte-limit-equality',0x2ce17f7,0x87),('optional-mode',0x2ce1834,2),('error-mode-tag',0x2ce1925,3),('first-store',0x2ce1915,0x18),('second-store',0x2ce1919,0x10),('third-store',0x2ce191d,0x18),('last-store',0x2ce1921,0x20),('tail-store',0x2ce1911,0x10),('scalar-charge',0x2cd7ad7,7),('error-expected',0x5822708,0x57)]
  rows=native.stimuli(); originals=[json.loads(x) for x in expected.splitlines()]
  witnesses=[('111d2b3d00',None,0),('111d2b3d0149',None,0),('111d2b3d02',None,0),('111d2b3d00',32,0),('111d2b3d00',33,0),('111d2b3d0149',41,0),('fe',None,0),('fe'+'00'*8,None,0),('111d2b3d00',8,0)]
  candidates=list(dict.fromkeys(witnesses+rows))
  reference={tuple(row):result for row,result in zip(rows,originals)}
  for row in witnesses:
   if row not in reference:reference[row]=native.evaluate(im,row)[0]
  for name,va,byte in anchors:
   changed=native.Image();changed.data=mmap.mmap(changed.view.file.fileno(),0,access=mmap.ACCESS_COPY)
   try:
    old=changed.data[changed.view.offset(va)];changed.data[changed.view.offset(va)]=byte
    for row in candidates:
     original=reference[tuple(row)]
     try:altered=native.evaluate(changed,row)[0]
     except (ValueError,native.cpu.ToolError):continue
     if original!=altered:
      controls.append(dict(name=name,va=hex(va),old=hex(old),new=hex(byte),input=row,original=original,changed=altered));break
    else:raise ValueError('ineffective control '+name)
    print('CONTROL',name,'PASS',flush=True)
   finally:changed.close()
  if hashlib.sha256(im.data).hexdigest()!=native.SHA:raise ValueError('capture mutated')
  p=native.PACKET;(p/'inputs.jsonl').write_bytes(inputs);(p/'expected.jsonl').write_bytes(expected)
  record=dict(target_sha256=native.SHA,base='05bc2de303c05525b71e7e257426e741bc66a390',rows=len(expected.splitlines()),input_sha256=hashlib.sha256(inputs).hexdigest(),expected_sha256=hashlib.sha256(expected).hexdigest(),owners=owners,visited_addresses=sorted(seen),visited_instructions=len(seen),complete_export_instructions=len(starts),unvisited_addresses=sorted(starts-seen),calls=[list(map(hex,c)) for c in sorted(calls)],slots={hex(k):hex(v) for k,v in im.slots.items()},tables=[dict(va=hex(a),raw_hex=im.view.read(a,n).hex()) for a,n in native.TABLES],captured_process_executed=False,normalization='logical active success/error fields plus consumed count and charged count; all inactive storage/padding omitted; fourth output canary retained on failure; canonical mode0/1 little-endian and disjoint valid objects; actual outer RET and all called helpers interpreted, no mocked returns')
  (p/'proof.json').write_text(json.dumps(record,indent=2)+'\n');(p/'native-controls.json').write_text(json.dumps(controls,indent=2)+'\n')
  print('FROZEN',record['rows'],'rows',len(seen),'/',len(starts),'instruction starts',len(controls),'COW controls',flush=True)
 finally:im.close()
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--objdump',type=Path,required=True);a=p.parse_args();generate(a.objdump.resolve())
