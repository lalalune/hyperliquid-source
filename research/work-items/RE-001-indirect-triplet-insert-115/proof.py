"""Full actual entry/guard/record-state insertion evidence; no copied source oracle."""
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
  inputs,expected,seen,traps=native.corpus(im);print('CORPUS COMPLETE',len(expected.splitlines()),'guardUD2',traps,flush=True)
  start,end=native.OWNER
  if im.view.fde(start)!=(start,end):raise ValueError('FDE mismatch')
  body=im.view.read(start,end-start);cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);seq=list(cs.disasm(body,start));starts={i.address for i in seq}
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
  if starts-seen!={0x26d42f6}:raise ValueError('unexpected unvisited starts')
  textva,textoff,textsize=im.view.sections['.text'];pos=textoff;aliases=[]
  while True:
   pos=im.data.find(body,pos,textoff+textsize)
   if pos<0:break
   va=textva+pos-textoff;aliases.append(dict(start=hex(va),fde=list(map(hex,im.view.fde(va)))));pos+=1
  if [a['start'] for a in aliases]!=[hex(start)]:raise ValueError('additional exact-body aliases need family scope '+str(aliases))
  site=48301698;raw=im.view.read(site,5);caller=im.view.fde(site);lea=48278338;loc=105192328;pathva=4448430
  if raw[0]!=0xe8 or site+5+int.from_bytes(raw[1:],'little',signed=True)!=start:raise ValueError('actual caller')
  lb=im.view.read(lea,7)
  if not caller[0]<=lea<caller[1] or lb[:3]!=bytes.fromhex('488d0d') or lea+7+int.from_bytes(lb[3:],'little',signed=True)!=loc:raise ValueError('source LEA')
  _,off,n=im.view.sections['.rela.dyn'];bound=[]
  for p in range(off,off+n,24):
   slot,kind,add=struct.unpack_from('<QQq',im.data,p)
   if slot==loc:bound.append((kind,add))
  length,line,col=struct.unpack('<QII',im.view.read(loc+8,16));path=im.view.read(pathva,length).decode()
  if bound!=[(8,pathva)] or (path,line,col)!=('node/src/consensus/state.rs',550,17):raise ValueError('source Location')
  cases=[json.loads(s) for s in inputs.decode().splitlines()];changes=[]
  anchors=[('guard-previous-index',0x26d4283,0xfe),('early-return',0x26d4291,0x85),('outer-first-signed',0x26d42d8,0x92),('outer-second-unsigned',0x26d42e6,0x9c),('outer-third-equality',0x26d42f2,0x77),('outer-first-branch',0x26d42da,0x74),('outer-second-branch',0x26d42e8,0x74),('inner-first-signed',0x26d4351,0x92),('inner-second-unsigned',0x26d435d,0x9c),('inner-third-stability',0x26d4367,0x76),('payload-register',0x26d42b2,0x0a)]
  for name,va,byte in anchors:
   changed=native.Image();changed.data=mmap.mmap(changed.view.file.fileno(),0,access=mmap.ACCESS_COPY)
   try:
    old=changed.data[changed.view.offset(va)];changed.data[changed.view.offset(va)]=byte
    for row in cases:
     original=native.evaluate(im,row)[0]
     try:actual=native.evaluate(changed,row)[0]
     except (ValueError,native.cpu.ToolError):continue
     if original!=actual:changes.append(dict(name=name,va=hex(va),old=hex(old),new=hex(byte),input=row,original=original,changed=actual));break
    else:raise ValueError('ineffective COW '+name)
   finally:changed.close()
  negatives=[]
  for name,va,byte in [('record-stride',0x26d429b,3),('key-origin-store',0x26d42b5,0x42),('guard-bound',0x26d4288,0x87)]:
   changed=native.Image();changed.data=mmap.mmap(changed.view.file.fileno(),0,access=mmap.ACCESS_COPY)
   try:
    changed.data[changed.view.offset(va)]=byte
    for row in cases:
     try:native.evaluate(changed,row)
     except (ValueError,native.cpu.ToolError) as e:negatives.append(dict(name=name,va=hex(va),new=hex(byte),input=row,rejected=str(e)));break
    else:raise ValueError('ineffective rejection '+name)
   finally:changed.close()
  assert hashlib.sha256(im.data).hexdigest()==native.SHA
  record=dict(target_sha256=native.SHA,base='05bc2de303c05525b71e7e257426e741bc66a390',rows=len(expected.splitlines()),guard_trap_rows=traps,input_sha256=hashlib.sha256(inputs).hexdigest(),expected_sha256=hashlib.sha256(expected).hexdigest(),owner=dict(start=hex(start),end=hex(end),bytes=len(body),instructions=len(seq),sha256=hashlib.sha256(body).hexdigest(),unwind=frame(im.view,start)),visited_addresses=sorted(seen),visited_bytes=sum(i.size for i in seq if i.address in seen),visited_instructions=len(seen),unvisited='unreachable10B alignmentNOP26d42f6..26d4300',callees=[],exact_body_census=aliases,actual_caller=dict(site=hex(site),bytes=raw.hex(),fde=list(map(hex,caller)),source_lea=hex(lea),source_lea_bytes=lb.hex(),location=hex(loc),path=path,line=line,column=col),captured_process_executed=False,normalization='Exact guardUD2/normalRET plus every payload and named key-pointer-origin coordinate; no record/payload mask, no scalarRAX meaning. Valid disjoint finite memory; readonlykeys; pristine entrytrap; k==n no record/keyread. No ABI/consensus policy.')
  p=native.PACKET;(p/'inputs.jsonl').write_bytes(inputs);(p/'expected.jsonl').write_bytes(expected);(p/'proof.json').write_text(json.dumps(record,indent=2)+'\n');(p/'native-controls.json').write_text(json.dumps(dict(output_changes=changes,rejections=negatives),indent=2)+'\n');(p/'26d4280.gnu.txt').write_text(text);print('FREEZE PASS',record['rows'],record['visited_bytes'],record['visited_instructions'],traps,'guardUD2',len(changes),'outputCOW',len(negatives),'negativeCOW',flush=True)
 finally:im.close()
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--objdump',type=Path,required=True);a=p.parse_args();generate(a.objdump.resolve())
