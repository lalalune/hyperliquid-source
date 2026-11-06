"""Authenticate complete fee leaf and freeze actual normal-return observations."""
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
  if parsed!=[(i.address,bytes(i.bytes)) for i in ins]:raise ValueError('GNU/Capstone disagreement')
  for i in ins:
   if im.fetch(i.address).size!=i.size:raise ValueError('evaluator length disagreement')
   if i.mnemonic.startswith('j') and int(i.op_str,0) not in starts:raise ValueError('branch escapes body')
  if starts-seen!={i.address for i in ins if i.address>=0x36e1b5c}:raise ValueError('unexpected unvisited starts')
  caller=0x36a283a;raw=im.view.read(caller,5)
  if raw[0]!=0xe8 or caller+5+int.from_bytes(raw[1:],'little',signed=True)!=start:raise ValueError('caller binding')
  if im.view.read(0x36a2826,12)!=bytes.fromhex('48c784245001000002000000'):raise ValueError('caller width2')
  slots={};_,off,n=im.view.sections['.rela.dyn']
  for q in range(off,off+n,24):
   slot,kind,add=struct.unpack_from('<QQq',im.data,q)
   if slot in [0x6468b98,0x64df620]:
    if kind!=8:raise ValueError('not RELATIVE')
    slots[slot]=add
  if slots!={0x6468b98:0x431b81,0x64df620:0x1680cbf}:raise ValueError('diagnostic binding')
  length,line,col=struct.unpack('<QII',im.view.read(0x6468ba0,16));path=im.view.read(slots[0x6468b98],length).decode()
  if (path,line,col)!=('l1/src/fees/fees.rs',259,57):raise ValueError('source Location')
  witnesses=[[2,[]],[2,[0]],[2,[0,0]],[2,[0,0x3ff0000000000000]],[2,[0x3ff0000000000000,0]],[3,[0,0x3ff0000000000000]],[2,[0,0,0]],[2,[0,0x7ff8000000000001,0x3ff0000000000000]],[3,[0,0,0x3ff0000000000000]],[2,[0,0x3ff0000000000000,0]]]
  changes=[]
  for name,va,byte in [('window-width-load',0x36e1b14,8),('count-load',0x36e1b1b,16),('result-condition',0x36e1b34,0x97),('window-bound',0x36e1b36,0x73),('count-direction',0x36e1b3a,0xc1),('compare-previous',0x36e1b4a,0),('next-stride',0x36e1b4e,0),('skip-equal',0x36e1b4f,0x72),('comparison-direction',0x36e1b4f,0x77)]:
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
  negative=[]
  for name,va,byte in [('width-diagnostic',0x36e1b1f,3),('initial-stride',0x36e1b25,0),('remaining-slot',0x36e1b41,16)]:
   changed=native.Image();changed.data=mmap.mmap(changed.view.file.fileno(),0,access=mmap.ACCESS_COPY)
   try:
    changed.data[changed.view.offset(va)]=byte
    for row in witnesses:
     try:native.evaluate(changed,row)
     except (ValueError,native.cpu.ToolError) as e:negative.append(dict(name=name,va=hex(va),new=hex(byte),input=row,rejected=str(e)));break
    else:raise ValueError('ineffective negativeCOW '+name)
   finally:changed.close()
  if hashlib.sha256(im.data).hexdigest()!=native.SHA:raise ValueError('capture changed')
  record=dict(target_sha256=native.SHA,base='05bc2de303c05525b71e7e257426e741bc66a390',rows=len(expected.splitlines()),input_sha256=hashlib.sha256(inputs).hexdigest(),expected_sha256=hashlib.sha256(expected).hexdigest(),owner=dict(start=hex(start),end=hex(end),bytes=len(body),instructions=len(ins),sha256=hashlib.sha256(body).hexdigest(),unwind=frame(im.view,start)),visited_addresses=sorted(seen),visited_bytes=sum(i.size for i in ins if i.address in seen),visited_instructions=len(seen),unvisited='invalid-width/nonempty diagnostic route36e1b5c..36e1b81, not evaluated or assigned a return',callees=[],context_call=dict(site='0x36e1b7b',slot='0x64df620',target='0x1680cbf',evaluated=False),actual_caller=dict(site=hex(caller),instruction_hex=raw.hex(),fde=list(map(hex,im.view.fde(caller))),width=2),source_location=dict(va='0x6468b98',path=path,line=line,column=col),captured_process_executed=False,normalization='exact AL/consumed-elements coordinate/storedremaining; unchangedwidth/input; ordinary UCOMISD with DAZclear and denormalexceptionmasked; no signalingNaNs. No diagnostic call or fakehelperreturn.')
  p=native.PACKET;(p/'inputs.jsonl').write_bytes(inputs);(p/'expected.jsonl').write_bytes(expected);(p/'proof.json').write_text(json.dumps(record,indent=2)+'\n');(p/'native-controls.json').write_text(json.dumps(dict(output_changes=changes,rejections=negative),indent=2)+'\n');(p/'36e1b10.gnu.txt').write_text(text)
  print('FREEZE PASS',record['rows'],record['visited_bytes'],record['visited_instructions'],len(changes),'outputCOW',len(negative),'negativeCOW',flush=True)
 finally:im.close()
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--objdump',type=Path,required=True);a=p.parse_args();generate(a.objdump.resolve())
