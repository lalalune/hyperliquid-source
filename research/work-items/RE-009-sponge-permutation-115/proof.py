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





def lfsr_constants():
 state=1;out=[]
 for _ in range(24):
  value=0
  for j in range(7):
   if state&1:value^=1<<((1<<j)-1)
   state=((state<<1)^(0x71 if state&0x80 else 0))&255
  out.append(value)
 return out

def corpus_inputs():
 rows=[bytes(200).hex(),('ff'*200),bytes(range(200)).hex(),('aa55'*100),('55aa'*100)]
 for lane in range(25):
  for bit in [0,1,7,8,31,32,62,63]:
   raw=bytearray(200);raw[lane*8:lane*8+8]=(1<<bit).to_bytes(8,'little');rows.append(raw.hex())
  raw=bytearray(200);raw[lane*8:lane*8+8]=bytes([255])*8;rows.append(raw.hex())
 word=0x5b4b3812ab092137
 for _ in range(32):
  raw=bytearray()
  for lane in range(25):
   word^=(word<<13)&native.MASK;word^=word>>7;word^=(word<<17)&native.MASK;word&=native.MASK;raw+=word.to_bytes(8,'little')
  rows.append(raw.hex())
 return list(dict.fromkeys(rows))

def generate(objdump):
 im=native.Image()
 try:
  if hashlib.sha256(im.data).hexdigest()!=native.SHA:raise ValueError('wrong target')
  start,end=native.OWNER
  if im.view.fde(start)!=(start,end):raise ValueError('FDE mismatch')
  body=im.view.read(start,end-start);cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);seq=list(cs.disasm(body,start));by={i.address:i for i in seq}
  if sum(i.size for i in seq)!=len(body):raise ValueError('decode gap')
  for i in seq:
   if im.fetch(i.address).size!=i.size:raise ValueError('evaluator length mismatch')
   if i.mnemonic=='call':raise ValueError('permutation has helpers')
   if i.mnemonic.startswith('j') and int(i.op_str,0) not in by:raise ValueError('branch escapes')
  text=subprocess.check_output([str(objdump),'-d','--wide','-M','intel',f'--start-address={start:#x}',f'--stop-address={end:#x}',str(native.TARGET)],text=True).replace(str(native.TARGET),'artifacts/node/115/hl-node');parsed=[]
  for line in text.splitlines():
   m=re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s)+)',line)
   if m:parsed.append((int(m[1],16),bytes.fromhex(m[2])))
  if parsed!=[(i.address,bytes(i.bytes)) for i in seq]:raise ValueError('GNU/Capstone mismatch')
  table=im.view.read(native.TABLE,192);constants=list(struct.unpack('<24Q',table))
  if constants!=lfsr_constants():raise ValueError('round constants differ from FIPS202 LFSR derivation')
  lea=by[0x5cda7f0];lb=bytes(lea.bytes)
  if lb[:3]!=bytes.fromhex('4c8d05') or lea.address+lea.size+int.from_bytes(lb[3:],'little',signed=True)!=native.TABLE:raise ValueError('actual RC table binding')
  rows=corpus_inputs();expected=[];seen=set();steps=set()
  for index,row in enumerate(rows):
   value,trace,n=native.evaluate(im,row);expected.append(value);seen|=trace;steps.add(n)
   if index%32==0:print('NATIVE',index+1,'of',len(rows),flush=True)
  if seen!=set(by):raise ValueError('unvisited instructions '+str(sorted(set(by)-seen)))
  probes=[rows[0],rows[2],rows[-1]];changes=[];negatives=[]
  anchors=[('round23',0x5cda81d,0xb8)]
  rotates=[i for i in seq if i.mnemonic=='rol' and len(i.bytes)==4]
  for i in [rotates[0],rotates[len(rotates)//2],rotates[-1]]:anchors.append(('rotation-'+hex(i.address),i.address+i.size-1,(i.bytes[-1]+1)&63))
  # Table bytes are read by the real XOR instruction in each actual round.
  for index in [0,1,7,15,23]:anchors.append(('constant-'+str(index),native.TABLE+8*index,table[8*index]^1))
  x=next(i for i in seq if i.mnemonic=='xor' and len(i.bytes)==3 and bytes(i.bytes)[1]==0x31);anchors.append(('theta-xor-to-or',x.address+1,9))
  x=next(i for i in seq if i.mnemonic=='not');anchors.append(('chi-not-to-neg',x.address+x.size-1,x.bytes[-1]^8))
  anchors.append(('lane-input-offset',0x5cda397,0x10))
  for label,va,byte in anchors:
   changed=native.Image();changed.data=mmap.mmap(changed.view.file.fileno(),0,access=mmap.ACCESS_COPY)
   try:
    off=changed.view.offset(va);old=changed.data[off];changed.data[off]=byte
    for row in probes:
     original=native.evaluate(im,row)[0]
     try:actual=native.evaluate(changed,row)[0]
     except (ValueError,native.cpu.ToolError):continue
     if original!=actual:changes.append({'name':label,'va':hex(va),'old':old,'new':byte,'input':row,'original':original,'changed':actual});break
    else:raise ValueError('ineffective outputCOW '+label)
   finally:changed.close()
  for label,va,byte in [('input-read-bound',0x5cda3b1,0xc8),('RC-table-origin',0x5cda7f3,0x22)]:
   changed=native.Image();changed.data=mmap.mmap(changed.view.file.fileno(),0,access=mmap.ACCESS_COPY)
   try:
    off=changed.view.offset(va);old=changed.data[off];changed.data[off]=byte
    try:native.evaluate(changed,rows[0])
    except (ValueError,native.cpu.ToolError) as e:negatives.append({'name':label,'va':hex(va),'old':old,'new':byte,'input':rows[0],'rejected':str(e)})
    else:raise ValueError('ineffective bound control '+label)
   finally:changed.close()
  if hashlib.sha256(im.data).hexdigest()!=native.SHA:raise ValueError('original mutated')
  inputs='\n'.join(rows)+'\n';gold='\n'.join(expected)+'\n';p=native.PACKET
  record={'target_sha256':native.SHA,'base':'05bc2de303c05525b71e7e257426e741bc66a390','rows':len(rows),'input_sha256':hashlib.sha256(inputs.encode()).hexdigest(),'expected_sha256':hashlib.sha256(gold.encode()).hexdigest(),'owner':{'start':hex(start),'end':hex(end),'bytes':len(body),'instructions':len(seq),'sha256':hashlib.sha256(body).hexdigest(),'unwind':frame(im.view,start)},'selected_addresses':sorted(by),'visited_addresses':sorted(seen),'selected_bytes':len(body),'selected_instructions':len(seq),'actual_steps':sorted(steps),'round_table':{'va':hex(native.TABLE),'raw':table.hex(),'sha256':hashlib.sha256(table).hexdigest(),'values':constants,'source_lea':'0x5cda7f0','independent_LFSR_match':True},'qualified_callees':[],'captured_process_executed':False,'normalization':'All200statebytes significant; actual RET/restoredstack and callee-savedregisters; exact access footprint and canaries; no padding/helper/output fields masked. Not absorb/finalize/hash/API/whole-node equivalence.'}
  (p/'inputs.txt').write_text(inputs);(p/'expected.txt').write_text(gold);(p/'proof.json').write_text(json.dumps(record,indent=2)+'\n');(p/'native-controls.json').write_text(json.dumps({'output_changes':changes,'rejections':negatives},indent=2)+'\n');(p/'5cda380.gnu.txt').write_text(text);print('FREEZE PASS',len(rows),len(body),len(seq),len(changes),'outputCOW',len(negatives),'boundCOW',flush=True)
 finally:im.close()
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--objdump',type=Path,required=True);a=p.parse_args();generate(a.objdump.resolve())
