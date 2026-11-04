"""Observe exact arithmetic and separately seeded continuations before Rust."""
import argparse,hashlib,json,mmap,re,subprocess
from collections import Counter
from pathlib import Path
import native,capstone
from fde_extents import eh_frame_records

def reciprocal_proof(im):
 k=int.from_bytes(im.data[im.view.offset(0x2a824f1):im.view.offset(0x2a824f1)+8],'little')
 d=1953125;delta=k*d-(1<<75);upper=((1<<56)-1)*delta
 if k!=0x44b82fa09b5a53 or delta!=399807 or not 0<upper<1<<75:raise ValueError('reciprocal literal/proof failed')
 return dict(captured_K=k,reduced_divisor=d,divisor=500000000,delta=delta,max_error_numerator=upper,bound=1<<75,kind='algebraic all-u64 proof, not executed-case count')

def freeze(out,objdump):
 if (native.ROOT/'src/node115-raw-threshold/lib.rs').exists():raise ValueError('freeze refuses existing new Rust')
 if out.exists():raise ValueError('new output required')
 im=native.Image()
 try:
  if hashlib.sha256(im.data).hexdigest()!=native.SHA:raise ValueError('wrong115target')
  inputs,expected,seen=native.corpus(im);proof=reciprocal_proof(im);start,end=0x2a82220,0x2a825b2
  _,fdes=eh_frame_records(im.data);fs=[f for f in fdes if (f['start'],f['end'])==(start,end)]
  cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);raw=im.view.read(start,end-start);rows=list(cs.disasm(raw,start))
  if len(fs)!=1 or sum(i.size for i in rows)!=end-start:raise ValueError('FDE/decode mismatch')
  unwind={}
  for name,address in [('fde',fs[0]['fde']),('cie',fs[0]['cie'])]:
   length=4+int.from_bytes(im.view.read(address,4),'little');unwind[name]={'va':hex(address),'raw_hex':im.view.read(address,length).hex()}
  text=subprocess.check_output([str(objdump),'-d','--wide','-M','intel',f'--start-address={start:#x}',f'--stop-address={end:#x}',str(native.TARGET)],text=True).replace(str(native.TARGET),'artifacts/node/115/hl-node')
  parsed=[]
  for line in text.splitlines():
   m=re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s)+)',line)
   if m:parsed.append((int(m[1],16),bytes.fromhex(m[2])))
  if parsed!=[(x.address,bytes(x.bytes)) for x in rows]:raise ValueError('GNU/Capstone mismatch')
  selected=[i for i in rows if any(a<=i.address<b for a,b in native.RANGES)]
  if {i.address for i in selected}!=seen:raise ValueError('selected visitation incomplete')
  U=native.cpu.U64;D=500000000
  specs=[('sum-guard',0x2a824dd,0x83,(0,1,1,0,0,1000)),('secondary-guard',0x2a824e6,0x86,(0,0,0,0,0,1000)),('reciprocal',0x2a824f1,0x52,(0,D,0,0,0,1001)),('pre-shift',0x2a824ee,9,(0,D,0,0,0,1001)),('post-shift',0x2a824ff,10,(0,D,0,0,0,1001)),('inner-clamp',0x2a8250e,0x47,(0,D,0,0,0,1001)),('ceiling',0x2a82508,0x9f,(0,D*4000,0,0,0,5000)),('baseline',0x2a82513,0xe9,(0,0,0,0,0,1000)),('strict-equality',0x2a82525,0x46,(0,0,0,0,0,1000)),('sum-continuation-saturation',0x2a8258d,0x42,(1,U,1,0,0,1000)),('retained-sum-width',0x2a825aa,0x40,(2,1<<32,0,0,0,1001))]
  controls=[]
  for name,address,byte,row in specs:
   changed=native.Image();changed.data=mmap.mmap(changed.view.file.fileno(),0,access=mmap.ACCESS_COPY)
   try:
    changed.data[changed.view.offset(address)]=byte
    before=native.evaluate(im,row)[0];after=native.evaluate(changed,row)[0]
    if before==after:raise ValueError('ineffective native control '+name)
    controls.append(dict(name=name,va=hex(address),original_byte=im.view.read(address,1).hex(),changed_byte=hex(byte),input=row,original=before,changed=after))
   finally:changed.close()
  if hashlib.sha256(im.data).hexdigest()!=native.SHA:raise ValueError('capture changed')
  record=dict(target_sha256=native.SHA,base='05bc2de303c05525b71e7e257426e741bc66a390',rows=len(expected.splitlines()),outcomes=dict(Counter(s.split(b':')[0].decode() for s in expected.splitlines())),input_sha256=hashlib.sha256(inputs).hexdigest(),expected_sha256=hashlib.sha256(expected).hexdigest(),owner=dict(start=hex(start),end=hex(end),bytes=end-start,instructions=len(rows),sha256=hashlib.sha256(raw).hexdigest(),unwind=unwind,scope='static containing context; only three point spans interpreted'),selected_bytes=sum(b-a for a,b in native.RANGES),selected_instructions=len(selected),spans=[[hex(a),hex(b)] for a,b in native.RANGES],visited_addresses=sorted(seen),proof=proof,new_rust_exists=False,captured_process_executed=False,normalization='V raw RDX quotient/RCX threshold/R13 head at2527, or A/B before opaque diagnostic entry; independent point states, not callback returns, composed trace, ABI or native errors',gnu_version=subprocess.check_output([str(objdump),'--version'],text=True).splitlines()[0])
  out.mkdir(parents=True);(out/'inputs.tsv').write_bytes(inputs);(out/'expected.tsv').write_bytes(expected);p=native.PACKET
  (p/'FREEZE.json').write_text(json.dumps(record,indent=2)+'\n');(p/'native-controls.json').write_text(json.dumps(controls,indent=2)+'\n');(p/'owner.gnu.txt').write_text(text);(p/'owner.capstone.tsv').write_text(''.join(f'{i.address:x}\t{i.bytes.hex()}\t{i.mnemonic}\t{i.op_str}'.rstrip()+'\n' for i in rows))
  pairs=list(zip(inputs.decode().splitlines(),expected.decode().splitlines()));sample=pairs[::max(1,len(pairs)//40)]+[('\t'.join(map(str,c['input'])),c['original']) for c in controls];(p/'target-smoke.tsv').write_text(''.join(a+'\t'+b+'\n' for a,b in sample));print('FREEZE PASS',record['rows'],record['outcomes'],'selected',record['selected_bytes'],record['selected_instructions'],'controls',len(controls),'smokes',len(sample))
 finally:im.close()
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('--objdump',type=Path,required=True);a=p.parse_args();freeze(a.output.resolve(),a.objdump.resolve())
