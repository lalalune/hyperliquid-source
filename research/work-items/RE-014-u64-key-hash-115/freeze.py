"""Observe original instructions and commit target expectations before new Rust."""
import argparse,hashlib,json,mmap,re,subprocess
from pathlib import Path
import native,capstone
from fde_extents import eh_frame_records

def freeze(out,objdump):
 if (native.ROOT/'src/node115-u64-key-hash/lib.rs').exists():raise RuntimeError('freeze refuses existing new Rust')
 if out.exists():raise ValueError('new output required')
 im=native.Image()
 try:
  if hashlib.sha256(im.data).hexdigest()!=native.SHA:raise ValueError('wrong115target')
  inputs,expected,seen=native.corpus(im);cies,fdes=eh_frame_records(im.data);cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);owners=[];exports=[];gnu=[];rotation=None
  for a,b in [(native.START,native.END),(native.WRITER,native.WRITER_END),(0x46aa570,0x46aa753)]:
   raw=im.view.read(a,b-a);rows=list(cs.disasm(raw,a));fs=[f for f in fdes if (f['start'],f['end'])==(a,b)]
   if len(fs)!=1 or sum(x.size for x in rows)!=b-a:raise ValueError('bad FDE/decode')
   unwind={}
   for name,va in [('fde',fs[0]['fde']),('cie',fs[0]['cie'])]:
    n=4+int.from_bytes(im.view.read(va,4),'little');unwind[name]=dict(va=hex(va),raw_hex=im.view.read(va,n).hex())
   text=subprocess.check_output([str(objdump),'-d','--wide','-M','intel',f'--start-address={a:#x}',f'--stop-address={b:#x}',str(native.TARGET)],text=True).replace(str(native.TARGET),'artifacts/node/115/hl-node');parsed=[]
   for line in text.splitlines():
    m=re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s)+)',line)
    if m:parsed.append((int(m[1],16),bytes.fromhex(m[2])))
   if parsed!=[(x.address,bytes(x.bytes)) for x in rows]:raise ValueError('GNU/Capstone mismatch')
   owners.append(dict(start=hex(a),end=hex(b),bytes=b-a,instructions=len(rows),visited=sum(x.address in seen for x in rows),sha256=hashlib.sha256(raw).hexdigest(),unwind=unwind,scope='static caller context' if a==0x46aa570 else 'original interpreted hash' if a==native.START else 'original writer fixed8/fresh-state only'))
   exports.extend(f'{x.address:x}\t{x.bytes.hex()}\t{x.mnemonic}\t{x.op_str}'.rstrip()+'\n' for x in rows);gnu.append(text)
   if a==native.WRITER:rotation=next(x.address+x.size-1 for x in rows if x.address in seen and x.mnemonic=='rol' and x.op_str.endswith('0xd'))
  controls=[]
  for name,va,byte in [('initializer',0x47172c6,0x74),('length',0x4717337,7),('writer-rotation',rotation,12),('final-xor',0x471739b,0xfe)]:
   changed=native.Image();changed.data=mmap.mmap(changed.view.file.fileno(),0,access=mmap.ACCESS_COPY);changed.data[changed.view.offset(va)]=byte
   row=(1,2,3);before=native.evaluate(im,row)[0];after=native.evaluate(changed,row)[0]
   if before==after:raise ValueError('ineffective actual-byte control '+name)
   controls.append(dict(name=name,va=hex(va),original_byte=im.view.read(va,1).hex(),changed_byte=hex(byte),input=row,original=before,changed=after));changed.close()
  if hashlib.sha256(im.data).hexdigest()!=native.SHA:raise ValueError('capture changed')
  record=dict(target_sha256=native.SHA,base='8fd8db680ec4bfef40996e5616bce3d5156d0b86',rows=len(expected.splitlines()),input_sha256=hashlib.sha256(inputs).hexdigest(),expected_sha256=hashlib.sha256(expected).hexdigest(),owners=owners,visited_addresses=sorted(seen),new_rust_exists=False,captured_process_executed=False,normalization='only raw returned u64; no output masks; synthetic stack saved unknown-register bytes not outputs',gnu_version=subprocess.check_output([str(objdump),'--version'],text=True).splitlines()[0])
  out.mkdir(parents=True);(out/'inputs.tsv').write_bytes(inputs);(out/'expected.tsv').write_bytes(expected);p=native.PACKET
  (p/'FREEZE.json').write_text(json.dumps(record,indent=2)+'\n');(p/'native-controls.json').write_text(json.dumps(controls,indent=2)+'\n');(p/'owners.capstone.tsv').write_text(''.join(exports));(p/'owners.gnu.txt').write_text(''.join(gnu))
  pairs=list(zip(inputs.decode().splitlines(),expected.decode().splitlines()));selected=pairs[::max(1,len(pairs)//40)];(p/'target-smoke.tsv').write_text(''.join(a+'\t'+b+'\n' for a,b in selected));print(json.dumps(record));print('CONTROLS',len(controls),'SMOKE',len(selected))
 finally:im.close()
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('--objdump',type=Path,required=True);a=p.parse_args();freeze(a.output.resolve(),a.objdump.resolve())
