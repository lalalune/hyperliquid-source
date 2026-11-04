"""Freeze iterator state/memory observations before the new Rust source."""
import argparse,hashlib,json,re,subprocess
from pathlib import Path
import native,capstone
from fde_extents import eh_frame_records

def freeze(out,objdump):
 if (native.ROOT/'src/node115-tree-next/lib.rs').exists():raise RuntimeError('freeze refuses existing Rust component')
 if out.exists():raise ValueError('refuse existing output directory')
 im=native.Image()
 try:
  if hashlib.sha256(im.data).hexdigest()!=native.SHA:raise ValueError('wrong115target')
  inputs,expected,seen=native.corpus(im)
  subprocess.run(['python3',str(native.PACKET/'probe-extended.py')],check=True)
  cies,fdes=eh_frame_records(im.data);cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);owners=[];exports=[];gnu=[]
  for start,end in [(native.START,native.END),(0x422e280,0x422e403),(0x3bcad50,0x3bcae80)]:
   rows=list(cs.disasm(im.view.read(start,end-start),start));raw=im.view.read(start,end-start);matches=[f for f in fdes if (f['start'],f['end'])==(start,end)]
   if len(matches)!=1 or sum(x.size for x in rows)!=len(raw):raise ValueError('FDE/decode mismatch')
   unwind={}
   for name,va in [('fde',matches[0]['fde']),('cie',matches[0]['cie'])]:
    size=4+int.from_bytes(im.view.read(va,4),'little');unwind[name]=dict(va=hex(va),raw_hex=im.view.read(va,size).hex())
   text=subprocess.check_output([str(objdump),'-d','--wide','-M','intel',f'--start-address={start:#x}',f'--stop-address={end:#x}',str(native.TARGET)],text=True).replace(str(native.TARGET),'artifacts/node/115/hl-node');parsed=[]
   for line in text.splitlines():
    m=re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s)+)',line)
    if m:parsed.append((int(m.group(1),16),bytes.fromhex(m.group(2))))
   if parsed!=[(x.address,bytes(x.bytes)) for x in rows]:raise ValueError('GNU/Capstone mismatch')
   owners.append(dict(start=hex(start),end=hex(end),bytes=len(raw),instructions=len(rows),visited=sum(x.address in seen for x in rows),sha256=hashlib.sha256(raw).hexdigest(),unwind_raw=unwind,scope='interpreted iterator' if start==native.START else 'unexecuted weighted-policy caller context'))
   exports.extend(f'{x.address:x}\t{x.bytes.hex()}\t{x.mnemonic}\t{x.op_str}'.rstrip()+'\n' for x in rows);gnu.append(text)
  record=dict(base='8fd8db680ec4bfef40996e5616bce3d5156d0b86',target_sha256=native.SHA,rows=len(expected.splitlines()),input_sha256=hashlib.sha256(inputs).hexdigest(),expected_sha256=hashlib.sha256(expected).hexdigest(),owners=owners,visited_addresses=sorted(seen),new115_rust_exists=False,captured_process_executed=False,normalization='node handles ->1basedIDs; key/value pointers independently ->node+byteoffset; observerreads20keybytes/u64value; all9statewords; NONEignoresunspecifiedRDX; PARENT/TAGbeforeunclosedpaniccalls',raw_fixture_limits='uniform trees height0..3/fanout2..4 and6,len0..11; synthetic sparse-tower shapes through17exerciseunrolledbranches,notassertedvalidstdBTreevalues; invalidtag/remainingstatesareboundarytests',gnu_version=subprocess.check_output([str(objdump),'--version'],text=True).splitlines()[0])
  if hashlib.sha256(im.data).hexdigest()!=native.SHA:raise ValueError('capture changed')
  out.mkdir(parents=True);(out/'inputs.tsv').write_bytes(inputs);(out/'expected.tsv').write_bytes(expected);(native.PACKET/'FREEZE.json').write_text(json.dumps(record,indent=2)+'\n');(native.PACKET/'owners.capstone.tsv').write_text(''.join(exports));(native.PACKET/'owners.gnu.txt').write_text(''.join(gnu))
  # Selected real rows include deep/unrolled walks, lazy/ready, empty/bad/high tags.
  pairs=list(zip(inputs.decode().splitlines(),expected.decode().splitlines()));selected=[]
  for row,result in pairs:
   f=list(map(int,row.split('\t')))
   if f[4]!=1000:continue
   if (f[0],f[1],f[2],f[3]) in [(0,0,2,0),(0,0,2,2),(0,1,2,2),(1,8,2,2),(1,9,2,2),(1,17,2,2)]:
    if f[6]==-1 or (f[0],f[1],f[6]) in [(0,1,1),(0,0,0)]:selected.append(row+'\t'+result+'\n')
  (native.PACKET/'target-smoke.tsv').write_text(''.join(selected));print(json.dumps(record));print('SMOKE',len(selected))
 finally:im.close()
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('--objdump',type=Path,required=True);a=p.parse_args();freeze(a.output.resolve(),a.objdump.resolve())
