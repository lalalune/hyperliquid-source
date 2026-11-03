"""Target-only group-reader expectations, before the new Rust source exists."""
from pathlib import Path
import argparse,hashlib,json,subprocess,re,capstone
import native
from fde_extents import eh_frame_records

def freeze(out,objdump):
 if (native.ROOT/'src/node115-ipv6-groups/lib.rs').exists():raise RuntimeError('freeze refuses existing Rust component')
 if out.exists():raise ValueError('refuse existing native output directory')
 im=native.Image()
 try:
  if hashlib.sha256(im.data).hexdigest()!=native.SHA:raise ValueError('wrong115target')
  # Demonstrate the real preexisting interpreter blocker, then its local fix.
  old=native.cpu.Machine(im);old.set_reg(native.cpu.RCX,0x0201);old.pc=0x16860ce
  try:old.step()
  except native.cpu.ToolError as e:before=str(e)
  else:raise ValueError('expected original ROL16 blocker')
  new=native.Machine(im,0);new.set_reg(native.cpu.RCX,0x0201);new.pc=0x16860ce;new.step()
  if new.get(native.cpu.RCX,16)!=0x0102:raise ValueError('local ROL16 repair failed')
  inputs,expected,seen=native.corpus(im);cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);cies,fdes=eh_frame_records(im.data);owners=[];exports=[];gnu=[]
  for start,end in native.RANGES+[(0x167d090,0x167d1e5)]:
   raw=im.view.read(start,end-start);rows=list(cs.disasm(raw,start));matches=[f for f in fdes if (f['start'],f['end'])==(start,end)]
   if len(matches)!=1 or sum(x.size for x in rows)!=len(raw):raise ValueError('incomplete/ambiguous FDE')
   unwind={}
   for name,va in [('fde',matches[0]['fde']),('cie',matches[0]['cie'])]:
    size=4+int.from_bytes(im.view.read(va,4),'little');unwind[name]=dict(va=hex(va),raw_hex=im.view.read(va,size).hex())
   text=subprocess.check_output([str(objdump),'-d','--wide','-M','intel',f'--start-address={start:#x}',f'--stop-address={end:#x}',str(native.TARGET)],text=True).replace(str(native.TARGET),'artifacts/node/115/hl-node');parsed=[]
   for line in text.splitlines():
    m=re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s)+)',line)
    if m:parsed.append((int(m.group(1),16),bytes.fromhex(m.group(2))))
   if parsed!=[(x.address,bytes(x.bytes)) for x in rows]:raise ValueError('GNU/Capstone mismatch')
   exports.extend(f'{x.address:x}\t{x.bytes.hex()}\t{x.mnemonic}\t{x.op_str}'.rstrip()+'\n' for x in rows);gnu.append(text)
   owners.append(dict(start=hex(start),end=hex(end),bytes=len(raw),instructions=len(rows),visited=sum(x.address in seen for x in rows),sha256=hashlib.sha256(raw).hexdigest(),unwind_raw=unwind,scope='group core' if start==native.START else 'fixed-configuration helper' if start==0x167c8b0 else 'reused IPv4 helper' if start==0x167ccb0 else 'unexecuted compression-wrapper context'))
  subprocess.run(['python3',str(native.PACKET/'control-probe.py')],check=True)
  controls=json.loads((native.PACKET/'native-controls.json').read_text());assert len(controls)==9
  if hashlib.sha256(im.data).hexdigest()!=native.SHA:raise ValueError('capture changed')
  record=dict(base='8fd8db680ec4bfef40996e5616bce3d5156d0b86',target_sha256=native.SHA,byte_cases=len(native.stimuli()),rows=len(expected.splitlines()),capacities=list(range(9)),initializations=['zero','5a00+index'],input_sha256=hashlib.sha256(inputs).hexdigest(),expected_sha256=hashlib.sha256(expected).hexdigest(),visited_addresses=sorted(seen),owners=owners,new115_rust_exists=False,source_reuse='IPv4 algorithm already project-MIT at PR2334; disclose reuse, not blind recovery',normalization='RAXcount,DLbit0,independent cursor offset/remaining,all8initializedu16outputwords; no failure-payload equality or whole-wrapper claim',captured_process_executed=False,no_import_substitute=True,gnu_version=subprocess.check_output([str(objdump),'--version'],text=True).splitlines()[0])
  out.mkdir(parents=True);(out/'inputs.tsv').write_bytes(inputs);(out/'expected.tsv').write_bytes(expected)
  for name,obj in [('FREEZE.json',record),('decoder-blocker.json',dict(site='0x16860ce',raw_hex='66c1c108',before=before,after_cx=0x0102,repair='packet-local ROL16 only; maintained decoder unchanged; no new tool PR'))]: (native.PACKET/name).write_text(json.dumps(obj,indent=2)+'\n')
  (native.PACKET/'owners.capstone.tsv').write_text(''.join(exports));(native.PACKET/'owners.gnu.txt').write_text(''.join(gnu))
  lookup=dict(zip(inputs.decode().splitlines(),expected.decode().splitlines()));keys=[]
  for data in [b'',b'1',b'1:2',b'::1',b'1::2',b'1;2',b'ff',b'1:f',b'00001',b'1:00001',b'1.2.3.4',b'1:2:192.0.2.1',b'1:2:01.2.3.4',b'1:bad:x',b'1:2:3:4:5:6:7:8']:
   for cap in (0,1,2,7,8):keys.append(f'{cap}\t1\t{data.hex()}')
  (native.PACKET/'target-smoke.tsv').write_text(''.join(k+'\t'+lookup[k]+'\n' for k in keys));print(json.dumps(record))
 finally:im.close()
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('--objdump',type=Path,required=True);a=p.parse_args();freeze(a.output.resolve(),a.objdump.resolve())
