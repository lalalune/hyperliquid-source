"""Seal original stake cursor and qualified posthelper points before independently authored Rust."""
import argparse,hashlib,json,mmap,re,subprocess
from collections import Counter
from pathlib import Path
import native,capstone
from fde_extents import eh_frame_records
def freeze(out,objdump):
 if (native.ROOT/'src/node115-stake-cursor/lib.rs').exists():raise ValueError('freeze refuses existing new Rust')
 if out.exists():raise ValueError('new output required')
 im=native.Image()
 try:
  if hashlib.sha256(im.data).hexdigest()!=native.SHA:raise ValueError('wrong115target')
  inputs,expected,seen,cleanup_calls=native.corpus(im)
  _,fdes=eh_frame_records(im.data);cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
  owners=[];all_rows=[];exports=[]
  for start,end in [(0x294ceb0,0x294cfbe),(native.CLEANUP,0x29ec5a8)]:
   fs=[f for f in fdes if (f['start'],f['end'])==(start,end)];raw=im.view.read(start,end-start);rows=list(cs.disasm(raw,start))
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
   owners.append(dict(start=hex(start),end=hex(end),bytes=end-start,instructions=len(rows),sha256=hashlib.sha256(raw).hexdigest(),unwind=unwind,scope='static full containing body, cursor prefix, independent posthelper point and actual C5 cleanup path only'))
   all_rows+=rows;exports.append((f'{start:x}.gnu.txt',text))
  selected=[i for i in all_rows if any(a<=i.address<b for a,b in native.RANGES)]
  if {i.address for i in selected}!=seen:raise ValueError('selected visitation incomplete')
  redirected=(native.ROWS[1]-native.TABLE).to_bytes(4,'little',signed=True)[1]
  specs=[('cursor-increment',0x294cec4,0xc8),('cursor-increment-overflow',0x294cec6,0x85),('offset-carry',0x294ced3,0x83),('cursor-threshold',0x294cedb,4),('cursor-cap',0x294cee0,3),('bonus-comparison',0x294cf10,0x95),('identity-tail-copy',0x294cf18,0x0f),('posthelper-increment',0x294cf3a,0x29),('posthelper-saturation',0x294cf45,0x42),('relative-row-selection',native.TABLE+1,redirected),('row0-last-column',native.ROWS[0]+24,1),('row1-first-column',native.ROWS[1],0x51),('row2-first-column',native.ROWS[2],0x41),('column-stride',0x294cf64,0x8e),('product-overflow',0x294cf65,0x71),('retained-product',0x294cf69,0xd6),('existing-slot-gate',0x294cf8f,0xa3),('output-raw-tag',0x294cf9e,0xc4)]

  controls=[];fixtures=native.stimuli(im)
  for name,address,byte in specs:
   changed=native.Image();changed.data=mmap.mmap(changed.view.file.fileno(),0,access=mmap.ACCESS_COPY)
   try:
    changed.data[changed.view.offset(address)]=byte
    for row in fixtures:
     before=native.evaluate(im,row)[0]
     try:after=native.evaluate(changed,row)[0]
     except (ValueError,native.cpu.ToolError):continue
     if before!=after:
      controls.append(dict(name=name,va=hex(address),original_byte=im.view.read(address,1).hex(),changed_byte=hex(byte),input=row,original=before,changed=after));break
    else:raise ValueError('ineffective native control '+name)
   finally:changed.close()
  rejected=[]
  for name,address in [('C5-dispatch-slot',native.DROP_SLOT),('C5-return',0x29ec566)]:
   changed=native.Image();changed.data=mmap.mmap(changed.view.file.fileno(),0,access=mmap.ACCESS_COPY)
   try:
    old=changed.data[changed.view.offset(address)];byte=(old+8)&255 if name=='C5-dispatch-slot' else 0x90;changed.data[changed.view.offset(address)]=byte
    row=(1,0,1,0,0,0x1a2)
    try:native.evaluate(changed,row)
    except (ValueError,native.cpu.ToolError) as error:rejected.append(dict(name=name,va=hex(address),original_byte=hex(old),changed_byte=hex(byte),input=row,rejection=str(error)))
    else:raise ValueError('C5 control failed to reject')
   finally:changed.close()
  if hashlib.sha256(im.data).hexdigest()!=native.SHA:raise ValueError('capture changed')
  record=dict(target_sha256=native.SHA,base='05bc2de303c05525b71e7e257426e741bc66a390',rows=len(expected.splitlines()),outcomes=dict(Counter((s.split(b':')[4] if s.startswith(b'E:') else s.split(b':')[3]).decode() for s in expected.splitlines())),point_counts=dict(Counter(s.split(b'\t')[0].decode() for s in inputs.splitlines())),input_sha256=hashlib.sha256(inputs).hexdigest(),expected_sha256=hashlib.sha256(expected).hexdigest(),owners=owners,selected_bytes=sum(b-a for a,b in native.RANGES),selected_instructions=len(selected),spans=[[hex(a),hex(b)] for a,b in native.RANGES],visited_addresses=sorted(seen),actual_cleanup_calls=cleanup_calls,index_table=dict(va=hex(native.TABLE),hex=im.view.read(native.TABLE,16).hex()),observed_rows=[dict(index=i,va=hex(va),columns=list(__import__('struct').unpack('<4Q',im.view.read(va,32))),hex=im.view.read(va,32).hex()) for i,va in enumerate(native.ROWS)],cleanup_C5=dict(slot=hex(native.DROP_SLOT),relative_hex=im.view.read(native.DROP_SLOT,4).hex(),target='0x29ec55f',selected_context='actual C5 branch only, no other tags executed'),new_rust_exists=False,captured_process_executed=False,normalization='actual entry prefix or independently fresh posthelper point; four observed columns are explicit qualified domain, not native validity; C5 cleanup executes actual CALL/RET, other helper/diagnostic/old-tag cleanup routes stop before call. Actual RET/status/RSP/active value or boundary; no fabricated numeric helper return, original enum/types or composed trace',gnu_version=subprocess.check_output([str(objdump),'--version'],text=True).splitlines()[0])
  out.mkdir(parents=True);(out/'inputs.tsv').write_bytes(inputs);(out/'expected.tsv').write_bytes(expected);p=native.PACKET
  (p/'FREEZE.json').write_text(json.dumps(record,indent=2)+'\n');(p/'native-controls.json').write_text(json.dumps(controls,indent=2)+'\n');(p/'cleanup-negative-controls.json').write_text(json.dumps(rejected,indent=2)+'\n')
  for name,text in exports:(p/name).write_text(text)
  (p/'owners.capstone.tsv').write_text(''.join(f'{i.address:x}\t{i.bytes.hex()}\t{i.mnemonic}\t{i.op_str}'.rstrip()+'\n' for i in sorted(all_rows,key=lambda x:x.address)))
  pairs=list(zip(inputs.decode().splitlines(),expected.decode().splitlines()));lookup=dict(pairs);chosen=dict(pairs[::max(1,len(pairs)//36)])
  for c in controls:
   key='\t'.join(map(str,c['input']));chosen[key]=lookup[key]
  for row in [(0,0,0,0,0,0x1a2),(0,4,0,0,0,0x1a2),(0,native.cpu.U64,0,0,0,0x1a2),(1,0,0,0,0,0x1a2),(1,0,native.cpu.U64,1,0,0xc5),(1,0,native.cpu.U64,1,0,0x1a2),(1,0,native.cpu.U64,1,0,0)]:
   key='\t'.join(map(str,row));chosen[key]=lookup[key]
  (p/'target-smoke.tsv').write_text(''.join(a+'\t'+b+'\n' for a,b in chosen.items()));print('FREEZE PASS',record['rows'],record['outcomes'],record['point_counts'],'selected',record['selected_bytes'],record['selected_instructions'],'controls',len(controls),'smokes',len(chosen))
 finally:im.close()
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('--objdump',type=Path,required=True);a=p.parse_args();freeze(a.output.resolve(),a.objdump.resolve())
