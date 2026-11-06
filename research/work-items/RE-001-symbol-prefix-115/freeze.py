"""Freeze original unqualified prefix results BEFORE any new Rust authorship."""
import argparse,hashlib,json,mmap,re,subprocess
from collections import Counter
from pathlib import Path
import native,capstone
from fde_extents import eh_frame_records
def freeze(out,objdump):
 if (native.ROOT/'src/node115-symbol-prefix/lib.rs').exists():raise ValueError('new Rust already exists')
 if out.exists():raise ValueError('new output required')
 im=native.Image()
 try:
  if hashlib.sha256(im.data).hexdigest()!=native.SHA:raise ValueError('wrong115target')
  inputs,expected,seen=native.corpus(im)
  start,end=0x46dbba0,0x46dc0ac;raw=im.view.read(start,end-start)
  _,fdes=eh_frame_records(im.data);fs=[f for f in fdes if (f['start'],f['end'])==(start,end)]
  cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);rows=list(cs.disasm(raw,start))
  if len(fs)!=1 or sum(i.size for i in rows)!=end-start:raise ValueError('FDE/decode mismatch')
  unwind={}
  for name,a in [('fde',fs[0]['fde']),('cie',fs[0]['cie'])]:
   length=4+int.from_bytes(im.view.read(a,4),'little');unwind[name]={'va':hex(a),'raw_hex':im.view.read(a,length).hex()}
  text=subprocess.check_output([str(objdump),'-d','--wide','-M','intel',f'--start-address={start:#x}',f'--stop-address={end:#x}',str(native.TARGET)],text=True).replace(str(native.TARGET),'artifacts/node/115/hl-node')
  parsed=[]
  for line in text.splitlines():
   m=re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s)+)',line)
   if m:parsed.append((int(m[1],16),bytes.fromhex(m[2])))
  if parsed!=[(x.address,bytes(x.bytes)) for x in rows]:raise ValueError('GNU/Capstone mismatch')
  selected=[i for i in rows if any(a<=i.address<b for a,b in native.RANGES)]
  for ins in selected:
   actual=im.fetch(ins.address)
   if actual.size!=ins.size:raise ValueError('evaluator decode mismatch')
  if not seen<={i.address for i in selected}:raise ValueError('visitation outside selected code')
  specs=[('USDC-shortcut',0x46dbd0e,0x56),('PURR-shortcut',0x46dbd17,0x51),('prefix-first',0x46dbd2e,0x70),('prefix-tail',0x46dbd40,0x70),('plus-sign',0x46dbda4,0x2d),('digit-limit',0x46dbdd2,8),('short-scale',0x46dbde2,0x3a),('long-overflow',0x46dbeb6,0x81),('addition-carry',0x46dbed8,0x75),('formatter-lane',0x46dbe49,0),('formatter-store',0x46dbe4f,0x0d),('digit-pair-table',native.TABLE+1,ord('9'))]
  controls=[];fixtures=native.stimuli()
  for name,a,b in specs:
   changed=native.Image();changed.data=mmap.mmap(changed.view.file.fileno(),0,access=mmap.ACCESS_COPY)
   try:
    changed.data[changed.view.offset(a)]=b
    for raw_input in fixtures:
     before=native.evaluate(im,raw_input)[0]
     try:after=native.evaluate(changed,raw_input)[0]
     except (ValueError,native.cpu.ToolError):continue
     if before!=after:
      controls.append(dict(name=name,va=hex(a),original_byte=im.view.read(a,1).hex(),changed_byte=hex(b),input_hex=raw_input.hex(),original=before,changed=after));break
    else:raise ValueError('ineffective control '+name)
   finally:changed.close()
  if hashlib.sha256(im.data).hexdigest()!=native.SHA:raise ValueError('capture changed')
  record=dict(target_sha256=native.SHA,base='05bc2de303c05525b71e7e257426e741bc66a390',rows=len(expected.splitlines()),outcomes=dict(Counter(s.split(b':')[0].decode() for s in expected.splitlines())),input_sha256=hashlib.sha256(inputs).hexdigest(),expected_sha256=hashlib.sha256(expected).hexdigest(),owner=dict(start=hex(start),end=hex(end),bytes=end-start,instructions=len(rows),sha256=hashlib.sha256(raw).hexdigest(),unwind=unwind),selected_bytes=sum(b-a for a,b in native.RANGES),selected_instructions=len(selected),spans=[[hex(a),hex(b)] for a,b in native.RANGES],visited_addresses=sorted(seen),unvisited_addresses=sorted({i.address for i in selected}-seen),digit_pair_table=dict(va=hex(native.TABLE),bytes=200,sha256=hashlib.sha256(im.view.read(native.TABLE,200)).hexdigest(),hex=im.view.read(native.TABLE,200).hex()),new_rust_exists=False,captured_process_executed=False,normalization='fresh unqualified lane and valid existing frame; exact bytes input; actual RET AL/active RDX/RSP or BEFORE allocator parsed u64 and canonical stack bytes; no allocator/memcpy/memcmp/metadata result or composed caller trace',gnu_version=subprocess.check_output([str(objdump),'--version'],text=True).splitlines()[0])
  out.mkdir(parents=True);(out/'inputs.hex').write_bytes(inputs);(out/'expected.tsv').write_bytes(expected)
  p=native.PACKET
  (p/'FREEZE.json').write_text(json.dumps(record,indent=2)+'\n');(p/'native-controls.json').write_text(json.dumps(controls,indent=2)+'\n');(p/'resolver.gnu.txt').write_text(text)
  (p/'owner.capstone.tsv').write_text(''.join(f'{i.address:x}\t{i.bytes.hex()}\t{i.mnemonic}\t{i.op_str}'.rstrip()+'\n' for i in rows))
  pairs=list(zip(inputs.decode().splitlines(),expected.decode().splitlines()));lookup=dict(pairs);chosen=dict(pairs[::max(1,len(pairs)//45)])
  for c in controls:chosen[c['input_hex']]=lookup[c['input_hex']]
  for s in [b'',b'USDC',b'PURR',b'outcomeToken',b'outcomeToken+',b'outcomeToken0',b'outcomeToken+0',b'outcomeToken00',b'outcomeToken18446744073709551615',b'outcomeToken18446744073709551616',b'outcomeToken'+b'0'*200]:chosen[s.hex()]=lookup[s.hex()]
  (p/'target-smoke.tsv').write_text(''.join(a+'\t'+b+'\n' for a,b in chosen.items()))
  print('FREEZE PASS',record['rows'],record['outcomes'],'selected',record['selected_bytes'],record['selected_instructions'],'visited',len(seen),'controls',len(controls),'smokes',len(chosen))
 finally:im.close()
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('--objdump',type=Path,required=True);a=p.parse_args();freeze(a.output.resolve(),a.objdump.resolve())
