"""Prepare target-only expectations before any new Rust; never execute capture."""
import argparse,hashlib,json,mmap,subprocess
from pathlib import Path
import native,capstone
from fde_extents import eh_frame_records

def freeze(out,objdump):
 if (native.ROOT/'src/node115-packed-millis/lib.rs').exists():raise RuntimeError('freeze refuses existing Rust component')
 im=native.Image()
 if hashlib.sha256(im.data).hexdigest()!=native.SHA:raise ValueError('wrong target115')
 if out.exists():raise ValueError('refuse existing output directory')
 inputs,expected,seen=native.corpus(im)
 cies,fdes=eh_frame_records(im.data)
 cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);cs.detail=True
 owners=[];exports=[];gnu=[];controls=[]
 for owner,(lo,hi,start,end,reg,disp) in enumerate(native.SPECS):
  if im.view.fde(lo)!=(lo,hi):raise ValueError('FDE mismatch')
  raw=im.view.read(lo,hi-lo);rows=list(cs.disasm(raw,lo));selected=[x for x in rows if start<=x.address<end]
  if sum(x.size for x in rows)!=len(raw):raise ValueError('incomplete owner decode')
  if any(x.mnemonic in ('call','ret') for x in selected):raise ValueError('unclosed conversion edge')
  if any(op.type==capstone.CS_OP_MEM and op.access&capstone.CS_AC_WRITE for x in selected for op in x.operands):raise ValueError('conversion writes memory')
  targets=[int(x.op_str,16) for x in selected if x.mnemonic.startswith('j')]
  if any(not start<=t<=end for t in targets):raise ValueError('conversion CFG escaped')
  if set(x.address for x in selected)!=seen[owner]:raise ValueError('unvisited selected instruction')
  # A separately initialized zero reaches the second owner through its prelude.
  if owner==1:
   prefix=[x for x in rows if 0x423070b<=x.address<start]
   if prefix[0].bytes.hex()!='31d2':raise ValueError('zero correction origin changed')
   if any(capstone.x86_const.X86_REG_RDX in x.regs_access()[1] or capstone.x86_const.X86_REG_EDX in x.regs_access()[1] for x in prefix[1:]):raise ValueError('correction register clobbered')
   if any(x.mnemonic=='call' for x in prefix):raise ValueError('prelude call')
  text=subprocess.check_output([str(objdump),'-d','--wide','-M','intel',f'--start-address={lo:#x}',f'--stop-address={hi:#x}',str(native.TARGET)],text=True).replace(str(native.TARGET),'artifacts/node/115/hl-node')
  import re
  parsed=[]
  for line in text.splitlines():
   match=re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s)+)',line)
   if match:parsed.append((int(match.group(1),16),bytes.fromhex(match.group(2))))
  if parsed!=[(x.address,bytes(x.bytes)) for x in rows]:raise ValueError('GNU/Capstone mismatch')
  gnu.append(text);exports.extend(f'{x.address:x}\t{x.bytes.hex()}\t{x.mnemonic}\t{x.op_str}'.rstrip()+'\n' for x in rows)
  matches=[f for f in fdes if (f['start'],f['end'])==(lo,hi)]
  if len(matches)!=1:raise ValueError('ambiguous unwind owner')
  unwind={}
  for name,va in [('fde',matches[0]['fde']),('cie',matches[0]['cie'])]:
   size=4+int.from_bytes(im.view.read(va,4),'little');unwind[name]=dict(va=hex(va),raw_hex=im.view.read(va,size).hex())
  owners.append(dict(unwind_raw=unwind,start=hex(lo),end=hex(hi),bytes=hi-lo,instructions=len(rows),sha256=hashlib.sha256(raw).hexdigest(),selected_start=hex(start),selected_end=hex(end),selected_instructions=len(selected),selected_visited=len(seen[owner]),input_register=reg,input_displacement=disp,targets=[hex(x) for x in targets]))
  def one(predicate):
   candidates=[x for x in selected if predicate(x)]
   if len(candidates)!=1:raise ValueError('ambiguous mutation anchor')
   return candidates[0]
  year=one(lambda x:x.mnemonic=='sar' and x.operands[-1].type==capstone.CS_OP_IMM and x.operands[-1].imm==13)
  mask=one(lambda x:x.mnemonic=='and' and x.operands[-1].type==capstone.CS_OP_IMM and x.operands[-1].imm==511)
  epoch=one(lambda x:x.mnemonic=='add' and bytes(x.bytes[-4:])==bytes.fromhex('c506f5ff'))
  seconds=selected[1]
  if seconds.mnemonic!='mov' or seconds.operands[1].type!=capstone.CS_OP_MEM or seconds.operands[1].mem.disp!=disp+4:raise ValueError('seconds field changed')
  nanos=one(lambda x:x.mnemonic=='shr' and x.operands[0].reg==capstone.x86_const.X86_REG_RAX and x.operands[-1].imm==50)
  clamp=one(lambda x:x.mnemonic=='cmovg')
  cycle=one(lambda x:x.mnemonic=='imul' and bytes(x.bytes[-4:])==bytes.fromhex('4fc5fdff'))
  witness=(((2000<<13)|(61<<4)),123,123456789);negative=((((-401)<<13)|(1<<4))&0xffffffff,0,0)
  specs=[('year-shift',year.address+year.size-1,12,witness),('ordinal-mask',mask.address+mask.size-4,0xfe,witness),('epoch-bias',epoch.address+epoch.size-4,0xc6,witness),('seconds-field',seconds.address+seconds.size-1,disp+8,witness),('nanos-divisor',nanos.address+nanos.size-1,49,witness),('signed-clamp',clamp.address+clamp.size-2,0x4c,witness),('negative-cycle',cycle.address+cycle.size-4,0x50,negative)]
  for name,va,byte,words in specs:
   mutant=native.Image();mutant.data=mmap.mmap(mutant.view.file.fileno(),0,access=mmap.ACCESS_COPY);mutant.data[mutant.view.offset(va)]=byte
   before,_=native.evaluate(im,owner,words);after,_=native.evaluate(mutant,owner,words)
   if before==after:raise ValueError('nondistinguishing '+name)
   controls.append(dict(owner=owner,name=name,va=hex(va),original_byte=im.view.read(va,1).hex(),mutant_byte=hex(byte),inputs=words,before=before,after=after));mutant.close()
 if hashlib.sha256(im.data).hexdigest()!=native.SHA:raise ValueError('original capture changed')
 record=dict(base='8fd8db680ec4bfef40996e5616bce3d5156d0b86',target_sha256=native.SHA,logical_rows=len(native.stimuli()),physical_rows=len(expected.splitlines()),owners=owners,input_sha256=hashlib.sha256(inputs).hexdigest(),expected_sha256=hashlib.sha256(expected).hexdigest(),visited_addresses=[sorted(x) for x in seen],normalization='RCX as signed64 raw milliseconds; RAX as unsigned64 signed-positive clamp. No masks or model-derived expectations.',new115_rust_exists=False,captured_process_executed=False,gnu_version=subprocess.check_output([str(objdump),'--version'],text=True).splitlines()[0],capstone_version=capstone.__version__)
 out.mkdir(parents=True);(out/'inputs.tsv').write_bytes(inputs);(out/'expected.tsv').write_bytes(expected)
 for name,value in [('FREEZE.json',record),('native-controls.json',controls)]: (out/name).write_text(json.dumps(value,indent=2)+'\n')
 (out/'owners.capstone.tsv').write_text(''.join(exports));(out/'owners.gnu.txt').write_text(''.join(gnu));im.close();print(json.dumps(record))
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('--objdump',type=Path,required=True);args=p.parse_args();freeze(args.output.resolve(),args.objdump.resolve())
