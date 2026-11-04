"""Complete native owners and selected branch/layout/helper identities."""
import argparse,hashlib,json,re,struct,subprocess
from pathlib import Path
import native
import capstone
from fde_extents import eh_frame_records
P=Path(__file__).resolve().parent

def audit(objdump):
 image=native.Image();data=image.data
 if hashlib.sha256(data).hexdigest()!=native.SHA:raise ValueError('wrong115 target')
 cies,fdes=eh_frame_records(data);_,off,n=image.view.sections['.rela.dyn'];rels={}
 for at in range(off,off+n,24):
  slot,kind,add=struct.unpack_from('<QQq',data,at)
  if kind&0xffffffff==8:
   if slot in rels:raise ValueError('duplicate RELATIVE slot')
   rels[slot]=add
 cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);cs.detail=True
 frozen=json.loads((P/'FREEZE.json').read_text());visited=set(frozen['visited_addresses']);owners=[];parts=[];gnu_parts=[];totals=0
 for spec in json.loads((P/'owners.json').read_text()):
  a=int(spec['start'],16);end=int(spec['end'],16);raw=image.view.read(a,end-a);rows=list(cs.disasm(raw,a));by={x.address:x for x in rows}
  if hashlib.sha256(raw).hexdigest()!=spec['sha256'] or len(rows)!=spec['instructions']:raise ValueError('owner changed')
  matches=[f for f in fdes if (f['start'],f['end'])==(a,end)]
  if len(matches)!=1:raise ValueError('FDE ambiguity')
  unwind={}
  for name,va in [('fde',matches[0]['fde']),('cie',matches[0]['cie'])]:
   at=image.view.offset(va);size=4+struct.unpack_from('<I',data,at)[0];unwind[name]={'va':hex(va),'raw_hex':data[at:at+size].hex()}
  selected=[x for x in rows if a+0xdb<=x.address<a+0xe0 or a+0x198<=x.address<a+0x1e3 or a+0x220<=x.address<a+0x230]
  if any(x.address not in visited for x in selected):raise ValueError('unvisited selected instruction')
  # The supplied post-conversion word is deliberately not derived here. Check
  # only preservation of the state pointer/fields through this local segment.
  conversion=[x for x in rows if a+0xf6<=x.address<a+0x198]
  if any(x.mnemonic in ('call','ret') for x in conversion):raise ValueError('unexpected conversion call')
  if any(op.type==capstone.CS_OP_MEM and op.access&capstone.CS_AC_WRITE for x in conversion for op in x.operands):raise ValueError('conversion writes memory')
  if any(capstone.x86_const.X86_REG_R12 in x.regs_access()[1] for x in conversion):raise ValueError('state pointer modified')
  local_targets=[int(x.op_str,16) for x in conversion if x.mnemonic.startswith('j')]
  if any(not a+0xf6<=target<=a+0x198 for target in local_targets):raise ValueError('conversion CFG escaped')
  label=by[a+0x1c9];op=label.operands[1]
  if op.type!=capstone.CS_OP_MEM or op.mem.base!=capstone.x86_const.X86_REG_RIP:raise ValueError('label RIP changed')
  label_va=label.address+label.size+op.mem.disp
  if image.view.read(label_va,28)!=b'hyperliquidity_ensure_orders' or by[a+0x1d5].bytes.hex()!='48c74424381c000000':raise ValueError('label bytes/length changed')
  calls=[];constants=[]
  for x in rows:
   if x.mnemonic=='call':
    record={'site':hex(x.address),'raw_hex':x.bytes.hex(),'operand':x.op_str,'executed':False}
    if x.op_str.startswith('0x'):record['target']=x.op_str
    elif x.bytes[:2]==b'\xff\x15':
     slot=x.address+x.size+struct.unpack_from('<i',x.bytes,2)[0];record.update(slot=hex(slot),relative_addend=hex(rels[slot]))
    else:record['closure']='dynamic unresolved'
    calls.append(record)
   for operand in x.operands:
    if operand.type==capstone.CS_OP_MEM and operand.mem.base==capstone.x86_const.X86_REG_RIP and x.mnemonic!='call':
     target=x.address+x.size+operand.mem.disp
     if a+0x1c9<=x.address<=a+0x1e3:constants.append({'site':hex(x.address),'target':hex(target),'raw_hex':x.bytes.hex(),'data_hex':image.view.read(target,28 if x.address==a+0x1c9 else operand.size).hex()})
  # A nonzero byte reaches the direct-call setup; its tail jumps to the return
  # epilogue, not into the local calendar/bucket route.
  direct_call=by[a+0xec];tail=by[a+0xf1]
  if direct_call.mnemonic!='call' or tail.mnemonic!='jmp' or int(tail.op_str,16)!=a+0x211:raise ValueError('direct call/tail changed')
  gnu=subprocess.check_output([str(objdump),'-d','--wide','-M','intel',f'--start-address={a:#x}',f'--stop-address={end:#x}',str(native.TARGET)],text=True).replace(str(native.TARGET),'artifacts/node/115/hl-node');parsed=[]
  for line in gnu.splitlines():
   m=re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s)+)',line)
   if m:parsed.append((int(m.group(1),16),bytes.fromhex(m.group(2))))
  if parsed!=[(x.address,bytes(x.bytes)) for x in rows]:raise ValueError('GNU/Capstone bytes differ')
  gnu_parts.append(gnu);parts.extend(f'{x.address:#x}\t{x.bytes.hex()}\t{x.mnemonic}\t{x.op_str}'.rstrip()+'\n' for x in rows)
  owners.append({'start':hex(a),'end':hex(end),'file_offset':image.view.offset(a),'bytes':len(raw),'instructions':len(rows),'selected_instructions':len(selected),'selected_visited':sum(x.address in visited for x in selected),'fde':matches[0],'cie':cies[matches[0]['cie']],'unwind_raw':unwind,'label':{'site':hex(label.address),'va':hex(label_va),'bytes_hex':image.view.read(label_va,28).hex(),'length':28},'constants':constants,'local_conversion_static_preservation':{'instructions':len(conversion),'no_calls_or_memory_writes':True,'R12_unchanged':True,'targets':[hex(t) for t in local_targets],'calendar_semantics_unclosed':True},'direct_handoff':{'boundary':hex(a+0xe0),'call':hex(a+0xec),'target':direct_call.op_str,'tail_target':hex(a+0x211),'callee_unclosed':True},'calls_unclosed':calls});totals+=len(raw)
 (P/'owners.capstone.tsv').write_text(''.join(parts));(P/'owners.gnu.txt').write_text(''.join(gnu_parts));report={'target_sha256':native.SHA,'owner_count':len(owners),'owner_bytes':totals,'full_instructions':sum(x['instructions'] for x in owners),'selected_instructions':sum(x['selected_instructions'] for x in owners),'owners':owners,'native_width_excluded_from_Rust_projection':True,'original_ABI_or_whole_method_claim':False,'gnu_version':subprocess.check_output([str(objdump),'--version'],text=True).splitlines()[0]};(P/'audit.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--objdump',type=Path,required=True);a=p.parse_args();audit(a.objdump.resolve())
