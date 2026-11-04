"""Bind full owner, selected constants, actual call sites and independent unwind."""
import argparse,hashlib,json,re,struct,subprocess
from pathlib import Path
import native
import capstone
from fde_extents import eh_frame_records
P=Path(__file__).resolve().parent

def audit(objdump):
 image=native.Image();blob=image.blob;record=json.loads((P/'FREEZE.json').read_text())
 if hashlib.sha256(blob).hexdigest()!=record['target_sha256']:raise ValueError('wrong115 target')
 lo,hi=image.view.fde(0x3be5790);raw=image.view.read(lo,hi-lo);cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);cs.detail=True;rows=list(cs.disasm(raw,lo))
 owner=json.loads((P/'owner.json').read_text())
 if (lo,hi,len(rows),hashlib.sha256(raw).hexdigest())!=(int(owner['start'],16),int(owner['end'],16),owner['instructions'],owner['sha256']):raise ValueError('owner changed')
 cies,fdes=eh_frame_records(blob);fs=[f for f in fdes if (f['start'],f['end'])==(lo,hi)]
 if len(fs)!=1:raise ValueError('FDE ambiguity')
 _,off,n=image.view.sections['.rela.dyn'];rels={}
 for at in range(off,off+n,24):
  slot,kind,add=struct.unpack_from('<QQq',blob,at)
  if kind&0xffffffff==8:
   if slot in rels:raise ValueError('duplicate relative slot')
   rels[slot]=add
 calls=[];constants=[]
 for x in rows:
  for op in x.operands:
   if op.type==capstone.CS_OP_MEM and op.mem.base==capstone.x86_const.X86_REG_RIP:
    target=x.address+x.size+op.mem.disp
    row={'site':hex(x.address),'raw_hex':x.bytes.hex(),'target':hex(target),'size':op.size,'data_hex':image.view.read(target,op.size).hex()}
    if x.mnemonic=='call':row['relative_addend']=hex(rels[target]);calls.append(row)
    elif x.address in record['visited_addresses']:constants.append(row)
 callers=json.loads((P/'callers.json').read_text())
 for row in callers:
  site=int(row['site'],16);slot=int(row['slot'],16)
  if image.view.read(site,6).hex()!=row['call_raw'] or rels[slot]!=lo:raise ValueError('caller changed')
  frames=[f for f in fdes if f['start']<=site<f['end']]
  if len(frames)!=1 or list(map(hex,(frames[0]['start'],frames[0]['end'])))!=row['caller_fde']:raise ValueError('caller FDE changed')
 text=subprocess.check_output([str(objdump),'-d','--wide','-M','intel',f'--start-address={lo:#x}',f'--stop-address={hi:#x}',str(native.ROOT/'artifacts/node/115/hl-node')],text=True).replace(str(native.ROOT/'artifacts/node/115/hl-node'),'artifacts/node/115/hl-node')
 gnu=[]
 for line in text.splitlines():
  m=re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s)+)',line)
  if m:gnu.append((int(m.group(1),16),bytes.fromhex(m.group(2))))
 if gnu!=[(x.address,bytes(x.bytes)) for x in rows]:raise ValueError('independent disassembly differs')
 unwind={}
 for name,va in [('fde',fs[0]['fde']),('cie',fs[0]['cie'])]:
  at=image.offset(va);size=4+struct.unpack_from('<I',blob,at)[0];unwind[name]={'va':hex(va),'raw_hex':blob[at:at+size].hex()}
 (P/'owner.gnu.txt').write_text(text)
 (P/'owner.capstone.tsv').write_text(''.join(f'{x.address:#x}\t{x.bytes.hex()}\t{x.mnemonic}\t{x.op_str}'.rstrip()+'\n' for x in rows))
 report={'target_sha256':record['target_sha256'],'owner':owner['start'],'owner_file_offset':image.offset(lo),'bytes':len(raw),'full_instruction_rows':len(rows),'selected_visited_instructions':len(record['visited_addresses']),'selected_region_instruction_count':sum(0x3be586d<=x.address<0x3be59f9 or x.address==0x3be57aa for x in rows),'unvisited_selected_addresses':[hex(x.address) for x in rows if (0x3be586d<=x.address<0x3be59f9 or x.address==0x3be57aa) and x.address not in record['visited_addresses']],'fde':fs[0],'cie':cies[fs[0]['cie']],'unwind_raw':unwind,'selected_rip_constants':constants,'prefix_helpers_unclosed':calls,'recorded_direct_RIP_callers':len(callers),'gnu_version':subprocess.check_output([str(objdump),'--version'],text=True).splitlines()[0],'machine_byte_equivalence_or_original_build_claim':False}
 (P/'audit.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--objdump',type=Path,required=True);a=p.parse_args();audit(a.objdump.resolve())
