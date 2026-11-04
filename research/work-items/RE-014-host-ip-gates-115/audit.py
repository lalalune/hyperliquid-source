"""Revalidate FDEs, independent disassembly, RIP data and relocation bindings."""
import argparse,hashlib,json,re,struct,subprocess
from pathlib import Path
import native,parser,capstone

def audit(objdump):
 image=native.Image()
 if hashlib.sha256(image.data).hexdigest()!=native.SHA:raise ValueError('target mismatch')
 frozen=json.loads((native.PACKET/'PARSER-FREEZE.json').read_text());owners=[];exports=[];gnu=[]
 cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);cs.detail=True
 by={}
 for spec in frozen['owners']:
  a,b=int(spec['start'],16),int(spec['end'],16);raw=image.view.read(a,b-a);rows=list(cs.disasm(raw,a));by.update({x.address:x for x in rows})
  if image.view.fde(a)!=(a,b) or hashlib.sha256(raw).hexdigest()!=spec['sha256'] or len(rows)!=spec['instructions']:raise ValueError('owner mismatch')
  text=subprocess.check_output([str(objdump),'-d','--wide','-M','intel',f'--start-address={a:#x}',f'--stop-address={b:#x}',str(native.TARGET)],text=True).replace(str(native.TARGET),'artifacts/node/115/hl-node')
  parsed=[]
  for line in text.splitlines():
   m=re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s)+)',line)
   if m:parsed.append((int(m.group(1),16),bytes.fromhex(m.group(2))))
  if parsed!=[(x.address,bytes(x.bytes)) for x in rows]:raise ValueError('GNU/Capstone disagree')
  gnu.append(text);exports.extend(f'{x.address:x}\t{x.bytes.hex()}\t{x.mnemonic}\t{x.op_str}\n' for x in rows);owners.append(spec)
 if any(x.mnemonic=='call' for va,x in by.items() if parser.LEAF<=va<parser.LEAF_END):raise ValueError('leaf contains call')
 call=by[0x1562c17]
 if call.mnemonic!='call' or int(call.op_str,16)!=parser.LEAF:raise ValueError('parser call mismatch')
 bindings=[]
 def rip(site):
  x=by[site];op=next(o for o in x.operands if o.type==capstone.CS_OP_MEM and o.mem.base==capstone.x86_const.X86_REG_RIP)
  return x.address+x.size+op.mem.disp
 for site,va,expected in [(0x156269d,0x467788,b"awk '{print $1}'"),(0x15626a8,0x46777a,b"hostname -I | awk '{print $1}'"),(0x156278e,0x4388a2,b'\xc0\x1b/override_public_ip_address\x00'),(0x1562899,0x467798,b'ifconfig.me'),(0x15628b4,0x4677a3,b'api.ipify.org'),(0x15628cf,0x4677b0,b'icanhazip.com')]:
  if rip(site)!=va or image.view.read(va,len(expected))!=expected:raise ValueError('literal binding mismatch')
  bindings.append(dict(site=hex(site),va=hex(va),data_hex=expected.hex(),executed=False))
 # ELF RELATIVE addends, not zero on-disk pointers, bind source/helper slots.
 _,off,size=image.view.sections['.rela.dyn'];rels={}
 for at in range(off,off+size,24):
  slot,kind,add=struct.unpack_from('<QQq',image.data,at)
  if kind&0xffffffff==8:rels[slot]=add
 if rip(0x15627cb)!=0x63fe480:raise ValueError('source location xref changed')
 source=image.view.read(0x63fe480,24);_,length,line,column=struct.unpack('<QQII',source);path=rels[0x63fe480]
 if (path,length,line,column)!=(0x442e9e,13,457,21) or image.view.read(path,length)!=b'base/src/u.rs':raise ValueError('source location changed')
 helpers=[]
 for site,slot,target in [(0x15626ea,0x64e0960,0x1536720),(0x15627e2,0x64e09d8,0x1502320),(0x1562b84,0x64e0ed8,0x1535f10)]:
  if rip(site)!=slot or rels[slot]!=target:raise ValueError('helper binding mismatch')
  helpers.append(dict(site=hex(site),slot=hex(slot),target=hex(target),closed=False))
 report=dict(target_sha256=native.SHA,owners=owners,parser_call=dict(site=hex(call.address),target=hex(parser.LEAF),stub=False),source_location=dict(va='0x63fe480',path='base/src/u.rs',line=line,column=column),bindings=bindings,unclosed_helpers=helpers,captured_process_executed=False,whole_caller_equivalence=False)
 (native.PACKET/'owners.capstone.tsv').write_text(''.join(exports));(native.PACKET/'owners.gnu.txt').write_text(''.join(gnu));(native.PACKET/'audit.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--objdump',type=Path,required=True);a=p.parse_args();audit(a.objdump.resolve())
