#!/usr/bin/env python3
"""RE-012: map node115 mutex contended acquisition and futex wait"""
import argparse,hashlib,json,re,struct,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3]
PACKET=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'tools'))
from elf_index import sections
from fde_extents import eh_frame_records
from capstone import Cs,CS_ARCH_X86,CS_MODE_64,__version__ as capstone_version
from capstone.x86 import X86_OP_IMM,X86_OP_MEM,X86_REG_RIP
TARGET=ROOT/'artifacts/node/115/hl-node'
SHA='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
RANGES={'contended': [97010608, 97010839], 'static_acquire_caller': [97112368, 97112467]}
BINDINGS={105776808: 97010608}
IMPORTS={105776824: 'syscall', 105775048: '__errno_location'}
def require(v,m):
 if not v:raise ValueError(m)
def sha(b):return hashlib.sha256(b).hexdigest()
def dump(v):return json.dumps(v,indent=2,sort_keys=True)+'\n'
class Image:
 def __init__(self,b):self.b=b;self.ss=sections(b)
 def offset(self,a,n):
  hits=[s for s in self.ss if s['type']!=8 and s['address']<=a and a+n<=s['address']+s['size']]
  require(n>=0 and len(hits)==1,'ambiguous VA');s=hits[0];return s['offset']+a-s['address']
 def read(self,a,n):
  o=self.offset(a,n);return self.b[o:o+n]
def obligations(im,only=None):
 scope=json.loads((PACKET/'scope.json').read_text());require(scope['target_sha256']==SHA,'wrong scope target')
 if only is not None:require(sum(p['name']==only for p in scope['pins']+scope['data_pins'])==1,'unknown obligation')
 for p in scope['pins']+scope['data_pins']:
  if only is not None and p['name']!=only:continue
  want=bytes.fromhex(p['bytes']);require(im.read(int(p['va'],16),len(want))==want,'changed obligation: '+p['name'])
 return scope

def native_rows(text,join_lock=False):
 rows=[]
 for line in text.splitlines():
  match=re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)',line)
  if match:
   address=int(match[1],16);raw=bytes.fromhex(match[2])
   if join_lock and rows and rows[-1][1]==b'\xf0' and rows[-1][0]+1==address:rows[-1]=(rows[-1][0],b'\xf0'+raw)
   else:rows.append((address,raw))
 return rows

def imports(im):
 rel=next(s for s in im.ss if s['name']=='.rela.dyn')
 syms=next(s for s in im.ss if s['name']=='.dynsym');strings=next(s for s in im.ss if s['name']=='.dynstr')
 require(syms['size']%24==0 and rel['size']%24==0,'truncated symbols or relocations');found={}
 for o in range(rel['offset'],rel['offset']+rel['size'],24):
  a,info,add=struct.unpack_from('<QQq',im.b,o)
  if a in IMPORTS:
   require(a not in found,'duplicate imported writer');index=info>>32
   require(info&0xffffffff==6 and 0<index<syms['size']//24,'invalid import binding')
   so=syms['offset']+index*24;name=struct.unpack_from('<I',im.b,so)[0]
   require(name<strings['size'],'symbol name outside strings');start=strings['offset']+name;end=im.b.find(b'\0',start,strings['offset']+strings['size']);require(end>=0,'unterminated import')
   actual=im.b[start:end].decode();require(actual==IMPORTS[a],'changed import '+hex(a))
   found[a]={'slot':hex(a),'name':actual,'info':info,'symbol_index':index,'weak':im.b[so+4]>>4==2,'symbol_file_offset':hex(so),'symbol_bytes':im.b[so:so+24].hex(),'rela_file_offset':hex(o),'rela_bytes':im.b[o:o+24].hex()}
 require(set(found)==set(IMPORTS),'missing imported writer');return list(found.values())


def collect(data,native=False):
 require(len(data)==105896032 and sha(data)==SHA,'wrong capture')
 im=Image(data);scope=obligations(im);imported=imports(im);_,frames=eh_frame_records(data,im.ss)
 md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True
 owners=[];calls=[];edges=[];exports={};rip_refs=set(BINDINGS);allstarts=set()
 for role,(a,b) in RANGES.items():
  fs=[f for f in frames if f['start']<b and a<f['end']]
  require(len(fs)==1 and (fs[0]['start'],fs[0]['end'])==(a,b),'wrong FDE extent')
  f=fs[0];body=im.read(a,b-a);ins=list(md.disasm(body,a));rows=[(i.address,bytes(i.bytes)) for i in ins]
  require(b''.join(raw for _,raw in rows)==body,'incomplete decode');starts={i.address for i in ins};allstarts.update(starts)
  leaders={a};local_edges=[]
  for i in ins:
   for op in i.operands:
    if op.type==X86_OP_MEM and op.mem.base==X86_REG_RIP:rip_refs.add(i.address+i.size+op.mem.disp)
   if i.mnemonic.startswith('j'):
    op=i.operands[0];edge={'role':role,'site':hex(i.address),'op':i.mnemonic,'bytes':bytes(i.bytes).hex()}
    if op.type==X86_OP_IMM:
     dest=op.imm;edge['to']=hex(dest);edge['local']=a<=dest<b
     if edge['local']:require(dest in starts,'branch into instruction');leaders.add(dest)
    else:edge['dynamic']=i.op_str
    if i.mnemonic!='jmp' and i.address+i.size<b:leaders.add(i.address+i.size);edge['fallthrough']=hex(i.address+i.size)
    edges.append(edge);local_edges.append(edge)
   if i.mnemonic=='call':
    c={'role':role,'site':hex(i.address),'bytes':bytes(i.bytes).hex()};op=i.operands[0]
    if op.type==X86_OP_IMM:c['direct']=hex(op.imm)
    elif op.type==X86_OP_MEM and op.mem.base==X86_REG_RIP:c['slot']=hex(i.address+i.size+op.mem.disp)
    else:c['dynamic']=i.op_str
    calls.append(c)
  unwind={}
  for kind in ['fde','cie']:
   va=f[kind];length=struct.unpack('<I',im.read(va,4))[0]+4;unwind[kind]={'va':hex(va),'bytes':im.read(va,length).hex()}
  owners.append({'role':role,'start':hex(a),'end':hex(b),'length':len(body),'instructions':len(ins),'sha256':sha(body),'file_offset':hex(im.offset(a,b-a)),'unwind':unwind,'lsda':hex(f['lsda']) if f['lsda'] else None,'branch_leaders':[hex(x) for x in sorted(leaders)]})
  if native:
   for name,command in [('gnu',['objdump','-d','-M','intel','--insn-width=16']),('llvm',['llvm-objdump','-d','--x86-asm-syntax=intel'])]:
    text=subprocess.check_output([*command,f'--start-address={a}',f'--stop-address={b}',str(TARGET)],text=True)
    require(native_rows(text,join_lock=name=='llvm')==rows,name+' instruction partition mismatch '+role)
    exports[f'{a:x}.{name}.txt']=text.replace(str(TARGET),'<authenticated-node115>')
 rela=next(s for s in im.ss if s['name']=='.rela.dyn');require(rela['size']%24==0,'truncated relocation section');bindings={}
 for o in range(rela['offset'],rela['offset']+rela['size'],24):
  slot,info,add=struct.unpack_from('<QQq',data,o)
  if slot in rip_refs:
   require(slot not in bindings,'duplicate relocation writer');bindings[slot]={'slot':hex(slot),'info':info,'type':info&0xffffffff,'addend':hex(add),'rela_file_offset':hex(o),'bytes':data[o:o+24].hex()}
 for slot,want in BINDINGS.items():require(slot in bindings and bindings[slot]['info']==8 and int(bindings[slot]['addend'],16)==want,'wrong binding '+hex(slot))
 if native:
  text=subprocess.check_output(['readelf','-wf',str(TARGET)],text=True);blocks=[block for block in text.split('\n\n') if any(f'pc={a:016x}..{b:016x}' in block for a,b in RANGES.values())]
  require(len(blocks)==len(RANGES),'readelf extents disagree');exports['frames.txt']='\n\n'.join(blocks)+'\n'
 return {'target_sha256':SHA,'coordinate_system':'original ELF VA','owners':owners,'scope':scope,'calls':calls,'branches':edges,'relocation_writers':list(bindings.values()),'bindings':{hex(k):hex(v) for k,v in BINDINGS.items()},'imports':imported,'limits':'Static contended acquisition through imported futex wait. Kernel scheduling and caller cleanup remain outside scope.'},exports
if __name__=='__main__':
 ap=argparse.ArgumentParser();ap.add_argument('--out',type=Path,required=True);a=ap.parse_args();require(not a.out.exists(),'output must be fresh');record,exports=collect(TARGET.read_bytes(),True);a.out.mkdir(parents=True);(a.out/'records.json').write_text(dump(record))
 for name,text in exports.items():(a.out/name).write_text(text)
 versions={'python':sys.version.split()[0],'capstone':capstone_version}
 for t in ['objdump','readelf','llvm-objdump']:
  lines=subprocess.check_output([t,'--version'],text=True).splitlines();versions[t]=next((l.strip() for l in lines if 'LLVM version' in l),lines[0])
 (a.out/'tools.json').write_text(dump(versions));print(dump({'fdes':len(record['owners']),'bytes':sum(o['length'] for o in record['owners']),'instructions':sum(o['instructions'] for o in record['owners']),'calls':len(record['calls']),'branches':len(record['branches'])}))
