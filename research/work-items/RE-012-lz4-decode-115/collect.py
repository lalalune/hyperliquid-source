#!/usr/bin/env python3
"""Static authentication only: no captured code or instruction interpreter runs."""
import hashlib,json,re,struct,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'tools'))
from elf_index import sections
from fde_extents import eh_frame_records,uleb
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from capstone.x86 import X86_OP_IMM,X86_OP_MEM,X86_REG_RIP
SHA='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
TARGET=ROOT/'artifacts/node/115/hl-node'
RANGES=[(0x477f8c0,0x4780322),(0x477e5c0,0x477e6d4)]
def need(v,s):
 if not v:raise ValueError(s)
def sha(d):return hashlib.sha256(d).hexdigest()
def dump(x):return json.dumps(x,indent=2,sort_keys=True)+'\n'
class Image:
 def __init__(self,d):
  self.d=d;self.ss=sections(d)
  for name in ['.text','.rela.dyn','.eh_frame','.eh_frame_hdr','.dynsym','.dynstr']:
   need(sum(s['name']==name for s in self.ss)==1,'ambiguous section '+name)
 def read(self,a,n):
  hits=[s for s in self.ss if s['type']!=8 and s['address']<=a and a+n<=s['address']+s['size']]
  need(n>=0 and len(hits)==1,'ambiguous VA');s=hits[0];o=s['offset']+a-s['address'];return self.d[o:o+n]
# Each obligation is the actual instruction sequence, including operand and branch destination.
PINS={
 'prefix minimum':(0x477f8d9,'4883fa030f86d7060000'),
 'little endian prefix':(0x477f8ee,'448b2e'),
 'unsigned prefix admission':(0x477f8f9,'4c39e90f8277080000'),
 'input fast reserve':(0x477f94f,'4883e912480f42c8'),
 'output fast reserve':(0x477f962,'4883e922480f42c8'),
 'empty compressed block':(0x477f978,'4885d20f8468060000'),
 'token and match nibble':(0x477f9f6,'470fb63c2b4d8d65014589fe4183e60f'),
 'fast match extension guard':(0x477fa06,'4983fe0f0f84f0010000'),
 'fast output guard':(0x477fa10,'483bac24a80000000f83e2010000'),
 'fast input guard':(0x477fa1e,'4c3bac24a00000000f83d4010000'),
 'fast literal extension guard':(0x477fa2c,'4180fff00f83ca010000'),
 'literal nibble':(0x477fc05,'41c1ef04'),
 'literal extension threshold':(0x477fc0f,'4180ff0f753c'),
 'literal extension input':(0x477fc24,'4939d40f8379030000'),
 'literal extension u32 overflow':(0x477fc33,'01c80f821a060000'),
 'literal extension continuation':(0x477fc3e,'80f9ff74dd'),
 'literal input before output':(0x477fc61,'4939c70f8718040000'),
 'literal output bound':(0x477fc76,'4939c70f870b040000'),
 'literal helper':(0x477fc8e,'e82de9ffff'),
 'terminal literals':(0x477fca5,'4939d44c8b7c24107223'),
 'zero literal terminal':(0x477fcc4,'4939d44c8b7c24100f83a1020000'),
 'offset truncation':(0x477fcd2,'4d8d6c24024939d50f8770030000'),
 'offset little endian and zero':(0x477fce0,'430fb704234885c00f846a030000'),
 'minimum match':(0x477fcee,'4983c6044983fe137549'),
 'match extension input':(0x477fd10,'4c39e60f847d020000'),
 'match extension u32 overflow':(0x477fd1e,'01f90f8226050000'),
 'match extension continuation':(0x477fd29,'4080ffff74e1'),
 'match extension base':(0x477fd2f,'4189ce4983c613'),
 'match output before history':(0x477fd5d,'4839dd0f8704030000'),
 'overlap branch':(0x477fd6b,'4939c67650'),
 'history underflow':(0x477fd70,'4889f94829c10f82d3010000'),
 'distance one specialization':(0x477fd7c,'66837c240c010f8588000000'),
 'scalar overlap recurrence':(0x477fec6,'440fb6043e4488043948ffc74839fd75d9'),
 'success returned logical length':(0x477ff73,'488b4424504c39e8490f43c5488b4c24304c89294c89790848894110'),
 'literal error tag':(0x4780082,'41be01000000'),
 'input error tag':(0x4780076,'41be02000000'),
 'zero offset tag':(0x4780058,'41be03000000'),
 'history error tag':(0x477ff4f,'41be04000000'),
 'output error tag':(0x478006a,'4989ef4531f6'),
 'error tuple before boxing':(0x47800ab,'4c897424404c897c244848895c2450'),
 'helper capacity':(0x477e5ce,'488b5f104889d84801d00f82dc0000004c8b47084c39c00f87b9000000'),
 'helper length update':(0x477e67c,'4801cb724648895f10'),
}
def obligations(img):
 for name,(a,h) in PINS.items():need(img.read(a,len(bytes.fromhex(h)))==bytes.fromhex(h),'changed obligation '+name)
 return [{'name':k,'va':hex(v[0]),'raw':v[1]} for k,v in PINS.items()]
def rows(text):
 out=[]
 for line in text.splitlines():
  m=re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)(.*)',line)
  if m:out.append((int(m[1],16),bytes.fromhex(m[2])))
 return out
def collect(d,native=False):
 need(len(d)==105896032 and sha(d)==SHA,'wrong capture')
 img=Image(d);pins=obligations(img);cies,fs=eh_frame_records(d,img.ss)
 md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True
 owners=[];calls=[];branches=[];rip=[];exports={};slots=set()
 for a,b in RANGES:
  ff=[f for f in fs if f['start']==a];need(len(ff)==1 and ff[0]['end']==b,'wrong/duplicate FDE');f=ff[0]
  need([v for v in fs if v['start']<b and a<v['end']]==ff,'overlapping FDE')
  body=img.read(a,b-a);ins=list(md.disasm(body,a));rr=[(i.address,bytes(i.bytes)) for i in ins]
  need(b''.join(r for _,r in rr)==body,'incomplete disassembly');bounds={i.address for i in ins}
  for i in ins:
   if i.mnemonic.startswith('j') and i.operands[0].type==X86_OP_IMM:
    to=i.operands[0].imm;need(to in bounds,'branch outside actual instruction boundary');branches.append({'site':hex(i.address),'op':i.mnemonic,'to':hex(to)})
   for op in i.operands:
    if op.type==X86_OP_MEM and op.mem.base==X86_REG_RIP:
     va=i.address+i.size+op.mem.disp;rip.append({'site':hex(i.address),'va':hex(va),'op':i.mnemonic+' '+i.op_str,'raw':bytes(i.bytes).hex()})
   if i.mnemonic=='call':
    op=i.operands[0];r={'site':hex(i.address),'raw':bytes(i.bytes).hex()}
    if op.type==X86_OP_IMM:r['direct']=hex(op.imm)
    elif op.type==X86_OP_MEM and op.mem.base==X86_REG_RIP:
     va=i.address+i.size+op.mem.disp;r['slot']=hex(va);slots.add(va)
    else:r['dynamic']=i.op_str
    calls.append(r)
  frame={}
  for k in ['fde','cie']:
   va=f[k];n=struct.unpack('<I',img.read(va,4))[0]+4;frame[k]={'va':hex(va),'raw':img.read(va,n).hex()}
  lsda=None
  if f['lsda'] is not None:
   raw=img.read(f['lsda'],2048);need(raw[0]==255,'LSDA LPStart');pos=2
   if raw[1]!=255:_,pos=uleb(raw,pos,len(raw))
   need(raw[pos]==1,'LSDA call-site encoding');pos+=1;length,pos=uleb(raw,pos,len(raw));end=pos+length;lr=[]
   while pos<end:
    v=[]
    for _ in range(4):x,pos=uleb(raw,pos,end);v.append(x)
    st,n,lp,action=v;need(not lp or a+lp in bounds,'LSDA landing boundary');lr.append({'start':hex(a+st),'length':n,'landing':hex(a+lp) if lp else None,'action':action})
   need(pos==end,'LSDA table end');lsda={'va':hex(f['lsda']),'raw_header_callsites':raw[:end].hex(),'rows':lr,'limits':'No type/action-chain or unwind execution proof'}
  owners.append({'lsda_callsites':lsda,'start':hex(a),'end':hex(b),'sha256':sha(body),'bytes':b-a,'instructions':len(ins),'fde':f,'frames':frame,'cie':cies[f['cie']]})
  if native:
   for k,cmd in [('gnu',['objdump','-d','-M','intel','--insn-width=16']),('llvm',['llvm-objdump','-d','--x86-asm-syntax=intel'])]:
    t=subprocess.check_output([*cmd,f'--start-address={a}',f'--stop-address={b}',str(TARGET)],text=True)
    need(rows(t)==rr,k+' partitions differ');exports[f'{a:x}.{k}.txt']=t.replace(str(TARGET),'<authenticated-node115>')
 reloc=next(s for s in img.ss if s['name']=='.rela.dyn');need(reloc['size']%24==0,'truncated relocation table')
 rels={}
 location_slots={int(r['va'],16) for r in rip if 0x6496eb0<=int(r['va'],16)<=0x6497700}
 wanted=slots|{0x64e7790}|location_slots
 for o in range(reloc['offset'],reloc['offset']+reloc['size'],24):
  slot,info,addend=struct.unpack_from('<QQq',d,o)
  if slot in wanted:
   need(slot not in rels,'duplicate relocation writer');rels[slot]={'slot':hex(slot),'info':info,'addend':hex(addend),'raw':d[o:o+24].hex()}
 need(set(rels)==wanted and all(v['info']==8 or v['info']&0xffffffff==6 for v in rels.values()),'missing/non-relative selected call binding')
 dyn=next(s for s in img.ss if s['name']=='.dynsym');st=next(s for s in img.ss if s['name']=='.dynstr')
 for v in rels.values():
  if v['info']&0xffffffff==6:
   ix=v['info']>>32;name=struct.unpack_from('<I',d,dyn['offset']+24*ix)[0];off=st['offset']+name;end=d.index(b'\0',off,st['offset']+st['size']);v['external_symbol']=d[off:end].decode()
 need(rels[0x64e7790]['addend']=='0x477f8c0','TCP transform target differs')
 locations=[]
 for slot in sorted(location_slots):
  need(rels[slot]['info']==8,'nonrelative source pointer');ptr=int(rels[slot]['addend'],16);n,line,col=struct.unpack('<QII',img.read(slot+8,16));path=img.read(ptr,n).decode()
  locations.append({'slot':hex(slot),'path':path,'line':line,'column':col})
 # Caller argument transfer and call are credited prior context from PR2076, freshly checked here.
 need(img.read(0x2b79abd,23)==bytes.fromhex('488b4b28488b7368488b5370488d7c2450ff15bc dc9603'.replace(' ','')),'caller binding changed')
 need(img.read(0x7e1aea,20)==b'lz4 bytes over limit','diagnostic differs')
 # Independently map bodies through program headers, rather than the section mapper.
 po=struct.unpack_from('<Q',d,32)[0];pe,pn=struct.unpack_from('<HH',d,54);loads=[]
 for i in range(pn):
  typ,flags,off,va,pa,filesz,memsz,al=struct.unpack_from('<IIQQQQQQ',d,po+i*pe)
  if typ==1:loads.append((va,off,filesz))
 for a,b in RANGES:
  hh=[(va,off) for va,off,n in loads if va<=a and b<=va+n];need(len(hh)==1,'ambiguous PT_LOAD');va,off=hh[0];need(d[off+a-va:off+b-va]==img.read(a,b-a),'PT_LOAD mismatch')
 return {'target_sha256':SHA,'target_bytes':len(d),'base':'8fd8db680ec4bfef40996e5616bce3d5156d0b86','owners':owners,'obligations':pins,'calls':calls,'branches':branches,'rip_references':rip,'source_locations':locations,'relocations':[rels[k] for k in sorted(rels)],'captured_execution':False},exports
if __name__=='__main__':
 out=Path(sys.argv[1]);out.mkdir(parents=True,exist_ok=False);r,es=collect(TARGET.read_bytes(),True)
 (out/'evidence.json').write_text(dump(r))
 for n,s in es.items():(out/n).write_text(s)
 print(dump({'bytes':sum(x['bytes'] for x in r['owners']),'instructions':sum(x['instructions'] for x in r['owners']),'obligations':len(PINS)}))
