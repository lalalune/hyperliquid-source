#!/usr/bin/env python3
"""Packet-specific static qualification; no captured execution/emulation."""
from pathlib import Path
import argparse,hashlib,json,re,struct,subprocess,sys
P=Path(__file__).resolve().parent;R=P.parents[2];sys.path.insert(0,str(R/'tools'))
from elf_index import sections
from fde_extents import eh_frame_records
from capstone import Cs,CS_ARCH_X86,CS_MODE_64,__version__
from capstone.x86 import X86_OP_IMM,X86_OP_MEM,X86_REG_RIP
SPEC=json.loads((P/'scope.json').read_text());TARGET=R/'artifacts/node/115/hl-node'
def need(v,m):
 if not v:raise ValueError(m)
def sha(d):return hashlib.sha256(d).hexdigest()
def dump(x):return json.dumps(x,indent=2,sort_keys=True)+'\n'
def check_pins(read):
 for v in SPEC['anchors']:need(read(v['va'],len(bytes.fromhex(v['raw'])))==bytes.fromhex(v['raw']),'semantic anchor')
def collect(d,native=False):
 need(sha(d)==SPEC['target_sha256'],'wrong capture');ss=sections(d)
 def read(a,n):
  hit=[s for s in ss if s['type']!=8 and s['address']<=a and a+n<=s['address']+s['size']];need(len(hit)==1,'VA mapping');s=hit[0];o=s['offset']+a-s['address'];return d[o:o+n]
 _,fs=eh_frame_records(d,ss);md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True
 owners=[];calls=[];branches=[];rip=set();exports={}
 for scope in SPEC['ranges']:
  a,b=scope['start'],scope['end'];f=[f for f in fs if f['start']<b and a<f['end']];need(len(f)==1 and (f[0]['start'],f[0]['end'])==(a,b),'FDE boundary');f=f[0];body=read(a,b-a);need(sha(body)==scope['sha256'],'body digest');ins=list(md.disasm(body,a));need(b''.join(bytes(i.bytes) for i in ins)==body,'complete partition');bounds={i.address for i in ins}
  for i in ins:
   for op in i.operands:
    if op.type==X86_OP_MEM and op.mem.base==X86_REG_RIP:rip.add(i.address+i.size+op.mem.disp)
   if i.mnemonic in ['call','jmp'] or i.mnemonic.startswith('j'):
    op=i.operands[0];r={'site':hex(i.address),'op':i.mnemonic,'raw':bytes(i.bytes).hex()}
    if op.type==X86_OP_IMM:r['target']=hex(op.imm)
    elif op.type==X86_OP_MEM and op.mem.base==X86_REG_RIP:r['slot']=hex(i.address+i.size+op.mem.disp)
    else:r['indirect']=i.op_str
    (calls if i.mnemonic=='call' else branches).append(r)
  frames={}
  for k in ['fde','cie']:
   va=f[k];n=struct.unpack('<I',read(va,4))[0]+4;frames[k]={'va':hex(va),'raw':read(va,n).hex()}
  owners.append({'start':hex(a),'end':hex(b),'sha256':sha(body),'bytes':len(body),'instructions':len(ins),'unwind':frames,'lsda':hex(f['lsda']) if f['lsda'] else None})
  if native:
   expected=[(i.address,bytes(i.bytes)) for i in ins]
   for name,cmd in [('gnu',['objdump','-d','-M','intel','--insn-width=16']),('llvm',['llvm-objdump','-d','--x86-asm-syntax=intel'])]:
    text=subprocess.check_output([*cmd,f'--start-address={a}',f'--stop-address={b}',str(TARGET)],text=True);rows=[]
    for line in text.splitlines():
     m=re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)',line)
     if m:rows.append((int(m[1],16),bytes.fromhex(m[2])))
    need(rows==expected,'native partition '+name);exports[f'{a:x}.{name}.txt']=text.replace(str(TARGET),'<authenticated-node115>')
 check_pins(read)
 rela=next(s for s in ss if s['name']=='.rela.dyn');bindings=[]
 for o in range(rela['offset'],rela['offset']+rela['size'],24):
  slot,info,addend=struct.unpack_from('<QQq',d,o)
  if slot in rip:bindings.append({'slot':hex(slot),'info':info,'addend':hex(addend),'raw':d[o:o+24].hex()})
 for v in json.loads((P/'locations.json').read_text()):
  a=int(v['va'],16);binding=next(x for x in bindings if x['slot']==v['va']);need(binding['raw']==v['writer_raw'] and read(a,24).hex()==v['raw'],'Source Location actual writer')
  n=struct.unpack('<Q',read(a+8,8))[0];need(int(binding['addend'],16)==int(v['filename_va'],16),'Source Location addend');need(read(int(v['filename_va'],16),n).decode()==v['filename'],'Source Location path')
 parent_bounds={i.address for i in md.disasm(read(0x5823db0,0x431),0x5823db0)}
 tables=json.loads((P/'dispatch.json').read_text())
 for v in tables:
  a=int(v['va'],16);raw=read(a,20);targets=[a+x for x in struct.unpack('<iiiii',raw)]
  need(raw.hex()==v['raw'] and [hex(x) for x in targets]==v['targets'],'actual parent dispatch table');need(all(x in parent_bounds for x in targets),'actual parent branch boundaries')
 need(tables[0]['targets'][2]=='0x5823e67' and tables[1]['targets'][2]=='0x5823fdb','selected raw-index2 parent arms')
 source=R/'src/node115-fixed20-record-encoder';primitive=json.loads((source/'scalar/PROVENANCE.json').read_text());need(sha((source/'scalar/lib.rs').read_bytes())==primitive['source_sha256'],'vendored scalar source');need(sha((source/'scalar/LICENSE').read_bytes())==primitive['license_sha256'],'vendored scalar license');counter=json.loads((source/'counter/PROVENANCE.json').read_text());need(sha((R/counter['source_path']).read_bytes())==counter['source_sha256'],'actual base counter source')
 if native:
  t=subprocess.check_output(['readelf','-wf',str(TARGET)],text=True);blocks=[v for v in t.split('\n\n') if any(f"pc={x['start']:016x}..{x['end']:016x}" in v for x in SPEC['ranges'])];need(len(blocks)==len(owners),'native FDE');exports['frames.txt']='\n\n'.join(blocks)+'\n'
 return {'target_sha256':sha(d),'coordinate_system':'ELF VA, no masks','owners':owners,'calls':calls,'branches':branches,'bindings':bindings,'anchors':SPEC['anchors'],'limits':'Whole fixed20-prefix/four-scalar type size/wire semantics; original output/panic ABI, allocator identity and other parent variants remain open.'},exports
if __name__=='__main__':
 ap=argparse.ArgumentParser();ap.add_argument('--freeze',action='store_true');args=ap.parse_args();d=TARGET.read_bytes();r,e=collect(d,True)
 if args.freeze:
  (P/'records.json').write_text(dump(r))
  for n,t in e.items():(P/n).write_text(t)
 else:
  need(r==json.loads((P/'records.json').read_text()),'record drift')
  for n,t in e.items():need(t==(P/n).read_text(),'native export drift '+n)
  # Public retained-record corruption controls, in addition to actual input
  # digest controls. These never execute a mutated captured instruction.
  for v in [d[:-1],bytes([d[0]^1])+d[1:]]:
   try:collect(v)
   except ValueError as err:need(str(err)=='wrong capture','identity rejection')
   else:raise ValueError('identity corruption accepted')
  ss=sections(d)
  for pin in SPEC['anchors']:
   a=pin['va'];n=len(bytes.fromhex(pin['raw']))
   def modified_read(va,size):
    sec=next(s for s in ss if s['type']!=8 and s['address']<=va and va+size<=s['address']+s['size']);off=sec['offset']+va-sec['address'];raw=bytearray(d[off:off+size])
    if va<=a+n-1<va+size:raw[a+n-1-va]^=1
    return bytes(raw)
   try:check_pins(modified_read)
   except ValueError:pass
   else:raise ValueError('anchor mutation accepted')
  print(dump({'anchor_mutations_rejected':len(SPEC['anchors']),'owners':len(r['owners']),'bytes':sum(x['bytes'] for x in r['owners']),'instructions':sum(x['instructions'] for x in r['owners']),'native_partitions':'GNU = LLVM = Capstone','identity_controls_rejected':2,'execution_or_emulation':False,'python':sys.version.split()[0],'capstone':__version__}))
