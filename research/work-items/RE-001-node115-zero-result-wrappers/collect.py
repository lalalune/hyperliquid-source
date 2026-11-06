#!/usr/bin/env python3
"""Authenticate and retain one bounded node115 static evidence packet; never execute target."""
import argparse,hashlib,json,platform,re,struct,subprocess,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
sys.dont_write_bytecode=True
sys.path.insert(0,str(ROOT/'tools'))
from elf_index import sections,unwind_index
from fde_extents import eh_frame_records
CONFIG={'packet': 'RE-001-node115-zero-result-wrappers', 'ranges': [(22332096, 22332633), (22332640, 22333177)], 'pins': [{'va': 22332121, 'raw': '807f20000f847c010000', 'name': 'enable-gate-0x0'}, {'va': 22332133, 'raw': '4c8b214c8b6908448b79104c896424', 'name': 'descriptor-copy-0x0'}, {'va': 22332179, 'raw': 'e8d87d0800', 'name': 'guard-entry-0x0'}, {'va': 22332189, 'raw': '4084ed0f8523010000', 'name': 'low-byte-gate-0x0'}, {'va': 22332198, 'raw': '48c7c078fbffff64488338000f8411010000', 'name': 'tls-slot-gate-0x0'}, {'va': 22332231, 'raw': 'e8b46f0800', 'name': 'table-provider-0x0'}, {'va': 22332278, 'raw': '4883f8010f85ae000000', 'name': 'raw-status-gate-0x0'}, {'va': 22332472, 'raw': '488b7c2420486bf03831d2ff155730f904', 'name': 'table-release-arguments-0x0'}, {'va': 22332491, 'raw': '4889dfe8ad86ffff', 'name': 'normal-payload-call-0x0'}, {'va': 22332499, 'raw': '488d7c2408e8532f0200', 'name': 'normal-guard-cleanup-0x0'}, {'va': 22332511, 'raw': '4889dfe89986ffff', 'name': 'disabled-payload-call-0x0'}, {'va': 22332519, 'raw': '31c04881c4c80000005b415c415d415e415f5dc3', 'name': 'zero-result-epilogue-0x0'}, {'va': 22332606, 'raw': '4084ed74084889dfe8852f0000', 'name': 'unwind-payload-cleanup-0x0'}, {'va': 22332665, 'raw': '807f20000f847c010000', 'name': 'enable-gate-0x220'}, {'va': 22332677, 'raw': '4c8b214c8b6908448b79104c896424', 'name': 'descriptor-copy-0x220'}, {'va': 22332723, 'raw': 'e898810800', 'name': 'guard-entry-0x220'}, {'va': 22332733, 'raw': '4084ed0f8523010000', 'name': 'low-byte-gate-0x220'}, {'va': 22332742, 'raw': '48c7c078fbffff64488338000f8411010000', 'name': 'tls-slot-gate-0x220'}, {'va': 22332775, 'raw': 'e8946d0800', 'name': 'table-provider-0x220'}, {'va': 22332822, 'raw': '4883f8010f85ae000000', 'name': 'raw-status-gate-0x220'}, {'va': 22333016, 'raw': '488b7c2420486bf03831d2ff15372ef904', 'name': 'table-release-arguments-0x220'}, {'va': 22333035, 'raw': '4889dfe85d7effff', 'name': 'normal-payload-call-0x220'}, {'va': 22333043, 'raw': '488d7c2408e8332d0200', 'name': 'normal-guard-cleanup-0x220'}, {'va': 22333055, 'raw': '4889dfe8497effff', 'name': 'disabled-payload-call-0x220'}, {'va': 22333063, 'raw': '31c04881c4c80000005b415c415d415e415f5dc3', 'name': 'zero-result-epilogue-0x220'}, {'va': 22333150, 'raw': '4084ed74084889dfe8a5310000', 'name': 'unwind-payload-cleanup-0x220'}], 'data': [], 'normal_zero_epilogues': [[22332519, 22332538], [22333063, 22333082]], 'extra_slots': []}
SHA='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
BASE='05bc2de303c05525b71e7e257426e741bc66a390'
LLVM='/Library/Developer/CommandLineTools/usr/bin/'
def need(ok,why):
 if not ok:raise ValueError(why)
def admit(data):
 need(len(data)==105896032 and hashlib.sha256(data).hexdigest()==SHA,'node115 full identity')
def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',type=Path);args=ap.parse_args()
 data=(ROOT/'artifacts/node/115/hl-node').read_bytes();admit(data)
 secs=sections(data)
 def off(va,n):
  rows=[s for s in secs if s['type']!=8 and s['address']<=va and va+n<=s['address']+s['size']]
  need(len(rows)==1,'unambiguous mapped span');return rows[0]['offset']+va-rows[0]['address']
 def read(va,n):
  o=off(va,n);return data[o:o+n]
 def validate(reader):
  for row in CONFIG['pins']+CONFIG['data']:
   need(reader(row['va'],len(bytes.fromhex(row['raw']))).hex()==row['raw'],'pin '+row['name'])
 validate(read)
 cies,fdes=eh_frame_records(data,secs);_,index=unwind_index(data)
 frames=next(s for s in secs if s['name']=='.eh_frame')
 selected=[];exports={};decoded={};direct=[];rip=[]
 for start,end in CONFIG['ranges']:
  fs=[f for f in fdes if f['start']==start];need(len(fs)==1 and fs[0]['end']==end,'FDE extent')
  f=fs[0];ix=[r for r in index if r['start']==start];need(len(ix)==1 and ix[0]['fde']==f['fde'],'index FDE identity')
  cmd=[LLVM+'llvm-objdump','-d','--x86-asm-syntax=intel',f'--start-address={start:#x}',f'--stop-address={end:#x}','artifacts/node/115/hl-node']
  text=subprocess.check_output(cmd,cwd=ROOT,text=True)
  rows=[];cursor=start
  for line in text.splitlines():
   m=re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)(.*)$',line)
   if not m:continue
   va=int(m[1],16);bs=bytes.fromhex(m[2]);asm=m[3].strip()
   need(va==cursor and read(va,len(bs))==bs and '<unknown>' not in asm,'continuous original instruction bytes');cursor+=len(bs);rows.append((va,bs,asm));decoded[va]=(bs,asm)
  need(cursor==end,'exact decode end')
  boundaries={r[0] for r in rows}
  for va,bs,asm in rows:
   op=asm.split()[0]
   target=None
   if len(bs)==5 and bs[0] in (0xe8,0xe9):target=va+5+struct.unpack_from('<i',bs,1)[0]
   elif len(bs)==2 and (bs[0]==0xeb or 0x70<=bs[0]<=0x7f):target=va+2+int.from_bytes(bs[1:],'little',signed=True)
   elif len(bs)==6 and bs[0]==15 and 0x80<=bs[1]<=0x8f:target=va+6+struct.unpack_from('<i',bs,2)[0]
   if target is not None:
    if op!='call' and start<=target<end:need(target in boundaries,'internal branch boundary')
    direct.append({'site':hex(va),'target':hex(target),'operation':op,'raw':bs.hex(),'in_owner':start<=target<end})
   if bs[:2] in (b'\xff\x15',b'\xff\x25') and len(bs)==6:
    slot=va+6+struct.unpack_from('<i',bs,2)[0];rip.append({'site':hex(va),'slot':hex(slot),'raw':bs.hex()})
  dc=[LLVM+'llvm-dwarfdump','--eh-frame='+hex(f['fde']-frames['address']),'artifacts/node/115/hl-node']
  dt=subprocess.check_output(dc,cwd=ROOT,text=True);need('pc='+format(start,'08x')+'...'+format(end,'08x') in dt,'independent LLVM unwind range')
  exports[f'{start:x}.llvm.txt']=' '.join(cmd)+'\n'+text.rstrip('\n')+'\n'
  exports[f'{start:x}.fde.llvm.txt']=' '.join(dc)+'\n'+dt.rstrip('\n')+'\n'
  def record(va):return read(va,struct.unpack('<I',read(va,4))[0]+4).hex()
  selected.append({'start':hex(start),'end':hex(end),'file_offset':hex(off(start,end-start)),'bytes':end-start,'instruction_rows':len(rows),'body_sha256':hashlib.sha256(read(start,end-start)).hexdigest(),'fde':{k:hex(v) if isinstance(v,int) else v for k,v in f.items()},'fde_raw':record(f['fde']),'cie_raw':record(f['cie'])})
 for row in CONFIG['pins']:need(row['va'] in decoded,'pin on instruction start')
 zero=[]
 for begin,ret in CONFIG['normal_zero_epilogues']:
  need(decoded[begin][0]==b'\x31\xc0' and decoded[ret][1]=='ret','zero/ret anchors')
  between=[(v,asm) for v,(_,asm) in decoded.items() if begin<v<ret]
  need(all(asm.split()[0] in ('add','pop') and not re.search(r'\b(?:rax|eax|ax|al)\b',asm) for _,asm in between),'zero epilogue no RAX writes/calls')
  owner=next(r for r in selected if int(r['start'],16)<=begin<int(r['end'],16))
  rets=[v for v,(_,asm) in decoded.items() if int(owner['start'],16)<=v<int(owner['end'],16) and asm=='ret']
  need(rets==[ret],'sole decoded RET')
  zero.append({'xor_eax_eax':hex(begin),'ret':hex(ret),'sole_ret':True,'epilogue_instructions':len(between),'limit':'ordinary local return only; opaque calls may fail, unwind or not return'})
 # Resolve each actual RIP call/jump slot, without dynamic loading.
 bindings=[]
 for row in rip+[{'site':'data-slot','slot':hex(s),'raw':''} for s in CONFIG.get('extra_slots',[])]:
  slot=int(row['slot'],16);matches=[]
  for sec in secs:
   if sec['name'] not in ('.rela.dyn','.rela.plt'):continue
   need(sec['size']%24==0,'RELA stride')
   for o in range(sec['offset'],sec['offset']+sec['size'],24):
    dst,info,add=struct.unpack_from('<QQq',data,o)
    if dst==slot:matches.append({'slot':hex(slot),'info':hex(info),'addend':hex(add),'file_offset':hex(o),'raw':data[o:o+24].hex()})
  need(len(matches)==1,'unique actual call slot relocation');bindings.append({**row,**matches[0]})
 controls=[]
 for row in CONFIG['pins']+CONFIG['data']:
  at=row['va']+len(bytes.fromhex(row['raw']))-1
  def changed(va,n):
   bs=bytearray(read(va,n))
   if va<=at<va+n:bs[at-va]^=1
   return bytes(bs)
  try:validate(changed)
  except ValueError as error:
   need(str(error)=='pin '+row['name'],'intended control obligation');controls.append({'name':row['name'],'mutated_va':hex(at),'rejected_by':str(error),'outer_digest_bypassed':True,'body_hash_bypassed':True})
  else:raise ValueError('unrejected control')
 # Separate metadata byte-admission checks deliberately bypass the image and body hashes.
 def metadata(reader):
  for owner in selected:
   fva=int(owner['fde']['fde'],16);need(reader(fva,len(bytes.fromhex(owner['fde_raw']))).hex()==owner['fde_raw'],'FDE raw')
  for binding in bindings:
   o=int(binding['file_offset'],16)
   sec=next(s for s in secs if s['type']!=8 and s['offset']<=o< s['offset']+s['size'])
   va=sec['address']+o-sec['offset'];need(reader(va,24).hex()==binding['raw'],'relocation raw')
 metadata(read)
 meta_cases=[('FDE-range-record',int(selected[0]['fde']['fde'],16)+12,'FDE raw')]
 if bindings:
  o=int(bindings[0]['file_offset'],16);sec=next(s for s in secs if s['type']!=8 and s['offset']<=o<s['offset']+s['size'])
  meta_cases.append(('call-slot-record',sec['address']+o-sec['offset']+16,'relocation raw'))
 for label,at,why in meta_cases:
  def altered(va,n):
   bs=bytearray(read(va,n))
   if va<=at<va+n:bs[at-va]^=1
   return bytes(bs)
  try:metadata(altered)
  except ValueError as error:
   need(str(error)==why,'intended metadata obligation');controls.append({'name':label,'mutated_va':hex(at),'rejected_by':why,'outer_digest_bypassed':True,'body_hash_bypassed':True})
  else:raise ValueError('metadata corruption escaped')
 # Identity controls exercise the public pre-parser gate separately.
 identity=[]
 for name,mutant in [('truncated',data[:-1]),('same-size-modified',data[:-1]+bytes([data[-1]^1]))]:
  try:admit(mutant)
  except ValueError:identity.append({'name':name,'rejected':True})
  else:raise ValueError('identity control escaped')
 rec={'packet':CONFIG['packet'],'target_sha256':SHA,'target_size':len(data),'base':BASE,'coordinates':'linked ELF virtual addresses; exclusive ends; mapped section offsets','selected_owners':selected,'instruction_pins':CONFIG['pins'],'selected_data':CONFIG['data'],'direct_edges':direct,'rip_call_bindings':bindings,'normal_zero_epilogues':zero,'negative_controls':controls,'identity_controls':identity,'tools':{'python':platform.python_version(),'host':platform.system()+' '+platform.machine(),'llvm':subprocess.check_output([LLVM+'llvm-objdump','--version'],text=True).splitlines()[0]},'parser_sha256':{s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in ('tools/elf_index.py','tools/fde_extents.py')},'limits':['No target execution or instruction evaluator','Static conditional facts, not runtime equivalence','No Rust reconstruction or acceptance gate','Full repository test gate not claimed; static-only subset is recorded by integration']}
 exports['records.json']=json.dumps(rec,indent=2)+'\n'
 if args.output:
  need(not args.output.exists(),'fresh output directory required');args.output.mkdir(parents=True)
  for name,text in exports.items():(args.output/name).write_text(text)
 else:
  for name,text in exports.items():need((HERE/name).read_text()==text,'exact retained export '+name)
 print(json.dumps({'packet':CONFIG['packet'],'owners':len(selected),'bytes':sum(r['bytes'] for r in selected),'instruction_rows':sum(r['instruction_rows'] for r in selected),'below_hash_controls':len(controls),'identity_controls':len(identity),'outputs':len(exports),'result':'PASS'},sort_keys=True))
if __name__=='__main__':main()
