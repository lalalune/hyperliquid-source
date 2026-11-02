"""Bounded static clone/surplus bridge intake. No target execution/evaluation."""
from pathlib import Path
import sys,json,hashlib,struct,subprocess,re,datetime
ROOT=Path(__file__).resolve().parents[2];HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'tools'))
from info_request_path import Elf
from elf_index import sections
from fde_extents import eh_frame_records
TARGET=Path('/workspace/hyperliquid-re007-row-lookup/artifacts/node/94/hl-node');LLVM='/workspace/.tools/llvm19/usr/lib/llvm-19/bin/llvm-objdump'
raw=TARGET.read_bytes();sha=lambda x:hashlib.sha256(x).hexdigest();assert len(raw)==91774280 and sha(raw)=='3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
elf=Elf(raw);_,fs=eh_frame_records(raw,sections(raw));fs={f['start']:f for f in fs};hva,hoff,_=elf.section('.eh_frame_hdr');assert raw[hoff:hoff+4]==bytes.fromhex('011b033b');pairs={}
for i in range(struct.unpack_from('<I',raw,hoff+8)[0]):
 b=raw[hoff+12+8*i:hoff+20+8*i];a,f=struct.unpack('<ii',b);pairs[hva+a]=(hva+f,hva+12+8*i,b.hex())
def rows(raw):
 out=[]
 for line in raw.decode().splitlines():
  m=re.match(r'\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}(?:\s+|$))+)',line)
  if m:out.append((int(m[1],16),bytes.fromhex(m[2])))
 return out
roles=[('credited-caller',0x37098a0),('credited-surplus',0x37d77e0),('credited-position',0x3717480),('positions-clone-wrapper',0x33ed7f0),('positions-cloner-leaf-selected',0x33eb860),('empty-companion-clone-wrapper',0x33ed610),('found-position-cursor',0x33bd420),('shadow-drop',0x3761d10),('one-leaf-drop-iterator',0x33b4700),('empty-companion-drop',0x33f2df0)]
functions=[]
for role,start in roles:
 f=fs[start];end=f['end'];assert pairs[start][0]==f['fde'];exports=[subprocess.check_output([exe,'-d',*(['-M','intel','--insn-width=16'] if exe=='objdump' else ['--x86-asm-syntax=intel']),'--start-address='+hex(start),'--stop-address='+hex(end),str(TARGET)]) for exe in ['objdump',LLVM]]
 parsed=[rows(b) for b in exports];assert parsed[0]==parsed[1];at=start
 for va,b in parsed[0]:assert va==at and elf.read(va,len(b))==b;at+=len(b)
 assert at==end
 r={'role':role,'start':hex(start),'end':hex(end),'bytes':end-start,'instructions':len(parsed[0]),'body_sha256':sha(elf.read(start,end-start)),'fde':hex(f['fde']),'cie':hex(f['cie']),'lsda':None if f['lsda'] is None else hex(f['lsda']),'header_pair_va':hex(pairs[start][1]),'header_pair_hex':pairs[start][2]}
 for kind in ['fde','cie']:
  n=struct.unpack('<I',elf.read(f[kind],4))[0];r[kind+'_hex']=elf.read(f[kind],n+4).hex()
 for kind,b in zip(['gnu','llvm'],exports):
  name=hex(start)+'.'+kind+'.txt';(HERE/name).write_bytes(b);r[kind+'_file']=name;r[kind+'_sha256']=sha(b)
 functions.append(r)
anchors=[('positions-clone-call',0x370a096,13),('clone-wrapper-nonempty-root',0x33ed7f1,30),('leaf-height-selection',0x33eb877,9),('leaf-allocation-328',0x33ebab9,20),('leaf-copy-load64',0x33ebb18,35),('leaf-copy-store64',0x33ebb64,39),('clone-key-count-and-result',0x33ebb4c,21),('clone-output-root-height-count',0x33ebba4,21),('empty-companion-wrapper',0x33ed634,17),('found-cursor-return',0x33bd525,16),('shadow-new-table-new-divisor',0x370a21a,14),('same-table-skips-mode2',0x370a228,5),('decrease-mode1-call',0x370a254,47),('caller-negative-only',0x370a280,5),('caller-47-and-cleanup',0x370a2eb,31),('caller-nonnegative-cleanup',0x370a285,15),('isolated-lowbit-selector',0x37d77f8,6),('single-position-copy64',0x37d78bb,44),('same-price-source',0x37d7908,30),('forward-mode1-to-position',0x37d7926,26),('surplus-requirement-and-sign',0x37d7947,16),('surplus-subtract-overflow',0x37d78a1,12),('single-node-drop-termination',0x33b4849,50),('selected-leaf-deallocation',0x33b4a51,34),('empty-companion-drop-return',0x33f2dfb,12)]
controls=[{'name':n,'va':hex(va),'hex':elf.read(va,size).hex(),'kind':'coordinate byte identity only'} for n,va,size in anchors]
rels=[];rva,_,size=elf.section('.rela.dyn');rb=elf.read(rva,size)
for slot,target in [(0x576dfd8,0x54c06b0),(0x576e010,0x54c8cb0),(0x57746f0,0x37d77e0),(0x57746d8,0x3717480),(0x5773190,0x358dcd0),(0x5775998,0x3333580)]:
 found=[rb[i:i+24] for i in range(0,size,24) if struct.unpack_from('<Q',rb,i)[0]==slot];assert len(found)==1;_,info,addend=struct.unpack('<QQq',found[0]);assert info==8 and addend==target;rels.append({'slot':hex(slot),'target':hex(target),'hex':found[0].hex()})
table=0x59742c;b=elf.read(table,20);targets=[hex(table+struct.unpack_from('<i',b,4*i)[0]) for i in range(5)];assert targets==['0x3717888','0x37174cb','0x371751f','0x37175b6','0x37174f0']
frozen={'status':'native facts frozen before new decrease oracle/Rust','utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'base':subprocess.check_output(['git','-C',str(ROOT),'rev-parse','HEAD'],text=True).strip(),'target_sha256':sha(raw),'target_bytes':len(raw),'functions':functions,'coordinate_controls':controls,'relocations':rels,'mode_jump_table':{'va':hex(table),'hex':b.hex(),'targets':targets},'domain':['Custom same-table active position, canonical mode word1, requested crossfalse, positive requested leverage strictly below old u32.','Valid one-leaf positions B-tree with one key; matching asset cursor; companion tree empty. Stable readable source and disjoint writable frames.','Allocator ordinary successful return of fresh disjoint0x328-byte leaf; deallocator and overflow-recorder ordinary returns. Their internals/side effects are not closed.','Same validated custom MarginTable supplies maximum/cap; same raw price feeds cap and isolated helper, with nonnegative signed price and checked signed notional/requirement domains for the selected normal path.','External account/custom-table admission, generic trees/cloning, cross aggregate, table change and post-EnterCommit effects remain open.'],'new_oracle_written':False,'new_Rust_written':False,'captured_execution':False,'instruction_interpreter':False}
p=(json.dumps(frozen,sort_keys=True,indent=2)+'\n').encode();(HERE/'NATIVE-FREEZE.json').write_bytes(p);print('freeze',sha(p));print([(f['role'],f['bytes'],f['instructions']) for f in functions]);print('total_export_bytes',sum((HERE/f[k+'_file']).stat().st_size for f in functions for k in ['gnu','llvm']))
