#!/usr/bin/env python3
"""Static reader sibling comparison; no instruction evaluation or target calls."""
from pathlib import Path
import argparse,json,struct,sys
P=Path(__file__).resolve().parent;R=P.parents[2];sys.path.insert(0,str(R/'tools'))
from elf_index import sections
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from capstone.x86 import X86_OP_IMM,X86_OP_MEM,X86_REG_RIP

def need(x,m):
 if not x:raise ValueError(m)
def collect(d):
 ss=sections(d)
 def raw(a,n):
  hits=[s for s in ss if s['type']!=8 and s['address']<=a and a+n<=s['address']+s['size']];need(len(hits)==1,'VA mapping');s=hits[0];o=s['offset']+a-s['address'];return d[o:o+n]
 re=next(x for x in ss if x['name']=='.rela.dyn');writers={}
 for off in range(re['offset'],re['offset']+re['size'],24):
  a,info,add=struct.unpack_from('<QQq',d,off);writers.setdefault(a,[]).append((info,add))
 def target(slot):
  rows=writers[slot];need(len(rows)==1 and rows[0][0]==8,'actual RELATIVE writer');return rows[0][1]
 md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True;out=[]
 for base,sibling,size,table_a,table_b,error_offsets,base_error in [(0x5821250,0x5821340,229,0x935bdc,0x935bec,[0xb8,0xd0],2),(0x58225c0,0x5822710,316,0x935c24,0x935c34,[0x10f,0x127],3)]:
  left=list(md.disasm(raw(base,size),base));right=list(md.disasm(raw(sibling,size),sibling));need(len(left)==len(right),'partition cardinality');diff=[]
  for a,b in zip(left,right):
   offset=a.address-base;need(offset==b.address-sibling and a.size==b.size and a.mnemonic==b.mnemonic,'same instruction skeleton')
   if a.op_str==b.op_str:continue
   reason=None
   if a.mnemonic.startswith('j') and a.operands[0].type==X86_OP_IMM and b.operands[0].type==X86_OP_IMM:
    need(a.operands[0].imm-base==b.operands[0].imm-sibling,'same internal branch destination');reason='same function-relative branch destination'
   elif a.mnemonic=='lea':
    aa=a.operands[-1];bb=b.operands[-1];need(aa.type==bb.type==X86_OP_MEM and aa.mem.base==bb.mem.base==X86_REG_RIP,'jump table operand')
    va=a.address+a.size+aa.mem.disp;vb=b.address+b.size+bb.mem.disp;need((va,vb)==(table_a,table_b),'actual jump table pair')
    xa=struct.unpack('<iiii',raw(va,16));xb=struct.unpack('<iiii',raw(vb,16));need([va+x-base for x in xa]==[vb+x-sibling for x in xb],'same four jump destinations');reason='distinct actual tables select same function-relative destinations'
   elif a.mnemonic=='call':
    aa=a.operands[0];bb=b.operands[0];need(aa.type==bb.type==X86_OP_MEM and aa.mem.base==bb.mem.base==X86_REG_RIP,'indirect call operands')
    va=a.address+a.size+aa.mem.disp;vb=b.address+b.size+bb.mem.disp;ta=target(va);tb=target(vb)
    if offset==0xaa and base==0x5821250:need((ta,tb)==(0x58225c0,0x5822710),'actual matching slow callees');reason='actual matching slow-reader RELATIVE bindings'
    else:need(ta==tb==0x5822700,'shared actual error constructor');reason='same shared error constructor through actual RELATIVE writers'
   elif a.mnemonic=='mov' and offset in error_offsets:
    need(a.op_str==f'esi, {base_error}' and b.op_str=='esi, 5','only expected raw error field changes');reason=f'raw error-constructor field1 {base_error} -> 5'
   need(reason is not None,'unexpected semantic difference')
   diff.append({'offset':hex(offset),'base_va':hex(a.address),'sibling_va':hex(b.address),'base':a.mnemonic+' '+a.op_str,'sibling':b.mnemonic+' '+b.op_str,'reason':reason})
  need(sum(x['reason'].startswith('raw error-constructor') for x in diff)==2,'both invalid branches mapped')
  out.append({'base':hex(base),'sibling':hex(sibling),'bytes_each':size,'instructions_each':len(left),'differences':diff})
 return {'pairs':out,'normalization':'Explicit function-relative branches, actual paired jump-table destinations, actual RELATIVE call targets and specified raw error field1 immediates only. No byte-equivalence credit.','limit':'Static reuse justification; not target execution or original ABI equivalence.'}
if __name__=='__main__':
 ap=argparse.ArgumentParser();ap.add_argument('--freeze',action='store_true');args=ap.parse_args();v=collect((R/'artifacts/node/115/hl-node').read_bytes())
 if args.freeze:(P/'sibling-equivalence.json').write_text(json.dumps(v,indent=2)+'\n')
 else:need(v==json.loads((P/'sibling-equivalence.json').read_text()),'sibling proof drift');print('Two complete scalar sibling pairs match under explicitly retained field/call/table normalization.')
