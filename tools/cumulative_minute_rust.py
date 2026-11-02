"""Authorized offline comparison of fourteen raw cumulative-minute windows.
No captured process, clock or assertion/narrowing callee is executed.
"""
import sys,hashlib,json,struct
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import cumulative_minute_static as native
import decimal_scaled_u64 as cpu
import capstone
REGS={name:i for i,name in enumerate(['rax','rcx','rdx','rbx','rsp','rbp','rsi','rdi','r8','r9','r10','r11','r12','r13','r14','r15'])}
class Machine(cpu.Machine):
 def bounds(self,a,n):
  if not cpu.INPUT<=a or a+n>cpu.INPUT+4:raise ValueError('outside raw input word')
 def load(self,a,n):self.bounds(a,n);return super().load(a,n)
 def reload(self,r,a,n):self.bounds(a,n);return super().reload(r,a,n)
 def store(self,*args):raise ValueError('writes forbidden')
 def spill(self,*args):raise ValueError('spills forbidden')
 def call(self,*args):raise ValueError('calls forbidden')
def bind(image):
 cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);cs.detail=True
 spec=json.loads((native.PACKET/'selected-windows.json').read_text());rows=[]
 for owner in spec:
  for block in owner['blocks']:
   a=int(block['start'],16);raw=bytes.fromhex(block['body_hex']);ins=list(cs.disasm(raw,a));assert sum(i.size for i in ins)==len(raw)
   first=ins[0];assert first.mnemonic=='mov' and first.operands[1].type==capstone.CS_OP_MEM and first.operands[1].size==4
   mem=first.operands[1].mem;assert not mem.index;pointer=REGS[first.reg_name(mem.base)]
   branches=[i for i in ins if i.mnemonic in ('ja','jae')];assert len(branches)==2
   lastcmp=[i for i in ins if i.mnemonic=='cmp'][-1];assert lastcmp.operands[0].size==4
   name=lastcmp.reg_name(lastcmp.operands[0].reg);wide='r'+name[1:] if name.startswith('e') else name[:-1];outputreg=REGS[wide]
   rows.append({'start':a,'end':a+len(raw),'pointer':pointer,'displacement':mem.disp,'output_reg':outputreg,'narrow':branches[0].operands[0].imm,'assertion':branches[1].operands[0].imm,'owner':owner['start'],'raw_hex':raw.hex()})
 return rows
def evaluate(image,block,raw):
 m=Machine(image);m.set_reg(block['pointer'],cpu.INPUT-block['displacement'])
 for i,b in enumerate(raw.to_bytes(4,'little')):m.mem[cpu.INPUT+i]=b
 m.pc=block['start']
 for _ in range(32):
  if m.pc==block['narrow']:return 'N',m.seen
  if m.pc==block['assertion']:return 'A',m.seen
  if m.pc==block['end']:return 'V\t'+str(m.get(block['output_reg'],32)),m.seen
  if not block['start']<=m.pc<block['end']:raise ValueError('escaped conversion window')
  m.step()
 raise ValueError('step bound')
def model(raw):
 q=raw//60
 return 'N' if q>65535 else 'A' if q>=1441 else 'V\t'+str(q)

def oracle(binary=native.TARGET):
 data=Path(binary).read_bytes()
 if len(data)!=91774280 or hashlib.sha256(data).hexdigest()!=native.SHA256:raise ValueError('pinned node94 identity mismatch')
 record=native.analyze(data);assert record==json.loads((native.PACKET/'records.json').read_text())
 image=cpu.Image(data);blocks=bind(image)
 values={m*60+d for m in range(1442) for d in [0,1,59]}
 for m in [65534,65535,65536]:values.update(m*60+d for d in [0,1,59])
 values.update([0,1,59,60,0x7fffffff,0x80000000,0xffffffff]);state=0x94c001
 for _ in range(256):state=(state*1664525+1013904223)&0xffffffff;values.add(state)
 values=sorted(values);rawin=''.join(f'{v}\n' for v in values).encode();expected=None;seen=set();window_results=[]
 for block in blocks:
  outputs=[]
  for value in values:
   actual,trace=evaluate(image,block,value);assert actual==model(value),(block['start'],value,actual);outputs.append(actual+'\n');seen.update(trace)
  output=''.join(outputs).encode()
  if expected is None:expected=output
  assert expected==output
  window_results.append({'start':hex(block['start']),'end':hex(block['end']),'rows':len(values),'stdout_sha256':hashlib.sha256(output).hexdigest()})
 controls=[];block=blocks[0];a=block['start'];raw=bytes.fromhex(block['raw_hex'])
 for name,needle,new,probe in [('narrowing',struct.pack('<I',65535),0xfe,65535*60),('inclusive1440',struct.pack('<I',1441),0xa0,86400),('minute-reciprocal',struct.pack('<I',0x88888889),0x88,60)]:
  assert raw.count(needle)==1;va=a+raw.index(needle);off=image.file_offset(va);changed=bytearray(data);old=changed[off];changed[off]=new
  private=cpu.Image(bytes(changed));before,_=evaluate(image,block,probe);after,_=evaluate(private,block,probe);assert before!=after,(name,before,after)
  try:native.analyze(changed)
  except ValueError as error:rejected=str(error)
  else:raise ValueError('static binding accepted changed instruction')
  controls.append({'name':name,'va':hex(va),'old':old,'new':new,'raw_input':probe,'before':before,'after':after,'binding_rejected':rejected})
 return {'inputs':rawin,'expected':expected,'record':record,'controls':controls,'bindings':blocks,'window_results':window_results,'rows':len(values)}
