"""Actual call-free compute points, including asymmetric raw-tag widths.

Fresh dispatcher/source fields are premises; no source enum or real caller
validity is inferred. Stops at the following continuation, not a native RET.
"""
from pathlib import Path
import hashlib,json,sys
ROOT=Path(__file__).resolve().parents[3];PACKET=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'tools'))
import decimal_scaled_u64 as cpu
from elfview import View
SHA='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
TARGET=ROOT/'artifacts/node/115/hl-node'
SPECS=[dict(start=0x2b6a7d2,end=0x2b6a834,field=0x78,result=cpu.R13,owner=0x2b69d20),dict(start=0x5a6b620,end=0x5a6b685,field=0x958,result=cpu.R15,owner=0x5a6a640)]
OBJ=cpu.INPUT;SOURCE=OBJ+0x1000
class Image:
 slots={};note_target=None;panic_targets=set()
 def __init__(self):self.view=View(TARGET);self.data=self.view.b;self.cache={}
 def read_only(self,a):return None
 def fetch(self,a):
  if not any(s['start']<=a<s['end'] for s in SPECS):raise ValueError('reader budget CFG escape')
  if a not in self.cache:self.cache[a]=cpu.decode(self.data,self.view.offset(a),a)
  return self.cache[a]
 def close(self):
  if self.data is not self.view.b:self.data.close()
  self.view.b.close();self.view.file.close()
class Machine(cpu.Machine):
 def __init__(self,im,spec):super().__init__(im);self.regions=[(OBJ+spec['field'],OBJ+spec['field']+8),(SOURCE,SOURCE+24)]
 def bounds(self,a,n):
  if not any(lo<=a and a+n<=hi for lo,hi in self.regions):raise ValueError('reader budget footprint')
 def load(self,a,n):self.bounds(a,n);return super().load(a,n)
 def reload(self,r,a,n):self.bounds(a,n);return super().reload(r,a,n)
 def store(self,*args):raise ValueError('reader budget stores forbidden')
 def spill(self,*args):raise ValueError('reader budget stores forbidden')
 def call(self,*args):raise ValueError('reader budget calls forbidden')
def evaluate(im,row):
 alias,tag,start,end=row
 if alias not in [0,1] or any(not 0<=v<=cpu.U64 for v in [tag,start,end]):raise ValueError('raw u64 input required')
 s=SPECS[alias];m=Machine(im,s)
 for a,v in [(OBJ+s['field'],SOURCE),(SOURCE,tag),(SOURCE+8,start),(SOURCE+16,end)]:
  for i,b in enumerate(v.to_bytes(8,'little')):m.mem[a+i]=b
 before=dict(m.mem);m.set_reg(cpu.RBX,OBJ);m.pc=s['start']
 for _ in range(80):
  if m.pc==s['end']:
   value=m.get(s['result'],64)
   if value is None or m.mem!=before:raise ValueError('reader budget unknown value/input mutation')
   return value,m.seen
  m.step()
 raise ValueError('reader budget step bound')
def declared_prediction(report,alias,tag,start,end):
 spec=report['dispatchers'][['twin_a','twin_b'][alias]];values=spec['case_values']
 if 'tag_conditions' in spec:
  for condition in spec['tag_conditions']:
   if tag&int(condition['mask'],16)==condition['equal']:return values[condition['case']]
 else:
  # The retained summary calls the source's first qword the tag and gives
  # no truncation qualifier. Preserve that old declared qword relation;
  # do not mistake a missing-schema exception for the before counterexample.
  if 'tag 2 -> 120, tag 1 -> 10000' not in report['twin_limit_value']:raise ValueError('unrecognized old declaration')
  if tag==2:return values['tag_2']
  if tag==1:return values['tag_1']
 return 1000000000 if end<start else min((end-start+1)*10000000,1000000000)
def check_declared_source(report):
 im=Image()
 try:
  if hashlib.sha256(im.data).hexdigest()!=SHA:raise ValueError('wrong115target')
  observed=[]
  for alias in [0,1]:
   row=(alias,0x100000001,0,9);actual,_=evaluate(im,row);predicted=declared_prediction(report,*row)
   observed.append(dict(alias=alias,raw_tag=hex(row[1]),start=0,end=9,actual=actual,declared_prediction=predicted))
  if any(r['actual']!=r['declared_prediction'] for r in observed):raise ValueError('declared qword-tag contract contradicts original '+json.dumps(observed))
  return observed
 finally:im.close()
def stimuli():
 rows=[];tags=[0,1,2,3,0x100000000,0x100000001,0x100000002,0xffffffff00000001,cpu.U64]
 pairs=[(0,0),(0,1),(0,8),(0,9),(0,10),(0,99),(0,100),(0,cpu.U64),(1,0),(cpu.U64,0),(cpu.U64,cpu.U64),(cpu.U64-1,cpu.U64),(1,1),(10,109),(10,110)]
 for alias in [0,1]:
  for tag in tags:
   for start,end in pairs:rows.append((alias,tag,start,end))
  for low in range(8):
   for high in [0,1,0xffffffff]:rows.append((alias,(high<<32)|low,0,9))
 return list(dict.fromkeys(rows))
def corpus(im):
 inputs=[];expected=[];seen=set()
 for row in stimuli():
  value,trace=evaluate(im,row);inputs.append('\t'.join(map(str,row))+'\n');expected.append(str(value)+'\n');seen|=trace
 return ''.join(inputs).encode(),''.join(expected).encode(),seen
if __name__=='__main__':
 report=json.loads((ROOT/'research/work-items/RE-005-node115-limit-writers/records.json').read_text());print(check_declared_source(report))
