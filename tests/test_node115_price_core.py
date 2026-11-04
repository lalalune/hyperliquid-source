"""Native scalar suffix, corruption controls and unknown-input boundary checks."""
from pathlib import Path
import hashlib,importlib.util,json,sys,unittest,subprocess
ROOT=Path(__file__).resolve().parents[1];P=ROOT/'research/work-items/RE-014-price-core-115';sys.path.insert(0,str(P))
spec=importlib.util.spec_from_file_location('price115_native',P/'native.py');native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
class Price115(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.image=native.Image();cls.record=json.loads((P/'FREEZE.json').read_text())
  if hashlib.sha256(cls.image.blob).hexdigest()!=cls.record['target_sha256']:raise ValueError('wrong115 target')
 def test_pre_rust_smoke_is_native(self):
  for line in (P/'target-smoke.tsv').read_text().splitlines():
   f=line.split('\t');actual,_=native.evaluate(self.image,*map(int,f[:4]));self.assertEqual(actual,'\t'.join(f[4:]))
 def test_four_actual_instruction_corruptions(self):
  controls=json.loads((P/'native-controls.json').read_text());self.assertEqual(len(controls),4)
  for row in controls:
   actual,_=native.evaluate(self.image,*row['inputs'],patch={int(row['va'],16):int(row['after_byte'],16)})
   self.assertEqual(actual,row['after']);self.assertNotEqual(actual,row['before'])
 def test_unknown_bits_and_footprint_fail_closed(self):
  for bad in [-1,1<<64,True]:
   with self.assertRaisesRegex(ValueError,'raw u64'):native.evaluate(self.image,bad,1,1,0)
  m=native.Machine(self.image)
  with self.assertRaisesRegex(ValueError,'unknown GPR'):m.get(('r',native.cpu.RAX),8)
  with self.assertRaisesRegex(ValueError,'unknown low lane'):m.low(('x',0))
  m.xknown[0]=native.U64
  with self.assertRaisesRegex(ValueError,'unknown packed lane'):m.vector(('x',0))
  with self.assertRaisesRegex(ValueError,'footprint'):m.memory.read(native.FIELDS+128,8)
  with self.assertRaisesRegex(ValueError,'footprint'):m.memory.write(native.FIELDS+16,8,1)
 def test_freeze_refuses_existing_component_even_optimized(self):
  before=(P/'frozen').exists()
  result=subprocess.run([sys.executable,'-B','-O',str(P/'freeze-producer.py')],cwd=ROOT,capture_output=True,text=True,timeout=30)
  self.assertNotEqual(result.returncode,0)
  self.assertIn('freeze refuses existing Rust component',result.stderr)
  self.assertEqual((P/'frozen').exists(),before)
 def test_owner_and_rip_constants_remain_bound(self):
  audit=json.loads((P/'audit.json').read_text());owner=json.loads((P/'owner.json').read_text())
  lo,hi=self.image.view.fde(int(owner['start'],16));self.assertEqual((hi-lo,owner['instructions']),(617,147));self.assertEqual(hashlib.sha256(self.image.view.read(lo,hi-lo)).hexdigest(),owner['sha256'])
  for row in audit['selected_rip_constants']:
   self.assertEqual(self.image.view.read(int(row['target'],16),row['size']).hex(),row['data_hex'])
  self.assertEqual(audit['recorded_direct_RIP_callers'],8);self.assertEqual(audit['selected_visited_instructions'],84)
if __name__=='__main__':unittest.main()
