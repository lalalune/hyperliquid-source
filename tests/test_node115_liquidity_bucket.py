"""Digest-specific route/state controls, no target process or opaque helpers."""
from pathlib import Path
import hashlib,importlib.util,json,mmap,sys,unittest,subprocess
ROOT=Path(__file__).resolve().parents[1];P=ROOT/'research/work-items/RE-014-liquidity-bucket-115';sys.path.insert(0,str(P));spec=importlib.util.spec_from_file_location('liquidity115_native',P/'native.py');native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
class LiquidityBucket115(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.image=native.Image();cls.addClassCleanup(cls.image.close)
  if hashlib.sha256(cls.image.data).hexdigest()!=native.SHA:raise ValueError('wrong115 target')
 def test_frozen_smoke_routes_are_native(self):
  for line in (P/'target-smoke.tsv').read_text().splitlines():
   f=line.split('\t');actual,_=native.select(self.image,*map(int,f[:5]));projection=actual[:4] if actual[0]=='T' else actual[:1]
   self.assertEqual('\t'.join(map(str,projection)),'\t'.join(f[5:]))
 def test_18_actual_corruptions_include_independent_divisor(self):
  controls=json.loads((P/'native-controls.json').read_text());self.assertEqual(len(controls),18);semantic_changes=0
  for row in controls:
   image=native.Image();self.addCleanup(image.close);image.data=mmap.mmap(image.view.file.fileno(),0,access=mmap.ACCESS_COPY);image.data[image.view.offset(int(row['va'],16))]=int(row['mutant_byte'],16)
   actual,_=native.select(image,row['owner'],*row['inputs']);self.assertEqual(list(actual),row['after']);self.assertNotEqual(list(actual),row['before'])
   before=row['before'];a=actual[:4] if actual[0]=='T' else actual[:1];b=before[:4] if before[0]=='T' else before[:1];semantic_changes+=list(a)!=list(b)
  self.assertEqual(semantic_changes,15)
 def test_full_owners_labels_and_local_preservation(self):
  audit=json.loads((P/'audit.json').read_text());self.assertEqual((audit['owner_count'],audit['owner_bytes'],audit['full_instructions']),(3,1890,489))
  for owner in audit['owners']:
   self.assertEqual(self.image.view.read(int(owner['label']['va'],16),28),b'hyperliquidity_ensure_orders');self.assertEqual(owner['selected_instructions'],owner['selected_visited']);self.assertTrue(owner['local_conversion_static_preservation']['no_calls_or_memory_writes'])
   for row in owner['constants']:self.assertEqual(self.image.view.read(int(row['target'],16),len(bytes.fromhex(row['data_hex']))).hex(),row['data_hex'])
 def test_unknown_and_invalid_input_rejected(self):
  m=native.Machine(self.image)
  self.assertIsNone(m.get(native.cpu.RAX,64))
  m.pc=native.SITES[0]+0xdb;m.step()
  with self.assertRaisesRegex(native.cpu.ToolError,'unknown flags'):m.step()
  for bad in [-1,1<<64,True]:
   with self.assertRaisesRegex(ValueError,'raw u64'):native.select(self.image,0,0,bad,1,0)
  with self.assertRaisesRegex(ValueError,'footprint'):m.load(native.cpu.INPUT+0x80,8)
 def test_spill_reload_cannot_bypass_footprint(self):
  m=native.Machine(None);m.set_reg(native.cpu.RAX,0x1122334455667788);outside=native.cpu.INPUT+0x80
  for operation,args in [(m.spill,(outside,native.cpu.RAX,8)),(m.reload,(native.cpu.RAX,outside,8))]:
   with self.assertRaisesRegex(ValueError,'bounded footprint'):operation(*args)
  self.assertFalse(m.mem)
  m=native.Machine(self.image);m.set_reg(native.cpu.RAX,0x1122334455667788);m.set_reg(native.cpu.R12,outside-0x28);m.pc=native.SITES[0]+0x1c1
  with self.assertRaisesRegex(ValueError,'bounded footprint'):m.step()
  self.assertFalse(m.mem)
 def test_pre_rust_guard_survives_optimized_python(self):
  before=(P/'frozen').exists();r=subprocess.run([sys.executable,'-B','-O',str(P/'freeze-producer.py')],cwd=ROOT,capture_output=True,text=True,timeout=30)
  self.assertNotEqual(r.returncode,0);self.assertIn('freeze refuses existing Rust component',r.stderr);self.assertEqual((P/'frozen').exists(),before)
if __name__=='__main__':unittest.main()
