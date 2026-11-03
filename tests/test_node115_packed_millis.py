"""Target-backed raw time conversion, independent fields and guard controls."""
from pathlib import Path
import hashlib,json,mmap,subprocess,sys,unittest
ROOT=Path(__file__).resolve().parents[1];P=ROOT/'research/work-items/RE-014-packed-millis-115';sys.path.insert(0,str(P));import native
class PackedMillis115(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.image=native.Image();cls.addClassCleanup(cls.image.close)
  if hashlib.sha256(cls.image.data).hexdigest()!=native.SHA:raise ValueError('wrong115target')
 def test_native_frozen_smoke_all_five_instances(self):
  for line in (P/'target-smoke.tsv').read_text().splitlines():
   f=list(map(int,line.split('\t')));actual,_=native.evaluate(self.image,f[0],f[1:4]);self.assertEqual(actual,tuple(f[4:]))
 def test_35_actual_code_corruptions_keep_raw_negative_observations(self):
  controls=json.loads((P/'native-controls.json').read_text());self.assertEqual(len(controls),35);raw_only=0
  for row in controls:
   im=native.Image();self.addCleanup(im.close);im.data=mmap.mmap(im.view.file.fileno(),0,access=mmap.ACCESS_COPY);im.data[im.view.offset(int(row['va'],16))]=int(row['mutant_byte'],16)
   actual,_=native.evaluate(im,row['owner'],row['inputs']);self.assertEqual(list(actual),row['after']);self.assertNotEqual(list(actual),row['before']);raw_only+=row['name']=='negative-cycle' and actual[1]==row['before'][1]==0 and actual[0]!=row['before'][0]
  self.assertEqual(raw_only,5)
 def test_full_extents_unwind_and_selected_coverage(self):
  r=json.loads((P/'FREEZE.json').read_text());self.assertEqual((sum(x['bytes'] for x in r['owners']),sum(x['instructions'] for x in r['owners'])),(2813,719));self.assertEqual(sum(x['selected_visited'] for x in r['owners']),219)
  for owner in r['owners']:
   lo,hi=int(owner['start'],16),int(owner['end'],16);self.assertEqual(self.image.view.fde(lo),(lo,hi));self.assertEqual(hashlib.sha256(self.image.view.read(lo,hi-lo)).hexdigest(),owner['sha256']);self.assertEqual(owner['selected_instructions'],owner['selected_visited'])
   for row in owner['unwind_raw'].values():self.assertEqual(self.image.view.read(int(row['va'],16),len(bytes.fromhex(row['raw_hex']))).hex(),row['raw_hex'])
 def test_magic_division_bounds_bind_original_immediates(self):
  c=int.from_bytes(self.image.view.read(0x3673a5c,4),'little');n=int.from_bytes(self.image.view.read(0x3673acc,4),'little');self.assertEqual(c,0x51eb851f);self.assertEqual(n,0x431bde83)
  self.assertLess((c*400-(1<<39))*262145,1<<39);self.assertLess((c*100-(1<<37))*262142,1<<37);self.assertLess((n*1000000-(1<<50))*((1<<32)-1),1<<50)
 def test_unknown_inputs_and_read_write_footprint_fail_closed(self):
  m=native.Machine(self.image);self.assertIsNone(m.get(native.cpu.RAX,64))
  with self.assertRaisesRegex(ValueError,'outside three'):m.reload(native.cpu.RAX,native.cpu.INPUT+12,4)
  with self.assertRaisesRegex(ValueError,'spills excluded'):m.spill(native.cpu.INPUT,native.cpu.RAX,8)
  m.set_reg(native.cpu.RSI,native.cpu.INPUT+12);m.pc=0x3673a38
  with self.assertRaisesRegex(ValueError,'outside three'):m.step()
  for bad in [-1,1<<32,True]:
   with self.assertRaisesRegex(ValueError,'raw u32'):native.evaluate(self.image,0,[bad,0,0])
 def test_pre_rust_guard_under_optimized_python(self):
  out=ROOT/'work/packed-millis115-guard-must-not-exist';before=out.exists();r=subprocess.run([sys.executable,'-B','-O',str(P/'freeze-producer.py'),'--output',str(out),'--objdump','unused'],cwd=ROOT,capture_output=True,text=True,timeout=30);self.assertNotEqual(r.returncode,0);self.assertIn('freeze refuses existing Rust component',r.stderr);self.assertEqual(out.exists(),before)
if __name__=='__main__':unittest.main()
