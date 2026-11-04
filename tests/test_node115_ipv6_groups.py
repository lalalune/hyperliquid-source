"""Real whole-reader helper composition and independent cursor/output effects."""
from pathlib import Path
import hashlib,json,mmap,subprocess,sys,unittest
ROOT=Path(__file__).resolve().parents[1];P=ROOT/'research/work-items/RE-012-ipv6-groups-115';sys.path.insert(0,str(P));import native
class IPv6Groups115(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.image=native.Image();cls.addClassCleanup(cls.image.close)
  if hashlib.sha256(cls.image.data).hexdigest()!=native.SHA:raise ValueError('wrong115target')
 def test_native_group_and_memory_effect_smoke(self):
  for line in (P/'target-smoke.tsv').read_text().splitlines():
   f=line.split('\t');data=bytes.fromhex(f[2]);actual,_=native.evaluate(self.image,data,int(f[0]),int(f[1]));self.assertEqual(actual,tuple(map(int,f[3:])));self.assertEqual(actual[2]+actual[3],len(data))
 def test_9_actual_code_corruptions_include_real_callee_dependence(self):
  rows=json.loads((P/'native-controls.json').read_text());self.assertEqual(len(rows),9)
  for row in rows:
   im=native.Image();self.addCleanup(im.close);im.data=mmap.mmap(im.view.file.fileno(),0,access=mmap.ACCESS_COPY);im.data[im.view.offset(int(row['va'],16))]=int(row['mutant_byte'],16)
   actual,_=native.evaluate(im,bytes.fromhex(row['data_hex']),row['cap'],row['canary']);self.assertEqual(list(actual),row['after']);self.assertNotEqual(list(actual),row['before'])
 def test_core_fde_and_explicit_helper_coverage(self):
  r=json.loads((P/'FREEZE.json').read_text());self.assertEqual((r['owners'][0]['instructions'],r['owners'][0]['visited']),(130,129));self.assertEqual(r['owners'][3]['visited'],0)
  self.assertEqual((sum(x['bytes'] for x in r['owners']),sum(x['instructions'] for x in r['owners'])),(2408,673))
  for owner in r['owners']:
   a,b=int(owner['start'],16),int(owner['end'],16);self.assertEqual(self.image.view.fde(a),(a,b));self.assertEqual(hashlib.sha256(self.image.view.read(a,b-a)).hexdigest(),owner['sha256'])
  missing=set(int(x.split('\t')[0],16) for x in (P/'owners.capstone.tsv').read_text().splitlines() if native.START<=int(x.split('\t')[0],16)<native.END)-set(r['visited_addresses']);self.assertEqual(missing,{0x16861c5})
 def test_actual_rol16_blocker_and_local_repair(self):
  old=native.cpu.Machine(self.image);old.set_reg(native.cpu.RCX,0x0201);old.pc=0x16860ce
  with self.assertRaisesRegex(native.cpu.ToolError,'rotate kind'):old.step()
  new=native.Machine(self.image,0);new.set_reg(native.cpu.RCX,0x0201);new.pc=0x16860ce;new.step();self.assertEqual(new.get(native.cpu.RCX,16),0x0102)
 def test_unknown_memory_and_call_boundaries_fail_closed(self):
  m=native.Machine(self.image,0)
  with self.assertRaisesRegex(ValueError,'footprint'):m.reload(native.cpu.RAX,native.BUF,1)
  with self.assertRaisesRegex(ValueError,'footprint'):m.spill(native.OUT+16,native.cpu.RAX,8)
  with self.assertRaisesRegex(ValueError,'unclosed helper'):m.call(0x167ccb0,0)
  m.pc=0x1686091;m.step()
  with self.assertRaisesRegex(native.cpu.ToolError,'unknown flags'):m.step()
  for cap in [-1,9,True]:
   with self.assertRaisesRegex(ValueError,'capacity'):native.evaluate(self.image,b'1',cap)
 def test_pre_rust_guard_survives_optimized_python(self):
  out=ROOT/'work/ipv6-groups115-guard-must-not-exist';before=out.exists();r=subprocess.run([sys.executable,'-B','-O',str(P/'freeze-producer.py'),'--output',str(out),'--objdump','unused'],cwd=ROOT,capture_output=True,text=True,timeout=30);self.assertNotEqual(r.returncode,0);self.assertIn('freeze refuses existing Rust component',r.stderr);self.assertEqual(out.exists(),before)
if __name__=='__main__':unittest.main()
