"""Original fixed8 hash observations, real callee dependence and footprint guards."""
import hashlib,importlib.util,json,mmap,subprocess,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];PACKET=ROOT/'research/work-items/RE-014-u64-key-hash-115'
sys.path.insert(0,str(PACKET));import native
class U64KeyHashTests(unittest.TestCase):
 def setUp(self):self.im=native.Image();self.addCleanup(self.im.close)
 def test_retained_original_smoke(self):
  for line in (PACKET/'target-smoke.tsv').read_text().splitlines():
   a,b,c,expected=map(int,line.split('\t'));actual,_=native.evaluate(self.im,(a,b,c));self.assertEqual(actual,expected)
 def test_actual_code_controls_and_writer_dependency(self):
  for rec in json.loads((PACKET/'native-controls.json').read_text()):
   changed=native.Image();self.addCleanup(changed.close);changed.data=mmap.mmap(changed.view.file.fileno(),0,access=mmap.ACCESS_COPY)
   va=int(rec['va'],16);self.assertEqual(changed.view.read(va,1).hex(),rec['original_byte']);changed.data[changed.view.offset(va)]=int(rec['changed_byte'],16)
   original,_=native.evaluate(self.im,rec['input']);altered,_=native.evaluate(changed,rec['input']);self.assertEqual((original,altered),(rec['original'],rec['changed']));self.assertNotEqual(original,altered)
  self.assertEqual(hashlib.sha256(self.im.data).hexdigest(),native.SHA)
 def test_fde_original_owner_bytes_and_static_caller_transfers(self):
  f=json.loads((PACKET/'FREEZE.json').read_text());self.assertEqual([(o['instructions'],o['visited']) for o in f['owners']],[(91,91),(141,56),(116,0)])
  rows={int(parts[0],16):bytes.fromhex(parts[1]) for line in (PACKET/'owners.capstone.tsv').read_text().splitlines() if (parts:=line.split('\t'))}
  for va in f['visited_addresses']:
   self.assertIn(va,rows);self.assertEqual(self.im.fetch(va).size,len(rows[va]))
  for o in f['owners']:
   a,b=int(o['start'],16),int(o['end'],16);self.assertEqual(self.im.view.fde(a),(a,b));self.assertEqual(hashlib.sha256(self.im.view.read(a,b-a)).hexdigest(),o['sha256'])
   for r in o['unwind'].values():self.assertEqual(self.im.view.read(int(r['va'],16),len(bytes.fromhex(r['raw_hex']))).hex(),r['raw_hex'])
  for site,target in [(0x46aa662,native.START),(0x46aa697,native.START),(0x471733b,native.WRITER)]:
   raw=self.im.view.read(site,5);self.assertEqual(raw[0],0xe8);self.assertEqual(site+5+int.from_bytes(raw[1:],'little',signed=True),target)
 def test_stack_spill_reload_and_call_guards(self):
  m=native.Machine(self.im);m.calls=0
  for action in [lambda:m.store(native.cpu.STACK+8,1,0),lambda:m.spill(native.cpu.STACK-1025,0,8),lambda:m.reload(0,native.cpu.STACK+1,8),lambda:m.load(native.START,8)]:
   with self.assertRaisesRegex(ValueError,'footprint'):action()
  with self.assertRaisesRegex(ValueError,'unclosed hash call'):m.call(native.WRITER+1,0x471733b)
 def test_local_rol_carry_overflow_and_preserved_flags(self):
  m=native.Machine(self.im);m.flags=[False,True,False,False]
  self.assertEqual(m.shift(0,1<<63,1,64),1);self.assertEqual(m.flags,[True,True,False,True])
  m.flags=[True,False,True,True];self.assertEqual(m.shift(0,1,0,64),1);self.assertEqual(m.flags,[True,False,True,True])
  self.assertEqual(m.shift(0,1,63,64),1<<63);self.assertEqual(m.flags,[False,False,True,None])
  self.assertIsNone(m.shift(0,None,13,64));self.assertEqual(m.flags,[None,False,True,None])
  m.flags=[False,False,True,None];self.assertEqual(m.shift(0,0,1,64),0);self.assertEqual(m.flags,[False,False,True,False])
 def test_freeze_guard_before_output_under_python_optimized(self):
  with tempfile.TemporaryDirectory() as d:
   out=Path(d)/'new';r=subprocess.run([sys.executable,'-O',str(PACKET/'freeze.py'),'--output',str(out),'--objdump','/missing/tool'],capture_output=True)
   self.assertNotEqual(r.returncode,0);self.assertIn(b'freeze refuses existing new Rust',r.stderr);self.assertFalse(out.exists())
if __name__=='__main__':unittest.main()
