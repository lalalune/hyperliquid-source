"""Real node115 IPv4 instructions, cursor and caller-boundary controls."""
from pathlib import Path
import hashlib,json,mmap,subprocess,sys,unittest
ROOT=Path(__file__).resolve().parents[1];P=ROOT/'research/work-items/RE-014-host-ip-gates-115';sys.path.insert(0,str(P))
import native,parser
class HostIp115(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.image=native.Image();cls.addClassCleanup(cls.image.close)
  if hashlib.sha256(cls.image.data).hexdigest()!=native.SHA:raise ValueError('wrong node115 capture')
 def test_raw_boundary_smoke(self):
  for line in (P/'target-smoke.tsv').read_text().splitlines():
   f=line.split('\t');actual,_=native.admission(self.image,*map(int,f[1:4])) if f[0]=='M' else native.override(self.image,int(f[1]));self.assertEqual(str(actual),f[-1])
 def test_real_parser_and_caller_call_return(self):
  for line in (P/'parser-smoke.tsv').read_text().splitlines():
   op,data,expected=line.split('\t');actual,_=parser.evaluate(self.image,bytes.fromhex(data),op=='C');self.assertEqual(actual,expected)
 def test_six_parser_byte_corruptions(self):
  controls=json.loads((P/'parser-controls.json').read_text());self.assertEqual(len(controls),6)
  for row in controls:
   im=native.Image();self.addCleanup(im.close);im.data=mmap.mmap(im.view.file.fileno(),0,access=mmap.ACCESS_COPY);im.data[im.view.offset(int(row['va'],16))]=int(row['mutant_byte'],16)
   actual,_=parser.evaluate(im,bytes.fromhex(row['input_hex']));self.assertEqual(actual,row['after']);self.assertNotEqual(actual,row['before'])
 def test_callee_mutation_changes_actual_caller_path(self):
  im=native.Image();self.addCleanup(im.close);im.data=mmap.mmap(im.view.file.fileno(),0,access=mmap.ACCESS_COPY);im.data[im.view.offset(0x167d062)]=0x57
  self.assertEqual(parser.evaluate(self.image,b'1.2.3.4',True)[0],'A,67305985,7,0')
  self.assertEqual(parser.evaluate(im,b'1.2.3.4',True)[0],'R,67305985,7,1')
 def test_seven_caller_gate_byte_corruptions(self):
  controls=json.loads((P/'native-controls.json').read_text());self.assertEqual(len(controls),7)
  for row in controls:
   im=native.Image();self.addCleanup(im.close);im.data=mmap.mmap(im.view.file.fileno(),0,access=mmap.ACCESS_COPY);im.data[im.view.offset(int(row['va'],16))]=int(row['mutant_byte'],16)
   actual,_=(native.admission if row['operation']=='M' else native.override)(im,*row['inputs']);self.assertEqual(actual,row['after']);self.assertNotEqual(actual,row['before'])
 def test_full_leaf_coverage_and_bounds(self):
  record=json.loads((P/'PARSER-FREEZE.json').read_text());leaf=record['owners'][1];self.assertEqual((leaf['instructions'],leaf['visited']),(278,278));self.assertEqual(self.image.view.fde(parser.LEAF),(parser.LEAF,parser.LEAF_END))
  m=parser.ParserMachine(self.image,b'');self.assertIsNone(m.get(native.cpu.RAX,64))
  with self.assertRaisesRegex(ValueError,'footprint'):m.load(parser.BUF,1)
  with self.assertRaisesRegex(ValueError,'unclosed call'):m.call(parser.LEAF,0)
  for bad in [-1,1<<64,True]:
   with self.assertRaises(ValueError):native.admission(self.image,bad,1,0)
 def test_freeze_guards_under_optimized_python(self):
  for name in ('freeze-producer.py','freeze-parser.py'):
   r=subprocess.run([sys.executable,'-B','-O',str(P/name)],cwd=ROOT,capture_output=True,text=True,timeout=30);self.assertNotEqual(r.returncode,0);self.assertIn('freeze refuses existing Rust component',r.stderr)
if __name__=='__main__':unittest.main()
