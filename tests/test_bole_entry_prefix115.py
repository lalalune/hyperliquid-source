"""Private entry prefix and strict non-composition checks."""
from pathlib import Path
import hashlib,importlib.util,json,sys,unittest
ROOT=Path(__file__).resolve().parents[1];P=ROOT/'research/work-items/RE-001-bole-entry-prefix-115'
sys.path.insert(0,str(P));spec=importlib.util.spec_from_file_location('bole115_native',P/'native.py');n=importlib.util.module_from_spec(spec);spec.loader.exec_module(n)
class BoleEntryPrefix(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.im=n.Image()
  if hashlib.sha256(cls.im.data).hexdigest()!=n.SHA:raise ValueError('wrong115target')
 @classmethod
 def tearDownClass(cls):cls.im.close()
 def test_sealed_files(self):
  d=json.loads((P/'proof.json').read_text())
  for file,key in [('inputs.jsonl','input_sha256'),('expected.jsonl','expected_sha256')]:self.assertEqual(hashlib.sha256((P/file).read_bytes()).hexdigest(),d[key])
  self.assertEqual(d['rows'],7420);self.assertEqual(d['selected_instructions'],65);self.assertEqual(d['selected_bytes'],281)
 def test_first_free_and_nonzero_words(self):
  self.assertEqual(n.evaluate(self.im,[1,2,[0,1,2],[n.cpu.U64,0,0],0,1,17,42])[0],['B',1,1,17,42])
  self.assertEqual(n.evaluate(self.im,[1,2,[2,1,0],[0,0,0],0,1,17,42])[0],['B',1,2,17,42])
  self.assertEqual(n.evaluate(self.im,[1,2,[0,0,1],[0,0],0,1,17,42])[0],['B',1,0,17,42])
 def test_guards_precede_later_free(self):
  self.assertEqual(n.evaluate(self.im,[0,0,[n.cpu.U64],[],0,0,17,42])[0],['R'])
  self.assertEqual(n.evaluate(self.im,[2,2,[0],[0],0,0,17,42])[0],['P',2,2])
  self.assertEqual(n.evaluate(self.im,[1,2,[n.cpu.U64,0],[0],0,0,17,42])[0],['S',n.cpu.U64,1])
 def test_header_order_and_no_helper_returns(self):
  for rep,size,tag in [(0,0,'B'),(1<<63,0,'R'),(1<<63,1,'A'),((1<<63)+1,0,'B')]:self.assertEqual(n.evaluate(self.im,[1,2,[0],[0],rep,size,17,42])[0][0],tag)
  self.assertEqual(n.evaluate(self.im,[1,2,[1],[0],1<<63,0,17,42])[0],['S',1,1])
  m=n.Machine(self.im,0,0,0)
  with self.assertRaisesRegex(ValueError,'stop before'):m.call(0x4556410,0x2c80780)
 def test_movsd_bit_copy(self):
  m=n.Machine(self.im,0,0,0);value=0x7ff0000000000042;m.store(n.ARG+16,8,value);m.set_reg(n.cpu.RDX,n.ARG);m.set_reg(n.cpu.RSP,n.FRAME);m.store(n.FRAME+8,8,n.cpu.U64);m.flags=[True,False,True,False];flags=list(m.flags)
  for va in [0x2c806a5,0x2c80709]:
   ins=self.im.fetch(va);m.two_byte(ins,ins.key,32,0,va)
  self.assertEqual(m.load(n.FRAME,8),value);self.assertEqual(m.load(n.FRAME+8,8),n.cpu.U64);self.assertEqual(m.xmm[0][8:],[0]*8);self.assertEqual(m.flags,flags)
 def test_real_controls_and_bindings(self):
  d=json.loads((P/'native-controls.json').read_text());self.assertEqual(len(d['output_changes']),9);self.assertEqual(len(d['rejections']),4)
  for c in d['output_changes']:self.assertNotEqual(c['original'],c['changed'])
  for c in json.loads((P/'proof.json').read_text())['actual_calls']:self.assertFalse(c['evaluated'])
 def test_frozen_sample_replay(self):
  rows=(P/'inputs.jsonl').read_text().splitlines();expected=(P/'expected.jsonl').read_text().splitlines()
  for i in sorted({0,len(rows)-1,*range(0,len(rows),max(1,len(rows)//40))}):self.assertEqual(n.evaluate(self.im,json.loads(rows[i]))[0],json.loads(expected[i]))
if __name__=='__main__':unittest.main()
