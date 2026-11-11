"""Whole three-body family, mixed signedness and u64 saturation boundaries."""
from pathlib import Path
import hashlib,importlib.util,json,sys,unittest
ROOT=Path(__file__).resolve().parents[1];P=ROOT/'research/work-items/RE-001-mixed-tuple-threshold-115'
sys.path.insert(0,str(P));spec=importlib.util.spec_from_file_location('mixed_tuple115_native',P/'native.py');n=importlib.util.module_from_spec(spec);spec.loader.exec_module(n)
class MixedTuple(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.im=n.Image()
  if hashlib.sha256(cls.im.data).hexdigest()!=n.SHA:raise ValueError('wrong115target')
 @classmethod
 def tearDownClass(cls):cls.im.close()
 def test_frozen_family(self):
  d=json.loads((P/'proof.json').read_text());self.assertEqual((d['visited_bytes'],d['visited_instructions']),(300,84));self.assertEqual(len(d['owners']),3);self.assertEqual(len({o['sha256'] for o in d['owners']}),2);self.assertEqual(d['callees'],[])
  for f,k in [('inputs.jsonl','input_sha256'),('expected.jsonl','expected_sha256')]:self.assertEqual(hashlib.sha256((P/f).read_bytes()).hexdigest(),d[k])
 def test_mixed_signedness(self):
  for a,b,want in [([0x80000000,0,0],[0x7fffffff,0,0],0),([0x7fffffff,0,0],[0x80000000,0,0],2),([0,0xffffffff,0],[0,0x80000000,0],2),([0,0,0xffffffff],[0,0,0x80000000],2),([0,0,0],[0,0,0],2)]:
   for family in range(3):self.assertEqual(n.evaluate(self.im,[family,*a,*b,0,0,0])[0],want)
 def test_saturation_boundary(self):
  M=n.MASK
  for x,t,want in [(0,4999,0),(0,5000,1),(M-5001,M-1,1),(M-5000,M-1,0),(M-5000,M,1),(M-4999,M-1,0),(M-4999,M,1),(M,0,0),(M,M,1)]:
   for family in range(3):self.assertEqual(n.evaluate(self.im,[family,0,0,0,1,0,0,t,x,0])[0],want)
 def test_primary_equality_and_precedence(self):
  for family in range(3):
   self.assertEqual(n.evaluate(self.im,[family,0,0,0,0,0,0,0,n.MASK,0])[0],2)
   self.assertEqual(n.evaluate(self.im,[family,0,0,0,0,0,0,0,n.MASK,1])[0],0)
   self.assertEqual(n.evaluate(self.im,[family,0,0,0,0,0,0,n.MASK,n.MASK,n.MASK])[0],2)
 def test_unknown_padding_and_writes(self):
  m=n.Machine(self.im,n.FIELDS)
  with self.assertRaises(ValueError):m.load(n.OBJ+0x5c,4)
  m.record=True
  with self.assertRaises(ValueError):m.store(n.OBJ+0x60,4,0)
  for row in [[3,*([0]*9)],[0,*([0]*8)],[0,1<<32,*([0]*8)]]:
   with self.assertRaises(ValueError):n.evaluate(self.im,row)
 def test_controls(self):
  d=json.loads((P/'native-controls.json').read_text());self.assertEqual(len(d['output_changes']),16);self.assertEqual(len(d['rejections']),2)
  for c in d['output_changes']:self.assertNotEqual(c['original'],c['changed'])
 def test_sealed_replay(self):
  rows=(P/'inputs.jsonl').read_text().splitlines();gold=(P/'expected.jsonl').read_text().splitlines()
  for i in sorted({0,len(rows)-1,*range(0,len(rows),max(1,len(rows)//42))}):self.assertEqual(n.evaluate(self.im,json.loads(rows[i]))[0],int(gold[i]))
if __name__=='__main__':unittest.main()
