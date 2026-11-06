"""Real entry guard, stable payload/key origins and mixed signed key order."""
from pathlib import Path
import hashlib,importlib.util,json,sys,unittest
ROOT=Path(__file__).resolve().parents[1];P=ROOT/'research/work-items/RE-001-indirect-triplet-insert-115'
sys.path.insert(0,str(P));spec=importlib.util.spec_from_file_location('triplet_insert115_native',P/'native.py');n=importlib.util.module_from_spec(spec);spec.loader.exec_module(n)
class TripletInsertion(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.im=n.Image()
  if hashlib.sha256(cls.im.data).hexdigest()!=n.SHA:raise ValueError('wrong115')
 @classmethod
 def tearDownClass(cls):cls.im.close()
 def test_frozen(self):
  d=json.loads((P/'proof.json').read_text());self.assertEqual((d['visited_bytes'],d['visited_instructions']),(236,73));self.assertEqual(d['callees'],[]);self.assertGreater(d['guard_trap_rows'],0)
  for file,k in [('inputs.jsonl','input_sha256'),('expected.jsonl','expected_sha256')]:self.assertEqual(hashlib.sha256((P/file).read_bytes()).hexdigest(),d[k])
 def test_actual_guard(self):
  table=[[0,0,0]]
  for k,records,kind in [(0,[],1),(1,[],1),(0,[[1,0]],1),(2,[[1,0]],1),(n.MASK,[[1,0]],1),(1,[[1,0]],0)]:self.assertEqual(n.evaluate(self.im,[k,records,table])[0],[kind,records])
 def test_stable_complete_records(self):
  table=[[7,11,13]]*3;records=[[0x123456789abcdef,2],[n.MASK,0],[0x8000000000000000,1]]
  for k in [1,2,3]:self.assertEqual(n.evaluate(self.im,[k,records,table])[0],[0,records])
  shared=[[91,0],[37,0],[83,0]];self.assertEqual(n.evaluate(self.im,[1,shared,table])[0],[0,shared])
 def test_mixed_signedness(self):
  for table in [[[0x80000000,0,0],[0x7fffffff,0,0]],[[0,0x80000000,0],[0,0xffffffff,0]],[[0,0,0x80000000],[0,0,0xffffffff]]]:
   records=[[100,1],[200,0]];self.assertEqual(n.evaluate(self.im,[1,records,table])[0],[0,list(reversed(records))])
 def test_unsorted_prefix_not_fully_sorted(self):
  table=[[0,0,0],[1,0,0],[2,0,0]];records=[[11,2],[22,0],[33,1]]
  self.assertEqual(n.evaluate(self.im,[2,records,table])[0],[0,records]);self.assertEqual(n.evaluate(self.im,[1,records,table])[0],[0,[records[1],records[2],records[0]]])
 def test_controls_and_immutable_keys(self):
  d=json.loads((P/'native-controls.json').read_text());self.assertEqual(len(d['output_changes']),11);self.assertEqual(len(d['rejections']),3)
  for c in d['output_changes']:self.assertNotEqual(c['original'],c['changed'])
  m=n.Machine(self.im,1,{0});m.record=True
  with self.assertRaises(ValueError):m.store(n.KEYS,4,0)
  with self.assertRaises(ValueError):m.load(n.KEYS+12,4)
 def test_sealed_replay(self):
  rows=(P/'inputs.jsonl').read_text().splitlines();gold=(P/'expected.jsonl').read_text().splitlines()
  for i in sorted({0,len(rows)-1,*range(0,len(rows),max(1,len(rows)//42))}):self.assertEqual(n.evaluate(self.im,json.loads(rows[i]))[0],json.loads(gold[i]))
if __name__=='__main__':unittest.main()
