"""Actual selector graph, sorted ring state and exact pointer identities."""
from pathlib import Path
import hashlib,importlib.util,json,sys,unittest
ROOT=Path(__file__).resolve().parents[1];P=ROOT/'research/work-items/RE-001-perp-tier-selector-115'
sys.path.insert(0,str(P));spec=importlib.util.spec_from_file_location('tier115_native',P/'native.py');n=importlib.util.module_from_spec(spec);spec.loader.exec_module(n)
class TierSelector(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.im=n.Image()
  if hashlib.sha256(cls.im.data).hexdigest()!=n.SHA:raise ValueError('wrong115target')
 @classmethod
 def tearDownClass(cls):cls.im.close()
 def test_frozen_files(self):
  d=json.loads((P/'proof.json').read_text())
  for name,key in [('inputs.jsonl','input_sha256'),('expected.jsonl','expected_sha256')]:self.assertEqual(hashlib.sha256((P/name).read_bytes()).hexdigest(),d[key])
  self.assertEqual(d['rows'],4015);self.assertEqual((d['selected_bytes'],d['selected_instructions']),(682,192))
 def test_global_priority_and_initializer_boundary(self):
  self.assertEqual(n.evaluate(self.im,[49,0,0,17,-1,0,[],n.ring_storage(0,0,[],0)])[0],['R',1,0,['G',49,0],17])
  self.assertEqual(n.evaluate(self.im,[49,0,1,17,-1,0,[],n.ring_storage(0,0,[],0)])[0],['I',49,17])
 def test_tree_unsigned_and_depth(self):
  row=[1<<31,1<<63,0,17,0,0,n.leaf([(1<<31)-1,1<<31],0),None]
  result,_,edges=n.evaluate(self.im,row);self.assertEqual(result[3],['T',0,1,24]);self.assertFalse(edges)
  tree=n.balanced(3,0);key=tree[-1][0][0];result,_,_=n.evaluate(self.im,[key,1<<63,0,17,0,3,tree,None]);self.assertEqual(result[0],'R')
 def test_actual_ring_call_and_wrap(self):
  ring=n.ring_storage(4,3,[50,60,70,80],0)
  for key,physical in [(50,3),(60,0),(70,1),(80,2)]:
   result,seen,edges=n.evaluate(self.im,[key,4,0,17,-1,0,[],ring]);self.assertEqual(result[3],['B',physical,32]);self.assertEqual(edges,[(0x3c4322c,0x4556c50)]);self.assertTrue(any(n.HELPER[0]<=a<n.HELPER[1] for a in seen))
  self.assertEqual(n.evaluate(self.im,[51,4,0,17,-1,0,[],ring])[0],['M'])
 def test_empty_and_unused_capacity(self):
  self.assertEqual(n.evaluate(self.im,[50,0,0,17,-1,0,[],n.ring_storage(0,0,[],0)])[0],['M'])
  for head in [0,7,15]:
   ring=n.ring_storage(16,head,[50],0);self.assertEqual(n.evaluate(self.im,[50,16,0,17,-1,0,[],ring])[0][3],['B',head,32])
  # Native evaluator never initializes unused slots; a bad read must propagate
  # unknownness, rather than quietly treating inactive storage as zero.
  m=n.Machine(self.im,0,16);self.assertIsNone(m.load(n.RING+8*72,4))
 def test_controls_and_real_bindings(self):
  controls=json.loads((P/'native-controls.json').read_text());self.assertEqual(len(controls['output_changes']),24);self.assertEqual(len(controls['rejections']),6)
  for c in controls['output_changes']:self.assertNotEqual(c['original'],c['changed'])
  calls=json.loads((P/'proof.json').read_text())['actual_calls'];self.assertTrue(calls[0]['evaluated']);self.assertEqual(calls[0]['actual_call_rows'],2264);self.assertTrue(all(not c['evaluated'] for c in calls[1:]))
  with self.assertRaisesRegex(ValueError,'unqualified'):n.Machine(self.im,0,0).call(0x5c87d50,0x3c432d9)
 def test_frozen_sample_replay(self):
  rows=(P/'inputs.jsonl').read_text().splitlines();gold=(P/'expected.jsonl').read_text().splitlines()
  for i in sorted({0,len(rows)-1,*range(0,len(rows),max(1,len(rows)//40))}):self.assertEqual(n.evaluate(self.im,json.loads(rows[i]))[0],json.loads(gold[i]))
if __name__=='__main__':unittest.main()
