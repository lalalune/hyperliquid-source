"""Full two-layout ring-search family, duplicate seam rule and unknown storage."""
from pathlib import Path
import hashlib,importlib.util,json,sys,unittest
ROOT=Path(__file__).resolve().parents[1];P=ROOT/'research/work-items/RE-001-wrapped-u64-search-115'
sys.path.insert(0,str(P));spec=importlib.util.spec_from_file_location('wrap_u64_115_native',P/'native.py');n=importlib.util.module_from_spec(spec);spec.loader.exec_module(n)
class WrappedSearch(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.im=n.Image()
  if hashlib.sha256(cls.im.data).hexdigest()!=n.SHA:raise ValueError('wrong115')
 @classmethod
 def tearDownClass(cls):cls.im.close()
 def test_frozen(self):
  d=json.loads((P/'proof.json').read_text());self.assertEqual((d['visited_bytes'],d['visited_instructions']),(572,181));self.assertEqual(len(d['owners']),2);self.assertEqual(d['callees'],[])
  for file,k in [('inputs.jsonl','input_sha256'),('expected.jsonl','expected_sha256')]:self.assertEqual(hashlib.sha256((P/file).read_bytes()).hexdigest(),d[k])
 def test_empty_no_query(self):
  for family in [0,1]:
   for c,h in [(0,0),(5,0),(5,9)]:self.assertEqual(n.evaluate(self.im,[family,c,h,[],n.MASK])[0],[1,0])
 def test_duplicate_seam(self):
  for family in [0,1]:
   for c,h,keys,want in [(4,0,[1]*4,3),(4,4,[1]*4,3),(4,3,[1]*4,1),(4,7,[1]*4,1),(6,4,[1]*4,2)]:self.assertEqual(n.evaluate(self.im,[family,c,h,keys,1])[0],[0,want])
 def test_unsigned_and_gaps(self):
  for family in [0,1]:
   for h in [0,1,2,3]:
    for query,want in [(0,[0,0]),(1,[1,1]),(1<<63,[1,1]),(n.MASK,[0,1])]:self.assertEqual(n.evaluate(self.im,[family,2,h,[0,n.MASK],query])[0],want)
   self.assertEqual(n.evaluate(self.im,[family,2,0,[1,1],0])[0],[1,0]);self.assertEqual(n.evaluate(self.im,[family,2,0,[1,1],2])[0],[1,2])
 def test_premises_and_unknown_storage(self):
  for row in [[0,0,0,[1],0],[0,2,4,[1],0],[0,2,0,[2,1],0],[0,33,0,[],0]]:
   with self.assertRaises(ValueError):n.evaluate(self.im,row)
  m=n.Machine(self.im,{n.DATA:0});m.record=True
  with self.assertRaises(ValueError):m.load(n.DATA+8,8)
  with self.assertRaises(ValueError):m.store(n.DATA,8,0)
  empty=n.Machine(self.im,{});empty.record=True
  with self.assertRaises(ValueError):empty.load(n.QUERY,8)
 def test_controls(self):
  d=json.loads((P/'native-controls.json').read_text());self.assertEqual(len(d['output_changes']),14);self.assertEqual(len(d['rejections']),4)
  for c in d['output_changes']:self.assertNotEqual(c['original'],c['changed'])
 def test_sealed_replay(self):
  rows=(P/'inputs.jsonl').read_text().splitlines();gold=(P/'expected.jsonl').read_text().splitlines()
  for i in sorted({0,len(rows)-1,*range(0,len(rows),max(1,len(rows)//42))}):self.assertEqual(n.evaluate(self.im,json.loads(rows[i]))[0],json.loads(gold[i]))
if __name__=='__main__':unittest.main()
