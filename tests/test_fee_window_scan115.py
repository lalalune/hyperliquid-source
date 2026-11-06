"""Target-instruction cursor state, floating boundaries and corruption controls."""
from pathlib import Path
import hashlib,importlib.util,json,struct,sys,unittest
ROOT=Path(__file__).resolve().parents[1];P=ROOT/'research/work-items/RE-004-fee-window-scan-115'
sys.path.insert(0,str(P));spec=importlib.util.spec_from_file_location('fee_scan115_native',P/'native.py');n=importlib.util.module_from_spec(spec);spec.loader.exec_module(n)
class FeeWindow(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.im=n.Image()
  if hashlib.sha256(cls.im.data).hexdigest()!=n.SHA:raise ValueError('wrong node115')
 @classmethod
 def tearDownClass(cls):cls.im.close()
 def test_frozen(self):
  d=json.loads((P/'proof.json').read_text());self.assertEqual((d['rows'],d['visited_bytes'],d['visited_instructions']),(6741,76,25));self.assertEqual(d['callees'],[])
  for f,k in [('inputs.jsonl','input_sha256'),('expected.jsonl','expected_sha256')]:self.assertEqual(hashlib.sha256((P/f).read_bytes()).hexdigest(),d[k])
 def test_exact_cursor(self):
  one=0x3ff0000000000000;two=0x4000000000000000
  for row,want in [([2,[]],[0,0,0]),([0,[]],[0,0,0]),([1,[]],[0,0,0]),([3,[0,one]],[0,0,2]),([2,[0,one]],[1,1,1]),([2,[one,0,0]],[0,2,1]),([3,[two,one,0,0]],[0,2,2]),([3,[0,0,one,0]],[1,2,2])]:self.assertEqual(n.evaluate(self.im,row)[0],want)
 def test_float_boundaries(self):
  qnan=0x7ff8000000000001
  for words,want in [([0,0x8000000000000000],0),([qnan,0],0),([0,qnan],0),([0,1],1),([0x8000000000000001,0x8000000000000000],1),([0x7ff0000000000000,0],0),([0xfff0000000000000,0],1)]:self.assertEqual(n.evaluate(self.im,[2,words])[0],[want,1,1])
 def test_isa_movsd_compare(self):
  m=n.Machine(self.im,2);m.set_reg(n.cpu.RDX,n.DATA+8);m.store(n.DATA,8,0);m.store(n.DATA+8,8,0x3ff0000000000000);m.xmm[0]=bytes([255])*16;flags=[True,True,True,True];m.flags=flags.copy()
  i=self.im.fetch(0x36e1b42);m.two_byte(i,i.key,32,0,i.va);self.assertEqual(m.xmm[0],struct.pack('<Q',0x3ff0000000000000)+bytes(8));self.assertEqual(m.flags,flags)
  i=self.im.fetch(0x36e1b46);m.two_byte(i,i.key,16,0,i.va);self.assertEqual(m.flags,[False,False,False,False]);self.assertEqual(n.relation(0x7ff8000000000001,0),[True,True,False,False]);self.assertEqual(n.relation(0x8000000000000000,0),[False,True,False,False])
 def test_refusals(self):
  for row in [[0,[0]],[1,[0]],[2,[0x7ff0000000000001]],[2,[0xfff0000000000001]],[2,[0]*33]]:
   with self.assertRaises(ValueError):n.evaluate(self.im,row)
 def test_controls(self):
  d=json.loads((P/'native-controls.json').read_text());self.assertEqual(len(d['output_changes']),9);self.assertEqual(len(d['rejections']),3)
  for c in d['output_changes']:self.assertNotEqual(c['original'],c['changed'])
 def test_sealed_replay(self):
  rows=(P/'inputs.jsonl').read_text().splitlines();gold=(P/'expected.jsonl').read_text().splitlines()
  for i in sorted({0,len(rows)-1,*range(0,len(rows),max(1,len(rows)//41))}):self.assertEqual(n.evaluate(self.im,json.loads(rows[i]))[0],json.loads(gold[i]))
if __name__=='__main__':unittest.main()
