"""Original multiplication boundaries, optional fields and first-call ordering."""
from pathlib import Path
import hashlib,importlib.util,json,sys,unittest
ROOT=Path(__file__).resolve().parents[1];P=ROOT/'research/work-items/RE-004-fee-active-scaling-rust-115'
sys.path.insert(0,str(P));spec=importlib.util.spec_from_file_location('fee_scaling115_native',P/'native.py');n=importlib.util.module_from_spec(spec);spec.loader.exec_module(n)
class FeeScaling(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.im=n.Image()
  if hashlib.sha256(cls.im.data).hexdigest()!=n.SHA:raise ValueError('wrong115target')
 @classmethod
 def tearDownClass(cls):cls.im.close()
 def eval(self,**kw):return n.evaluate(self.im,n.stimulus(**kw))[0]
 def test_closed_cfg_and_sealed_inputs(self):
  d=json.loads((P/'proof.json').read_text());self.assertEqual(d['selected_addresses'],d['visited_addresses']);self.assertEqual(len(d['unexecuted_first_calls']),3);self.assertEqual(d['qualified_callees'],[])
  for name,key in [('inputs.jsonl','input_sha256'),('expected.jsonl','expected_sha256')]:self.assertEqual(hashlib.sha256((P/name).read_bytes()).hexdigest(),d[key])
 def test_all_five_exact_multiply_boundaries(self):
  for i in range(5):
   a=[0]*5;a[i]=n.LIMIT;self.assertEqual(self.eval(values=a)[0],'R');a[i]+=1;self.assertEqual(self.eval(values=a)[0],['A','A','A','I','L'][i])
 def test_optional_skip_and_raw_nonboolean_outer(self):
  for outer in [0,2,n.MIN,n.MASK]:self.assertEqual(self.eval(outer=outer,values=(0,0,n.MASK,0,0))[0],'R')
  for outer in [0,1,2]:self.assertEqual(self.eval(outer=outer,inner=n.MIN,values=(0,0,0,n.MASK,0))[0],'R')
  for inner in [0,1,n.MIN-1,n.MIN+1,n.MASK]:self.assertEqual(self.eval(inner=inner,values=(0,0,0,n.MASK,0))[0],'I')
 def test_failure_priority_and_no_output_store(self):
  for a,want in [((n.MASK,n.MASK,n.MASK,n.MASK,n.MASK),'A'),((0,0,0,n.MASK,n.MASK),'I'),((0,0,0,0,n.MASK),'L')]:self.assertEqual(self.eval(values=a),[want,'a5'*120])
 def test_exact_active_payloads_and_padding(self):
  row=n.stimulus(values=(2,3,5,7,11));out=n.evaluate(self.im,row)[0][1];raw=bytes.fromhex(row[0]);self.assertEqual(out[32:72],raw[16:36].hex());self.assertEqual(out[144:184],raw[72:92].hex());self.assertEqual(out[72:80],'a5'*4);self.assertEqual(out[184:192],'a5'*4)
  for off,value in [(96,200),(104,300),(8,500),(64,700),(112,1100)]:self.assertEqual(out[off*2:off*2+16],value.to_bytes(8,'little').hex())
 def test_explicit_inactive_mask_not_zero_fill(self):
  out=self.eval(outer=2,inner=n.MIN)[1];self.assertEqual(out[16:72],'??'*28);self.assertEqual(out[112:184],'??'*36);self.assertEqual(out[:16],'00'*8);self.assertEqual(out[72:80],'a5'*4)
 def test_control_receipts_and_raw_replay(self):
  c=json.loads((P/'native-controls.json').read_text());self.assertEqual(len(c['output_changes']),16);self.assertEqual(len(c['rejections']),3)
  for row in c['output_changes']:self.assertNotEqual(row['original'],row['changed'])
  inputs=(P/'inputs.jsonl').read_text().splitlines();expected=(P/'expected.jsonl').read_text().splitlines()
  for i in sorted({0,len(inputs)-1,*range(0,len(inputs),max(1,len(inputs)//40))}):self.assertEqual(n.evaluate(self.im,json.loads(inputs[i]))[0],json.loads(expected[i]))
if __name__=='__main__':unittest.main()
