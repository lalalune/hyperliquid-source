"""Actual admission-prefix order, overlapping fields, first-call/RET distinction."""
from pathlib import Path
import hashlib,importlib.util,json,sys,unittest
ROOT=Path(__file__).resolve().parents[1];P=ROOT/'research/work-items/RE-001-user-admission-prefix-115'
sys.path.insert(0,str(P));spec=importlib.util.spec_from_file_location('user_prefix115_native',P/'native.py');n=importlib.util.module_from_spec(spec);spec.loader.exec_module(n)
class UserPrefix(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.im=n.Image()
  if hashlib.sha256(cls.im.data).hexdigest()!=n.SHA:raise ValueError('wrong115target')
 @classmethod
 def tearDownClass(cls):cls.im.close()
 def test_frozen_closed_cfg(self):
  d=json.loads((P/'proof.json').read_text());self.assertEqual(d['selected_addresses'],d['visited_addresses']);self.assertEqual(len(d['unexecuted_first_calls']),4);self.assertEqual(d['qualified_callees'],[]);self.assertEqual(set(d['frontier_counts']),{'R','I','C','B','O'});self.assertIn('unknown',d['unresolved_import']['runtime_pointer'])
  for f,k in [('inputs.jsonl','input_sha256'),('expected.jsonl','expected_sha256')]:self.assertEqual(hashlib.sha256((P/f).read_bytes()).hexdigest(),d[k])
 def test_early_tag_before_state_or_identity_reads(self):
  m=n.Machine(self.im,0);m.store(n.DESC,8,(1<<63)+1);m.store(n.SP,8,n.cpu.RETURN_MARK)
  for i in range(16):m.mem[n.OUT+i]=0xa5
  for reg,value in [(n.cpu.RDI,n.OUT),(n.cpu.RSI,n.STATE),(n.cpu.RDX,n.IDENT),(n.cpu.RCX,n.DESC),(n.cpu.RSP,n.SP)]:m.set_reg(reg,value)
  m.record=True
  with self.assertRaises(n.cpu.Done):m.run(n.OWNER[0])
  self.assertFalse(any(n.STATE<=a<n.STATE+0x1100 or n.IDENT<=a<n.IDENT+20 for a in m.reads));self.assertEqual(m.get(n.cpu.RSP,64),n.SP+8);self.assertEqual(n.memory_hex(m,n.OUT,2),'9200')
 def test_raw_byte_gate_order(self):
  for op in [1,3,255]:self.assertEqual(n.evaluate(self.im,n.stimulus(raw=1<<63,op=op))[0][1][:4],'9200')
  self.assertEqual(n.evaluate(self.im,n.stimulus(raw=1<<63,op=2))[0][0],'O')
  self.assertEqual(n.evaluate(self.im,n.stimulus(raw=1<<63,identity_bit=2))[0][0],'O')
  self.assertEqual(n.evaluate(self.im,n.stimulus(raw=1<<63,identity_bit=3,op=1))[0][0],'I')
  self.assertEqual(n.evaluate(self.im,n.stimulus(raw=1<<63,active=2))[0][0],'O')
 def test_amount_or_budget_and_canaries(self):
  row=n.stimulus(mode=1,amount=n.LIMIT);out=n.evaluate(self.im,row)[0];self.assertEqual(out,['R','5401'+('a5'*6)+n.LIMIT.to_bytes(8,'little').hex(),[]])
  self.assertEqual(n.evaluate(self.im,n.stimulus(mode=1,amount=0,budget=0,guard=1,aux=1))[0][0],'O')
  self.assertEqual(n.evaluate(self.im,n.stimulus(mode=1,amount=1,budget=n.MASK,guard=1))[0][1],'0c01'+'a5'*14)
  self.assertEqual(n.evaluate(self.im,n.stimulus(mode=1,amount=1,aux=0))[0][1],'0a01'+'a5'*14)
  out=n.evaluate(self.im,n.stimulus(mode=255,amount=1,budget=0,aux=1))[0];self.assertEqual(out,['B','a5'*16,[0,255,1,0]])
 def test_empty_tree_and_unknown_comparison_frontier(self):
  self.assertEqual(n.evaluate(self.im,n.stimulus(active=0,height=2,counts=[0,0,0]))[0][1],'9800'+'a5'*14)
  out=n.evaluate(self.im,n.stimulus(raw=1<<63,active=0,height=2,counts=[0,0,11]))[0];self.assertEqual(out,['C','a5'*16,[1,2,0,220]])
  out=n.evaluate(self.im,n.stimulus(active=0,height=n.MASK,counts=[256]))[0];self.assertEqual(out,['C','a5'*16,[0,0,n.MASK,5120]])
 def test_overlapping_peer_identity_and_context_bytes(self):
  row=n.stimulus(raw=1<<63,identity_bit=1,mode=255,op=255,amount=n.MASK,guard=2,pattern=37);out=n.evaluate(self.im,row)[0];self.assertEqual(out,['I','a5'*16,[1,255,255,bytes.fromhex(row[0])[0x4f:0x63].hex(),row[7]]])
  row=n.stimulus(raw=1<<63,mode=2,pattern=37);self.assertEqual(n.evaluate(self.im,row)[0],['O','a5'*16,[1,2,row[8]]])
 def test_controls_and_sealed_replay(self):
  d=json.loads((P/'native-controls.json').read_text());self.assertEqual(len(d['output_changes']),16);self.assertEqual(len(d['rejections']),3)
  for c in d['output_changes']:self.assertNotEqual(c['original'],c['changed'])
  rows=(P/'inputs.jsonl').read_text().splitlines();gold=(P/'expected.jsonl').read_text().splitlines()
  for i in sorted({0,len(rows)-1,*range(0,len(rows),max(1,len(rows)//42))}):self.assertEqual(n.evaluate(self.im,json.loads(rows[i]))[0],json.loads(gold[i]))
if __name__=='__main__':unittest.main()
