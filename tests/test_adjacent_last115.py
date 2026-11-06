"""Actual full leaf, all key/payload bytes, backing-tail state and SIMD ISA."""
from pathlib import Path
import hashlib,importlib.util,json,sys,unittest
ROOT=Path(__file__).resolve().parents[1];P=ROOT/'research/work-items/RE-001-adjacent-last-115'
sys.path.insert(0,str(P));spec=importlib.util.spec_from_file_location('adjacent115_native',P/'native.py');n=importlib.util.module_from_spec(spec);spec.loader.exec_module(n)
class AdjacentLast(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.im=n.Image()
  if hashlib.sha256(cls.im.data).hexdigest()!=n.SHA:raise ValueError('wrong115target')
 @classmethod
 def tearDownClass(cls):cls.im.close()
 def test_frozen(self):
  d=json.loads((P/'proof.json').read_text())
  for file,key in [('inputs.hex','input_sha256'),('expected.jsonl','expected_sha256')]:self.assertEqual(hashlib.sha256((P/file).read_bytes()).hexdigest(),d[key])
  self.assertEqual((d['visited_bytes'],d['visited_instructions']),(308,73));self.assertEqual(d['callees'],[])
 def test_short_and_distinct_no_writes(self):
  for keys in [[],[1],[1,2],[1,2,1],list(range(32))]:
   raw=n.records(keys).hex();result,_,writes=n.evaluate(self.im,raw);self.assertEqual(result,[len(keys),raw]);self.assertFalse(writes)
 def test_complete_last_row_and_tail(self):
  raw=n.records([0,0,1,2,2]);rows=[raw[i:i+32] for i in range(0,len(raw),32)];result,_,_=n.evaluate(self.im,raw.hex())
  self.assertEqual(result,[3,b''.join([rows[1],rows[2],rows[4],rows[3],rows[3]]).hex()])
 def test_all_key_and_payload_bytes(self):
  raw=n.records([1,1])
  for at in range(32):
   changed=bytearray(raw);changed[32+at]^=1;result,_,_=n.evaluate(self.im,changed.hex());self.assertEqual(result[0],2 if at<20 else 1)
   if at>=20:self.assertEqual(result[1][:64],changed[32:].hex())
 def test_simd_architecture(self):
  m=n.Machine(self.im,2);m.set_reg(n.cpu.RCX,n.BUFFER);m.set_reg(n.cpu.RSI,0);m.store(n.BUFFER+48,4,0x12345678);m.flags=[True,False,True,False];flags=list(m.flags)
  ins=self.im.fetch(0x5b2d54f);m.two_byte(ins,ins.key,16,0,ins.va);self.assertEqual(m.xmm[0],bytes.fromhex('78563412')+bytes(12))
  m.xmm[2]=m.xmm[0];ins=self.im.fetch(0x5b2d55b);m.two_byte(ins,ins.key,16,0,ins.va);self.assertEqual(m.xmm[2],bytes([255])*16)
  m.xmm[1]=bytes([255])*15+b'\x00';ins=self.im.fetch(0x5b2d55f);m.two_byte(ins,ins.key,16,0,ins.va);ins=self.im.fetch(0x5b2d563);m.two_byte(ins,ins.key,16,8,ins.va);self.assertEqual(m.get(n.cpu.R9,64),0x7fff);self.assertEqual(m.flags,flags)
 def test_controls(self):
  d=json.loads((P/'native-controls.json').read_text());self.assertEqual(len(d['output_changes']),17);self.assertEqual(len(d['rejections']),2)
  for c in d['output_changes']:self.assertNotEqual(c['original'],c['changed'])
 def test_sealed_sample_replay(self):
  rows=(P/'inputs.hex').read_text().splitlines();gold=(P/'expected.jsonl').read_text().splitlines()
  for i in sorted({0,len(rows)-1,*range(0,len(rows),max(1,len(rows)//35))}):self.assertEqual(n.evaluate(self.im,rows[i])[0],json.loads(gold[i]))
if __name__=='__main__':unittest.main()
