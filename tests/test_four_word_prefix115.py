"""Target-specific decoder checks; no captured process execution."""
from pathlib import Path
import hashlib, importlib.util, json, sys, unittest
ROOT=Path(__file__).resolve().parents[1]
PACKET=ROOT/'research/work-items/RE-005-four-word-prefix-115'
spec=importlib.util.spec_from_file_location('four115_native',PACKET/'native.py')
native=importlib.util.module_from_spec(spec)
sys.path.insert(0,str(PACKET));spec.loader.exec_module(native)

class FourWordPrefix(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.im=native.Image()
  if hashlib.sha256(cls.im.data).hexdigest()!=native.SHA:raise ValueError('wrong node115')
 @classmethod
 def tearDownClass(cls):cls.im.close()
 def test_frozen_fixtures(self):
  proof=json.loads((PACKET/'proof.json').read_text())
  for name,key in [('inputs.jsonl','input_sha256'),('expected.jsonl','expected_sha256')]:self.assertEqual(hashlib.sha256((PACKET/name).read_bytes()).hexdigest(),proof[key])
  self.assertEqual(len((PACKET/'inputs.jsonl').read_bytes().splitlines()),proof['rows'])
 def test_sequential_charge(self):
  # A reused aggregate precharge32 would incorrectly read zero bytes here.
  result,_,calls=native.evaluate(self.im,('111d2b3d00',8,0))
  self.assertEqual(result,[['limit'],1,16]);self.assertEqual(sum(b==0x2cd7ac0 for a,b in calls),2)
 def test_mode_boundaries(self):
  for limit,result in [(32,[['limit'],4,33]),(33,[['ok',[17,29,43,61],None],5,33])]:self.assertEqual(native.evaluate(self.im,('111d2b3d00',limit,0))[0],result)
  self.assertEqual(native.evaluate(self.im,('111d2b3d0149',40,0))[0],[['limit'],5,41])
  self.assertEqual(native.evaluate(self.im,('111d2b3d02ff',None,0))[0],[['mode',2],5,0])
 def test_slow_fast_invalid(self):
  self.assertEqual(native.evaluate(self.im,('fe',None,0))[0],[['invalid',3,4],1,0])
  self.assertEqual(native.evaluate(self.im,('fe'+'00'*8,None,0))[0],[['invalid',2,4],0,0])
  self.assertEqual(native.evaluate(self.im,('0005',None,0))[0],[['end',1],2,0])
  self.assertEqual(native.evaluate(self.im,('111d2b3d01fe',None,0))[0],[['invalid',3,4],6,0])
 def test_isa_knownness_and_rotate(self):
  m=native.Machine(self.im,0);a=native.STACK
  m.store(a,8,0x123456789abcdef0)
  # Genuine third/fourth-error MOVUPS instructions copy known low qword
  # and unknown high qword without manufacturing padding.
  m.set_reg(native.cpu.RSP,a-16);m.set_reg(native.cpu.RBX,native.OUT)
  ins=self.im.fetch(0x2ce18cf);m.two_byte(ins,ins.key,32,0,ins.va)
  ins=self.im.fetch(0x2ce18ea);m.two_byte(ins,ins.key,32,0,ins.va)
  self.assertEqual(m.load(native.OUT+16,8),0x123456789abcdef0);self.assertIsNone(m.load(native.OUT+24,8))
  self.assertEqual(m.shift(0,0x1234,8,16),0x3412)
  for va,value,want,bits in [(0x5822671,0x0123456789abcdef,0xefcdab8967452301,64),(0x58226b8,0x12345678,0x78563412,32)]:
   m.set_reg(native.cpu.RAX,value);ins=self.im.fetch(va);m.two_byte(ins,ins.key,bits,0,va);self.assertEqual(m.get(native.cpu.RAX,64),want)
 def test_real_edges_and_controls(self):
  p=json.loads((PACKET/'proof.json').read_text());controls=json.loads((PACKET/'native-controls.json').read_text())
  self.assertEqual(p['slots'],{hex(k):hex(v) for k,v in self.im.slots.items()});self.assertGreaterEqual(len(p['calls']),10)
  self.assertEqual(len(controls),11)
  for c in controls:self.assertNotEqual(c['original'],c['changed'])
 def test_frozen_sample_replay(self):
  rows=(PACKET/'inputs.jsonl').read_text().splitlines();expected=(PACKET/'expected.jsonl').read_text().splitlines()
  for i in sorted({0,len(rows)-1,*range(0,len(rows),max(1,len(rows)//30))}):self.assertEqual(native.evaluate(self.im,json.loads(rows[i]))[0],json.loads(expected[i]))

if __name__=='__main__':unittest.main()
