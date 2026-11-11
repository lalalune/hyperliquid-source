"""Whole permutation, authentic states and exact task-local actual ROL forms."""
from pathlib import Path
import hashlib,importlib.util,json,sys,unittest
ROOT=Path(__file__).resolve().parents[1];P=ROOT/'research/work-items/RE-009-sponge-permutation-115'
sys.path.insert(0,str(P));spec=importlib.util.spec_from_file_location('sponge115_native',P/'native.py');n=importlib.util.module_from_spec(spec);spec.loader.exec_module(n)
class SpongePermutation(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.im=n.Image();cls.rows=(P/'inputs.txt').read_text().splitlines();cls.gold=(P/'expected.txt').read_text().splitlines()
  if hashlib.sha256(cls.im.data).hexdigest()!=n.SHA:raise ValueError('wrong115target')
 @classmethod
 def tearDownClass(cls):cls.im.close()
 def test_sealed_entire_extent_and_full_states(self):
  d=json.loads((P/'proof.json').read_text());self.assertEqual(d['selected_addresses'],d['visited_addresses']);self.assertEqual((d['selected_bytes'],d['selected_instructions'],d['rows']),(1410,354,262));self.assertEqual(d['qualified_callees'],[]);self.assertEqual(d['actual_steps'],[6219]);self.assertTrue(all(len(x)==400 for x in self.rows+self.gold))
  for name,key in [('inputs.txt','input_sha256'),('expected.txt','expected_sha256')]:self.assertEqual(hashlib.sha256((P/name).read_bytes()).hexdigest(),d[key])
 def test_zero_and_ones_full200bytes(self):
  for i in [0,1]:self.assertEqual(n.evaluate(self.im,self.rows[i])[0],self.gold[i])
 def test_every_lane_significant_from_original_states(self):
  for lane in range(25):
   i=5+9*lane;self.assertEqual(n.evaluate(self.im,self.rows[i])[0],self.gold[i])
  self.assertEqual(len(set(self.gold)),len(self.gold))
 @unittest.skipUnless(importlib.util.find_spec('capstone'),'optional Capstone missing; skip is not a decoder pass')
 def test_actual_rol_forms_and_flags(self):
  import capstone
  cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);a,b=n.OWNER;seq=list(cs.disasm(self.im.view.read(a,b-a),a));rolls=[i for i in seq if i.mnemonic=='rol'];chosen=[next(i for i in rolls if len(i.bytes)==3),next(i for i in rolls if len(i.bytes)==4)]
  for i in chosen:
   ins=self.im.fetch(i.address);count=1 if ins.key==0xd1 else i.bytes[-1];reg=n.Machine(self.im).operand(ins)[1]
   for value in [0,1,1<<63,n.MASK,0x8123456789abcdef]:
    m=n.Machine(self.im);m.pc=i.address;m.set_reg(reg,value);m.flags=[False,True,False,False];want=value
    for _ in range(count&63):want=((want<<1)|((want>>63)&1))&n.MASK
    m.step();self.assertEqual(m.get(reg,64),want);self.assertEqual(m.flags[1:3],[True,False]);self.assertEqual(m.flags[0],bool(want&1));self.assertEqual(m.flags[3],bool((want>>63)^int(bool(want&1))) if count==1 else None)
 def test_frozen_real_byte_controls_classified_separately(self):
  c=json.loads((P/'native-controls.json').read_text());self.assertEqual(len(c['output_changes']),12);self.assertEqual(len(c['rejections']),2)
  for x in c['output_changes']:self.assertNotEqual(x['original'],x['changed']);self.assertEqual(len(x['original']),400);self.assertEqual(len(x['changed']),400)
 def test_readonly_table_and_state_shape_refusals_are_harness_policy(self):
  m=n.Machine(self.im);m.record=True
  with self.assertRaisesRegex(ValueError,'readonly'):m.store(n.TABLE,8,0)
  with self.assertRaises(ValueError):n.evaluate(self.im,'00'*199)
  with self.assertRaises(ValueError):m.store(n.STATE+200,1,0)
 def test_dense_and_endian_asymmetric_states(self):
  for i in [2,3,4,len(self.rows)-2,len(self.rows)-1]:
   output,seen,steps=n.evaluate(self.im,self.rows[i]);self.assertEqual(output,self.gold[i]);self.assertEqual(steps,6219);self.assertEqual(len(seen),354)
if __name__=='__main__':unittest.main()
