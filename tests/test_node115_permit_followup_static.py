"""Pinned operand/caller/metadata controls and explicitly synthetic algebra checks."""
import importlib.util,json,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];PACKET=ROOT/'research/work-items/RE-014-permit-followup-115'
spec=importlib.util.spec_from_file_location('permit_followup115',PACKET/'analyze.py');subject=importlib.util.module_from_spec(spec);spec.loader.exec_module(subject)
class PermitFollowupTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):cls.data=bytearray(subject.TARGET.read_bytes());cls.report=subject.analyze(cls.data)
 def test_original_owner_records_and_explicit_zero_native_denominator(self):
  self.assertEqual(self.report,json.loads((PACKET/'records.json').read_text()))
  self.assertEqual([len(o['instructions']) for o in self.report['owners']],[234,101]);self.assertEqual(sum(o['bytes'] for o in self.report['owners']),1397)
  self.assertEqual(self.report['native_behavioral_comparisons'],0)
 def test_exact_regeneration(self):
  with tempfile.TemporaryDirectory() as d:
   out=Path(d)/'new';subject.generate(out)
   for p in out.iterdir():self.assertEqual(p.read_bytes(),(PACKET/p.name).read_bytes())
 def test_actual_operand_and_call_displacement_damage(self):
  for va,message in [(x,'operand changed') for x,_ in subject.ANCHORS]+[(0x477106f,'call changed')]:
   off=subject.read(self.data,va,1)[0];old=self.data[off];self.data[off]^=1
   try:
    with self.assertRaisesRegex(ValueError,message):subject.analyze(self.data,authenticate=False)
   finally:self.data[off]=old
 def test_other_helper_branches_remain_hash_bound(self):
  off=subject.read(self.data,0x5ce5538,1)[0];old=self.data[off];self.data[off]^=1
  try:
   with self.assertRaisesRegex(ValueError,'owner instruction bytes'):subject.analyze(self.data,authenticate=False)
  finally:self.data[off]=old
 def test_fde_extent_is_not_inferred_from_instruction_export(self):
  va=int(self.report['owners'][0]['unwind']['fde']['va'],16)+12;off=subject.read(self.data,va,1)[0];old=self.data[off];self.data[off]^=1
  try:
   with self.assertRaises(ValueError):subject.analyze(self.data,authenticate=False)
  finally:self.data[off]=old
 def test_synthetic_restore_algebra_and_post_write_guard_boundary(self):
  p=self.report['parameters'];capacities={1,2,3,(1<<61)-1,(1<<61)-2}
  capacities.update((1<<k)+d for k in range(1,61) for d in (-1,0,1))
  for n in capacities:
   r=subject.empty_relation(p,2*n-2);self.assertEqual(r,dict(after=2*n,post_guard=True,low_bit_preserved=True))
  self.assertEqual(p['owner_to_lock']+p['state_from_lock'],0x30)
  self.assertEqual(p['owner_to_lock']+p['queue_from_lock'],0x20)
  r=subject.empty_relation(p,(1<<62)-2);self.assertEqual(r['after'],1<<62);self.assertFalse(r['post_guard'])
  changed=dict(p,state_scale=4);self.assertNotEqual(subject.empty_relation(changed,0)['after'],2)
  for w in [1,3,(1<<62)-3]:self.assertTrue(subject.empty_relation(p,w)['low_bit_preserved'])
 def test_public_identity_gate(self):
  off=subject.read(self.data,0x5ce5310,1)[0];old=self.data[off];self.data[off]^=1
  try:
   with self.assertRaisesRegex(ValueError,'wrong pinned node115'):subject.analyze(self.data)
  finally:self.data[off]=old
if __name__=='__main__':unittest.main()
