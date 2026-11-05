"""Authentic private floor dataflow, symbolic scope and unresolved dependencies."""
from pathlib import Path
import hashlib,importlib.util,json,tempfile,unittest
from unittest import mock
ROOT=Path(__file__).resolve().parents[1];P=ROOT/'research/work-items/RE-004-fee-floor-policy-115'
spec=importlib.util.spec_from_file_location('fee_floor_policy115_collect',P/'collect.py');c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
class FeeFloorPolicy(unittest.TestCase):
 @classmethod
 def setUpClass(cls):cls.data=(ROOT/'artifacts/node/115/hl-node').read_bytes()
 def test_full_target_extents_and_separate_context(self):
  self.assertEqual(hashlib.sha256(self.data).hexdigest(),c.SHA);d=json.loads((P/'records.json').read_text());self.assertEqual((d['new_helper_bytes'],d['conditional_math_context_bytes'],d['exported_bytes']),(1136,1240,2376));self.assertEqual(d['implementation_bytes'],0);self.assertEqual(d['requested_gates'],[])
  for w in d['windows']:self.assertEqual(hashlib.sha256(c.read(self.data,int(w['start'],16),w['bytes'])[1]).hexdigest(),w['sha256'])
 def test_actual_constants_and_late_head(self):
  facts=c.anchors(self.data);self.assertEqual(facts['epsilon_bits'],'0x3ed4f8b588e368f1');self.assertEqual(facts['coefficients'],[0.2,6.0,0.1,2.0,40.0]);self.assertEqual(facts['late_success_head'],2);self.assertFalse(facts['whole_gate_implemented']);self.assertEqual(len(bytes.fromhex(c.DATA[0x79d4d0])),48)
 def test_structural_corruptions_below_identity(self):
  controls=json.loads((P/'controls.json').read_text());self.assertEqual(len(controls),26)
  for item in controls:
   at=int(item['va'],16);off,_=c.read(self.data,at,1);changed=bytearray(self.data);changed[off]=item['new']
   with self.assertRaises(ValueError):c.anchors(changed)
 def test_wrong_identity_before_tools_and_output(self):
  with tempfile.TemporaryDirectory() as tmp:
   out=Path(tmp)/'absent';changed=bytearray(self.data);changed[0]^=1
   with mock.patch.object(c.subprocess,'check_output',side_effect=AssertionError('tool before identity')):
    with self.assertRaisesRegex(ValueError,'identity mismatch'):c.collect(changed,out)
   self.assertFalse(out.exists())
 def test_ten_math_calls_match_actual_sites_and_cached_indirection(self):
  d=json.loads((P/'records.json').read_text());w=d['windows'][0];calls=[x for x in w['calls'] if x.get('slot')=='0x64e0fd0' or x.get('raw')=='41ffd6'];plan=json.loads((P/'symbolic-plan.json').read_text());self.assertEqual({x['pc'] for x in calls},{x['site'] for x in plan['calls']});self.assertEqual(len(calls),10)
  bindings={x['slot']:x for x in d['bindings']};self.assertEqual(bindings['0x64e0fd0']['addend'],'0x63f0210');self.assertEqual(bindings['0x64ffe00']['addend'],'0x63f06a0');self.assertTrue(all(x['target']=='unresolved runtime pointer' for x in calls if x['kind']=='register-indirect'))
 def test_unordered_and_equality_local_flags_not_admission_oracle(self):
  p=json.loads((P/'symbolic-plan.json').read_text());self.assertFalse(p['native_or_rust_execution']);self.assertFalse(p['helper_results_supplied']);self.assertFalse(p['whole_function_model']);rows={r['relation']:r for r in p['ucomisd_epsilon_value']}
  self.assertFalse(rows['unordered']['JA']);self.assertTrue(rows['unordered']['JBE']);self.assertFalse(rows['value==epsilon']['JA']);self.assertTrue(rows['value<epsilon']['JA'])
 def test_symbolic_results_stay_opaque_and_late_gate_separate(self):
  p=json.loads((P/'symbolic-plan.json').read_text());self.assertTrue(all(x['result']=='opaqueM'+str(i) for i,x in enumerate(p['calls'])));self.assertEqual(len(p['sum_checks']),2);self.assertEqual(p['late_gate']['head_qword_equal'],2);self.assertEqual(p['late_gate']['call'],'0x36a5cb2')
if __name__=='__main__':unittest.main()
