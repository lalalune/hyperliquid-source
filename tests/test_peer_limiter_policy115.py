"""Static limiter evidence; no oracle or native behavioral execution claim."""
from pathlib import Path
import hashlib,importlib.util,json,sys,tempfile,unittest
from unittest import mock
ROOT=Path(__file__).resolve().parents[1];P=ROOT/'research/work-items/RE-012-peer-limiter-counter-policy-115'
spec=importlib.util.spec_from_file_location('peer_limiter_policy115_collect',P/'collect.py');c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
class LimiterPolicy(unittest.TestCase):
 @classmethod
 def setUpClass(cls):cls.data=(ROOT/'artifacts/node/115/hl-node').read_bytes()
 def test_target_and_retained_full_extents(self):
  self.assertEqual(hashlib.sha256(self.data).hexdigest(),c.SHA);d=json.loads((P/'records.json').read_text());self.assertEqual(d['new_helper_bytes'],1751);self.assertEqual(d['credited_caller_bytes'],4137);self.assertEqual(d['implementation_bytes'],0);self.assertEqual(d['requested_gates'],[])
  for w in d['windows']:self.assertEqual(hashlib.sha256(c.read(self.data,int(w['start'],16),w['bytes'])[1]).hexdigest(),w['sha256'])
 def test_actual_operand_derived_scalars(self):
  f=c.anchors(self.data);self.assertEqual((f['raw_charge_minimum'],f['budget_wrapping_factor'],f['key_bytes']),(1,10,20))
 def test_every_selected_instruction_group_rejects_below_identity(self):
  controls=json.loads((P/'controls.json').read_text());self.assertEqual(len(controls),26)
  for address,raw in c.CONFIG['anchors'].items():
   at=int(address,16);off,_=c.read(self.data,at,len(bytes.fromhex(raw)));changed=bytearray(self.data);changed[off]^=1
   with self.assertRaises(ValueError):c.anchors(changed)
 def test_wrong_identity_is_rejected_before_output_or_tools(self):
  with tempfile.TemporaryDirectory() as tmp:
   out=Path(tmp)/'must-not-exist';changed=bytearray(self.data);changed[0]^=1
   with mock.patch.object(c.subprocess,'check_output',side_effect=AssertionError('native tool called before identity')):
    with self.assertRaisesRegex(ValueError,'identity mismatch'):c.collect(changed,out)
   self.assertFalse(out.exists())
 def test_runtime_targets_remain_explicitly_unknown(self):
  d=json.loads((P/'records.json').read_text());helper=next(w for w in d['windows'] if w['start']=='0x595ec00');calls=helper['calls'];self.assertEqual({x['pc'] for x in calls if x['kind']=='register-indirect'},{'0x595ec83','0x595ee2f'});self.assertTrue(all(x['target']=='unresolved runtime pointer' for x in calls if x['kind']=='register-indirect'));binding=next(x for x in d['bindings'] if x['slot']=='0x64dfb50');self.assertEqual(binding['symbol'],'memcmp')
 def test_boundary_tables_are_local_math_only(self):
  d=json.loads((P/'relations.json').read_text());self.assertFalse(d['native_or_rust_execution']);self.assertFalse(d['whole_function_model']);self.assertTrue(any(x['budget']==(1<<64)-1 and x['wrapped10']!=(1<<64)-1 for x in d['budgets']));self.assertEqual(next(x['charge'] for x in d['charges'] if x['raw']==0),1)
 def test_final_equality_is_not_strict_overbudget(self):
  d=json.loads((P/'relations.json').read_text());self.assertTrue(all(not x['strictly_over'] for x in d['final_compare'] if x['charge']==x['budget10']));self.assertTrue(any(x['strictly_over'] for x in d['final_compare']));self.assertTrue(any(x['overflow'] and not x['secondary_call_local'] for x in d['secondary_compare']))
if __name__=='__main__':unittest.main()
