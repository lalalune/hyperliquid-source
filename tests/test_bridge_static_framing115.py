"""Private bridge tags, count units and explicit conditional framing scope."""
from pathlib import Path
import hashlib,importlib.util,json,tempfile,unittest
from unittest import mock
ROOT=Path(__file__).resolve().parents[1];P=ROOT/'research/work-items/RE-005-bridge-static-framing-115'
spec=importlib.util.spec_from_file_location('bridge_framing115_collect',P/'collect.py');c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
class BridgeFraming(unittest.TestCase):
 @classmethod
 def setUpClass(cls):cls.data=(ROOT/'artifacts/node/115/hl-node').read_bytes()
 def test_exact_target_and_role_denominators(self):
  d=json.loads((P/'records.json').read_text());self.assertEqual(hashlib.sha256(self.data).hexdigest(),c.SHA);self.assertEqual((d['new_helper_bytes'],d['conditional_framing_context_bytes'],d['exported_bytes']),(369,4062,4431));self.assertEqual(d['implementation_bytes'],0);self.assertEqual(d['requested_gates'],[])
  for w in d['windows']:self.assertEqual(hashlib.sha256(c.read(self.data,int(w['start'],16),w['bytes'])[1]).hexdigest(),w['sha256'])
 def test_actual_private_tags_and_count(self):
  f=c.anchors(self.data);self.assertEqual((f['token_count'],f['first_raw_tag'],f['second_raw_tag'],f['second_payload_bytes']),(2,0,1,32));self.assertFalse(f['whole_encoding_executed']);self.assertFalse(f['whole_bridge_implemented'])
 def test_selected_real_byte_structural_controls(self):
  controls=json.loads((P/'controls.json').read_text());self.assertEqual(len(controls),26)
  for row in controls:
   at=int(row['va'],16);off,_=c.read(self.data,at,1);changed=bytearray(self.data);changed[off]=row['new']
   with self.assertRaises(ValueError):c.anchors(changed)
 def test_wrong_identity_before_tools_or_output(self):
  with tempfile.TemporaryDirectory() as tmp:
   out=Path(tmp)/'absent';changed=bytearray(self.data);changed[0]^=1
   with mock.patch.object(c.subprocess,'check_output',side_effect=AssertionError('tools before identity')):
    with self.assertRaisesRegex(ValueError,'identity mismatch'):c.collect(changed,out)
   self.assertFalse(out.exists())
 def test_table_bindings_have_actual_owning_instruction_starts(self):
  p=json.loads((P/'framing-plan.json').read_text());self.assertEqual(len(p['dispatch_tables']),4);self.assertTrue(all(x['all_instruction_starts'] for x in p['dispatch_tables']));t=c.anchors(self.data)['dispatch_targets'];self.assertEqual(t['0x47b72c'][:3],['0x169dce3','0x169ddb9','0x169dd62']);self.assertEqual(t['0x47b784'][0],'0x169e78c')
 def test_head_tail_units_and_counterfactual_are_not_executed(self):
  p=json.loads((P/'framing-plan.json').read_text());self.assertFalse(p['native_or_rust_execution']);self.assertFalse(p['whole_encoding_model']);self.assertFalse(p['helper_results_supplied']);self.assertEqual(p['actual']['total_accounting'],64);self.assertEqual(p['actual']['allocation_call_RDI'],2048);self.assertEqual(p['tag_byte_counterfactual']['pair_total_accounting'],128);self.assertFalse(p['tag_byte_counterfactual']['executed'])
 def test_actual_codec_relocation_and_source_context(self):
  d=json.loads((P/'records.json').read_text());bindings={x['slot']:x for x in d['bindings']};self.assertEqual(bindings['0x64e0140']['addend'],'0x169e350');self.assertEqual(bindings['0x64e0140']['info'],8)
  helper=next(w for w in d['windows'] if w['start']=='0x4302cd0');self.assertTrue(any(x.get('slot')=='0x64e0140' and x['pc']=='0x4302d85' for x in helper['calls']))
  source=next(x for x in d['source_locations'] if x['slot']=='0x648f278');self.assertEqual((source['path'],source['line'],source['column']),('l1/src/bridge_request.rs',83,78));self.assertTrue(source['xrefs'])
if __name__=='__main__':unittest.main()
