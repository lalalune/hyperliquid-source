"""Frozen target-derived monotone/run controls, without captured execution."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

PACKET=Path(__file__).resolve().parents[1]/'research/work-items/RE-006-large-sort-monotone-path-94'
spec=importlib.util.spec_from_file_location('large_sort_monotone94',PACKET/'verify.py')
packet=importlib.util.module_from_spec(spec); spec.loader.exec_module(packet)


class MonotonePathTests(unittest.TestCase):
    def test_pre_model_freeze_and_all_frozen_vectors(self):
        result=packet.vector_controls()
        self.assertEqual((result['complete_monotone_cases'],result['tie_boundary_cases']), (76,20))
        self.assertEqual(len(result['cases']),96)

    def test_all_equal_is_non_decreasing_and_unwritten(self):
        for n in [21,64,65,512,513,4096]:
            words=[2**63]*n; output,result=packet.first_run_model(words)
            self.assertEqual(output,words)
            self.assertFalse(result['descending'])
            self.assertEqual(result['input_qwords_written'],0)

    def test_unsigned_crossing_is_one_complete_run(self):
        case=next(c for c in packet.frozen('fixtures.json')['cases'] if c['name']=='increasing-21')
        words=packet.words_for(case); output,result=packet.first_run_model(words)
        self.assertLess(words[0],2**63); self.assertGreater(words[-1],2**63)
        self.assertEqual(output,words); self.assertEqual(result['run'],21)

    def test_descending_tie_terminates_and_threshold_is_inclusive(self):
        for index in [10,11,12]:
            words=list(range(21,0,-1)); words[index]=words[index-1]
            output,result=packet.first_run_model(words)
            self.assertEqual(result['run'],index)
            self.assertEqual(result['accepted'],index>=11)
            self.assertEqual(output[index:],words[index:])

    def test_vector_four_pairs_scalar_tail_and_odd_center(self):
        for n in range(21,38):
            words=list(range(n,0,-1)); output,result=packet.first_run_model(words)
            self.assertEqual(output,list(range(1,n+1)))
            self.assertEqual(result['vector_blocks'],(n//2)//4)
            self.assertEqual(result['tail_pairs'],(n//2)%4)
            self.assertEqual(result['input_qwords_written'],2*(n//2))
            self.assertEqual(result['encoded_run'],2*n+1)
            if n%2: self.assertEqual(output[n//2],words[n//2])

    def test_model_scope_is_explicit(self):
        for n in [20,4097]:
            with self.subTest(count=n),self.assertRaises(ValueError): packet.first_run_model(list(range(n)))

    def test_target_admission_and_all_frozen_operand_corruptions(self):
        data=packet.scratch.TARGET.read_bytes(); self.assertEqual(packet.sha(data),packet.scratch.SHA)
        image=packet.scratch.Image(data); packet.operand_obligations(image)
        for mutation in packet.frozen('mutations.json')['controls']:
            raw=bytes.fromhex(mutation['mutation_hex']); pos=image.offset(int(mutation['va'],16),len(raw))
            changed=bytearray(data); changed[pos:pos+len(raw)]=raw
            with self.subTest(name=mutation['name']),self.assertRaisesRegex(ValueError,'frozen operand mismatch'):
                packet.operand_obligations(packet.scratch.Image(changed))

    def test_selected_graph_rejects_calls_and_input_writes(self):
        records=json.loads((PACKET/'records.json').read_text())
        data=packet.scratch.TARGET.read_bytes()
        self.assertEqual(packet.scratch.Image(data).window(*packet.BOUNDS),records['complete_inner_body'])
        nodes,calls=records['normal_cfg'],records['all_calls']
        for direction in ['nondecreasing','strictly-decreasing']:
            result=packet.selected_graph(nodes,calls,direction); self.assertEqual(result['reachable_calls'],[])
        calls=copy.deepcopy(calls)+[{'site':'0x4dbd647','kind':'synthetic corrupt call'}]
        with self.assertRaisesRegex(ValueError,'reaches unresolved call'):
            packet.selected_graph(nodes,calls,'nondecreasing')
        changed=copy.deepcopy(nodes)
        next(n for n in changed if n['site']=='0x4dbd647')['native']='mov QWORD PTR [rdi],rax'
        with self.assertRaisesRegex(ValueError,'unexpected selected input write'):
            packet.selected_graph(changed,records['all_calls'],'nondecreasing')


if __name__=='__main__': unittest.main()
