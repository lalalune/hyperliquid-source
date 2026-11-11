"""Original quantity stores/frontiers, without helper-return assumptions."""
import hashlib
import importlib.util
import json
import mmap
from pathlib import Path
import sys
import unittest
ROOT=Path(__file__).resolve().parents[1]
PACKET=ROOT/'research/work-items/RE-004-quantity-change-115'
sys.path.insert(0,str(PACKET));sys.path.insert(0,str(ROOT/'tools'))
spec=importlib.util.spec_from_file_location('quantity_change_native115',PACKET/'native.py')
n=importlib.util.module_from_spec(spec);spec.loader.exec_module(n)

class QuantityChangeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.im=n.Image()
        if hashlib.sha256(cls.im.data).hexdigest()!=n.SHA:
            cls.im.close();raise ValueError('wrong115target')
        cls.proof=json.loads((PACKET/'FREEZE.json').read_text())
    @classmethod
    def tearDownClass(cls):cls.im.close()

    def test_sealed_original_stream_and_all_selected_starts(self):
        inputs,expected,seen=n.corpus(self.im)
        self.assertEqual(len(set(inputs.splitlines())),3403)
        self.assertEqual(hashlib.sha256(inputs).hexdigest(),self.proof['input_sha256'])
        self.assertEqual(hashlib.sha256(expected).hexdigest(),self.proof['expected_sha256'])
        self.assertEqual(sorted(seen),self.proof['visited_addresses']);self.assertEqual(len(seen),103)

    def test_counter_store_before_lookup_and_saturated_store(self):
        maximum=n.cpu.U64
        for row,expected in [((1,0,1,0,0,90),'E:1:1:L'),((0,0,1,maximum,0,90),f'E:{maximum}:{maximum}:R'),((0,1,0,0,0,90),'E:0:-:R'),((0,1,0,1,0,90),'E:0:0:R'),((0,1,1,3,1,90),'E:3:-:R')]:
            with self.subTest(row=row):self.assertEqual(n.evaluate(self.im,row)[0],expected)

    def test_actual_ordered_total_stores_and_diagnostic_boundaries(self):
        minimum=1<<63;maximum=minimum-1;allones=n.cpu.U64
        for row,expected in [((2,0,0,0,0,90),'T:0:0,0:R'),((2,minimum,0,0,0,90),'T:0:-:I'),((2,1,minimum,0,0,90),f'T:{allones}:{allones}:I'),((2,1,1,minimum,0,90),f'T:{minimum}:-:S:{minimum}'),((2,0,1,maximum,0,90),f'T:{maximum}:{maximum}:A:{maximum}')]:
            with self.subTest(row=row):self.assertEqual(n.evaluate(self.im,row)[0],expected)

    def test_notification_words_payload_and_call_refusal(self):
        for seed in [0,90,255]:
            expected=f'E:4:4:N:{n.cpu.U64}:1:'+n.payload(seed).hex()
            self.assertEqual(n.evaluate(self.im,(0,0,1,3,n.cpu.U64,seed))[0],expected)
        with self.assertRaisesRegex(ValueError,'forbidden'):n.Machine(self.im).call()
        with self.assertRaisesRegex(ValueError,'CFG escape'):self.im.fetch(0x4206fe5)
        with self.assertRaisesRegex(ValueError,'footprint'):n.Machine(self.im).load(n.DESC+31,2)
        with self.assertRaisesRegex(ValueError,'footprint'):n.Machine(self.im).store(n.DESC,8,1)

    def test_sixteen_real_instruction_controls(self):
        controls=json.loads((PACKET/'native-controls.json').read_text());self.assertEqual(len(controls),16)
        for c in controls:
            with self.subTest(name=c['name']):
                changed=n.Image();changed.data=mmap.mmap(changed.view.file.fileno(),0,access=mmap.ACCESS_COPY)
                try:
                    a=int(c['va'],16);off=changed.view.offset(a)
                    self.assertEqual(bytes([changed.data[off]]).hex(),c['original_byte'])
                    changed.data[off]=int(c['changed_byte'],16);row=tuple(map(int,c['input_tsv'].split('\t')))
                    self.assertEqual(n.evaluate(self.im,row)[0],c['original'])
                    self.assertEqual(n.evaluate(changed,row)[0],c['changed'])
                    self.assertNotEqual(c['original'],c['changed'])
                finally:changed.close()

    def test_full_owner_unwind_and_selected_decode(self):
        import capstone
        owner=self.proof['owner'];lo,hi=int(owner['start'],16),int(owner['end'],16)
        self.assertEqual(self.im.view.fde(lo),(lo,hi));body=self.im.view.read(lo,hi-lo)
        self.assertEqual(hashlib.sha256(body).hexdigest(),owner['sha256'])
        cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);rows=list(cs.disasm(body,lo))
        self.assertEqual(len(rows),115);self.assertEqual(sum(i.size for i in rows),404)
        selected=[i for i in rows if any(a<=i.address<b for a,b in n.RANGES)]
        self.assertEqual(sum(i.size for i in selected),348)
        self.assertEqual({i.address for i in selected},set(self.proof['visited_addresses']))
        for i in selected:self.assertEqual(self.im.fetch(i.address).size,i.size)
        for record in owner['unwind'].values():
            raw=bytes.fromhex(record['raw_hex']);self.assertEqual(self.im.view.read(int(record['va'],16),len(raw)),raw)

    def test_retained_owned_builds_bound_to_source_and_original(self):
        report=json.loads((PACKET/'rust-results.json').read_text());self.assertEqual(report['target_sha256'],n.SHA)
        for file,key in [('src/node115-quantity-change/lib.rs','source_sha256'),('src/node115-quantity-change/input_only_driver.rs','driver_sha256'),('research/work-items/RE-004-quantity-change-115/client_fixture.rs','fixture_sha256')]:
            self.assertEqual(hashlib.sha256((ROOT/file).read_bytes()).hexdigest(),report[key])
        self.assertEqual(report['input_sha256'],self.proof['input_sha256']);self.assertEqual(report['expected_sha256'],self.proof['expected_sha256'])
        originals=[r for r in report['runs'] if r['variant']=='original'];self.assertEqual([r['opt'] for r in originals],['0','3'])
        self.assertTrue(all(r['mismatches']==0 and r['smoke_exit']==0 and r['rows']==3403 for r in originals))
        mutants=[r for r in report['runs'] if r['variant']!='original'];self.assertEqual(len(mutants),13)
        self.assertTrue(all(r['mismatches']>0 and r['smoke_exit']==101 and r['rows']==3403 for r in mutants))
        self.assertFalse(report['captured_process_executed']);self.assertFalse(report['ABI_or_whole_caller_equivalence'])

if __name__=='__main__':unittest.main()
