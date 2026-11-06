"""Original-byte prefix correspondence; allocator and metadata stay opaque."""
import hashlib
import importlib.util
import json
import mmap
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
PACKET=ROOT/'research/work-items/RE-001-symbol-prefix-115'
sys.path.insert(0,str(PACKET));sys.path.insert(0,str(ROOT/'tools'))
spec=importlib.util.spec_from_file_location('symbol_prefix_native115',PACKET/'native.py')
n=importlib.util.module_from_spec(spec);spec.loader.exec_module(n)

class SymbolPrefixTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.im=n.Image()
        if hashlib.sha256(cls.im.data).hexdigest()!=n.SHA:
            cls.im.close();raise ValueError('wrong115target')
        cls.proof=json.loads((PACKET/'FREEZE.json').read_text())
    @classmethod
    def tearDownClass(cls):cls.im.close()

    def test_original_streams_and_all_selected_starts(self):
        inputs,expected,seen=n.corpus(self.im)
        self.assertEqual(len(set(inputs.splitlines())),4072)
        self.assertEqual(hashlib.sha256(inputs).hexdigest(),self.proof['input_sha256'])
        self.assertEqual(hashlib.sha256(expected).hexdigest(),self.proof['expected_sha256'])
        self.assertEqual(sorted(seen),self.proof['visited_addresses'])
        self.assertEqual(len(seen),143)

    def test_observation_is_provisional_not_symbol_acceptance(self):
        for raw,expected in [(b'USDC','D:0'),(b'PURR','D:1'),(b'ABCD','R'),(b'outcomeToken','R'),(b'outcomeToken+','R'),(b'outcomeToken-','R'),(b'outcomeToken+0','A:0:30'),(b'outcomeToken00','A:0:30'),(b'outcomeToken001','A:1:31'),(b'outcomeToken18446744073709551616','R'),(b'outcomeToken'+b'0'*200,'A:0:30')]:
            with self.subTest(raw=raw):self.assertEqual(n.evaluate(self.im,raw)[0],expected)
        with self.assertRaisesRegex(ValueError,'forbidden'):n.Machine(self.im,0).call()
        with self.assertRaisesRegex(ValueError,'CFG escape'):self.im.fetch(n.FRONTIER)
        with self.assertRaisesRegex(ValueError,'length'):n.evaluate(self.im,b'x'*257)
        with self.assertRaisesRegex(ValueError,'footprint'):n.Machine(self.im,0).load(n.cpu.INPUT,1)

    def test_actual_movd_pinsrw_and_store_scalar_sse_forms(self):
        m=n.Machine(self.im,0);m.pc=0x46dbe3f;m.set_reg(n.cpu.RAX,0x11223344)
        m.xmm[0]=bytes([255])*16;m.step()
        self.assertEqual(m.xmm[0],bytes.fromhex('44332211')+bytes(12))
        m.pc=0x46dbe43;m.set_reg(n.cpu.RSI,n.TABLE);m.set_reg(n.cpu.R8,37)
        old=bytes(range(16));m.xmm[0]=old;m.step()
        self.assertEqual(m.xmm[0],old[:2]+b'37'+old[4:])
        m.pc=0x46dbe4a;m.set_reg(n.cpu.RSP,n.cpu.STACK);m.set_reg(n.cpu.RBX,7);m.step()
        self.assertEqual(bytes(m.mem[n.cpu.STACK+19+i] for i in range(4)),old[:2]+b'37')
        m.pc=0x46dbe43;m.xmm[0]=None
        with self.assertRaisesRegex(ValueError,'unknown'):m.step()

    def test_twelve_real_instruction_and_data_controls(self):
        controls=json.loads((PACKET/'native-controls.json').read_text());self.assertEqual(len(controls),12)
        for c in controls:
            with self.subTest(name=c['name']):
                changed=n.Image();changed.data=mmap.mmap(changed.view.file.fileno(),0,access=mmap.ACCESS_COPY)
                try:
                    a=int(c['va'],16);off=changed.view.offset(a)
                    self.assertEqual(bytes([changed.data[off]]).hex(),c['original_byte'])
                    changed.data[off]=int(c['changed_byte'],16);raw=bytes.fromhex(c['input_hex'])
                    self.assertEqual(n.evaluate(self.im,raw)[0],c['original'])
                    self.assertEqual(n.evaluate(changed,raw)[0],c['changed'])
                    self.assertNotEqual(c['original'],c['changed'])
                finally:changed.close()

    def test_formatter_reciprocal_bounds_from_original_operands(self):
        spec=importlib.util.spec_from_file_location('symbol_decimal_proof',PACKET/'decimal-proof.py')
        proof=importlib.util.module_from_spec(spec);spec.loader.exec_module(proof)
        rows=proof.prove(self.im)
        self.assertEqual([r['delta'] for r in rows],[432,12,3])
        self.assertTrue(all(r['max_error_numerator']<r['strict_bound'] for r in rows))

    def test_complete_owner_decode_unwind_and_actual_data(self):
        import capstone
        owner=self.proof['owner'];lo,hi=int(owner['start'],16),int(owner['end'],16)
        self.assertEqual(self.im.view.fde(lo),(lo,hi));body=self.im.view.read(lo,hi-lo)
        self.assertEqual(hashlib.sha256(body).hexdigest(),owner['sha256'])
        cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);rows=list(cs.disasm(body,lo))
        self.assertEqual(len(rows),315);self.assertEqual(sum(i.size for i in rows),1292)
        selected=[i for i in rows if any(a<=i.address<b for a,b in n.RANGES)]
        self.assertEqual(sum(i.size for i in selected),508)
        self.assertEqual({i.address for i in selected},set(self.proof['visited_addresses']))
        for i in selected:self.assertEqual(self.im.fetch(i.address).size,i.size)
        for record in owner['unwind'].values():
            raw=bytes.fromhex(record['raw_hex']);self.assertEqual(self.im.view.read(int(record['va'],16),len(raw)),raw)
        self.assertEqual(self.im.view.read(n.TABLE,200),b''.join(f'{i:02d}'.encode() for i in range(100)))

    def test_retained_owned_builds_are_digest_bound(self):
        report=json.loads((PACKET/'rust-results.json').read_text())
        self.assertEqual(report['target_sha256'],n.SHA)
        for file,key in [('src/node115-symbol-prefix/lib.rs','source_sha256'),('src/node115-symbol-prefix/input_only_driver.rs','driver_sha256'),('research/work-items/RE-001-symbol-prefix-115/client_fixture.rs','fixture_sha256')]:
            self.assertEqual(hashlib.sha256((ROOT/file).read_bytes()).hexdigest(),report[key])
        self.assertEqual(report['input_sha256'],self.proof['input_sha256'])
        self.assertEqual(report['expected_sha256'],self.proof['expected_sha256'])
        original=[r for r in report['runs'] if r['variant']=='original']
        self.assertEqual([r['opt'] for r in original],['0','3'])
        self.assertTrue(all(r['mismatches']==0 and r['smoke_exit']==0 and r['rows']==4072 for r in original))
        mutants=[r for r in report['runs'] if r['variant']!='original'];self.assertEqual(len(mutants),12)
        self.assertTrue(all(r['mismatches']>0 and r['smoke_exit']==101 and r['rows']==4072 for r in mutants))
        self.assertFalse(report['captured_process_executed']);self.assertFalse(report['ABI_or_whole_caller_equivalence'])

if __name__=='__main__':unittest.main()
