"""Digest-bound static evidence controls; no instruction execution."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]
PACKET=ROOT/'research/work-items/RE-001-node115-exchange-divisibility-handoff'
spec=importlib.util.spec_from_file_location('twenty_exchange',PACKET/'collect.py')
collector=importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)

class NativeEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=(ROOT/'artifacts/node/115/hl-node').read_bytes()
    def test_actual_anchor_records(self):
        self.assertEqual(collector.anchors(self.data),json.loads((PACKET/'records.json').read_text())['facts'])
    def test_every_native_instruction_group_corruption_rejected(self):
        mutated=bytearray(self.data)
        for address,raw in collector.CONFIG['anchors'].items():
            offset,_=collector.read(self.data,int(address,16),len(bytes.fromhex(raw)))
            with self.subTest(address=address):
                mutated[offset]^=1
                with self.assertRaisesRegex(ValueError,'changed native anchor'):
                    collector.anchors(mutated)
                mutated[offset]^=1
    def test_actual_operand_and_branch_tail_mutations(self):
        mutated=bytearray(self.data)
        for address,delta in [(94821168, 4), (94821234, 8), (94821299, 12), (94821362, 13), (94821426, 17), (94821509, 19)]:
            offset,_=collector.read(self.data,address+delta,1)
            with self.subTest(address=hex(address+delta)):
                mutated[offset]^=1
                with self.assertRaisesRegex(ValueError,'changed native anchor'):
                    collector.anchors(mutated)
                mutated[offset]^=1
    def test_wrong_target_rejected_before_output(self):
        mutated=bytearray(self.data);mutated[-1]^=1
        with tempfile.TemporaryDirectory() as directory:
            out=Path(directory)/'not-created'
            with self.assertRaisesRegex(ValueError,'identity mismatch'):
                collector.collect(mutated,out)
            self.assertFalse(out.exists())
    def test_complete_exports_and_records_regenerate(self):
        with tempfile.TemporaryDirectory() as directory:
            out=Path(directory)
            self.assertEqual(collector.collect(self.data,out),json.loads((PACKET/'records.json').read_text()))
            for n in ['frames.txt','relocations.txt','records.json',*[x.name for x in PACKET.glob('*.objdump.txt')]]:
                self.assertEqual((out/n).read_bytes(),(PACKET/n).read_bytes(),n)

    def test_unsigned_divisibility_constants_and_bound(self):
        raw=b''.join(bytes.fromhex(x) for x in collector.CONFIG['anchors'].values())
        # Actual immediate bytes must be present before applying this proof.
        m=0xd288ce703afb7e91; maximum=(1<<64)-1; bound=0x68db8bac710cb
        native=(PACKET/'0x5a6db30-0x5a6dd2f.objdump.txt')
        allraw=collector.read(self.data,0x5a6db30,0x1ff)[1]
        self.assertIn(m.to_bytes(8,'little'),allraw)
        self.assertIn(bound.to_bytes(8,'little'),allraw)
        self.assertEqual((625*m) & maximum,1)
        self.assertEqual(bound,maximum//10000)
        self.assertLess(bound,1<<60)
        self.assertLessEqual(10000*bound,maximum)
        self.assertGreater(10000*(bound+1),maximum)
        for n in [0,1,9999,10000,10001,maximum,maximum-maximum%10000]:
            product=n*m & maximum
            rotated=(product>>4)|((product&15)<<60)
            self.assertEqual(rotated<=bound,n%10000==0)

if __name__=='__main__':
    unittest.main()
