"""Digest-bound static evidence controls; no instruction execution."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]
PACKET=ROOT/'research/work-items/RE-001-node115-chain-dispatch-globals'
spec=importlib.util.spec_from_file_location('twenty_chain',PACKET/'collect.py')
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
        for address,delta in [(74399681, 14), (74399705, 9), (74399728, 9), (74399751, 9), (74399774, 18), (74399799, 13)]:
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

    def test_each_actual_dispatch_entry_corruption_rejected(self):
        mutated=bytearray(self.data)
        table=collector.CONFIG['tables'][0]
        self.assertEqual(len(table['targets']),4)
        self.assertEqual(set(table['targets']),{'0x46f3fd9','0x46f3ff0','0x46f4007','0x46f401e'})
        for i in range(4):
            offset,_=collector.read(self.data,int(table['va'],16)+4*i,4)
            mutated[offset]^=1
            with self.assertRaisesRegex(ValueError,'changed dispatch data'):
                collector.anchors(mutated)
            mutated[offset]^=1

if __name__=='__main__':
    unittest.main()
