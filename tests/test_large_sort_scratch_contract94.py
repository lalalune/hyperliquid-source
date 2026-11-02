"""Static target-admission and synthetic arithmetic controls; no target evaluator."""
import importlib.util
from pathlib import Path
import unittest

PACKET = Path(__file__).resolve().parents[1] / 'research/work-items/RE-006-large-sort-scratch-contract-94'
spec = importlib.util.spec_from_file_location('large_sort_scratch94', PACKET / 'verify.py')
packet = importlib.util.module_from_spec(spec)
spec.loader.exec_module(packet)


class ScratchContractTests(unittest.TestCase):
    def test_small_flag_64_65(self):
        self.assertEqual(packet.scratch_relation(64)['small_flag'], 1)
        self.assertEqual(packet.scratch_relation(65)['small_flag'], 0)

    def test_stack_heap_512_513(self):
        self.assertEqual(packet.scratch_relation(512), dict(selected=512,path='stack',capacity=512,allocation_bytes=0,small_flag=0))
        self.assertEqual(packet.scratch_relation(513), dict(selected=513,path='heap',capacity=513,allocation_bytes=4104,small_flag=0))

    def test_plateau_and_odd_half(self):
        for n,capacity in [(999999,999999),(1000000,1000000),(1000001,1000000),(2000000,1000000),(2000001,1000001)]:
            with self.subTest(count=n):
                self.assertEqual(packet.scratch_relation(n)['capacity'],capacity)

    def test_last_valid_count_and_wrapping_refusals(self):
        valid = packet.scratch_relation(2**61-2)
        self.assertEqual((valid['path'],valid['allocation_bytes']),('heap',0x7ffffffffffffff8))
        for n in [2**61-1,2**62-2,2**62-1,2**63,2**64-1]:
            with self.subTest(count=n):
                self.assertEqual(packet.scratch_relation(n)['path'],'layout-dispatch')

    def test_independent_piecewise_oracle(self):
        for n in packet.control_counts():
            with self.subTest(count=n):
                self.assertEqual(packet.scratch_relation(n),packet.oracle(n))

    def test_invalid_count_is_only_model_api_rejection(self):
        for n in [-1,2**64,1.5,'21']:
            with self.subTest(count=n), self.assertRaises(ValueError):
                packet.scratch_relation(n)

    def test_target_operand_and_lsda_controls_below_digest_gate(self):
        data=packet.TARGET.read_bytes()
        self.assertEqual(packet.sha(data),packet.SHA)
        original=packet.Image(data)
        packet.local_obligations(original)
        packet.lsda(original)
        for name,va,_ in packet.PINS:
            changed=bytearray(data); changed[original.offset(va,1)]^=1
            with self.subTest(obligation=name), self.assertRaisesRegex(ValueError,'operand/control mismatch'):
                packet.local_obligations(packet.Image(changed))
        changed=bytearray(data); changed[original.offset(0xb4200c,1)]^=1
        with self.assertRaisesRegex(ValueError,'LSDA cleanup range mismatch'):
            packet.lsda(packet.Image(changed))


if __name__=='__main__': unittest.main()
