"""Static byte admission and unsigned saturation-order controls for RE-007."""
import importlib.util
import json
from pathlib import Path
import struct
import unittest

ROOT=Path(__file__).resolve().parents[1]
PACKET=ROOT/'research/work-items/RE-007-reserve-reweight-order-94'
spec=importlib.util.spec_from_file_location('reweight_packet94',PACKET/'verify.py')
packet=importlib.util.module_from_spec(spec)
spec.loader.exec_module(packet)


class ReserveReweightOrder94Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=(ROOT/'artifacts/node/94/hl-node').read_bytes()
        cls.elf=packet.Elf(cls.data)

    def corrupt(self,va,offset=0):
        data=bytearray(self.data)
        data[self.elf.off(va)+offset] ^= 1
        return data

    def test_packet_reproduces(self):
        self.assertEqual(packet.build(self.data),json.loads((PACKET/'evidence.json').read_text()))
        self.assertEqual(packet.samples(),json.loads((PACKET/'samples.json').read_text()))

    def test_full_digest_and_branch_identity_controls(self):
        with self.assertRaisesRegex(ValueError,'SHA-256'):
            packet.build(self.corrupt(0x370e2a0))
        for b in json.loads((PACKET/'evidence.json').read_text())['branches']:
            with self.subTest(site=b['site']):
                with self.assertRaises(ValueError):
                    packet.structural(self.corrupt(int(b['site'],16)))

    def test_divide_store_and_reader_link_byte_controls(self):
        for va in (0x370e399,0x370e3c9,0x370e39f,0x370e3ce,
                   0x370e466,0x370e493,0x370e49f,0x370e4a5,0x370e4aa,
                   0x3709f4d,0x3709f60,0x370e854,0x370e86a,0x3708d50):
            with self.subTest(va=hex(va)):
                with self.assertRaises(ValueError):
                    packet.structural(self.corrupt(va))

    def test_fde_cie_location_and_recorder_slot_controls(self):
        for f in packet.frozen():
            for k in ('fde','cie'):
                with self.subTest(role=f['role'],kind=k):
                    with self.assertRaises(ValueError):
                        packet.structural(self.corrupt(int(f[k],16),8))
        for va in (0x56f1f00,0x56f1f30,0x56f1de8):
            with self.assertRaises(ValueError):
                packet.structural(self.corrupt(va,16))
        sec=next(s for s in packet.sections(self.data) if s['name'] == '.rela.dyn')
        matches=[o for o in range(sec['offset'],sec['offset']+sec['size'],24)
                 if struct.unpack_from('<Q',self.data,o)[0] == 0x5773190]
        self.assertEqual(len(matches),1)
        data=bytearray(self.data)
        data[matches[0]+16] ^= 1
        with self.assertRaises(ValueError):
            packet.structural(data)

    def test_subtract_before_add_has_both_saturation_witnesses(self):
        self.assertEqual(packet.model(2,10,1,2)['total'],5)
        self.assertEqual(max(0,min(packet.U64,2+10//2)-10//1),0)
        self.assertEqual(packet.model(packet.U64,10,2,1)['total'],packet.U64)
        self.assertEqual(max(0,min(packet.U64,packet.U64+10//1)-10//2),packet.U64-5)
        sweep=packet.samples()['sweep']
        self.assertEqual(sweep['total_cases'],672)
        self.assertEqual(sweep['normal_changed_cases'],504)
        self.assertEqual(sweep['changed_case_mismatches'],0)
        self.assertGreater(sweep['wrong_add_first_mismatches'],0)

    def test_positive_divisor_shortcut_and_store_order(self):
        unchanged=packet.model(5,0,3,3)
        self.assertEqual(unchanged['status'],'no_op')
        self.assertEqual(unchanged['writes'],[])
        ordinary=packet.model(100,10,1,2)
        self.assertEqual(ordinary['writes'],[['row+0x30',2],['total',90],['total',95]])

    def test_recorder_return_is_separate_from_stored_state(self):
        first=packet.model(2,10,1,2,recorder_returns=False)
        self.assertEqual(first['status'],'recorder_continuation_unknown')
        self.assertEqual(first['total'],2)
        self.assertEqual(first['writes'],[['row+0x30',2]])
        second=packet.model(packet.U64,10,2,1,recorder_returns=False)
        self.assertEqual(second['total'],packet.U64-5)
        self.assertEqual(second['writes'],[['row+0x30',1],['total',packet.U64-5]])
        self.assertEqual(second['recorders'],['unsigned_addition'])

    def test_widths_and_integer_rounding(self):
        self.assertEqual(packet.model(100,10,3,2)['total'],102)
        for args in ((-1,0,1,2),(0,packet.U64+1,1,2),(0,0,packet.U32+1,2),(0,0,1,-1)):
            with self.assertRaises(ValueError):
                packet.model(*args)


if __name__ == '__main__':
    unittest.main()
