"""Target-byte and independent table fixtures for the node94 row selector."""
import importlib.util
import json
from pathlib import Path
import struct
import unittest

ROOT=Path(__file__).resolve().parents[1]
PACKET=ROOT/'research/work-items/RE-007-row-lookup-default-94'
spec=importlib.util.spec_from_file_location('row_lookup_packet94',PACKET/'verify.py')
packet=importlib.util.module_from_spec(spec)
spec.loader.exec_module(packet)


class RowLookupDefault94Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=(ROOT/'artifacts/node/94/hl-node').read_bytes()
        cls.elf=packet.Elf(cls.data)

    def changed(self,va,offset=0):
        data=bytearray(self.data)
        data[self.elf.off(va)+offset] ^= 1
        return data

    def test_authenticated_packet_reproduces(self):
        self.assertEqual(packet.build(self.data),json.loads((PACKET/'evidence.json').read_text()))
        self.assertEqual(packet.fixtures(),json.loads((PACKET/'fixtures.json').read_text()))

    def test_digest_and_every_branch_byte_admission(self):
        with self.assertRaisesRegex(ValueError,'SHA-256'):
            packet.build(self.changed(0x36f57f0))
        for b in json.loads((PACKET/'evidence.json').read_text())['branches']:
            with self.subTest(site=b['site']):
                with self.assertRaises(ValueError):
                    packet.structural(self.changed(int(b['site'],16)))

    def test_layout_default_data_and_metadata_corruptions(self):
        for va in (0x36f5869,0x36f58d4,0x3708c09,0x3708dd0,
                   packet.DEFAULT+32,packet.STATE,0x56f2288+8,0x3790fd4,0x379100f):
            with self.subTest(va=hex(va)):
                with self.assertRaises(ValueError):
                    packet.structural(self.changed(va))
        for f in packet.frozen():
            for key in ('fde','cie'):
                with self.subTest(role=f['role'],kind=key):
                    with self.assertRaises(ValueError):
                        packet.structural(self.changed(int(f[key],16),8))

    def test_all_recorded_relative_slot_targets_are_bound(self):
        sec=next(s for s in packet.sections(self.data) if s['name']=='.rela.dyn')
        for row in json.loads((PACKET/'evidence.json').read_text())['slots']:
            slot=int(row['slot'],16)
            matches=[o for o in range(sec['offset'],sec['offset']+sec['size'],24)
                     if struct.unpack_from('<Q',self.data,o)[0]==slot]
            self.assertEqual(len(matches),1)
            changed=bytearray(self.data)
            changed[matches[0]+16] ^= 1
            with self.subTest(slot=row['slot']):
                with self.assertRaises(ValueError):
                    packet.structural(changed)

    def test_empty_count_skips_key_hash_and_control_reads(self):
        for state in (0,1,3,(1<<32)-1):
            out=packet.select_row(0,None,None,None,None,state=state)
            self.assertEqual(out['row'],hex(packet.DEFAULT))
            self.assertEqual(out['hash_called'],False)
            self.assertEqual(out['initializer_called'],state!=0)
            self.assertEqual(out['groups'],[])

    def test_all_twenty_key_bytes_and_no_key_padding(self):
        query=bytes(range(20))
        controls=[255]*32
        controls[5]=0x35
        keys={5:query+b'AAAA'}
        expected=0x100000-6*120+24
        for state in (0,3):
            out=packet.select_row(1,query+b'BBBB',controls,keys,0x35<<57,state=state)
            self.assertEqual(out['row'],hex(expected))
            self.assertEqual(out['flag_word_address'],hex(expected+32))
            self.assertEqual(out['initializer_called'],state!=0)
        for index in range(20):
            wrong=bytearray(query)
            wrong[index] ^= 1
            with self.subTest(compared_byte=index):
                out=packet.select_row(1,wrong,controls,keys,0x35<<57)
                self.assertEqual(out['row'],hex(packet.DEFAULT))

    def test_candidates_precede_empty_stop_and_decoy_tail_matters(self):
        query=bytes(range(20))
        controls=[255]*32
        controls[1]=controls[3]=0x35
        keys={1:query[:19]+bytes([query[19]^1]),3:query}
        oracle={value[:20]:index for index,value in keys.items()}
        out=packet.select_row(2,query,controls,keys,0x35<<57)
        self.assertEqual(out['bucket'],oracle[query])
        self.assertEqual(out['groups'][0]['candidates'],[1,3])
        # A wrong slot-by-slot implementation would stop at empty lane zero.
        self.assertEqual(controls[0],255)
        self.assertNotEqual(out['row'],hex(packet.DEFAULT))

    def test_later_group_and_masked_wrap_use_correct_bucket_address(self):
        query=bytes(range(20))
        controls=[128]*16+[255]*16
        controls[18]=0x35
        out=packet.select_row(1,query,controls,{18:query},0x35<<57)
        self.assertEqual([g['pos'] for g in out['groups']],[0,16])
        self.assertEqual(out['bucket'],18)
        self.assertEqual(out['row'],hex(0x100000-19*120+24))
        controls=[255]*32
        controls[0]=0x35
        wrapped=packet.select_row(1,query,controls,{0:query},(0x35<<57)|31)
        self.assertEqual(wrapped['bucket'],0)
        self.assertEqual(wrapped['row'],hex(0x100000-120+24))

    def test_constructor_flag_bytes_are_defined_without_inventing_padding(self):
        known=packet.constructor_defined_bytes(0x12345678)
        self.assertEqual(known[32:40],[0]*8)
        self.assertEqual(bytes(known[80:84]),b'\x78\x56\x34\x12')
        self.assertEqual({i for i,v in enumerate(known) if v is None},
                         set(range(16,24))|set(range(48,56))|set(range(92,96)))
        with self.assertRaises(ValueError):
            packet.constructor_defined_bytes(0)


if __name__=='__main__':
    unittest.main()
