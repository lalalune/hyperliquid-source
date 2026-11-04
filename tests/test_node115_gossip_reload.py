"""Digest-specific controls for the gossip metadata parser handoff."""
from pathlib import Path
import hashlib
import importlib.util
import json
import sys
import unittest
ROOT=Path(__file__).resolve().parents[1]
PACKET=ROOT/'research/work-items/RE-014-gossip-reload-115'
spec=importlib.util.spec_from_file_location('gossip_reload115_native',PACKET/'native.py')
native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)

class GossipReload115(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=native.TARGET.read_bytes();cls.image=native.authenticate(cls.data)

    def read(self,va,size):
        off=self.image.file_offset(va);return self.data[off:off+size]

    def test_owner_and_real_source_callers(self):
        owner=json.loads((PACKET/'owner.json').read_text())
        self.assertEqual((owner['start'],owner['end_exclusive']),('0x57d2f80','0x57d329b'))
        self.assertEqual(self.image.fde_of(native.START),(native.START,native.END))
        self.assertEqual(hashlib.sha256(self.read(native.START,native.END-native.START)).hexdigest(),owner['sha256'])
        locations=json.loads((PACKET/'caller-locations.json').read_text())
        self.assertEqual(len(locations),2)
        for row in locations:
            for key,raw in [('lea','lea_raw'),('call','call_raw'),('location','location_raw')]:
                self.assertEqual(self.read(int(row[key],16),len(bytes.fromhex(row[raw]))),bytes.fromhex(row[raw]))
            loc=int(row['location'],16)
            self.assertEqual(self.image.slots[loc],int(row['relative_path_addend'],16))
            self.assertEqual(self.read(self.image.slots[loc],row['length']),b'node/src/gossip_config.rs')
            self.assertEqual((row['line'],row['column']),(103,32))
            self.assertEqual(list(map(hex,self.image.fde_of(int(row['call'],16)))),row['caller_fde'])

    def test_indirect_and_dynamic_call_closure(self):
        rows=json.loads((PACKET/'calls.json').read_text())
        self.assertEqual(len(rows),18)
        for row in rows:
            self.assertFalse(row['executed'])
            self.assertEqual(self.read(int(row['site'],16),len(bytes.fromhex(row['raw']))),bytes.fromhex(row['raw']))
            if 'slot' in row:self.assertEqual(self.image.slots[int(row['slot'],16)],int(row['relative_addend'],16))
        self.assertTrue(any('dynamic' in row.get('closure','') for row in rows))

    def test_error_payload_metadata_store_order_is_byte_bound(self):
        controls={0x57d3052:'83bc248000000002',0x57d305a:'0f85be000000',
                  0x57d3104:'4c897b78',0x57d3108:'31ed',0x57d311e:'488b7310',
                  0x57d3178:'0f1103',0x57d317f:'898380000000',0x57d3189:'898384000000',
                  0x57d3192:'898388000000',0x57d31a6:'48c7437800000000'}
        for va,raw in controls.items():self.assertEqual(self.read(va,len(bytes.fromhex(raw))),bytes.fromhex(raw))
        # Error tag2 falls into the carrier path; its local join precedes the
        # success block and does not execute the success-only cache stores.
        self.assertEqual(self.image.fetch(0x57d305a).target,0x57d311e)

    def test_actual_instruction_corruptions_change_routes(self):
        controls=json.loads((PACKET/'native-controls.json').read_text())
        self.assertEqual(len(controls),4)
        for row in controls:
            at=self.image.file_offset(int(row['va'],16));data=bytearray(self.data)
            self.assertEqual(data[at],row['before_byte']);data[at]=row['after_byte']
            mutant=native.cpu.Image(bytes(data))
            actual,_=native.evaluate(mutant,row['new'],row['cached'])
            self.assertEqual(actual,row['mutant']);self.assertNotEqual(actual,row['original'])

    def test_frozen_corpus_and_no_fabricated_input(self):
        inputs,expected=native.verify()
        self.assertEqual(len(inputs.splitlines()),16649);self.assertEqual(len(expected.splitlines()),16649)
        for new,old in [([0,0,2**32],[0,0,0]),([0,0],[0,0,0]),([False,0,0],[0,0,0])]:
            with self.assertRaises(ValueError):native.evaluate(self.image,new,old)

if __name__=='__main__':unittest.main()
