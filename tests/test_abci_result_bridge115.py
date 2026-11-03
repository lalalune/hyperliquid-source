"""Controls for the #115 static result-container evidence extractor."""
import csv
import io
import json
import struct
import unittest

from tools import abci_result_bridge115 as m


class EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Missing input is a failure, never a skip.
        cls.data = m.TARGET.read_bytes()
        cls.secs = m.sections(cls.data)
        cls.outputs = m.collect(cls.data)
        cls.facts = json.loads(cls.outputs['facts.json'])

    def test_digest_authenticates_real_target(self):
        self.assertEqual(m.authenticate(self.data), m.SHA256)

    def test_digest_rejects_damage_or_missing_input(self):
        for data in (b'', b'not the captured node', self.data[:4096]):
            with self.subTest(size=len(data)), self.assertRaises(ValueError):
                m.authenticate(data)
        with self.assertRaises(ValueError):
            m.authenticate(self.data, '0'*64)

    def test_every_window_and_single_byte_corruption(self):
        for name, scope, start, end, digest in m.WINDOWS:
            raw = m.read_va(self.data, self.secs, start, end-start)
            m.check_window(raw, digest)
            bad = bytearray(raw)
            bad[len(bad)//2] ^= 1
            with self.subTest(name=name, scope=scope), self.assertRaises(ValueError):
                m.check_window(bytes(bad), digest)

    def test_every_transfer_and_displacement_corruption(self):
        for va, expected in m.TRANSFERS:
            raw = m.read_va(self.data, self.secs, va, len(expected)//2)
            kind, dest = m.checked_transfer(va, raw, expected)
            self.assertGreater(dest, 0)
            self.assertTrue(kind in ('call', 'jump', 'call_slot', 'jump_slot') or kind.startswith('jcc_'))
            for pos in (0, len(raw)-1):
                bad = bytearray(raw)
                bad[pos] ^= 1
                with self.subTest(va=hex(va), byte=pos), self.assertRaises(ValueError):
                    m.checked_transfer(va, bytes(bad), expected)

    def test_transfer_sign_and_forms(self):
        self.assertEqual(m.decode_transfer(0x100, bytes.fromhex('ebfe')), ('jump', 0x100))
        self.assertEqual(m.decode_transfer(0x100, bytes.fromhex('e8fbffffff')), ('call', 0x100))
        self.assertEqual(m.decode_transfer(0x100, bytes.fromhex('0f85faffffff')), ('jcc_5', 0x100))
        self.assertEqual(m.decode_transfer(0x100, bytes.fromhex('ff1500000000')), ('call_slot', 0x106))
        for raw in (b'', b'\xe8', b'\x90', b'\xff\x15\0'):
            with self.assertRaises(ValueError):
                m.decode_transfer(0x100, raw)

    def test_every_operand_and_corruption(self):
        for name, va, expected, offset, width, kind in m.OPERANDS:
            raw = m.read_va(self.data, self.secs, va, len(expected)//2)
            value = m.check_operand(raw, expected, offset, width, kind)
            self.assertEqual(value, self.facts[name])
            bad = bytearray(raw)
            bad[offset] ^= 1
            with self.subTest(name=name), self.assertRaises(ValueError):
                m.check_operand(bytes(bad), expected, offset, width, kind)

    def test_invalid_operand_ranges_and_kinds(self):
        for offset, width, kind in ((-1, 1, 'imm'), (1, 2, 'imm'), (0, 1, 'unknown'), (0, 2, 'sibscale')):
            with self.assertRaises(ValueError):
                m.check_operand(b'\x80', '80', offset, width, kind)

    def test_file_backed_mapping_and_boundaries(self):
        raw = bytes(range(64))
        sec = {'type': 1, 'size': 16, 'address': 0x100, 'offset': 8}
        self.assertEqual(m.read_va(raw, [sec], 0x100, 1), b'\x08')
        self.assertEqual(m.read_va(raw, [sec], 0x10f, 1), b'\x17')
        for address, size in ((0xff,1),(0x110,1),(0x10f,2),(0x100,0),(-1,1)):
            with self.subTest(address=address,size=size), self.assertRaises(ValueError):
                m.mapped_offset(raw, [sec], address, size)
        with self.assertRaises(ValueError):
            m.mapped_offset(raw, [dict(sec, type=8)], 0x100, 1)
        with self.assertRaises(ValueError):
            m.mapped_offset(raw, [sec, dict(sec)], 0x100, 1)
        with self.assertRaises(ValueError):
            m.mapped_offset(raw, [dict(sec, offset=60)], 0x100, 8)

    def test_actual_nobits_never_has_file_bytes(self):
        for sec in (s for s in self.secs if s['type'] == 8 and s['size']):
            with self.subTest(name=sec['name']), self.assertRaises(ValueError):
                m.mapped_offset(self.data, [sec], sec['address'], 1)

    def test_synthetic_fde_agreement_and_failures(self):
        fdes = [{'start': s, 'end': e, 'fde': i+1} for i, (_,s,e) in enumerate(m.FUNCTIONS)]
        index = [{'start': s, 'fde': i+1, 'section': '.text'} for i, (_,s,e) in enumerate(m.FUNCTIONS)]
        selected, _ = m.select_functions(fdes, index)
        self.assertEqual(len(selected), len(m.FUNCTIONS))
        cases = [fdes[:-1], fdes+[dict(fdes[0])], [dict(fdes[0], end=fdes[0]['end']+1)]+fdes[1:]]
        for invalid in cases:
            with self.assertRaises(ValueError):
                m.select_functions(invalid, index)
        with self.assertRaises(ValueError):
            m.select_functions(fdes, index+[dict(index[0])])
        with self.assertRaises(ValueError):
            m.select_functions(fdes, [dict(index[0], fde=99999)]+index[1:])
        with self.assertRaises(ValueError):
            m.select_functions(fdes, [dict(index[0], section='.rodata')]+index[1:])

    def test_actual_fde_rows_are_disjoint_and_complete(self):
        rows = list(csv.DictReader(io.StringIO(self.outputs['functions.tsv'].decode()), delimiter='\t'))
        self.assertEqual(len(rows), len(m.FUNCTIONS))
        extents = sorted((int(r['start_va'],16),int(r['end_va_exclusive'],16)) for r in rows)
        self.assertTrue(all(a[1] <= b[0] for a,b in zip(extents,extents[1:])))
        for r in rows:
            self.assertEqual(len(bytes.fromhex(r['body_hex'])), int(r['size']))

    def test_drop_table_every_entry_and_corruption(self):
        base = m.lea_target(0x5b232d7, m.read_va(self.data, self.secs, 0x5b232d7, 7))
        raw = m.read_va(self.data, self.secs, base, 4*len(m.DROP_WORDS))
        entries = m.decode_drop_table(raw, base, len(m.DROP_WORDS))
        self.assertEqual(len(entries), 13)
        for i in range(len(entries)):
            bad = bytearray(raw)
            bad[4*i] ^= 1
            with self.subTest(tag=i), self.assertRaises(ValueError):
                m.decode_drop_table(bytes(bad), base, len(entries))
        for damaged in (raw[:-1], raw+b'\0'):
            with self.assertRaises(ValueError):
                m.decode_drop_table(damaged, base, len(entries))
        with self.assertRaises(ValueError):
            m.decode_drop_table(raw, 0, len(entries))

    def test_table_tag_to_target_groups(self):
        rows = list(csv.DictReader(io.StringIO(self.outputs['drop-table.tsv'].decode()),delimiter='\t'))
        by_tag = {int(r['tag']):r['target_va'] for r in rows}
        self.assertEqual(by_tag[4], by_tag[5])
        self.assertEqual(len({by_tag[i] for i in (2,6,7,8,9,10,11)}), 1)
        self.assertEqual(len(set(by_tag.values())), 6)

    def test_pivot_boundary_table(self):
        cases = [(4,0,0),(4,0,1),(4,0,2),(4,0,3),(4,0,4),
                 (5,0,5),(5,1,0),(6,1,0),(6,1,1),(6,1,2),(6,1,3),(6,1,4)]
        self.assertEqual([m.split_pivot(i,self.facts) for i in range(12)], cases)
        for i in (-1,12,1<<64):
            with self.assertRaises(ValueError):
                m.split_pivot(i,self.facts)

    def test_representation_transition_boundaries(self):
        for n in (0, 30, 31):
            self.assertEqual(m.transition(True,n,False,self.facts), 'tree_to_ring')
            self.assertEqual(m.transition(True,n,True,self.facts), 'tree_to_ring')
        for n in (32, 33, 63, 64):
            self.assertEqual(m.transition(True,n,True,self.facts), 'keep')
        for n in (0, 31, 32, 63):
            self.assertEqual(m.transition(False,n,True,self.facts), 'keep')
        for n in (64, 65, (1<<64)-1):
            self.assertEqual(m.transition(False,n,True,self.facts), 'ring_to_tree')
            self.assertEqual(m.transition(False,n,False,self.facts), 'keep')
        for n in (-1,1<<64):
            with self.assertRaises(ValueError):
                m.transition(False,n,True,self.facts)

    def test_same_input_index_can_have_different_representation(self):
        self.assertEqual(m.transition(False,40,True,self.facts), 'keep')
        self.assertEqual(m.transition(True,40,True,self.facts), 'keep')

    def test_layout_joins_and_ser_offsets(self):
        f = self.facts
        self.assertEqual(f['joined_row_bytes'],f['key_bytes']+f['outer_value_bytes'])
        self.assertEqual(f['outer_value_bytes'],f['identifier_bytes']+f['nested_vector_metadata_bytes'])
        self.assertEqual(f['projected_source_stride']-f['projected_result_stride'],f['key_bytes'])
        self.assertEqual((f['serializer_nested_pointer'],f['serializer_nested_count']), (40,48))

    def test_synthetic_projection_and_vector_handoff(self):
        # Distinct bytes expose accidental swaps, omission or an 8-byte skew.
        original = bytes(range(72))
        projected = original[:self.facts['projected_result_stride']]
        identifier = bytes(range(160,192))
        triple = struct.pack('<QQQ', 7, 0x1122334455667788, 1)
        joined = struct.pack('<Q', 9) + identifier + triple
        self.assertEqual(len(joined), self.facts['joined_row_bytes'])
        leaf_value = joined[self.facts['key_bytes']:]
        output = leaf_value[:]
        ptr = struct.unpack_from('<Q',output,self.facts['serializer_nested_pointer'])[0]
        count = struct.unpack_from('<Q',output,self.facts['serializer_nested_count'])[0]
        self.assertEqual((ptr,count),(0x1122334455667788,1))
        self.assertEqual(projected,bytes(range(64)))
        damaged = bytearray(joined)
        damaged[48] ^= 1
        self.assertNotEqual(bytes(damaged[8:]), output)
        self.assertNotEqual(joined[:56], output)

    def test_location_and_release_specific_clue(self):
        loc = self.facts['location']
        self.assertEqual((loc['file_suffix'],loc['line'],loc['column']), ('l1/src/abci/state.rs',123,37))
        self.assertEqual(m.lea_target(0x3c1352f,m.read_va(self.data,self.secs,0x3c1352f,7)), int(loc['location_va'],16))
        with self.assertRaises(ValueError):
            m.verify_historical(b'corrupt historical capture')
        with self.assertRaises(ValueError):
            m.lea_target(0x100,b'\x90'*7)

    def test_historical_fde_corruption(self):
        fdes = [{'start': 0x32725d0, 'end': 0x3272b3a, 'fde': 1},
                {'start': 0x3273810, 'end': 0x327396c, 'fde': 2}]
        index = [{'start': 0x32725d0, 'fde': 1, 'section': '.text'},
                 {'start': 0x3273810, 'fde': 2, 'section': '.text'}]
        m.check_historical_extents(fdes, index)
        for invalid_fdes, invalid_index in (
            (fdes[:-1], index),
            ([dict(fdes[0], end=fdes[0]['end']-1), fdes[1]], index),
            (fdes, [dict(index[0], fde=3), index[1]]),
            (fdes, index + [dict(index[0])]),
        ):
            with self.subTest(fdes=invalid_fdes, index=invalid_index), self.assertRaises(ValueError):
                m.check_historical_extents(invalid_fdes, invalid_index)

    def test_relocation_negative_controls(self):
        row = struct.pack('<QQq',0x100,8,0x123)
        sec = {'name':'.rela.dyn','type':4,'offset':0,'size':24}
        self.assertEqual(m.relocation_at(row,[sec],0x100)[3],0x123)
        with self.assertRaises(ValueError):
            m.relocation_at(row,[sec],0x101)
        with self.assertRaises(ValueError):
            m.relocation_at(row+row,[dict(sec,size=48)],0x100)
        with self.assertRaises(ValueError):
            m.relocation_at(row,[dict(sec,type=8)],0x100)
        with self.assertRaises(ValueError):
            m.relocation_at(row,[dict(sec,size=23)],0x100)
        with self.assertRaises(ValueError):
            m.relocation_at(struct.pack('<QQq',0x100,7,0),[sec],0x100)

    def test_lsda_row_and_corruption_controls(self):
        data = bytes.fromhex('ffff010401020300')
        sec = {'name':'.gcc_except_table','type':1,'address':0x20,'offset':0,'size':len(data)}
        fde = {'start':0x1000,'end':0x1100,'lsda':0x20}
        rows = m.parse_call_sites(data,[sec],fde)
        self.assertEqual(rows[0][:4],(0x1001,0x1003,0x1003,0))
        self.assertEqual(m.parse_call_sites(data,[sec],dict(fde,lsda=None)),[])
        for bad in (b'\0'+data[1:], data[:2]+b'\x02'+data[3:], data[:-1]):
            with self.assertRaises(ValueError):
                m.parse_call_sites(bad,[dict(sec,size=len(bad))],fde)
        with self.assertRaises(ValueError):
            m.parse_call_sites(data,[sec],dict(fde,end=0x1002))
        with self.assertRaises(ValueError):
            m.parse_call_sites(data,[dict(sec,type=8)],fde)
        with self.assertRaises(ValueError):
            m.parse_call_sites(data,[sec,sec],fde)

    def test_allocation_bound(self):
        limit=self.facts['collector_allocation_limit']
        self.assertEqual(limit,((1<<63)-1)//self.facts['outer_output_stride'])
        self.assertLessEqual(limit*self.facts['outer_output_stride'],(1<<63)-1)
        self.assertGreater((limit+1)*self.facts['outer_output_stride'],(1<<63)-1)

    def test_output_names_and_counts(self):
        self.assertEqual(set(self.outputs), {'functions.tsv','windows.tsv','transfers.tsv','operands.tsv',
                                              'drop-table.tsv','pivot-cases.tsv','transition-cases.tsv','facts.json','context-functions.tsv',
                                              'unwind.tsv','unwind-links.tsv'})
        self.assertEqual(self.facts['selected_function_count'],14)
        self.assertEqual(self.facts['transfer_count'],len(m.TRANSFERS))
        self.assertEqual(self.facts['drop_table_entries'],len(m.DROP_WORDS))


if __name__ == '__main__':
    unittest.main()
