import hashlib
import struct
import unittest
from tools import apphash_header_94 as subject


class HeaderEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = subject.TARGET.read_bytes()
        cls.records = subject.collect(cls.data)
        cls.image = subject.Image(cls.data)

    def test_authenticated_target(self):
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), subject.DIGEST)
        with self.assertRaisesRegex(ValueError, 'digest mismatch'):
            subject.check_digest(b'not the node')

    def test_header_sequence_and_lanes(self):
        rows = self.records['fields']
        self.assertEqual(len(rows), 26)
        low = [r for r in rows if r['lane'] == 'low']
        high = [r for r in rows if r['lane'] == 'shared']
        self.assertEqual([r['key'] for r in low], [r['key'] for r in high])
        self.assertEqual([r.get('value_offset') for r in high],
                         [16,24,40,0,48,96,108,56,64,72,80,120,88])
        self.assertEqual([x['value_offset'] for x in self.records['low_hardfork_fields']], [24,32])
        self.assertEqual([x['key'] for x in self.records['low_hardfork_fields']], ['version','round'])

    def test_integer_boundaries(self):
        vectors = {v['value']:v['encoded_hex'] for v in self.records['unsigned_integer_vectors']}
        self.assertEqual(vectors, {0:'00',127:'7f',128:'cc80',255:'ccff',256:'cd0100',
                                   65535:'cdffff',65536:'ce00010000',
                                   4294967295:'ceffffffff',4294967296:'cf0000000100000000',
                                   18446744073709551615:'cfffffffffffffffff'})

    def test_symbolic_prefix(self):
        self.assertEqual(self.records['symbolic_prefix']['bytes'],
                         '8dae696e697469616c5f68656967687400a868617264666f726b82'
                         'a776657273696f6e01a5726f756e6402a668656967687403'
                         'a874785f696e646578c0a5726f756e6404')

    def test_complete_symbolic_fixture(self):
        example = self.records['time_example']
        self.assertEqual(example['text'], '1970-01-01T00:00:00')
        self.assertEqual(example['date_table_index'], 2)
        self.assertEqual(example['table_byte'], 64)
        result = bytes.fromhex(self.records['symbolic_complete_low']['bytes'])
        self.assertEqual(len(result), 194)
        self.assertEqual(result.count(b'1970-01-01T00:00:00'), 2)
        expected = (b'\x8d\xaeinitial_height\x00\xa8hardfork\x82\xa7version\x01'
                    b'\xa5round\x02\xa6height\x03\xa8tx_index\xc0\xa5round\x04'
                    b'\xa4time\xb31970-01-01T00:00:00'
                    b'\xa9prev_time\xb31970-01-01T00:00:00'
                    b'\xa8next_oid\x00\xa8next_lid\x00\xacnext_twap_id\x00'
                    b'\xacsystem_nonce\x00\xb0use_system_nonce\xc2\xa3mac\x00')
        self.assertEqual(result, expected)

    def test_present_value_and_true_boolean_fixture(self):
        absent = bytes.fromhex(self.records['symbolic_complete_low']['bytes'])
        present = bytes.fromhex(self.records['symbolic_present_low']['bytes'])
        expected = absent.replace(b'\xa8tx_index\xc0', b'\xa8tx_index\x05', 1)
        expected = expected.replace(b'\xb0use_system_nonce\xc2', b'\xb0use_system_nonce\xc3', 1)
        self.assertEqual(present, expected)
        self.assertEqual(self.records['symbolic_present_low']['keccak256'],
                         '18d7bd6591c8bf5a8d7d30010326a092b738cae65e80dab972b3f84346741c5b')
        self.assertNotEqual(self.records['symbolic_present_low']['keccak256'],
                            self.records['symbolic_complete_low']['keccak256'])

    def test_fraction_branch_examples(self):
        result = {x['nanosecond_word']: x['branch'] for x in self.records['fraction_branch_examples']}
        self.assertEqual(result, {0:'zero', 1:'descriptor_9', 999:'descriptor_9',
                                  1000:'descriptor_6', 1000000:'descriptor_3',
                                  999999999:'descriptor_9'})
        self.assertEqual([x['tag'] for x in self.records['fraction_branch_descriptors']],
                         [0x369, 0x669, 0x969])

    def test_corrupt_fraction_descriptor_rejected(self):
        data = bytearray(self.data)
        sec = next(s for s in self.image.secs if s['name'] == '.rodata')
        at = sec['offset'] + 0x250cb0 - sec['address']
        data[at] ^= 1
        with self.assertRaisesRegex(ValueError, 'formatter descriptor mismatch'):
            subject.collect(data, verify_digest=False)

    def test_corrupt_date_table_rejected(self):
        data = bytearray(self.data)
        sec = next(s for s in self.image.secs if s['name'] == '.rodata')
        at = sec['offset'] + 0x250677 - sec['address']
        data[at] ^= 1
        with self.assertRaisesRegex(ValueError, 'unexpected time example'):
            subject.collect(data, verify_digest=False)

    def test_keccak_model_against_known_and_sha3_vectors(self):
        rc = struct.unpack('<24Q', self.image.read(0x7d04c8, 192, False))
        self.assertEqual(subject.keccak256(b'', rc).hex(),
                         'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470')
        self.assertEqual(subject.keccak256(b'abc', rc).hex(),
                         '4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45')
        for n in (0, 135, 136, 137, 194, 271):
            msg = b'a' * n
            self.assertEqual(subject.keccak256(msg, rc, 6), hashlib.sha3_256(msg).digest())
        with self.assertRaises(ValueError): subject.keccak256(b'', rc[:-1])
        with self.assertRaises(ValueError): subject.keccak256(b'', rc, 2)
        self.assertEqual(self.records['symbolic_complete_low']['keccak256'],
                         'a20a6c0b3a9f6d3c34feed28e34e1c4ffa239d91dffb11c17340aa3549a9a3f3')

    def test_corrupt_round_constant_rejected(self):
        data = bytearray(self.data)
        sec = next(s for s in self.image.secs if s['name'] == '.rodata')
        at = sec['offset'] + 0x7d04c8 + 40 - sec['address']
        data[at] ^= 1
        with self.assertRaisesRegex(ValueError, 'round constant table mismatch'):
            subject.collect(data, verify_digest=False)

    def test_row_vtable_links(self):
        self.assertEqual(self.records['low_builder_row_zero']['job_count'], 41)
        self.assertEqual(self.records['low_builder_row_zero']['table'], '0x56bda38')
        links = self.records['row_vtable_links']
        self.assertEqual([x['vtable_slot'] for x in links], ['0x56bda50','0x5744700'])
        self.assertEqual([x['closure_body'] for x in links], ['0x2819480','0x4ae5740'])

    def test_corrupt_formatter_relocation_rejected(self):
        data = bytearray(self.data)
        for sec in self.image.secs:
            if sec['type'] != 4:
                continue
            for pos in range(sec['offset'],sec['offset']+sec['size'],24):
                if struct.unpack_from('<Q',data,pos)[0] == 0x576f560:
                    data[pos+16] ^= 1
                    with self.assertRaisesRegex(ValueError, 'relocation mismatch'):
                        subject.collect(data, verify_digest=False)
                    return
        self.fail('formatter relocation not found')

    def test_out_of_range_and_nobits(self):
        with self.assertRaises(ValueError):
            self.image.read(0xffffffffffffffff, 1)
        bss = next(s for s in self.image.secs if s['name'] == '.bss')
        with self.assertRaises(ValueError):
            self.image.read(bss['address'], 1)
        with self.assertRaises(ValueError):
            self.image.read(-1, 1)

    def test_invalid_instruction_and_load(self):
        with self.assertRaises(ValueError): self.image.rip(0x2218e60)
        with self.assertRaises(ValueError): self.image.call(0x2218e60)
        with self.assertRaises(ValueError): self.image.slot_call(0x2218e60)
        with self.assertRaises(ValueError): self.image.branch(0x2218e60)
        with self.assertRaises(ValueError): subject.load_offset(b'\x00'*4)

    def test_selected_branches(self):
        rows = {x['va']:x for x in self.records['selected_conditional_branches']}
        self.assertEqual(rows['0x221908a']['target'], '0x22190b2')
        self.assertEqual(rows['0x4c6351f']['target'], '0x4c63579')
        for va in (0x2219166, 0x221918e, 0x22191b6, 0x22191de,
                   0x2219206, 0x2219222, 0x221924a, 0x221926e):
            self.assertEqual(rows[hex(va)]['target'], '0x22192b6')

    def test_corrupt_body_rejected(self):
        data = bytearray(self.data)
        sec = next(s for s in self.image.secs if s['name'] == '.text')
        at = sec['offset'] + 0x2218e60 - sec['address']
        data[at] ^= 1
        with self.assertRaisesRegex(ValueError, 'body mismatch'):
            subject.collect(data, verify_digest=False)

    def test_corrupt_field_name_rejected(self):
        data = bytearray(self.data)
        sec = next(s for s in self.image.secs if s['name'] == '.rodata')
        at = sec['offset'] + 0x3d69d8 - sec['address']
        data[at] ^= 1
        with self.assertRaisesRegex(ValueError, 'field sequence mismatch'):
            subject.collect(data, verify_digest=False)

    def test_corrupt_call_edge_rejected(self):
        data = bytearray(self.data)
        sec = next(s for s in self.image.secs if s['name'] == '.text')
        at = sec['offset'] + 0x28194d1 - sec['address']
        data[at] ^= 1
        with self.assertRaisesRegex(ValueError, 'closure edge mismatch'):
            subject.collect(data, verify_digest=False)

if __name__ == '__main__':
    unittest.main()
