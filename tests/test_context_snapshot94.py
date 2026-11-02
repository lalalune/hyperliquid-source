import unittest

from tools import context_snapshot94 as m


class ContextSnapshotEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = m.BINARY.read_bytes()
        cls.record = m.build(cls.data)
        cls.sections = m.sections(cls.data)
        cls.image, _ = m.read_va(cls.data, cls.sections, 0x21e4170, 0x21e4663-0x21e4170)
        cls.table, _ = m.read_va(cls.data, cls.sections, 0x3d4114, 56)

    def classify(self, name):
        return m.classify(self.image, 0x21e4170, self.table, name)

    def test_identity_and_extents(self):
        self.assertEqual(len(self.record['functions']), 11)
        self.assertEqual(self.record['binary_sha256'], m.DIGEST)
        with self.assertRaises(ValueError):
            m.check_digest(b'not the capture')
        with self.assertRaises(ValueError):
            m.check_digest(self.data, '0' * 64)

    def test_field_order_and_alias(self):
        names = [x['name'] for x in self.record['fields']]
        self.assertEqual(names, ['initial_height','hardfork','height','tx_index',
            'round','time','prev_time','next_oid','next_lid','next_twap_id',
            'system_nonce','use_system_nonce','mac'])
        self.assertEqual([self.classify(x.encode()) for x in names],list(range(13)))
        self.assertEqual(self.classify(b'consensus_round'), 4)
        self.assertEqual(self.record['classifier_alias']['name'],'consensus_round')
        self.assertEqual(self.classify(b'consensus_round\x00'),13)
        self.assertEqual(self.classify(b'rounds'),13)
        self.assertEqual(self.classify(b''),13)
        self.assertEqual(self.classify(b'x' * 17),13)

    def test_every_key_byte_has_a_negative_control(self):
        self.assertEqual(self.record['single_byte_substitution_controls'],32640)
        for s in (b'initial_height', b'consensus_round', b'system_nonce'):
            ident = self.classify(s)
            for i in range(len(s)):
                bad = s[:i] + bytes([s[i] ^ 1]) + s[i+1:]
                self.assertNotEqual(self.classify(bad), ident)

    def test_dispatch_and_duplicate_edges(self):
        arms=self.record['reader_dispatch']
        self.assertEqual(len(arms),14)
        self.assertEqual([x['index'] for x in arms],list(range(14)))
        self.assertEqual(arms[13]['field'],'unknown')
        self.assertEqual(len(self.record['duplicate_branches']),13)
        self.assertEqual(self.record['duplicate_branches'][4]['target'],'0x18596cb')
        self.assertEqual(self.record['duplicate_branches'][4]['condition'],'equal')
        self.assertEqual(self.classify(b'round'), self.classify(b'consensus_round'))

    def test_missing_routes_and_offsets(self):
        self.assertEqual(len(self.record['missing_branches']),12)
        self.assertEqual([x['value_offset'] for x in self.record['fields']],
            ['0x10','0x18','0x28','0x8','0x30','0x60','0x6c','0x38','0x40','0x48','0x50','0x78','0x58'])
        self.assertEqual(self.record['missing_branches'][0]['target'],'0x1858863')
        self.assertEqual(self.record['missing_branches'][6]['target'],'0x1cc0265')

    def test_corrupt_classifier_code_and_table(self):
        bad=bytearray(self.image)
        bad[0x21e4191-0x21e4170]=0xff
        with self.assertRaises(ValueError):
            m.classify(bytes(bad),0x21e4170,self.table,b'mac')
        badtable=bytearray(self.table)
        badtable[0:4]=b'\xff\xff\xff\x7f'
        with self.assertRaises(ValueError):
            m.classify(self.image,0x21e4170,bytes(badtable),b'mac')
        with self.assertRaises(ValueError):
            m.classify(self.image,0x21e4170,b'',b'mac')

    def test_reject_unbacked_ranges_and_bad_branch(self):
        with self.assertRaises(ValueError):
            m.read_va(self.data,self.sections,0xffffffffffffffff,1)
        bss=next(s for s in self.sections if s['type']==8 and s['size'])
        with self.assertRaises(ValueError):
            m.read_va(self.data,[bss],bss['address'],1)
        with self.assertRaises(ValueError):
            m.read_va(self.data,self.sections,0,-1)
        with self.assertRaises(ValueError):
            m.branch(self.data,self.sections,0x18571b0)
        with self.assertRaises(ValueError):
            m.relative(self.data,self.sections,0x2218ee4,b'\x00\x00\x00')

    def test_timestamp_route(self):
        time=self.record['timestamp']
        self.assertEqual(time['type_name'],'Time')
        self.assertEqual(time['separator_immediate'],'be54000000')
        self.assertEqual(len(time['edges']),4)
        self.assertEqual(time['edges'][0]['target'],time['edges'][1]['target'])
        self.assertEqual(time['edges'][2]['target'],'0x1e4fc10')

    def test_wrong_fde_body_bytes_are_caught(self):
        # Change only the selected body, leaving the expected hash unchanged.
        start=0x2218e60
        end, expected, _=m.FUNCTIONS[start]
        body,_=m.read_va(self.data,self.sections,start,end-start)
        altered=bytearray(body)
        altered[-1] ^= 1
        m.check_body(body,expected)
        with self.assertRaises(ValueError):
            m.check_body(altered,expected)


if __name__ == '__main__':
    unittest.main()
