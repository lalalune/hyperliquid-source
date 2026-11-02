import contextlib
import hashlib
import mmap
import unittest

from tools import agent_tracker_snapshot94 as packet


class AgentTrackerEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.handle = packet.BINARY.open('rb')
        cls.data = mmap.mmap(cls.handle.fileno(), 0, access=mmap.ACCESS_COPY)
        cls.sections = packet.sections(cls.data)
        cls.result = packet.extract(cls.data)

    @classmethod
    def tearDownClass(cls):
        cls.data.close()
        cls.handle.close()

    @contextlib.contextmanager
    def changed(self, va):
        sec = next(s for s in self.sections if s['type'] != 8 and
                   s['address'] <= va < s['address'] + s['size'])
        offset = sec['offset'] + va - sec['address']
        original = self.data[offset]
        self.data[offset] ^= 1
        try:
            yield
        finally:
            self.data[offset] = original

    def test_authentication_and_scoped_body(self):
        packet.verify_digest(self.data)
        with self.changed(0x230d1b0):
            with self.assertRaises(ValueError):
                packet.verify_digest(self.data)
            _, end, digest = packet.FUNCTIONS[0x230d1b0]
            with self.assertRaises(ValueError):
                packet.check_function(self.data, self.sections, 0x230d1b0, end, digest)
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), packet.DIGEST)

    def test_field_order_writers_and_readers(self):
        rows = self.result['fields']
        self.assertEqual([row['name'] for row in rows], list(packet.NAMES))
        self.assertEqual([row['writer_offset'] for row in rows], [0, 48, 96, 144, 192])
        self.assertEqual([row['writer_call']['target'] for row in rows],
                         [hex(x) for x in packet.EXPECTED_CHILDREN])
        self.assertEqual([row['binary_reader_call']['target'] for row in rows],
                         [hex(x) for x in packet.EXPECTED_READERS])
        self.assertTrue(all(row['writer_child_failure']['target'] == '0x230d37b' for row in rows))
        self.assertTrue(all(row['writer_name_failure']['target'] == '0x230d36c' for row in rows))

    def test_classifier_positive_and_negative_names(self):
        keys = packet.classifier_keys(self.data, self.sections)
        for i, key in enumerate(keys):
            self.assertEqual(packet.classify(key, keys), i)
            for changed in (key[:-1], key + b'x', bytes([key[0] ^ 1]) + key[1:]):
                self.assertEqual(packet.classify(changed, keys), 5)
        self.assertEqual(packet.classify(b'', keys), 5)
        self.assertEqual(packet.classify(b'agent_to_useR', keys), 5)

    def test_classifier_vector_corruption(self):
        with self.changed(0x2048b0):
            with self.assertRaises(ValueError):
                packet.classifier_keys(self.data, self.sections)
        with self.changed(0x341e313):
            with self.assertRaises(ValueError):
                packet.classifier_keys(self.data, self.sections)

    def test_both_dispatch_tables_and_corruption(self):
        binary = self.result['binary_dispatch']
        other = self.result['json_dispatch']
        self.assertEqual(binary['targets'], ['0x2da0382', '0x2da065a', '0x2da04ee',
                                             '0x2da05a4', '0x2da0438', '0x2da070d'])
        self.assertEqual(other['targets'], ['0x31b04ac', '0x31b0609', '0x31b055d',
                                            '0x31b05b3', '0x31b0502', '0x31b065f'])
        with self.changed(0x51b254):
            with self.assertRaises(ValueError):
                packet.table(self.data, self.sections, 0x51b254, 6,
                             tuple(int(v, 16) for v in binary['targets']))

    def test_duplicate_branches_and_wrong_destinations(self):
        rows = self.result['fields']
        self.assertEqual([r['binary_duplicate_branch']['target'] for r in rows],
                         ['0x2da0a67', '0x2da0b94', '0x2da0a15', '0x2da0ab9', '0x2da0b0b'])
        self.assertEqual([r['json_duplicate_branch']['target'] for r in rows],
                         ['0x31b23e5', '0x31b229b', '0x31b21f6', '0x31b2340', '0x31b248a'])
        with self.changed(0x2da038a):
            with self.assertRaises(ValueError):
                packet.branch(self.data, self.sections, 0x2da0388, 0x2da0a67, b'\x0f\x85')
        with self.changed(0x31b04af):
            with self.assertRaises(ValueError):
                packet.branch(self.data, self.sections, 0x31b04af, 0x31b23e5, b'\x0f\x85')

    def test_missing_default_and_sequence_control_windows(self):
        windows = {x['name']: x['bytes'] for x in self.result['windows']}
        self.assertEqual(windows['map_missing_first'], '48837c2448000f8465eeffff')
        self.assertEqual(windows['map_default_second'], '48837c2408007436')
        self.assertEqual(windows['map_default_fifth'], '4d85ff742a')
        self.assertEqual(windows['sequence_count_two'], '4183fd020f85ae000000')
        self.assertEqual(windows['sequence_count_three'], '4183fd030f85af000000')
        self.assertEqual(windows['sequence_count_four'], '4183fd040f850f040000')
        self.assertEqual(windows['sequence_remainder'], '418d45fb4889442408')
        with self.changed(0x2d9ea4b):
            with self.assertRaises(ValueError):
                packet.pin(self.data, self.sections, 0x2d9ea48, windows['sequence_count_three'])

    def test_call_and_rip_destination_tampering(self):
        packet.call(self.data, self.sections, 0x230d255, packet.EXPECTED_CHILDREN[0])
        with self.changed(0x230d255):
            with self.assertRaises(ValueError):
                packet.call(self.data, self.sections, 0x230d255, packet.EXPECTED_CHILDREN[0])
        with self.changed(0x230d256):
            with self.assertRaises(ValueError):
                packet.call(self.data, self.sections, 0x230d255, packet.EXPECTED_CHILDREN[0])
        with self.changed(0x230d22f):
            with self.assertRaises(ValueError):
                packet.lea(self.data, self.sections, 0x230d22c, 0x3e0135)

    def test_file_backed_address_boundaries(self):
        with self.assertRaises(ValueError):
            packet.at(self.data, self.sections, -1, 1)
        with self.assertRaises(ValueError):
            packet.at(self.data, self.sections, 0, 0)
        with self.assertRaises(ValueError):
            packet.at(self.data, self.sections, 1 << 63, 1)
        sec = next(s for s in self.sections if s['name'] == '.text')
        with self.assertRaises(ValueError):
            packet.at(self.data, self.sections, sec['address'] + sec['size'] - 1, 2)
        with self.assertRaises(ValueError):
            packet.at(b'1234', [{'type': 8, 'address': 0, 'size': 4, 'offset': 0}], 0, 1)
        overlapping = [{'type': 1, 'address': 0, 'size': 4, 'offset': 0}] * 2
        with self.assertRaises(ValueError):
            packet.at(b'1234', overlapping, 0, 1)

    def test_fde_missing_duplicate_and_extent_changes(self):
        funcs = []
        for start, (_, end, _) in packet.FUNCTIONS.items():
            funcs.append({'start': start, 'end': end, 'fde': 1})
        packet.load_functions(self.data, self.sections, funcs)
        with self.assertRaises(ValueError):
            packet.load_functions(self.data, self.sections, funcs[:-1])
        with self.assertRaises(ValueError):
            packet.load_functions(self.data, self.sections, funcs + [funcs[0]])
        changed = [dict(row) for row in funcs]
        changed[0]['end'] -= 1
        with self.assertRaises(ValueError):
            packet.load_functions(self.data, self.sections, changed)

    @contextlib.contextmanager
    def changed_file_offset(self, offset):
        original = self.data[offset]
        self.data[offset] ^= 1
        try:
            yield
        finally:
            self.data[offset] = original

    def test_nonce_field_path_and_small_comparator(self):
        evidence = self.result
        self.assertEqual(evidence['nonce_comparator_import']['name'], 'memcmp')
        self.assertEqual(evidence['nonce_comparator_import']['kind'], 6)
        self.assertEqual(len(evidence['nonce_comparator_calls']), 5)
        windows = {x['name']: x['bytes'] for x in evidence['windows']}
        self.assertEqual(windows['nonce_small_key_compare'],
                         '4a8b7c2810ba140000004889deff1500c7780385c079c6')
        self.assertEqual(windows['nonce_pair_sequence_marker'][-8:], 'c6040192')
        with self.changed(0x1fe1d82):
            with self.assertRaises(ValueError):
                packet.indirect_call(self.data, self.sections, 0x1fe1d82, 0x576e488)
        with self.changed(0x1fe1d7b):
            with self.assertRaises(ValueError):
                packet.pin(self.data, self.sections, 0x1fe1d75,
                           windows['nonce_small_key_compare'])

    def test_nonce_comparator_relocation_corruption(self):
        imported = self.result['nonce_comparator_import']
        self.assertEqual(packet.imported_symbol(self.data, self.sections, 0x576e488, 'memcmp')['name'], 'memcmp')
        with self.changed_file_offset(int(imported['rela_file_offset'], 16) + 8):
            with self.assertRaises(ValueError):
                packet.imported_symbol(self.data, self.sections, 0x576e488, 'memcmp')
        with self.changed_file_offset(int(imported['name_file_offset'], 16)):
            with self.assertRaises(ValueError):
                packet.imported_symbol(self.data, self.sections, 0x576e488, 'memcmp')
        with self.assertRaises(ValueError):
            packet.imported_symbol(self.data, self.sections, 0x576e488, 'different')
        with self.assertRaises(ValueError):
            packet.imported_symbol(self.data, self.sections, 0x576e489, 'memcmp')

    def test_size_and_enclosing_call(self):
        functions = self.result['functions']
        self.assertEqual(len(functions), 12)
        self.assertEqual(functions['binary_reader']['size'], 10959)
        self.assertEqual(functions['json_reader']['size'], 11285)
        self.assertEqual(self.result['context_call']['target'], '0x230d1b0')
        self.assertEqual(len(self.result['binary_classifier_length_dispatch']['targets']), 18)
        self.assertEqual(len(self.result['json_classifier_length_dispatch']['targets']), 18)


if __name__ == '__main__':
    unittest.main()
