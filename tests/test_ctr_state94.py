import hashlib
from pathlib import Path
import struct
import unittest

from tools import ctr_state94 as study


class CtrStateEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = study.BINARY.read_bytes()
        cls.evidence = study.analyze(cls.binary)
        cls.image = study.Image(cls.binary)

    def modified_image(self, va, replacement):
        copy = bytearray(self.binary)
        off = self.image.offset(va, len(replacement))
        copy[off:off + len(replacement)] = replacement
        return study.Image(copy)

    def test_authentication_and_file_backed_mapping(self):
        self.assertEqual(study.authenticate(self.binary), study.SHA256)
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            study.authenticate(self.binary, '0' * 64)
        changed = bytearray(self.binary)
        changed[0] ^= 1
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            study.authenticate(changed)
        with self.assertRaisesRegex(ValueError, 'negative'):
            self.image.read(-1, 1)
        with self.assertRaisesRegex(ValueError, 'file-backed'):
            self.image.read(1 << 63, 1)
        n = next(s for s in self.image.sections if s['name'] == '.bss' and s['type'] == 8)
        with self.assertRaisesRegex(ValueError, 'file-backed'):
            self.image.read(n['address'], 1)

    def test_mutable_input_is_snapshotted(self):
        source = bytearray(self.binary)
        im = study.Image(source)
        at = study.FUNCTIONS['json_key_classifier']
        original = im.read(at, 1)
        source[im.offset(at, 1)] ^= 1
        self.assertEqual(im.read(at, 1), original)

    def test_function_extents_and_observed_key_order(self):
        self.assertEqual(len(self.evidence['functions']), 20)
        self.assertEqual([r['key'] for r in self.evidence['fields']],
                         ['tn', 'vn', 'tc', 'sc', 'to', 'so', 'ac', 'ad'])
        self.assertEqual([r['state_offset'] for r in self.evidence['fields']],
                         ['0xc8', '0xd0', '0xd8', '0xe0', '0xe8', '0xf0', None, '0xf8'])
        self.assertEqual([x['key'] for x in self.evidence['nested_writer_fields']],
                         ['p', 'm', 'l', 'L', 'M', 'b', 'c', 's', 't'])
        self.assertEqual(self.evidence['nested_json_dispatch']['slot_count'], 41)
        self.assertEqual(self.evidence['nested_messagepack_dispatch']['slot_count'], 41)
        self.assertEqual(len({r['messagepack_reader']['duplicate_target'] for r in self.evidence['nested_writer_fields']}), 9)
        self.assertEqual(len({r['json_reader']['duplicate_target'] for r in self.evidence['nested_writer_fields']}), 9)
        self.assertEqual(self.evidence['nested_writer_fields'][4]['state_offsets'],
                         ['0x50', '0x58', '0x60', '0x68', '0x70'])
        for f in self.evidence['functions']:
            self.assertLess(int(f['start'], 16), int(f['end'], 16))

    def test_classifier_exact_key_length_and_unknowns(self):
        names = [r['key'] for r in self.evidence['fields']]
        for i, key in enumerate(names):
            self.assertEqual(study.evaluate_classifier(names, key.encode()), i)
        recognized = {key.encode() for key in names}
        for value in range(65536):
            key = value.to_bytes(2, 'big')
            self.assertEqual(study.evaluate_classifier(names, key) < 8, key in recognized)
        for key in (b'', b't', b'tnn', b'Tn', b'zz', b'ac\x00', b'\x00\x00'):
            self.assertEqual(study.evaluate_classifier(names, key), 8)
        with self.assertRaises(TypeError):
            study.evaluate_classifier(names, 'tn')
        changed = self.modified_image(study.FUNCTIONS['json_key_classifier'] + 11, b'\x90')
        with self.assertRaisesRegex(ValueError, 'classifier compare'):
            study.parse_classifier(changed, study.FUNCTIONS['json_key_classifier'], 0)

    def test_dispatch_and_duplicate_corruption(self):
        fields = self.evidence['fields']
        self.assertEqual(len({r['json_reader']['duplicate_target'] for r in fields}), 8)
        self.assertEqual(len({r['messagepack_reader']['duplicate_target'] for r in fields}), 8)
        im = self.modified_image(0x3b68f4, struct.pack('<i', 0))
        with self.assertRaisesRegex(ValueError, 'outside reader'):
            study.table(im, 0x3b68f4, 0x1caa410, 0x1cab737)
        arm = int(fields[0]['json_reader']['arm'], 16)
        im = self.modified_image(arm + 6, b'\x90\x90')
        with self.assertRaisesRegex(ValueError, 'duplicate branch'):
            study.duplicate_arm(im, arm, 'tn')
        with self.assertRaisesRegex(ValueError, 'diagnostic key'):
            study.duplicate_arm(self.image, arm, 'vn')
        im = self.modified_image(arm + 7, b'\x85')
        with self.assertRaisesRegex(ValueError, 'branch condition'):
            study.duplicate_arm(im, arm, 'tn')
        nested = self.evidence['nested_writer_fields'][0]
        nested_arm = int(nested['json_reader']['arm'], 16)
        with self.assertRaisesRegex(ValueError, 'diagnostic key'):
            study.duplicate_arm(self.image, nested_arm, 'm')

    def test_selected_writer_paths_and_name_flag(self):
        names = [r['key'] for r in self.evidence['fields']]
        for bits in range(256):
            words = [int(bool(bits & (1 << i))) for i in (0, 1, 2, 3, 4, 5, 7)]
            selected = study.selected_fields(words, not bool(bits & 64))
            self.assertEqual(selected, [i for i in range(8) if bits & (1 << i)])
        self.assertEqual([names[i] for i in study.selected_fields([0]*7, True)], [])
        self.assertEqual([names[i] for i in study.selected_fields([0]*7, False)], ['ac'])
        with self.assertRaises(ValueError):
            study.selected_fields([1 << 64] + [0]*6, True)
        with self.assertRaises(ValueError):
            study.selected_fields([0]*7, 1)
        for row in self.evidence['fields']:
            gate = bytes.fromhex(row['name_gate_bytes'])
            self.assertEqual([study.name_written((gate[4], gate[5]), f) for f in (0, 1, 2)],
                             row['name_written_for_flags_0_1_2'])
        self.assertEqual([r['key'] for r in self.evidence['fields']
                          if r['name_written_for_flags_0_1_2'][2]], ['to', 'so', 'ad'])
        with self.assertRaises(ValueError):
            study.name_written((0, 0x90), 0)

    def test_shared_time_pair_writer(self):
        row = self.evidence['time_pair']
        self.assertEqual(row['keys'], ['n', 't'])
        self.assertEqual(row['type_literal'], 'Time')
        self.assertEqual(row['packed_default'], '0xf6401a')
        epoch = int(row['packed_default'], 16)
        self.assertEqual(study.time_pair_presence(0, epoch, 0, 0, epoch), [])
        self.assertEqual(study.time_pair_presence(1, epoch, 0, 0, epoch), ['n'])
        self.assertEqual(study.time_pair_presence(0, epoch ^ 1, 0, 0, epoch), ['t'])
        self.assertEqual(study.time_pair_presence(0, epoch, 1, 0, epoch), ['t'])
        self.assertEqual(study.time_pair_presence(1, epoch, 0, 1, epoch), ['n', 't'])
        with self.assertRaises(ValueError):
            study.time_pair_presence(0, epoch, 0, 1 << 32, epoch)
        im = self.modified_image(0x297a26b, b'\x90')
        with self.assertRaisesRegex(ValueError, 'direct jump'):
            im.jump(0x297a26b)

    def test_five_word_child_keys_and_negative_cases(self):
        rows = self.evidence['five_word_fields']
        self.assertEqual([r['key'] for r in rows], ['t', 's', 'c', 'u', 'l'])
        self.assertEqual([r['offset'] for r in rows], ['0x0', '0x8', '0x10', '0x18', '0x20'])
        self.assertEqual(self.evidence['five_word_json_dispatch']['slot_count'], 19)
        self.assertEqual(len({r['json_reader']['duplicate_target'] for r in rows}), 5)
        for bits in range(32):
            words = [(1 << 64) - 1 if bits & (1 << i) else 0 for i in range(5)]
            self.assertEqual(study.five_word_presence(words),
                             [r['key'] for i, r in enumerate(rows) if bits & (1 << i)])
        with self.assertRaises(ValueError):
            study.five_word_presence([0] * 4)
        with self.assertRaises(ValueError):
            study.five_word_presence([0, 0, 0, 0, 1 << 64])
        with self.assertRaisesRegex(ValueError, 'diagnostic key'):
            study.duplicate_arm(self.image, int(rows[0]['json_reader']['arm'], 16), 's')

    def test_expected_type_vtables_and_literal_corruption(self):
        rows = self.evidence['expected_types']
        self.assertEqual([r['text'] for r in rows],
                         ['struct ExchangeCounters', 'struct AbstractionCounters'])
        va = int(rows[0]['literal_va'], 16)
        im = self.modified_image(va, b'X')
        with self.assertRaisesRegex(ValueError, 'text mismatch'):
            study.expected_type(im, 0x1cab5cb, 0x276bb50, 'struct ExchangeCounters')
        with self.assertRaisesRegex(ValueError, 'formatter relocation'):
            study.expected_type(self.image, 0x1cab5cb, 0x28e82a0, 'struct ExchangeCounters')

    def test_shared_time_pair_json_reader(self):
        row = self.evidence['time_pair']
        self.assertEqual(row['json_reader'], '0x1cae020')
        self.assertEqual([a['duplicate_target'] for a in row['json_reader_duplicate_arms']],
                         ['0x1cae642', '0x1cae639'])
        with self.assertRaisesRegex(ValueError, 'diagnostic key'):
            study.duplicate_arm(self.image, 0x1cae2cd, 't')
        im = self.modified_image(0x1cae1f1, b'\x84')
        with self.assertRaisesRegex(ValueError, 'branch condition'):
            study.duplicate_arm(im, 0x1cae1ee, 't')

    def test_nested_default_and_helper_failure_controls(self):
        zeros = [0] * 19
        one = (0, 17, 0, 0)
        two = (0, 29, 0, 0)
        self.assertTrue(study.nested_default(zeros, one, 17, two, 29))
        self.assertTrue(study.nested_default(zeros, list(one), 17, list(two), 29))
        for i in range(19):
            changed = zeros.copy()
            changed[i] = 1
            self.assertFalse(study.nested_default(changed, one, 17, two, 29))
        for i in range(4):
            v = list(one)
            v[i] ^= 1
            self.assertFalse(study.nested_default(zeros, tuple(v), 17, two, 29))
        for i in range(4):
            v = list(two)
            v[i] ^= 1
            self.assertFalse(study.nested_default(zeros, one, 17, tuple(v), 29))
        with self.assertRaisesRegex(ValueError, 'helper-failure'):
            study.nested_default(zeros, one, 0, two, 29)
        with self.assertRaises(ValueError):
            study.nested_default(zeros[:-1], one, 17, two, 29)
        offsets, branches = study.nested_zero_offsets(self.image)
        self.assertEqual(offsets, list(range(0x30, 0xc8, 8)))
        self.assertEqual(len(branches), 19)
        im = self.modified_image(0x282fcf7, b'\x90\x90')
        with self.assertRaisesRegex(ValueError, 'comparison branch'):
            study.nested_zero_offsets(im)

    def test_relocation_and_call_tampering(self):
        calls = self.evidence['nested_default']['helper_calls']
        self.assertEqual(calls[0]['argument'], 719163)
        self.assertEqual(calls[0]['relocation_addend'], '0x151f6f0')
        self.assertEqual(study.relocation(self.image, 0x576e890), 0x151f6f0)
        with self.assertRaisesRegex(ValueError, 'relocation'):
            study.relocation(self.image, 0x576e891)
        im = self.modified_image(study.EDGES['mp_to_nested_writer'], b'\x90')
        with self.assertRaisesRegex(ValueError, 'direct call'):
            im.call(study.EDGES['mp_to_nested_writer'])

    def test_nested_table_rejected_after_digest_is_rebound(self):
        copy = bytearray(self.binary)
        base = int(self.evidence['nested_json_dispatch']['table'], 16)
        at = base + (ord('p') - self.evidence['nested_json_dispatch']['minimum_byte']) * 4
        offset = self.image.offset(at, 4)
        other = base + (ord('m') - self.evidence['nested_json_dispatch']['minimum_byte']) * 4
        copy[offset:offset+4] = self.image.read(other, 4)
        with self.assertRaisesRegex(ValueError, 'diagnostic key'):
            study.analyze(copy, expected=hashlib.sha256(copy).hexdigest())

    def test_nested_writer_gate_rejected_after_digest_is_rebound(self):
        copy = bytearray(self.binary)
        off = self.image.offset(0x28e7418, 1)
        copy[off] ^= 1
        with self.assertRaisesRegex(ValueError, 'nested_s_guard'):
            study.analyze(copy, expected=hashlib.sha256(copy).hexdigest())

    def test_five_word_table_rejected_after_digest_is_rebound(self):
        copy = bytearray(self.binary)
        base = int(self.evidence['five_word_json_dispatch']['table'], 16)
        t = self.image.offset(base + (ord('t') - ord('c')) * 4, 4)
        s = self.image.offset(base + (ord('s') - ord('c')) * 4, 4)
        copy[t:t+4] = copy[s:s+4]
        with self.assertRaisesRegex(ValueError, 'diagnostic key'):
            study.analyze(copy, expected=hashlib.sha256(copy).hexdigest())

    def test_full_analysis_rejects_changed_code_after_digest_is_rebound(self):
        copy = bytearray(self.binary)
        off = self.image.offset(study.GATES[0][0], 1)
        copy[off] ^= 1
        with self.assertRaisesRegex(ValueError, 'writer omission gate'):
            study.analyze(copy, expected=hashlib.sha256(copy).hexdigest())


if __name__ == '__main__':
    unittest.main()
