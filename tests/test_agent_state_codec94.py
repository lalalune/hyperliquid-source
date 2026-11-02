import hashlib
import json
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import agent_state_codec94 as m


class StaticEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = m.TARGET.read_bytes()
        cls.secs = m.sections(cls.data)
        cls.out = m.extract(cls.data)
        cls.record = json.loads(cls.out['evidence.json'])

    def file_offset(self, va):
        s = next(s for s in self.secs if s['type'] != 8 and
                 s['address'] <= va < s['address'] + s['size'])
        return s['offset'] + va - s['address']

    def test_fields_and_boundaries(self):
        fields = self.record['fields']
        self.assertEqual([x['name'] for x in fields], [
            'user_to_main_agent', 'user_to_extra_agents', 'agent_to_user',
            'address_to_nonce_set', 'user_to_pending_agent_removals'])
        self.assertEqual([x['writer_input_offset'] for x in fields],
                         ['0x0','0x30','0x60','0x90','0xc0'])
        self.assertEqual([x['duplicate_target'] for x in fields],
                         ['0x31b23e5','0x31b229b','0x31b21f6','0x31b2340','0x31b248a'])
        self.assertEqual({x['key_failure_target'] for x in fields}, {'0x230d36c'})
        self.assertEqual({x['value_failure_target'] for x in fields}, {'0x230d37b'})
        self.assertEqual(len(self.record['functions']), 6)
        self.assertEqual(self.record['json_unknown_dispatch'], '0x31b065f')
        self.assertEqual(self.record['context_writer_field']['input_offset'], '0x36d0')

    def test_classifier_exact_and_single_bit_mutations(self):
        names = [x['name'].encode('ascii') for x in self.record['fields']]
        for tag, name in enumerate(names):
            self.assertEqual(m.classify(name, names), tag)
            self.assertEqual(m.classify(name[:-1], names), 5)
            for offset in range(len(name)):
                value = bytearray(name)
                value[offset] ^= 1
                self.assertEqual(m.classify(bytes(value), names), 5)
        self.assertEqual(len(self.out['name-cases.tsv'].splitlines()),112)
        with self.assertRaises(ValueError):
            m.classify('user_to_main_agent', names)

    def test_required_and_default_matrix(self):
        for mask in range(32):
            expected = ('missing_0' if not mask & 1 else
                        'missing_2' if not mask & 4 else 'required_present')
            self.assertEqual(m.presence(mask), expected)
        for mask in (-1, 32):
            with self.assertRaises(ValueError):
                m.presence(mask)
        self.assertEqual(len(self.out['presence.tsv'].splitlines()), 33)

    def test_sequence_boundaries(self):
        expected = ['short_0','short_2','short_2','default_3_4','default_4',
                    'five_children','forward_extra_count','forward_extra_count']
        self.assertEqual([m.sequence(i) for i in range(8)], expected)
        self.assertEqual(m.sequence(0xffffffff), 'forward_extra_count')
        for value in (-1, 1 << 32):
            with self.assertRaises(ValueError):
                m.sequence(value)

    def test_wrong_digest_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            m.extract(self.data, expected_digest='0' * 64)

    def test_rehashed_code_corruption_is_rejected(self):
        damaged = bytearray(self.data)
        damaged[self.file_offset(0x31b0468)] ^= 1
        with self.assertRaisesRegex(ValueError, 'instruction mismatch'):
            m.extract(damaged, hashlib.sha256(damaged).hexdigest())

    def test_rehashed_field_corruption_is_rejected(self):
        damaged = bytearray(self.data)
        damaged[self.file_offset(0x3e0135)] ^= 1
        with self.assertRaisesRegex(ValueError, 'field copies disagree'):
            m.extract(damaged, hashlib.sha256(damaged).hexdigest())

    def test_rehashed_classifier_constant_corruption_is_rejected(self):
        damaged = bytearray(self.data)
        damaged[self.file_offset(0x2048b0)] ^= 1
        with self.assertRaisesRegex(ValueError, 'classifier comparison constants'):
            m.extract(damaged, hashlib.sha256(damaged).hexdigest())

    def test_table_out_of_range_and_wrong_dispatch(self):
        va = 0x57cbd4
        offset = self.file_offset(va)
        damaged = bytearray(self.data)
        struct.pack_into('<i', damaged, offset, 0)
        with self.assertRaisesRegex(ValueError, 'outside FDE'):
            m.relative_table(damaged,self.secs,va,6,0x31b0240,0x31b2e55)
        with self.assertRaises(ValueError):
            m.read_va(self.data,self.secs,va,-1)

    def test_rehashed_in_range_dispatch_swap_rejected(self):
        damaged = bytearray(self.data)
        off = self.file_offset(0x57cbd4)
        damaged[off:off+4] = damaged[off+4:off+8]
        with self.assertRaisesRegex(ValueError, 'checked guards'):
            m.extract(damaged, hashlib.sha256(damaged).hexdigest())

    def test_unmapped_crossing_nobits_and_ambiguity(self):
        with self.assertRaises(ValueError):
            m.read_va(self.data,self.secs,0,1)
        text_sec = next(s for s in self.secs if s['name'] == '.text')
        with self.assertRaises(ValueError):
            m.read_va(self.data,[text_sec],text_sec['address']+text_sec['size']-1,2)
        fake = {'type':8,'address':1,'size':4,'offset':0}
        with self.assertRaises(ValueError):
            m.read_va(b'abcd',[fake],1,1)
        fake['type'] = 1
        with self.assertRaises(ValueError):
            m.read_va(b'abcd',[fake,fake],1,1)

    def test_corrupt_relative_instructions(self):
        for site,expected in ((0x31b0468,0x341e420),(0x2fe78b7,0x31b0240)):
            self.assertEqual(m.rel32(self.data,self.secs,site,b'\xe8'), expected)
            raw = bytearray(m.read_va(self.data,self.secs,site,5))
            fake = [{'type':1,'address':site,'size':5,'offset':0}]
            raw[0] = 0x90
            with self.assertRaises(ValueError):
                m.rel32(raw,fake,site,b'\xe8')
            raw[0] = 0xe8
            raw[1] ^= 1
            self.assertNotEqual(m.rel32(raw,fake,site,b'\xe8'),expected)

    def test_every_pinned_window_rejects_mutation(self):
        altered = bytearray(self.data)
        for va in m.PINS:
            off = self.file_offset(va)
            altered[off] ^= 1
            with self.subTest(va=hex(va)), self.assertRaises(ValueError):
                m.check_pins(altered,self.secs)
            altered[off] ^= 1

    def test_table_and_length_extraction(self):
        self.assertEqual(len(self.out['fields.tsv'].splitlines()),6)
        self.assertEqual(len(self.out['sequence.tsv'].splitlines()),10)
        targets = self.record['classifier_length_targets']
        self.assertEqual(len(targets),18)
        self.assertEqual(targets[0], '0x341e441')
        self.assertEqual(targets[5], '0x341e4cd')
        self.assertEqual(targets[7], '0x341e46e')
        self.assertEqual(targets[17], '0x341e502')
        self.assertTrue(all(targets[i] == '0x341e52b' for i in range(18)
                            if i not in (0,5,7,17)))


if __name__ == '__main__':
    unittest.main()
