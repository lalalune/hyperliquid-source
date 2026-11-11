"""Native target evidence and set-initializer counterfactuals."""
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import set_initializer_static as subject
from elf_index import sections

PACKET = (Path(__file__).resolve().parents[1] / 'research' / 'work-items'
          / 'RE-015-node115-set-initializer')


class SetInitializerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not subject.TARGET.is_file() or \
                subject.TARGET.stat().st_size != 105896032:
            raise unittest.SkipTest('materialized node115 required')
        cls.data = subject.TARGET.read_bytes()
        if hashlib.sha256(cls.data).hexdigest() != subject.SHA:
            raise ValueError('wrong node115 capture')
        cls.secs = sections(cls.data)
        cls.report = subject.analyze(cls.data)

    def offset(self, va):
        s = next(s for s in self.secs
                 if s['type'] != 8
                 and s['address'] <= va < s['address'] + s['size'])
        return s['offset'] + va - s['address']

    def mutate(self, va, value=None):
        b = bytearray(self.data)
        o = self.offset(va)
        b[o] = b[o] ^ 1 if value is None else value
        return b

    def test_analysis_shape(self):
        owners = {row['role'] for row in self.report['owners']}
        self.assertEqual(owners, {'set_initializer'})
        self.assertEqual(self.report['target_sha256'], subject.SHA)
        owner = self.report['owners'][0]
        self.assertEqual(owner['start'], '0x4743990')
        self.assertEqual(owner['end'], '0x4743ff0')
        self.assertEqual(owner['bytes'], 1632)
        self.assertEqual(owner['sha256'], subject.INIT_SHA)
        bindings = self.report['slot_bindings']
        self.assertEqual(bindings['set_init']['addend'], '0x4743990')
        self.assertEqual(bindings['alloc']['addend'], '0x6355830')
        self.assertEqual(bindings['dealloc']['addend'], '0x635de30')
        self.assertEqual(bindings['panic_entry']['addend'], '0x1680e80')
        self.assertEqual(bindings['memset']['symbol'], 'memset')
        self.assertEqual(bindings['memmove']['symbol'], 'memmove')

    def test_no_bulk_copy_census(self):
        census = self.report['call_census']
        self.assertFalse(census['memcpy_slot_called'])
        self.assertEqual(census['hash_direct_call_sites'],
                         ['0x4743be4', '0x4743d5d'])
        slots = census['slot_calls']
        self.assertEqual(slots['0x4743b22'], '0x64df750')
        self.assertEqual(slots['0x4743d1f'], '0x64df568')
        self.assertNotIn('0x64df508', slots.values())

    def test_template_image_is_empty_static(self):
        image = self.report['template_image']
        self.assertEqual(image['first_control_byte'], '0xff')
        self.assertEqual(image['relocations_located_in_image_range'], [])
        self.assertEqual(image['binary_wide_addend_references'], 62)
        self.assertEqual(image['deleted_vector_hex'], '80' * 16)
        self.assertEqual(image['panic_literal'],
                         'Hash table capacity overflow')

    def test_first_init_trace_model(self):
        trace = self.report['first_init_trace']
        self.assertEqual(trace['needed'], 1)
        self.assertEqual(trace['capacity_before'], 0)
        self.assertEqual(trace['path'], 'grow')
        self.assertEqual(trace['new_buckets'], 4)
        self.assertEqual(trace['alloc_size'], 116)
        self.assertEqual(trace['bucket_bytes'], 96)
        self.assertEqual(trace['ctrl_bytes'], 20)
        self.assertEqual(trace['records_moved'], 0)
        self.assertEqual(trace['image_bytes_copied'], 0)
        self.assertEqual(trace['writeback']['mask'], 3)
        self.assertEqual(trace['writeback']['growth_left'], 3)
        self.assertEqual(trace['writeback']['items'], 0)
        self.assertFalse(trace['old_table_freed'])
        self.assertEqual(trace['return'], '0x8000000000000001')

    def test_capacity_model(self):
        cap = subject.buckets_to_capacity
        self.assertEqual([cap(b) for b in (1, 2, 4, 8, 16, 128)],
                         [0, 1, 3, 7, 14, 112])

    def test_counterfactual_memset_value(self):
        # The control fill must be 0xFF (EMPTY); any other fill
        # breaks the starts-empty verdict.
        bad = self.mutate(0x4743b1a + 1, 0x00)
        with self.assertRaises(ValueError):
            subject.analyze(bytes(bad))

    def test_counterfactual_items_skip(self):
        # Removing the items==0 skip of the move loop would make
        # the starts-empty claim untestable; the pin must catch it.
        bad = self.mutate(0x4743b62)
        with self.assertRaises(ValueError):
            subject.analyze(bytes(bad))

    def test_counterfactual_image_byte(self):
        bad = self.mutate(0x450150, 0x00)
        with self.assertRaises(ValueError):
            subject.analyze(bytes(bad))

    def test_counterfactual_success_const(self):
        bad = self.mutate(0x4743f80 + 2)
        with self.assertRaises(ValueError):
            subject.analyze(bytes(bad))

    def test_counterfactual_writeback(self):
        bad = self.mutate(0x4743f3e)
        with self.assertRaises(ValueError):
            subject.analyze(bytes(bad))

    def test_generate_roundtrip(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / 'packet'
            subject.generate(subject.TARGET, out)
            records = json.loads((out / 'records.json').read_text())
            self.assertEqual(records['target_sha256'], subject.SHA)
            self.assertEqual(
                records['first_init_trace']['image_bytes_copied'], 0)
            frames = (out / 'frames.txt').read_text()
            self.assertIn('pc=0000000004743990..0000000004743ff0',
                          frames)
            self.assertTrue(
                (out / 'set_initializer_objdump.txt').is_file())
            self.assertTrue(
                (out / 'delegate_entry_template_window'
                       '_47485a0_47485d0_objdump.txt').is_file())

    def test_packet_records_match(self):
        committed = json.loads((PACKET / 'records.json').read_text())
        self.assertEqual(committed, self.report)


if __name__ == '__main__':
    unittest.main()
