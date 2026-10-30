"""Target-grounded controls for the static foundation packet (no node execution)."""
import json
from pathlib import Path
import unittest

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import foundation_set_once as so
from elf_index import sections


class SetOnceEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not so.TARGET.is_file() or so.TARGET.stat().st_size != 91774280:
            raise unittest.SkipTest('Requires materialized node #94 Git LFS input')
        # Authenticate once; structural mutation controls intentionally bypass
        # the identity gate so each downstream evidence check is exercised.
        cls.result = so.inspect(so.TARGET)
        cls.data = so.TARGET.read_bytes()
        cls.sections = sections(cls.data)

    def offset(self, va):
        s = next(s for s in self.sections if s['type'] != 8 and s['address'] <= va < s['address'] + s['size'])
        return s['offset'] + va - s['address']

    def mutated(self, va, raw):
        data = bytearray(self.data)
        off = self.offset(va)
        data[off:off + len(raw)] = raw
        return data

    def test_retained_record_matches_authenticated_target(self):
        record = so.ROOT / 'research/work-items/foundation-set-once-94/evidence.json'
        self.assertEqual(self.result, json.loads(record.read_text()))

    def test_windows_fde_and_padding_from_retained_bytes(self):
        windows = self.result['windows']
        expected = [
            ('0x1515880', '0x15158b2', 50, '0x14454', 14),
            ('0x15158c0', '0x1515900', 64, '0x14468', 0),
            ('0x1515900', '0x1515937', 55, '0x1447c', 9),
            ('0x1515940', '0x1515979', 57, '0x14490', 7),
            ('0x1515980', '0x15159b9', 57, '0x144a4', 7),
        ]
        for got, (start, end, nbytes, foff, pad) in zip(windows, expected):
            self.assertEqual(got['start_va'], start)
            self.assertEqual(got['fde_end_va_exclusive'], end)
            self.assertEqual(got['fde_bytes'], nbytes)
            self.assertEqual(got['fde_section_offset'], foff)
            self.assertEqual(got['padding_int3_bytes'], pad)
        self.assertEqual(self.result['claim'],
                         'these windows implement the same set-once protocol with '
                         'per-window fields and ranges')
        self.assertIsNone(self.result['inferred_label'])
        self.assertFalse(self.result['captured_binary_executed'])
        self.assertFalse(self.result['progress_gate_requested'])

    def test_byte_cell_entry_and_sentinel(self):
        w1 = self.data[self.offset(0x1515880):self.offset(0x1515880) + 50]
        self.assertEqual(w1[0:3], b'\x48\xff\xce')
        self.assertEqual(w1[3:7], b'\x48\x83\xfe\x06')
        self.assertEqual(w1[7], 0x77)
        self.assertEqual(0x1515880 + 7 + 2 + w1[8], 0x151589e)
        self.assertEqual(w1[9:16], b'\x0f\xb6\x87\xa0\x00\x00\x00')
        self.assertEqual(w1[16:18], b'\x3c\x07')
        self.assertEqual(w1[18], 0x75)
        self.assertEqual(0x1515880 + 18 + 2 + w1[19], 0x15158a1)
        self.assertEqual(w1[20:27], b'\x40\x88\xb7\xa0\x00\x00\x00')
        self.assertEqual(w1[33:36], b'\x40\x38\xf0')
        self.assertEqual(w1[46:49], b'\x0f\x44\xc1')

    def test_table_cell_map_and_cell(self):
        w2 = self.data[self.offset(0x15158c0):self.offset(0x15158c0) + 64]
        self.assertEqual(w2[0:4], b'\x48\x83\xfe\x06')
        self.assertEqual(w2[4], 0x77)
        self.assertEqual(0x15158c0 + 4 + 2 + w2[5], 0x15158ed)
        self.assertEqual(w2[9:11], b'\x48\xb8')
        import struct
        self.assertEqual(struct.unpack_from('<Q', w2, 11)[0], 0x5040302010006)
        self.assertEqual([so.TABLE[i] for i in range(7)], [6, 0, 1, 2, 3, 4, 5])
        self.assertEqual(w2[24:31], b'\x0f\xb6\x8f\xa0\x00\x00\x00')
        self.assertEqual(w2[31:34], b'\x80\xf9\x07')
        self.assertEqual(w2[36:42], b'\x88\x87\xa0\x00\x00\x00')

    def test_flag_windows_fields_ranges_and_remap(self):
        w3 = self.data[self.offset(0x1515900):self.offset(0x1515900) + 55]
        self.assertEqual(w3[0:4], b'\x48\x8d\x4e\xff')
        self.assertEqual(w3[6:10], b'\x48\x83\xf9\x0b')
        self.assertEqual(w3[12:16], b'\x48\x83\xfe\x0c')
        self.assertEqual(w3[16:19], b'\x0f\x44\xf0')
        # The window-3 set test reads only the low byte of the flag field.
        self.assertEqual(w3[19:23], b'\x80\x7f\x78\x00')
        self.assertEqual(w3[23], 0x74)
        self.assertEqual(0x1515900 + 23 + 2 + w3[24], 0x151592a)
        self.assertEqual(w3[42:49], b'\xc7\x47\x78\x01\x00\x00\x00')
        self.assertEqual(w3[49:52], b'\x89\x77\x7c')
        w4 = self.data[self.offset(0x1515940):self.offset(0x1515940) + 57]
        w5 = self.data[self.offset(0x1515980):self.offset(0x1515980) + 57]
        self.assertEqual(w4[3], 0x3b)
        self.assertEqual(w5[3], 0x3c)
        self.assertEqual(w4[6:8], b'\x83\xbf')
        self.assertEqual(w4[8], 0x80)
        self.assertEqual(w5[8], 0x88)
        self.assertEqual(w4[12], 0x01)
        self.assertEqual(w5[12], 0x01)
        self.assertEqual(w4[17], 0x84)
        self.assertEqual(w5[17], 0x8c)

    def test_protocol_model(self):
        self.assertEqual(so.byte_cell_path(7, 1), (8, 0))
        self.assertEqual(so.byte_cell_path(7, 7), (8, 6))
        self.assertEqual(so.byte_cell_path(2, 3), (8, None))
        self.assertEqual(so.byte_cell_path(5, 3), (1, None))
        self.assertEqual(so.byte_cell_path(7, 0), (0, None))
        self.assertEqual(so.byte_cell_path(7, 8), (0, None))
        self.assertEqual(so.table_cell_path(7, 0), (8, 6))
        self.assertEqual(so.table_cell_path(7, 1), (8, 0))
        self.assertEqual(so.table_cell_path(1, 2), (8, None))
        self.assertEqual(so.table_cell_path(3, 2), (1, None))
        self.assertEqual(so.table_cell_path(7, 7), (0, None))
        remap12 = lambda v: 0 if v == 12 else v
        self.assertEqual(so.flag_cell_path(False, 0, 12, 1, 12, remap12), (8, 0))
        self.assertEqual(so.flag_cell_path(False, 0, 13, 1, 12, remap12), (0, None))
        self.assertEqual(so.flag_cell_path(True, 5, 5, 0, 59), (8, None))
        self.assertEqual(so.flag_cell_path(True, 6, 5, 0, 59), (1, None))
        self.assertEqual(so.flag_cell_path(False, 0, 60, 0, 59), (0, None))
        self.assertEqual(so.flag_cell_path(False, 0, 60, 0, 60), (8, 60))

    def test_mutation_table_byte_fails(self):
        with self.assertRaises(ValueError):
            so.analyze(self.mutated(0x15158c0 + 11, b'\x07'))

    def test_mutation_sentinel_compare_fails(self):
        with self.assertRaises(ValueError):
            so.analyze(self.mutated(0x1515880 + 17, b'\x06'))

    def test_mutation_range_immediate_fails(self):
        with self.assertRaises(ValueError):
            so.analyze(self.mutated(0x1515940 + 3, b'\x3a'))

    def test_mutation_flag_compare_fails(self):
        with self.assertRaises(ValueError):
            so.analyze(self.mutated(0x1515940 + 12, b'\x02'))

    def test_mutation_store_opcode_fails(self):
        with self.assertRaises(ValueError):
            so.analyze(self.mutated(0x1515940 + 38, b'\xc6'))

    def test_mutation_padding_fails(self):
        with self.assertRaises(ValueError):
            so.analyze(self.mutated(0x15158b2, b'\x90'))

    def test_mutation_fde_range_fails(self):
        # FDE record for window 1 lives in .eh_frame; its range field is at
        # record offset 12.
        with self.assertRaises(ValueError):
            so.analyze(self.mutated(0xce1518 + 0x14454 + 12, b'\x31'))


if __name__ == '__main__':
    unittest.main()
