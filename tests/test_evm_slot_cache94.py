import hashlib
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import evm_slot_cache94 as subject


class SlotCacheEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = subject.checked_data()
        cls.sections = subject.sections(cls.data)
        cls.evidence = subject.generate(cls.data)

    def test_fdes_and_paired_code(self):
        self.assertEqual(len(self.evidence['functions']), 6)
        twin = self.evidence['twin_comparison']
        self.assertEqual((twin['raw_equal_positions'], twin['compared_positions']), (911, 929))
        self.assertEqual((twin['excluded_bytes'], twin['equal_outside_excluded']), (36, 893))

    def test_lookup_and_update_edges(self):
        calls = {r['site']:r['target'] for r in self.evidence['calls']}
        self.assertEqual(calls['0x32ac095'], '0x32abca0')
        self.assertEqual(calls['0x32ab9d2'], '0x37d0fb0')
        self.assertEqual(calls['0x32aba26'], '0x37d11d0')
        self.assertEqual(calls['0x32ac112'], '0x37a0e50')
        branches = {r['site']:(r['condition'],r['target']) for r in self.evidence['branches']}
        self.assertEqual(branches['0x32ab965'], ('equal','0x32aba43'))
        self.assertEqual(branches['0x32ac145'], ('equal','0x32ac24d'))
        self.assertEqual(branches['0x32ac11a'], ('equal','0x32ac2d1'))

    def test_location_and_result_windows(self):
        self.assertEqual([x['line'] for x in self.evidence['locations']], [684, 711, 734, 737, 753])
        w = {r['name']:bytes.fromhex(r['bytes']) for r in self.evidence['windows']}
        self.assertIn(bytes.fromhex('c6040807'), w['journal_tag_7'])
        self.assertIn(bytes.fromhex('c6041106'), w['journal_tag_6_and_update'])
        self.assertIn(bytes.fromhex('4188442420'), w['return_layout'])

    def test_reject_wrong_digest(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'invalid'
            path.write_bytes(b'not an ELF')
            with self.assertRaisesRegex(ValueError, 'SHA-256'):
                subject.checked_data(path)
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            subject.generate(self.data[:-1])

    def test_reject_corrupt_branch_and_call(self):
        for address, decoder in ((0x32ab965, subject.branch), (0x32ab917, subject.direct_call)):
            sec = next(s for s in self.sections if s['address'] <= address < s['address'] + s['size'])
            off = sec['offset'] + address - sec['address']
            damaged = bytearray(self.data)
            damaged[off] = 0xcc
            with self.assertRaises(ValueError):
                decoder(damaged, address, self.sections)

    def test_reject_non_file_backed_or_invalid_ranges(self):
        bss = next(s for s in self.sections if s['type'] == 8 and s['name'] == '.bss')
        for address, size in ((-1, 1), (0x32ab8f0, 0), (bss['address'], 1), (1 << 63, 1)):
            with self.assertRaises(ValueError):
                subject.read_va(self.data, address, size, self.sections)

    def test_corrupt_metadata_rejected(self):
        location = 0x56dff80
        sec = next(s for s in self.sections if s['address'] <= location < s['address'] + s['size'])
        off = sec['offset'] + location - sec['address']
        damaged = bytearray(self.data)
        damaged[off] = 1
        with self.assertRaisesRegex(ValueError, 'location record'):
            subject.metadata(damaged, self.sections)


if __name__ == '__main__':
    unittest.main()
