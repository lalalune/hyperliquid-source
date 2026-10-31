"""Target-grounded controls for the static crossroads body packet (no node execution)."""
import json
import struct
import sys
import unittest
import unittest.mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import crossroads_body_static as cb
from elf_index import sections


class CrossroadsBodyEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not cb.TARGET.is_file() or cb.TARGET.stat().st_size != 91774280:
            raise unittest.SkipTest('Requires materialized node #94 Git LFS input')
        cls.result = cb.inspect(cb.TARGET)
        cls.data = cb.TARGET.read_bytes()
        cls.sections = sections(cls.data)

    def test_retained_record_matches_authenticated_target(self):
        record = cb.ROOT / 'research/work-items/RE-001-crossroads-body-94/evidence.json'
        self.assertEqual(self.result, json.loads(record.read_text()))

    def test_call_site_targets(self):
        sites = self.result['call_sites']
        self.assertEqual(len(sites), 13)
        by_target = {int(s['target'], 16): s for s in sites}
        # The four crossroads callees from earlier packets are present.
        for target, offset in [(0x1450a60, '0xc12'), (0x15206e0, '0x253'),
                               (0x151f870, '0x2b0'), (0x4ee3b20, '0xeec')]:
            self.assertIn(target, by_target)
            self.assertEqual(by_target[target]['offset'], offset)

    def test_panic_locations_shared(self):
        locations = self.result['panic_locations']
        self.assertEqual((locations[0]['file'], locations[0]['line']),
                         ('std/src/sync/once.rs', 219))
        self.assertEqual((locations[1]['file'], locations[1]['line']),
                         ('chrono-0.4.38/src/naive/datetime/mod.rs', 1631))

    def test_census_three_direct_callers_one_parent(self):
        census = self.result['call_census']
        self.assertEqual(census['direct_e8'], 3)
        self.assertEqual(census['got_indirect'], 0)
        self.assertEqual(census['lea_refs'], 0)
        self.assertEqual(census['caller_fde'], '0x44adfa0..0x44b303a (one parent body)')
        for site in cb.CALLERS:
            self.assertTrue(cb.CALLER_FN[0] <= site < cb.CALLER_FN[1])

    def test_body_size(self):
        self.assertEqual(self.result['crossroads']['bytes'], 4027)

    def test_mutation_control_body(self):
        mutated = bytearray(cb.BODY)
        mutated[len(mutated) // 2] ^= 0xFF
        with unittest.mock.patch.object(cb, 'BODY', bytes(mutated)):
            with self.assertRaises(ValueError):
                cb.analyze(self.data)

    def test_mutation_control_call_site(self):
        # Flip a byte of the datediff wrapper call site in the raw image.
        matches = [s for s in self.sections if s['type'] != 8
                   and s['address'] <= cb.START < s['address'] + s['size']]
        s = matches[0]
        off = s['offset'] + cb.START + 0xc12 - s['address']
        data = bytearray(self.data)
        data[off + 5] ^= 0x01
        with self.assertRaises(ValueError):
            cb.analyze(bytes(data))


if __name__ == '__main__':
    unittest.main()
