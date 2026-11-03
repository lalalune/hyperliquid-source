import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))

from sorted_set_read_side_static import (
    PACKET,
    PacketError,
    TARGET,
    analyze,
    authenticate,
    generate,
)
from elf_index import sections


def file_offset(data, va):
    for section in sections(data):
        if (section['type'] != 8 and section['address'] <= va
                < section['address'] + section['size']):
            return section['offset'] + va - section['address']
    raise AssertionError(f'VA not mapped: {va:#x}')


class SortedSetReadSideStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not TARGET.exists():
            raise unittest.SkipTest('node 115 target is not materialized')
        cls.data = TARGET.read_bytes()
        authenticate(cls.data)
        cls.report = analyze(cls.data, TARGET)

    def test_native_regeneration_matches_retained_packet(self):
        retained = json.loads((PACKET / 'records.json').read_text())
        self.assertEqual(
            self.report,
            {key: value for key, value in retained.items()
             if key != 'source_exports'},
        )
        self.assertEqual(self.report['owners']['find']['size'], 123)
        self.assertEqual(self.report['owners']['contains']['size'], 169)
        self.assertEqual(self.report['owners']['remove']['size'], 273)
        self.assertEqual(
            self.report['owners']['consumer_a']['size'], 1171)
        self.assertEqual(
            self.report['owners']['consumer_b']['size'], 3173)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'packet'
            generated = generate(TARGET, output)
            self.assertEqual(generated, retained)
            for name, entry in retained['source_exports'].items():
                text = (output / entry['full_body']['file']).read_text()
                retained_text = (
                    PACKET / entry['full_body']['file']).read_text()
                self.assertEqual(text, retained_text)

    def test_census_facts(self):
        counters = self.report['counters']
        self.assertEqual(counters, {
            'find_call_sites': 7,
            'find_family_fdes': 3,
            'contains_call_sites': 2,
            'remove_call_sites': 4,
            'remove_clone_call_sites': 8,
            'node_remove_helper_call_sites': 4,
            'forward_2_call_sites': 6,
            'consumer_a_call_sites': 2,
            'consumer_b_call_sites': 1,
            'walk_signature_fdes': 126,
            'small_reader_fdes': 16,
            'find_result_tests': 7,
        })
        self.assertEqual(self.report['hash_families'], {
            'find': ['0x243ca40', '0x39007b0', '0x51d1a80'],
            'contains': ['0x243d260'],
            'cursor_search': ['0x1d65920', '0x35bdd20'],
        })
        sites = self.report['call_sites']
        self.assertEqual(sites['0x51d5010'], {
            '0x58e1d31': '0x58e1400', '0x58e2871': '0x58e1f40',
            '0x58e3440': '0x58e2a80', '0x58e4080': '0x58e36c0',
        })
        self.assertEqual(sites['0x243d260'], {
            '0x23eeb94': '0x23ebea0', '0x23f3c25': '0x23f0a80',
        })
        self.assertEqual(self.report['rela_slots']['owners_with_slots'],
                         [])
        self.assertEqual(self.report['rela_slots']['free_slot'],
                         '0x64df4a0')
        self.assertEqual(self.report['rela_slots']['free_target'],
                         '0x635de30')

    def test_find_result_tests(self):
        self.assertEqual(self.report['find_result_tests'], {
            '0x5392879': '0x539287e', '0x539d699': '0x539d69e',
            '0x55af04d': '0x55af055', '0x55b4d4d': '0x55b4d55',
            '0x28d37b2': '0x28d37b7', '0x2c49c8d': '0x2c49c95',
            '0x3c0984a': '0x3c0984f',
        })

    def test_owner_pins_present(self):
        find_pins = self.report['owners']['find']['pins']
        self.assertEqual(find_pins['0x51d1af0'], '4883c164')
        self.assertEqual(find_pins['0x51d1a91'], '440fb74162')
        contains_pins = self.report['owners']['contains']['pins']
        self.assertEqual(contains_pins['0x243d2d0'], 'b001')
        remove_pins = self.report['owners']['remove']['pins']
        self.assertEqual(remove_pins['0x51d50ad'], '48ff4b10')
        self.assertEqual(
            self.report['owners']['remove']['calls'],
            {'0x51d50a8': '0x4d2fe70'})
        consumer_b_pins = self.report['owners']['consumer_b']['pins']
        self.assertEqual(consumer_b_pins['0x23e542c'], '4d8b64dc08')
        self.assertEqual(
            consumer_b_pins['0x23e5503'], '48b8c5a9622eea7a35f1')
        window = self.report['windows']['consumer_parent_a']
        self.assertEqual(window['pins']['0x23eeb87'], '4883c040')
        self.assertEqual(window['calls'], {'0x23eeb94': '0x243d260'})

    def mutate_va_byte(self, va, mask=0x01):
        changed = bytearray(self.data)
        changed[file_offset(self.data, va)] ^= mask
        return bytes(changed)

    def test_counterfactuals(self):
        cases = (
            # find's count-word displacement (0x62 -> 0x63).
            (0x51D1A95, 'find pin bytes changed at 0x51d1a91'),
            # contains' found exit (mov $0x1,%al -> mov $0x0,%al).
            (0x243D2D1, 'contains pin bytes changed at 0x243d2d0'),
            # consumer_b's member-key load displacement.
            (0x23E5430, 'consumer_b pin bytes changed at 0x23e542c'),
            # remove's helper call displacement (the call bytes
            # are themselves pinned, so the pin reports first).
            (0x51D50A9, 'remove pin bytes changed at 0x51d50a8'),
            # the parent window's +0x40 handle displacement: the
            # window lives inside the parent's digest-pinned body,
            # so the boundary digest reports first.
            (0x23EEB8A, 'Boundary body hash changed: consumer_parent_a'),
            # an uncited byte inside forward_2's digest-pinned body.
            (0x51D1B10, 'Boundary body hash changed: forward_2'),
            # a find call site's displacement: the site is lost.
            (0x539287B, 'Call sites changed for 0x51d1a80'),
            # a find result test byte (test %rax,%rax).
            (0x539287F, 'Result test bytes changed at 0x539287e'),
            # an uncited byte inside the cursor search body: the
            # boundary digest reports before the family census.
            (0x1D65930, 'Boundary body hash changed: cursor_search_a'),
        )
        for va, message in cases:
            with self.subTest(va=hex(va)):
                with self.assertRaisesRegex(PacketError, message):
                    analyze(self.mutate_va_byte(va), TARGET)


if __name__ == '__main__':
    unittest.main()
