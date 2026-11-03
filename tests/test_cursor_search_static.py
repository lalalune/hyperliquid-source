import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))

from cursor_search_static import (
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


class CursorSearchStaticTests(unittest.TestCase):
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
        self.assertEqual(
            self.report['owners']['cursor_search_a']['size'], 143)
        self.assertEqual(
            self.report['owners']['cursor_search_b']['size'], 143)
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
        self.assertEqual(self.report['counters'], {
            'cursor_search_a_call_sites': 2,
            'cursor_search_b_call_sites': 1,
            'cursor_search_call_sites': 3,
            'variant_search_call_sites': 26,
            'variant_search_caller_sites': 3,
            'cursor_family_fdes': 2,
            'walk_signature_fdes': 126,
            'small_reader_fdes': 16,
            'flag_tests': 6,
            'variant_window_field_reads': 4,
            'clone_record_field_reads': 0,
        })
        self.assertEqual(self.report['hash_families'], {
            'cursor_search': ['0x1d65920', '0x35bdd20'],
            'variant_search_a': ['0x35bd660'],
            'variant_search_b': ['0x35bd800'],
        })
        sites = self.report['call_sites']
        self.assertEqual(sites['0x1d65920'], {
            '0x2379648': '0x23795c0', '0x23798ed': '0x23795c0',
        })
        self.assertEqual(sites['0x35bdd20'], {
            '0x2667b87': '0x2667140',
        })
        self.assertEqual(len(sites['0x35bd660']), 8)
        self.assertEqual(len(sites['0x35bd800']), 18)
        self.assertEqual(sites['0x35bd660']['0x2379742'], '0x23795c0')
        self.assertEqual(sites['0x35bd660']['0x23799c0'], '0x23795c0')
        self.assertEqual(sites['0x35bd800']['0x2667ac0'], '0x2667140')
        self.assertEqual(
            self.report['rela_slots']['owners_with_slots'], [])

    def test_flag_tests_and_slot_reads(self):
        self.assertEqual(self.report['flag_tests'], {
            '0x2379648': '0x237964d', '0x23798ed': '0x23798f2',
            '0x2667b87': '0x2667b8c', '0x2379742': '0x2379747',
            '0x23799c0': '0x23799c5', '0x2667ac0': '0x2667ac5',
        })
        slots = self.report['slot_reads']
        self.assertEqual(slots['caller_a']['0x68'], [
            '0x237964d', '0x2379747', '0x23798f2', '0x23799c5'])
        self.assertEqual(slots['caller_a']['0x70'],
                         ['0x237974e', '0x23799cc'])
        self.assertEqual(slots['caller_a']['0x78'], [])
        self.assertEqual(slots['caller_a']['0x80'],
                         ['0x2379753', '0x23799d1'])
        self.assertEqual(slots['caller_b']['0x140'],
                         ['0x2667ac5', '0x2667b8c'])
        self.assertEqual(slots['caller_b']['0x148'], [])
        self.assertEqual(slots['caller_b']['0x150'], [])
        self.assertEqual(slots['caller_b']['0x158'], [])

    def test_owner_pins_present(self):
        pins_a = self.report['owners']['cursor_search_a']['pins']
        pins_b = self.report['owners']['cursor_search_b']['pins']
        self.assertEqual(pins_a['0x1d65926'], '440fb74662')
        self.assertEqual(pins_a['0x1d65945'], '483b4cfe10')
        self.assertEqual(pins_a['0x1d659a8'], 'b901000000')
        self.assertEqual(pins_b['0x35bdd8c'], '488b74fe68')
        self.assertEqual(pins_b['0x35bdda0'], '48897818')
        window = self.report['windows']['caller_b_search']
        self.assertEqual(window['pins']['0x2667b8c'],
                         '83bc244001000001')
        self.assertEqual(window['calls'], {'0x2667b87': '0x35bdd20'})

    def mutate_va_byte(self, va, mask=0x01):
        changed = bytearray(self.data)
        changed[file_offset(self.data, va)] ^= mask
        return bytes(changed)

    def test_counterfactuals(self):
        cases = (
            # clone A's count-word displacement (0x62 -> 0x63).
            (0x1D6592A, 'cursor_search_a pin bytes changed '
                        'at 0x1d65926'),
            # an uncited byte inside clone B's body.
            (0x35BDD60, 'Owner body hash changed: cursor_search_b'),
            # caller A loop A's call displacement: the window
            # lives inside caller A's digest-pinned body, so
            # the boundary digest reports first.
            (0x2379649, 'Boundary body hash changed: caller_a'),
            # caller B's flag-test displacement byte: caller
            # B's boundary digest likewise reports first.
            (0x2667B8D, 'Boundary body hash changed: caller_b'),
            # the variant window's node-field load byte: again
            # inside caller A's digest-pinned body.
            (0x2379750, 'Boundary body hash changed: caller_a'),
            # an uncited byte inside variant A's digest-pinned
            # body.
            (0x35BD665, 'Boundary body hash changed: '
                        'variant_search_a'),
            # an uncited byte inside caller B's digest-pinned
            # body.
            (0x2667200, 'Boundary body hash changed: caller_b'),
        )
        for va, message in cases:
            with self.subTest(va=hex(va)):
                with self.assertRaisesRegex(PacketError, message):
                    analyze(self.mutate_va_byte(va), TARGET)


if __name__ == '__main__':
    unittest.main()
