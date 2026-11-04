import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))

from variant_cursor_static import (
    ARTIFACT,
    PACKET_DIR,
    PacketError,
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


class VariantCursorStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not ARTIFACT.exists():
            raise unittest.SkipTest('node 115 target is not materialized')
        cls.data = ARTIFACT.read_bytes()
        authenticate(cls.data)
        cls.report = analyze(cls.data, ARTIFACT)

    def test_native_regeneration_matches_retained_packet(self):
        retained = json.loads((PACKET_DIR / 'records.json').read_text())
        self.assertEqual(
            self.report,
            {key: value for key, value in retained.items()
             if key != 'source_exports'},
        )
        self.assertEqual(
            self.report['owners']['variant_search_a']['size'], 146)
        self.assertEqual(
            self.report['owners']['variant_search_b']['size'], 146)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'packet'
            generated = generate(ARTIFACT, output)
            self.assertEqual(generated, retained)
            self.assertEqual(
                (output / 'frames.txt').read_text(),
                (PACKET_DIR / 'frames.txt').read_text())
            for name, entry in retained['source_exports'].items():
                text = (output / entry['full_body']['file']).read_text()
                retained_text = (
                    PACKET_DIR / entry['full_body']['file']).read_text()
                self.assertEqual(text, retained_text)

    def test_census_facts(self):
        self.assertEqual(self.report['counters'], {
            'variant_search_a_call_sites': 8,
            'variant_search_b_call_sites': 18,
            'variant_search_call_sites': 26,
            'variant_caller_fdes': 18,
            'caller_windows': 38,
            'flag_test_sites': 23,
            'deferred_flag_sites': 3,
            'node_position_sites': 18,
            'flag_only_sites': 5,
            'family_standalone_bodies': 13,
            'family_distinct_bodies': 11,
            'family_inlined_instances': 1,
            'height_never_read_callers': 10,
            'height_scalar_read_callers': 2,
            'height_vector_copy_callers': 3,
            'height_other_phase_callers': 3,
        })
        sites = self.report['call_sites']
        self.assertEqual(len(sites['variant_search_a']), 8)
        self.assertEqual(len(sites['variant_search_b']), 18)
        self.assertEqual(
            sites['variant_search_a']['0x2379742'], '0x23795c0')
        self.assertEqual(
            sites['variant_search_a']['0x23799c0'], '0x23795c0')
        self.assertEqual(
            sites['variant_search_b']['0x2667ac0'], '0x2667140')
        self.assertEqual(
            sites['variant_search_b']['0x55f942a'], '0x55f9290')
        self.assertEqual(self.report['tail_call_sites'], {})
        self.assertEqual(self.report['rela_slots'], [])
        members = self.report['family']['members']
        self.assertEqual(len(members), 13)
        self.assertEqual(
            len({m['sha256'] for m in members}), 11)
        by_name = {m['name']: m for m in members}
        self.assertEqual(
            by_name['family_0x35bd660']['key_capacity'], 22)
        self.assertEqual(
            by_name['family_0x35bd800']['keys_base'], '0x168')
        self.assertEqual(
            by_name['family_0x1d65b20']['direct_call_sites'],
            by_name['family_0x4d380a0']['direct_call_sites'])
        self.assertEqual(
            self.report['family']['inlined_instances'][0]['fde'],
            ['0x4d38c10', '0x4d38e67'])

    def test_flag_tests_and_slot_reads(self):
        self.assertEqual(len(self.report['flag_tests']), 23)
        self.assertEqual(
            self.report['flag_tests']['0x2c50127'], '0x2c5012c')
        self.assertEqual(
            self.report['flag_tests']['0x2667ac0'], '0x2667ac5')
        self.assertEqual(self.report['deferred_flag_sites'], {
            '0x2a89849': '0x2a89910',
            '0x55a0b29': '0x55a0bf0',
            '0x55a1629': '0x55a16f0',
        })
        slots = self.report['slot_reads']
        # The variant record slots of the cursor-search packet's
        # caller A keep exactly the read census that packet retained.
        self.assertEqual(slots['caller_0x23795c0']['0x68'], [
            '0x237964d', '0x2379747', '0x23798f2', '0x23799c5'])
        self.assertEqual(slots['caller_0x23795c0']['0x70'],
                         ['0x237974e', '0x23799cc'])
        self.assertEqual(slots['caller_0x23795c0']['0x78'], [])
        self.assertEqual(slots['caller_0x23795c0']['0x80'],
                         ['0x2379753', '0x23799d1'])
        self.assertEqual(slots['caller_0x2667140']['0x150'], [])
        # No instruction anywhere in the 2816-byte caller reads the
        # height slot, even though its joins read the sibling's
        # flag/node/position from the same record address.
        self.assertEqual(slots['caller_0x2a89500']['0x90'], [])
        # The two scalar height consumers.
        self.assertEqual(slots['caller_0x3d987f0']['0x40'],
                         ['0x3d989b0'])
        self.assertEqual(slots['caller_0x2a918f0']['0x140'],
                         ['0x2a92201'])

    def test_owner_pins_present(self):
        pins_a = self.report['owners']['variant_search_a']['pins']
        pins_b = self.report['owners']['variant_search_b']['pins']
        self.assertEqual(pins_a['0x35bd666'], '440fb786ba000000')
        self.assertEqual(pins_a['0x35bd6cc'], '488bb4fec0000000')
        self.assertEqual(pins_b['0x35bd806'], '440fb786c2010000')
        self.assertEqual(pins_b['0x35bd86c'], '488bb4fec8010000')
        self.assertEqual(
            self.report['owners']['variant_search_a']['layout'], {
                'key_kind': 'u64', 'keys_base': '0x8',
                'key_capacity': 22, 'child_index_offset': '0xb8',
                'count_offset': '0xba', 'edges_base': '0xc0',
            })
        window = self.report['windows']['caller_0x2a89500_join_overwrite']
        self.assertEqual(window['calls'], {'0x2a89910': '0x35bf460'})
        self.assertEqual(
            window['pins']['0x2a8991f'],
            '4869bc2498000000b0000000')

    def mutate_va_byte(self, va, mask=0x01):
        changed = bytearray(self.data)
        changed[file_offset(self.data, va)] ^= mask
        return bytes(changed)

    def test_counterfactuals(self):
        cases = (
            # variant A's count-word displacement (0xba -> 0xbb).
            (0x35BD66A, 'variant_search_a pin bytes changed '
                        'at 0x35bd666'),
            # an uncited byte inside variant B's body.
            (0x35BD840, 'Owner body hash changed: variant_search_b'),
            # an uncited byte inside caller 0x2667140's body.
            (0x2667200, 'Boundary body hash changed: caller_0x2667140'),
            # a window flag-test byte inside caller 0x2c4fe30: the
            # caller's boundary digest reports first.
            (0x2C5012D, 'Boundary body hash changed: caller_0x2c4fe30'),
            # the wide family member's count-word displacement.
            (0x1D65B2A, 'family_0x1d65b20 signature pin bytes changed '
                        'at 0x1d65b26'),
            # the inlined instance's epilogue store byte.
            (0x4D38E48, 'cursor family census changed'),
        )
        for va, message in cases:
            with self.subTest(va=hex(va)):
                with self.assertRaisesRegex(PacketError, message):
                    analyze(self.mutate_va_byte(va), ARTIFACT)

    def test_rejects_wrong_artifact(self):
        with self.assertRaisesRegex(
                PacketError, 'Node 115 artifact hash mismatch'):
            authenticate(self.data[:-1])


if __name__ == '__main__':
    unittest.main()
