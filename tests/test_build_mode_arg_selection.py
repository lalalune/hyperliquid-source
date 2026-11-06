import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import build_mode_arg_selection as bm
from build_mode_arg_selection import PACKET, SHA, SIZE, TARGET, analyze, generate

# Body pins retained by PR #2999 (lu LazyLock value packet) and the
# H11 packet (branch h11/lazylock-consumers); this packet re-derives
# the overlapping bodies and must not contradict them.
PR2999_ACCESSOR_SHA = '4dd07ff0fab8b3133d896254e0fecef4f983867a' \
                      '311629f10ccedb52d03ac6bc'
PR2999_INIT_SHA = 'c87c9590e5ab4cebd4a7110f74eda4a33237fac3843' \
                  '105dab89bc132924ac41c'
PR2999_TRANSFORM_SHA = '85a51029abee0fc7b2eeb3656db65feb440ea5a193' \
                       'c9687c990316cc75f78e5f'


def va_offset(data, va):
    for s in bm.sections(data):
        if (s['type'] != 8 and s['address'] <= va
                < s['address'] + s['size']):
            return s['offset'] + (va - s['address'])
    raise AssertionError(f'va {va:#x} not file-backed')


class BuildModeArgSelectionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not TARGET.exists() or TARGET.stat().st_size != SIZE:
            raise unittest.SkipTest('pinned node115 target is not '
                                    'materialised')
        cls.data = TARGET.read_bytes()
        if hashlib.sha256(cls.data).hexdigest() != SHA:
            raise unittest.SkipTest('target digest is not the '
                                    'pinned node115 distribution')
        cls.retained = json.loads(
            (PACKET / 'records.json').read_text())
        cls.payload = analyze(cls.data)
        cls.regen_dir = Path(tempfile.mkdtemp())
        generate(TARGET, cls.regen_dir)

    def test_records_match_artifact(self):
        self.assertEqual(self.payload, self.retained)

    def test_regeneration_byte_identical(self):
        for path in sorted(PACKET.iterdir()):
            if path.name == 'README.md':
                continue
            self.assertEqual(
                (self.regen_dir / path.name).read_bytes(),
                path.read_bytes(), path.name)

    def test_no_contradiction_with_prior_packets(self):
        bodies = self.payload['bodies']
        self.assertEqual(bodies['initializer']['sha256'],
                         PR2999_INIT_SHA)
        self.assertEqual(bodies['accessor']['sha256'],
                         PR2999_ACCESSOR_SHA)
        self.assertEqual(bodies['transform']['sha256'],
                         PR2999_TRANSFORM_SHA)
        locs = self.payload['locations']
        self.assertEqual(locs['build_mode_line28']['line'], 28)
        self.assertEqual(locs['build_mode_line28']['column'], 13)
        self.assertEqual(locs['build_mode_line30']['line'], 30)
        self.assertEqual(locs['build_mode_line30']['column'], 26)

    def test_iteration_is_std_env_args(self):
        slots = self.payload['slots']
        self.assertEqual(slots['args_ctor']['target'], '0x5c9a530')
        self.assertEqual(slots['args_next']['target'], '0x5caa830')
        loc = self.payload['locations']['env_args_unwrap']
        self.assertTrue(loc['file'].endswith(
            '/library/std/src/env.rs'))
        self.assertEqual((loc['line'], loc['column']), (864, 51))
        self.assertEqual(self.payload['messages']['args_unwrap']
                         ['text'],
                         'called `Result::unwrap()` on an `Err` value')

    def test_packed_formats(self):
        packed = self.payload['packed_formats']
        self.assertEqual(packed['init_merge']['decoded'], '{0} {1}')
        self.assertEqual(packed['enum_join']['decoded'], '{0}/{1}')
        self.assertEqual(packed['enum_aws_build']['decoded'],
                         '{0}/aws_build/{1}')

    def test_literal_census(self):
        census = self.payload['literal_ref_census']
        # "/cham/" itself is never loaded by a RIP-relative reference;
        # the contains path references its tail ("cham/", length 5)
        # exactly once, from the initializer.
        self.assertEqual(census['0x4676f2']['count'], 0)
        self.assertEqual(census['0x4676f3']['count'], 1)
        self.assertEqual(census['0x4676f3']['disp_field_vas'],
                         ['0x1568fc8'])
        # Each candidate literal is loaded exactly once, and never
        # by the initializer: debug/release in the neighbouring enum
        # body, run-client as a key in its own body.
        self.assertEqual(census['0x46771d']['disp_field_vas'],
                         ['0x15648f5'])
        self.assertEqual(census['0x467722']['disp_field_vas'],
                         ['0x15648d3'])
        self.assertEqual(census['0x467729']['disp_field_vas'],
                         ['0x155f93a'])

    def test_simulation_vectors(self):
        for vec in self.payload['simulation_vectors']:
            self.assertEqual(
                bm.build_mode_value(list(vec['argv'])), vec['value'],
                vec['argv'])
        # The stored value is never exactly one of the candidates:
        # it carries a leading space whenever anything contributed,
        # and run-client loses its tail at the last '-'.
        values = {tuple(v['argv']): v['value']
                  for v in self.payload['simulation_vectors']}
        self.assertEqual(values[('/opt/hl/cham/run-client',)], ' run')
        self.assertEqual(values[('/opt/hl/cham/release',)], ' release')
        for value in values.values():
            if value.startswith('panic:'):
                continue
            self.assertNotIn(value,
                             ('debug', 'release', 'run-client'))

    def _mutated_analyze(self, va, xor):
        data = bytearray(self.data)
        off = va_offset(bytes(data), va)
        data[off] ^= xor
        data = bytes(data)
        # Point the digest gate at the mutated copy so the failure
        # must come from the pin / literal / decode layer itself.
        saved = bm.SHA
        bm.SHA = hashlib.sha256(data).hexdigest()
        try:
            with self.assertRaises(ValueError):
                analyze(data)
        finally:
            bm.SHA = saved

    def test_mutation_packed_format_space(self):
        # The literal chunk byte of "{0} {1}" at 0x444a46: flipping
        # the space changes the decoded merge format.
        self._mutated_analyze(0x444a46, 0x01)

    def test_mutation_flag_prefix_immediate(self):
        # One byte of the "--" immediate in the prefix dispatch at
        # 0x1568f40 breaks the byte pin.
        self._mutated_analyze(0x1568f41, 0x03)

    def test_mutation_candidate_literal(self):
        # One byte of the "run-client" literal breaks the literal
        # decode.
        self._mutated_analyze(0x467729, 0x01)


if __name__ == '__main__':
    unittest.main()
