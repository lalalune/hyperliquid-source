import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from lu_lazylock_consumers import (ACCESSOR, INIT_FN, PACKET, SHA,
                                   SIZE, TARGET, analyze, generate)

# Body pins retained by PR #2999 (lu LazyLock value packet); this
# packet must not contradict them.
PR2999_ACCESSOR_SHA = '4dd07ff0fab8b3133d896254e0fecef4f983867a' \
                      '311629f10ccedb52d03ac6bc'
PR2999_INIT_SHA = 'c87c9590e5ab4cebd4a7110f74eda4a33237fac3843' \
                  '105dab89bc132924ac41c'


class LuLazyLockConsumersTest(unittest.TestCase):
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

    def test_no_contradiction_with_pr_2999(self):
        self.assertEqual(self.payload['accessor']['sha256'],
                         PR2999_ACCESSOR_SHA)
        self.assertEqual(self.payload['initializer']['sha256'],
                         PR2999_INIT_SHA)
        self.assertEqual(self.payload['accessor']['start'],
                         hex(ACCESSOR[0]))
        self.assertEqual(self.payload['initializer']['start'],
                         hex(INIT_FN[0]))

    def test_census(self):
        census = self.payload['census']
        self.assertEqual(census['call_sites'], 100)
        self.assertEqual(census['consumer_bodies'], 65)
        self.assertEqual(census['direct_e8_sites'], 0)
        self.assertEqual(census['slot_load_sites'], 0)
        self.assertEqual(census['jmp_sites'], 0)
        sites = [s for c in self.payload['consumers']
                 for s in c['sites']]
        self.assertEqual(len(sites), 100)
        self.assertEqual(len({s['site'] for s in sites}), 100)

    def test_pair_is_never_read_as_data(self):
        fate = self.payload['fate']
        self.assertEqual(fate['sites_where_pair_is_read_as_data'],
                         0)
        self.assertEqual(fate['sites_where_pair_is_discarded'],
                         100)

    def test_context_classification(self):
        self.assertEqual(self.payload['context_counts'],
                         {'drop_glue': 38, 'statement': 54,
                          'err_exit': 6, 'cleanup_block': 2})
        legend = self.payload['context_legend']
        for c in self.payload['consumers']:
            for s in c['sites']:
                self.assertIn(s['context'], legend)

    def test_value_is_build_mode_string(self):
        value = self.payload['initializer_value']
        locs = value['source_locations']
        self.assertEqual(
            [(l['file'], l['line'], l['column']) for l in locs],
            [('base/src/build_mode.rs', 28, 13),
             ('base/src/build_mode.rs', 30, 26)])
        self.assertEqual(
            [l['text'] for l in value['literal_block']],
            ['/cham/', "assertion failed: !arg.ends_with('/')",
             'debug', 'release', 'run-client'])
        transform = value['transform_fn']
        self.assertEqual(transform['start'], '0x150caf0')
        self.assertEqual(transform['end'], '0x150cd87')

    def test_ensure_blocks_pass_only_the_address(self):
        total = sum(c['ensure_blocks_in_body']
                    for c in self.payload['consumers'])
        bodies = sum(1 for c in self.payload['consumers']
                     if c['ensure_blocks_in_body'])
        self.assertEqual(total, 32)
        self.assertEqual(bodies, 19)

    def test_packet_regeneration(self):
        for name in ('records.json', 'accessor.objdump.txt',
                     'init_fn.objdump.txt', 'consumer-windows.txt',
                     'frames.txt', 'MANIFEST.sha256'):
            self.assertEqual((self.regen_dir / name).read_bytes(),
                             (PACKET / name).read_bytes(), name)

    def test_mutation_control_accessor_load(self):
        data = bytearray(self.data)
        # corrupt the accessor's +8 load displacement
        from lu_lazylock_consumers import offset_of, sections
        off = offset_of(self.data, sections(self.data), 0x1560a4a)
        data[off + 3] ^= 0xff
        with self.assertRaises(AssertionError):
            analyze(bytes(data))

    def test_mutation_control_census_site(self):
        data = bytearray(self.data)
        from lu_lazylock_consumers import offset_of, sections
        # corrupt one call site's slot displacement
        site = int(self.payload['consumers'][0]['sites'][0]
                   ['site'], 16)
        off = offset_of(self.data, sections(self.data), site)
        data[off + 2] ^= 0xff
        with self.assertRaises(AssertionError):
            analyze(bytes(data))


if __name__ == '__main__':
    unittest.main()
