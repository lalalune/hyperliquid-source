import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

_spec = importlib.util.spec_from_file_location(
    'argument_producers_static', ROOT / 'tools' / 'argument_producers_static.py')
aps = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(aps)

PACKET = (ROOT / 'research' / 'work-items'
          / 'RE-006-node115-argument-producers')
ARTIFACT = ROOT / 'artifacts' / 'node' / '115' / 'hl-node'


def artifact_bytes():
    data = ARTIFACT.read_bytes()
    if hashlib.sha256(data).hexdigest() != aps.ARTIFACT_SHA256:
        raise unittest.SkipTest('node 115 artifact is not materialised')
    return data


class ArgumentProducersStaticTest(unittest.TestCase):
    def test_packet_regenerates_byte_for_byte(self):
        data = artifact_bytes()
        with tempfile.TemporaryDirectory() as tmp:
            aps.generate(data, tmp)
            for name in ('records.json', 'frames.txt'):
                self.assertEqual((Path(tmp) / name).read_bytes(),
                                 (PACKET / name).read_bytes(), name)
            exports = sorted(p.name for p in PACKET.glob('*_objdump.txt'))
            self.assertEqual(len(exports), 16)
            for name in exports:
                self.assertEqual((Path(tmp) / name).read_bytes(),
                                 (PACKET / name).read_bytes(), name)

    def test_analysis_counters_and_verdict_shape(self):
        data = artifact_bytes()
        with tempfile.TemporaryDirectory() as tmp:
            records = aps.generate(data, tmp)
        self.assertEqual(records['counters'], aps.EXPECTED)
        self.assertEqual(records['counters']['bodies'], 34)
        self.assertEqual(records['counters']['jc_sites'], 6)
        self.assertEqual(records['counters']['s3_sites'], 4)
        kinds = {}
        for site in records['sites']:
            kinds[site['kind']] = kinds.get(site['kind'], 0) + 1
        self.assertEqual(kinds, {
            'helper-output-record': 3,
            'incoming-argument-copy': 3,
            'inlined-record-assembly': 3,
            'helper-output-record-restage': 3,
            'helper-output-record-copy': 4})
        jc = records['boundary']['jc_e8_callers']
        self.assertEqual(
            {k: len(jc[k]) for k in ('jc1', 'jc2', 'jc3')},
            {'jc1': 2, 'jc2': 2, 'jc3': 2})
        adapters = records['boundary']['adapter_slot_callers']
        self.assertEqual(
            {k: len(v) for k, v in adapters.items()},
            {'s1': 3, 's2': 3, 'helper_s2': 3, 's3': 4})
        helpers = records['boundary']['helper_e8_callers']
        self.assertEqual(len(helpers['sublookup_ca']), 1)
        self.assertEqual(len(helpers['sublookup_jc1']), 1)
        self.assertEqual(len(helpers['helper_s3a']), 4)
        self.assertEqual(len(helpers['helper_s3b']), 4)
        self.assertEqual(records['slots']['memcpy']['symbol'], 'memcpy')
        self.assertEqual(records['slots']['s1']['rela_addend'], '0x369a3d0')
        self.assertEqual(records['slots']['s2']['rela_addend'], '0x369b650')
        self.assertEqual(records['slots']['s3']['rela_addend'], '0x3f10ac0')
        self.assertIn('one record family with many producers',
                      records['verdict'])

    def test_wrong_artifact_is_rejected_before_writing(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(aps.PacketError):
                aps.generate(b'\0' * aps.ARTIFACT_SIZE, tmp)
            self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_small_body_digest_drift_fails(self):
        data = bytearray(artifact_bytes())
        start, _end = aps.BODIES['jc1wb']['range']
        secs = aps.sections(bytes(data))
        sec = next(s for s in secs
                   if s['address'] <= start < s['address'] + s['size'])
        data[sec['offset'] + (start - sec['address']) + 7] ^= 0xFF
        with self.assertRaises(AssertionError) as ctx:
            aps.analyze(bytes(data))
        self.assertIn('jc1wb', str(ctx.exception))

    def test_big3_digest_drift_fails(self):
        data = bytearray(artifact_bytes())
        start, _end = aps.BODIES['big3']['range']
        secs = aps.sections(bytes(data))
        sec = next(s for s in secs
                   if s['address'] <= start < s['address'] + s['size'])
        data[sec['offset'] + (start - sec['address']) + 100] ^= 0xFF
        with self.assertRaises(AssertionError) as ctx:
            aps.analyze(bytes(data))
        self.assertIn('big3', str(ctx.exception))

    def test_full_pin_drift_fails(self):
        data = bytearray(artifact_bytes())
        start, _end = aps.BODIES['s2c_a']['range']
        secs = aps.sections(bytes(data))
        sec = next(s for s in secs
                   if s['address'] <= start < s['address'] + s['size'])
        off = sec['offset'] + (0x2761c90 - sec['address'])
        data[off] ^= 0xFF
        mutated = bytes(data)
        original = aps.BODIES['s2c_a']['sha256']
        aps.BODIES['s2c_a']['sha256'] = hashlib.sha256(
            aps._section_bytes(mutated, secs, start, _end)).hexdigest()
        try:
            with self.assertRaises(AssertionError) as ctx:
                aps.analyze(mutated)
            self.assertIn('s2c_a', str(ctx.exception))
        finally:
            aps.BODIES['s2c_a']['sha256'] = original

    def test_partial_pin_drift_fails(self):
        data = bytearray(artifact_bytes())
        start, end = aps.BODIES['big3']['range']
        secs = aps.sections(bytes(data))
        sec = next(s for s in secs
                   if s['address'] <= start < s['address'] + s['size'])
        off = sec['offset'] + (0x55e0313 - sec['address'])
        data[off] ^= 0xFF
        mutated = bytes(data)
        original = aps.BODIES['big3']['sha256']
        aps.BODIES['big3']['sha256'] = hashlib.sha256(
            aps._section_bytes(mutated, secs, start, end)).hexdigest()
        try:
            with self.assertRaises(AssertionError) as ctx:
                aps.analyze(mutated)
            self.assertIn('big3', str(ctx.exception))
        finally:
            aps.BODIES['big3']['sha256'] = original


if __name__ == '__main__':
    unittest.main()
