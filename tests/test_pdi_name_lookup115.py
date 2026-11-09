import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools import pdi_name_lookup115 as m

PACKET = (Path(__file__).resolve().parents[1] / 'research' / 'work-items'
          / 'RE-007-node115-asset-name-lookup-evaluation')
GENERATED = ('function-rows.tsv', 'call-sites.tsv', 'constants.tsv',
             'outcomes.tsv', 'sweep-outcomes.tsv', 'controls.tsv',
             'evidence.json', 'measure.json')


class PdiNameLookupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = m.TARGET.read_bytes()
        cls.secs = m.sections(cls.data)
        off = m.va_to_offset(cls.secs, m.BODY_START)
        cls.body = cls.data[off:off + (m.BODY_END - m.BODY_START)]
        cls.roles = m.slot_targets(cls.data, cls.secs)
        cls.insns = m.decode_body(cls.body)

    def test_target_and_body_digests(self):
        self.assertEqual(len(self.data), m.TARGET_SIZE)
        self.assertEqual(m.sha256(self.data), m.TARGET_SHA256)
        self.assertEqual(m.sha256(self.body), m.BODY_SHA256)

    def test_wrong_digest_is_refused_before_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bad = root / 'bad.bin'
            bad.write_bytes(b'not the node')
            out = root / 'evidence'
            with patch.object(m, 'TARGET', bad):
                with self.assertRaises(SystemExit):
                    self._run_main(out)
            self.assertFalse(out.exists())

    def _run_main(self, out):
        import sys
        with patch.object(sys, 'argv',
                          ['pdi_name_lookup115.py', '--out', str(out)]):
            return m.main()

    def test_decode_lands_on_fde_end(self):
        self.assertEqual(len(self.insns), 78)
        last = self.insns[-1]
        self.assertEqual(last.va + last.size, m.BODY_END)

    def test_decode_fails_closed_on_unknown_opcode(self):
        mutant = bytearray(self.body)
        mutant[0] = 0xEA  # not an encoding the body uses
        with self.assertRaises(m.DecodeError):
            m.decode_body(bytes(mutant))

    def test_decode_from_non_fde_start_fails(self):
        with self.assertRaises(m.DecodeError):
            m.decode_body(self.body, m.BODY_START + 1, m.BODY_END)

    def test_lookup_slot_relocation(self):
        rel = m.relocations(self.data, self.secs)
        self.assertEqual(rel[m.LOOKUP_SLOT], ('relative', m.BODY_START))

    def test_rule_hit_and_miss(self):
        fx = m.Fixture([(b'ABC', 3), (b'DEF', 3)], b'DEF', page=7)
        outcome = m.outcome_of(m.run_rule(fx))
        self.assertEqual(outcome, ('ok', 7 * 10_000 + 1))
        fx = m.Fixture([(b'ABC', 3)], b'ABD', page=0)
        outcome = m.outcome_of(m.run_rule(fx))
        self.assertEqual(outcome, ('err', 3, m.HEAP_VA, 3))

    def test_rule_zero_length_bcmp_always_equal(self):
        fx = m.Fixture([(b'ABC', 0)], b'', page=0)
        self.assertEqual(m.outcome_of(m.run_rule(fx)), ('ok', 0))

    def test_rule_empty_miss_allocates_nothing(self):
        fx = m.Fixture([(b'ABC', 3)], b'', page=0)
        outcome = m.outcome_of(m.run_rule(fx))
        self.assertEqual(outcome, ('err', 0, 1, 0))

    def test_rule_index_wrap_guard(self):
        records = [(b'R%04d' % i, 5) for i in range(1617)]
        fx = m.Fixture(records, b'R1616', page=m.PAGE_MAX)
        outcome = m.outcome_of(m.run_rule(fx))
        self.assertEqual(outcome, ('trap', 'panic_add', (m.LOCATION_VA,)))
        fx = m.Fixture(records, b'R1615', page=m.PAGE_MAX)
        outcome = m.outcome_of(m.run_rule(fx))
        self.assertEqual(outcome, ('ok', 2**64 - 1))

    def test_named_cases_all_match(self):
        for name, fx in m.named_cases():
            match, got, want = m.run_case(self.insns, fx, self.roles)
            self.assertTrue(match, f'{name}: evaluator {got} != rule {want}')

    def test_sweep_sample_matches(self):
        for fx in m.sweep_cases(200, seed=99):
            match, got, want = m.run_case(self.insns, fx, self.roles)
            self.assertTrue(match, f'evaluator {got} != rule {want}')

    def test_regeneration_matches_committed_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / 'packet'
            with patch('sys.argv',
                       ['pdi_name_lookup115.py', '--out', str(out)]):
                self.assertEqual(m.main(), 0)
            for name in GENERATED:
                self.assertEqual((out / name).read_bytes(),
                                 (PACKET / name).read_bytes(),
                                 f'{name} differs from committed evidence')

    def test_manifest(self):
        manifest = (PACKET / 'MANIFEST.sha256').read_text().splitlines()
        self.assertTrue(manifest)
        for line in manifest:
            digest, name = line.split('  ', 1)
            payload = (PACKET / name).read_bytes()
            self.assertEqual(hashlib.sha256(payload).hexdigest(), digest,
                             f'MANIFEST entry for {name} does not verify')


if __name__ == '__main__':
    unittest.main()
