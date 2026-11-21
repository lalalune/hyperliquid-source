import tempfile
import unittest
from pathlib import Path

from tools.link_staking_action_decode_115 import DIGEST, TARGET, generate, parse


class LinkStakingActionDecode115Tests(unittest.TestCase):
    def test_index_11_reaches_link_staking_variant(self):
        summary, rows = parse(TARGET)
        self.assertEqual(summary['binary_sha256'], DIGEST)
        self.assertEqual(summary['decoder_fde'], ['0x2bd6140', '0x2bd8476'])
        self.assertEqual(summary['dispatch_arm_va'], '0x2bd6d56')
        self.assertEqual(summary['table_entry_bytes_hex'], '36d15c02')
        self.assertEqual(summary['table_entry_signed_rel32'], 39637302)
        self.assertEqual(summary['dispatch_sequence_bytes_hex'], '488d0dde39a3fd486304814801c8ffe0')
        self.assertEqual(summary['variant_name'], 'LinkStakingUserAction')
        self.assertEqual(summary['result_internal_tag'], '0x91')
        self.assertEqual(summary['field_count_argument'], 5)
        self.assertTrue(summary['arm_bytes_hex'].endswith('b891000000e9bb150000'))
        self.assertEqual(len(rows), 10)

    def test_generation_is_deterministic(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            generate(TARGET, out)
            before = {p.name: p.read_bytes() for p in out.iterdir()}
            generate(TARGET, out)
            after = {p.name: p.read_bytes() for p in out.iterdir()}
            self.assertEqual(before, after)

    def test_wrong_digest_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / 'wrong.bin'
            bad.write_bytes(TARGET.read_bytes() + b'changed')
            with self.assertRaisesRegex(ValueError, 'wrong node #115 digest'):
                parse(bad)


if __name__ == '__main__':
    unittest.main()
