import tempfile
import unittest
from pathlib import Path

from tools.action_wire_variant_methods_115 import DIGEST, TARGET, generate, load


class VariantMethods115Tests(unittest.TestCase):
    def test_inventory_is_digest_bound_and_complete(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = generate(TARGET, Path(tmp))
            self.assertEqual(result['binary_sha256'], DIGEST)
            self.assertEqual(result['entries'], 92)
            self.assertEqual(result['unique_targets'], 92)
            self.assertEqual(result['indirect_call_arms'], 20)
            self.assertEqual(result['zero_byte_local_prefix_arms'], 72)
            self.assertEqual(result['other_prefix_arms'], 0)
            lines = (Path(tmp) / 'arms.tsv').read_text().splitlines()
            self.assertEqual(len(lines), 93)

    def test_wrong_digest_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'wrong.bin'
            path.write_bytes(TARGET.read_bytes() + b'changed')
            with self.assertRaisesRegex(ValueError, 'wrong node #115 digest'):
                load(path)


if __name__ == '__main__':
    unittest.main()
