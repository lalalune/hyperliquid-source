"""Node115 cache-specific control/data obligations, not an invented cache model."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import node115_gossip_cache_static as subject


class CacheStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = subject.TARGET.read_bytes()
        cls.image, cls.record = subject.core(cls.data)

    def test_four_complete115_bodies_and_fresh_source_location(self):
        self.assertEqual(sum(x['bytes'] for x in self.record['bodies']), 3168)
        self.assertEqual(len(self.record['bodies']), 4)
        self.assertEqual(self.record['location']['path'], 'node/src/gossip_rpc.rs')
        self.assertEqual((self.record['location']['line'], self.record['location']['column']), (245, 43))

    def test_both_actual_unsigned_retention_branches_agree_at_boundaries(self):
        image, data = self.image, self.data
        a, b = image.file_offset(0x5a5d7f0), image.file_offset(0x5a5d820)
        first = int.from_bytes(data[a+4:a+8], 'little')
        repeat = int.from_bytes(data[b+4:b+8], 'little')
        self.assertEqual(data[image.file_offset(0x5a5d7f8)], 0x72)  # JB
        self.assertEqual(data[image.file_offset(0x5a5d828)], 0x76)  # JBE
        for count in (0, 149999, 150000, 150001, 150002, (1 << 64)-1):
            self.assertEqual(count < first, count <= repeat)
            self.assertEqual(count >= first, count > 150000)

    def test_semantic_corruption_rejected_without_hash_shortcuts(self):
        changed = bytearray(self.data)
        changed[self.image.file_offset(0x5a5d7f0)+7] ^= 1
        with self.assertRaisesRegex(ValueError, 'instruction obligation: initial-limit'):
            subject.core(bytes(changed), identity=False, body_hashes=False)

    def test_wrong_artifact_rejected_before_parsing(self):
        with self.assertRaisesRegex(ValueError, 'target identity'):
            subject.core(b'wrong target')


if __name__ == '__main__':
    unittest.main()
