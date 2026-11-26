import hashlib
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import re010_display_name_wire_decode_115 as profile


class DisplayNameWireDecodeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = profile.BINARY.read_bytes()

    def test_selected_wire_name_maps_to_payload_and_tag(self):
        summary, edges, functions, windows, _, _ = profile.extract(self.data)
        self.assertEqual(summary['wire_name'], 'setDisplayName')
        self.assertEqual(summary['variant_index'], 19)
        self.assertEqual(summary['matcher_length_arm'], '0x2ba0d30')
        self.assertEqual(summary['action_arm'], '0x2b8367b')
        self.assertEqual(summary['action_type'], 'SetDisplayNameAction')
        self.assertEqual(summary['field_name'], 'displayName')
        self.assertEqual(summary['payload_helper'], '0x20647f0')
        self.assertEqual(summary['internal_tag'], '0x99')
        self.assertEqual(summary['action_output_size'], 0xf0)
        self.assertEqual(summary['action_output_pointer_register'], 'rdx')
        self.assertEqual(len(edges), 7)
        self.assertEqual(len(functions), 3)
        self.assertGreaterEqual(len(windows), 10)

    def test_output_is_deterministic_and_manifested(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            profile.generate(profile.BINARY, root / 'a')
            profile.generate(profile.BINARY, root / 'b')
            a, b = root / 'a', root / 'b'
            names = sorted(p.name for p in a.iterdir())
            self.assertEqual(names, sorted(p.name for p in b.iterdir()))
            for name in names:
                self.assertEqual((a / name).read_bytes(), (b / name).read_bytes())
            for line in (a / 'MANIFEST.sha256').read_text().splitlines():
                digest, name = line.split('  ', 1)
                self.assertEqual(hashlib.sha256((a / name).read_bytes()).hexdigest(), digest)

    def test_wrong_artifact_digest_is_rejected(self):
        mutated = bytearray(self.data)
        mutated[-1] ^= 1
        with self.assertRaisesRegex(ValueError, 'Unexpected node #115 digest'):
            profile.extract(bytes(mutated))

    def test_index_nineteen_table_mutation_is_rejected(self):
        secs = profile.sections(self.data)
        mutated = bytearray(self.data)
        off = profile.va_to_offset(mutated, secs, 0x607074, 4)
        mutated[off] ^= 1
        with patch.object(profile, 'DIGEST', hashlib.sha256(mutated).hexdigest()):
            with self.assertRaisesRegex(ValueError, 'Unexpected index-19 target'):
                profile.extract(bytes(mutated))

    def test_set_display_name_compare_mutation_is_rejected(self):
        secs = profile.sections(self.data)
        mutated = bytearray(self.data)
        off = profile.va_to_offset(mutated, secs, 0x2ba0d56, 1)
        mutated[off] ^= 1
        with patch.object(profile, 'DIGEST', hashlib.sha256(mutated).hexdigest()):
            with self.assertRaisesRegex(ValueError, 'SetDisplayName matcher arm mismatch'):
                profile.extract(bytes(mutated))


if __name__ == '__main__':
    unittest.main()
