"""Real node115 coordinate checks and lower-level corruption controls."""
import json
import struct
import unittest
from tools import node115_rate_limit_coordinates as proof


class RateLimitCoordinatesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = proof.TARGET.read_bytes()
        cls.elf = proof.Elf(cls.data)
        cls.relas = cls.elf.relocations()
        cls.result, cls.native = proof.run()
        cls.frames = '\n'.join(cls.result['fde_rows'])
        cls.location_offset = cls.elf.offset(proof.LOCATION, 24)
        cls.ref_offset = cls.elf.offset(proof.REFS[0], 12)

    def mutated_elf(self, offset, replacement):
        data = bytearray(self.data)
        data[offset:offset + len(replacement)] = replacement
        return proof.Elf(data)

    def test_target_identity(self):
        proof.authenticate(self.data)

    def test_size_corruption(self):
        with self.assertRaisesRegex(ValueError, 'target size'):
            proof.authenticate(self.data[:-1])

    def test_digest_corruption(self):
        data = bytearray(self.data)
        data[-1] ^= 1
        with self.assertRaisesRegex(ValueError, 'target digest'):
            proof.authenticate(data)

    def test_real_location(self):
        record = proof.check_location(self.elf, self.relas)
        self.assertEqual((record['path'], record['line'], record['column']),
                         (proof.SOURCE.decode(), 131, 20))

    def test_bad_location_fields(self):
        elf = self.mutated_elf(self.location_offset + 16, struct.pack('<I', 132))
        with self.assertRaisesRegex(ValueError, 'Location fields'):
            proof.check_location(elf, self.relas)

    def test_bad_path(self):
        at = int(self.result['location']['path_file_offset'], 16)
        elf = self.mutated_elf(at, b'X')
        with self.assertRaisesRegex(ValueError, 'source path'):
            proof.check_location(elf, self.relas)

    def test_relocation_corruptions(self):
        row = next(r for r in self.relas if r[1] == proof.LOCATION)
        rest = [r for r in self.relas if r[1] != proof.LOCATION]
        cases = (rest, self.relas + [row],
                 rest + [(row[0], row[1], 1, row[3])],
                 rest + [(row[0], row[1], row[2], len(self.data) * 2)])
        for records in cases:
            with self.subTest(records=len(records)), self.assertRaises(ValueError):
                proof.check_location(self.elf, records)

    def test_elf_magic_control(self):
        with self.assertRaisesRegex(ValueError, 'ELF64'):
            self.mutated_elf(0, b'X')

    def test_va_range_control(self):
        with self.assertRaisesRegex(ValueError, 'unique file-backed VA'):
            self.elf.offset(len(self.data) * 2)

    def test_two_native_bindings(self):
        for i, lo in enumerate(proof.STARTS):
            record = proof.check_native(self.elf, i, self.native[f'native-{lo:x}.txt'])
            self.assertEqual(record['extent_bytes'], 653)
            self.assertEqual(record['direct_call_target'], hex(proof.CALLEE))
        self.assertEqual(self.result['counts'],
                         {'source_locations': 1, 'native_references': 2, 'unwind_extents': 2})

    def test_instruction_byte_controls(self):
        text = self.native[f'native-{proof.STARTS[0]:x}.txt']
        for offset, value in ((self.ref_offset + 3, b'\x45'),
                              (self.ref_offset + 7, b'\x90'),
                              (self.ref_offset + 8, b'\x00')):
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                proof.check_native(self.mutated_elf(offset, value), 0, text)

    def test_alignment_control(self):
        text = self.native[f'native-{proof.STARTS[0]:x}.txt']
        changed = text.replace(f'{proof.REFS[0]:x}:', '0:')
        with self.assertRaisesRegex(ValueError, 'native instruction boundary'):
            proof.check_native(self.elf, 0, changed)

    def test_native_decode_control(self):
        text = self.native[f'native-{proof.STARTS[0]:x}.txt'].replace('48 8d 35 44', '48 8d 35 45')
        with self.assertRaisesRegex(ValueError, 'native decode'):
            proof.check_native(self.elf, 0, text)

    def test_frame_controls(self):
        self.assertEqual(len(proof.check_frames(self.frames)), 2)
        first = self.result['fde_rows'][0]
        endpoint = format(proof.STARTS[0] + proof.LENGTH, 'x')
        cases = ('', self.frames + '\n' + first,
                 self.frames.replace(endpoint, format(proof.STARTS[0] + proof.LENGTH - 1, 'x')))
        for frames in cases:
            with self.subTest(frames=frames), self.assertRaises(ValueError):
                proof.check_frames(frames)

    def test_committed_structured_proof(self):
        packet = proof.ROOT / 'research/work-items/RE-001-node115-rate-limit-coordinates'
        committed = json.loads((packet / 'proof.json').read_text())
        observed = dict(self.result)
        # Raw readelf formatting is provenance, not a cross-version equality field.
        committed.pop('fde_rows')
        observed.pop('fde_rows')
        self.assertEqual(committed, observed)

    def test_repeat_static_decode(self):
        other, native = proof.run()
        self.assertEqual(other, self.result)
        self.assertEqual(native, self.native)


if __name__ == '__main__':
    unittest.main()
