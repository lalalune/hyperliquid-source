from pathlib import Path
import struct
import tempfile
import unittest

from tools import net_deposit_display94 as m


class DisplayPathTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = m.read_target()
        cls.record = m.checked(cls.data)

    def test_authenticated_fdes_and_edge(self):
        self.assertEqual([row['start_va'] for row in self.record['functions']], ['0x2588fa0', '0x27d6040', '0x2a2e340', '0x2a33860'])
        self.assertEqual(self.record['lookup_slot']['relative_relocation_addend'], '0x3332270')
        self.assertEqual(sum(map(len, self.record['branches'].values())), 33)
        self.assertEqual(self.record['variant']['tag'], 41)

    def test_zero_sign_and_boundaries(self):
        self.assertEqual(m.display_bits(0), 0)
        self.assertEqual(m.display_bits(1000000), 0x3ff0000000000000)
        self.assertEqual(m.display_bits(-1000000), 0xbff0000000000000)
        for x in (-(1<<63), -(1<<53)-1, -1, 0, 1, (1<<53)+1, (1<<63)-1):
            bits = struct.unpack('<Q', struct.pack('<d', float(x) / 1000000.0))[0]
            self.assertEqual(m.display_bits(x), bits)

    def test_integer_rounding_ties(self):
        self.assertEqual(m.f64_bits((1<<53)+1), m.f64_bits(1<<53))
        self.assertEqual(m.f64_bits((1<<53)+3), m.f64_bits((1<<53)+4))
        self.assertNotEqual(m.f64_bits((1<<53)+2), m.f64_bits(1<<53))
        with self.assertRaises(ValueError):
            m.display_bits(1<<63)
        with self.assertRaises(ValueError):
            m.display_bits(-(1<<63)-1)

    def test_fraction_roundtrip(self):
        for n in (1, -1, 1000000, (1<<53)+2, -(1<<63)):
            bits = m.f64_bits(n)
            self.assertEqual(m.f64_bits(m.fraction_from_bits(bits)), bits)
        with self.assertRaises(ValueError):
            m.fraction_from_bits(0x7ff0000000000000)

    def test_digest_control(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)/'bad'
            p.write_bytes(b'not the captured target')
            with self.assertRaises(ValueError):
                m.read_target(p)

    def test_changed_code_rejected(self):
        edited = bytearray(self.data)
        edited[m.resolve(edited, 0x27d6170, 1)] ^= 1
        with self.assertRaises(ValueError):
            m.checked(edited)

    def test_branch_and_key_corruption_controls(self):
        edited = bytearray(self.data)
        off = m.resolve(edited, 0x27d6166, 2)
        edited[off + 1] = 0x7f
        self.assertNotEqual(m.branch(edited, 0x27d6166, 0x27d6040, 0x27d645f),
                            m.branch(self.data, 0x27d6166, 0x27d6040, 0x27d645f))
        with self.assertRaises(ValueError):
            m.checked(edited)
        edited = bytearray(self.data)
        pos = m.resolve(edited, 0x598c55, 1)
        edited[pos] ^= 1
        with self.assertRaises(ValueError):
            m.checked(edited)

    def test_lookup_relocation_corruption_rejected(self):
        edited = bytearray(self.data)
        sec = next(s for s in m.elf_index.sections(edited) if s['name'] == '.rela.dyn')
        positions = [p for p in range(sec['offset'], sec['offset'] + sec['size'], 24)
                     if struct.unpack_from('<Q', edited, p)[0] == 0x5774708]
        self.assertEqual(len(positions), 1)
        edited[positions[0] + 16] ^= 1
        with self.assertRaises(ValueError):
            m.checked(edited)

    def test_response_table_corruption_rejected(self):
        for va in (0x41fe50, 0x42000f):
            edited = bytearray(self.data)
            edited[m.resolve(edited, va, 1)] ^= 1
            with self.assertRaises(ValueError):
                m.checked(edited)

    def test_changed_divisor_rejected(self):
        edited = bytearray(self.data)
        edited[m.resolve(edited, 0x20ae60, 8)] ^= 1
        with self.assertRaises(ValueError):
            m.checked(edited)

    def test_bad_address_and_branch_rejected(self):
        with self.assertRaises(ValueError):
            m.resolve(self.data, 0xffffffffffffffff, 8)
        with self.assertRaises(ValueError):
            m.branch(self.data, 0x27d6170, 0x27d6040, 0x27d645f)
        with self.assertRaises(ValueError):
            m.branch(self.data, 0x27d6166, 0x27d6040, 0x27d6170)

    def test_output_is_stable(self):
        with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
            m.write_outputs(self.data, Path(a))
            m.write_outputs(self.data, Path(b))
            for name in ('evidence.json', 'vectors.tsv', 'decisions.tsv'):
                self.assertEqual((Path(a)/name).read_bytes(), (Path(b)/name).read_bytes())


if __name__ == '__main__':
    unittest.main()
