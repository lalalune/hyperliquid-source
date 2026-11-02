import hashlib
import tempfile
import unittest
from pathlib import Path
from tools import config_channels94 as m


class ChannelEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = m.TARGET.read_bytes()
        cls.result = m.inspect(cls.data)
        cls.view = cls.result[0]

    def altered(self, va):
        data = bytearray(self.data)
        data[self.view.offset(va, 1)] ^= 1
        return data

    def test_identity_and_full_input(self):
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), m.DIGEST)
        m.verify_identity(self.data)

    def test_changed_digest_rejected(self):
        with self.assertRaises(ValueError):
            m.verify_identity(self.altered(0x143c577))

    def test_truncated_input_rejected(self):
        with self.assertRaises(ValueError):
            m.verify_identity(self.data[:-1])

    def test_selected_extents_and_instruction_boundaries(self):
        functions, grouped = self.result[1], self.result[2]
        self.assertEqual(len(functions), 5)
        self.assertTrue(all(rows and rows[-1]['end'] == next(f[2] for f in m.FUNCTIONS if f[0] == name)
                            for name, rows in grouped.items()))

    def test_selector_known_domain(self):
        rows = self.result[7]
        self.assertEqual([r[1] for r in rows], ['Local', 'Sandbox', 'Testnet', 'Mainnet'])
        self.assertEqual([r[-1] for r in rows], ['', '0x100', '0xe8', '0xd0'])

    def test_selector_table_corruption_rejected(self):
        with self.assertRaises(ValueError):
            m.inspect(self.altered(0x2193f8), authenticate=False)

    def test_descriptor_length_corruption_rejected(self):
        with self.assertRaises(ValueError):
            m.inspect(self.altered(0x5668250), authenticate=False)

    def test_descriptor_text_corruption_rejected(self):
        with self.assertRaises(ValueError):
            m.inspect(self.altered(0x217ff1), authenticate=False)

    def test_code_witness_corruption_rejected(self):
        with self.assertRaises(ValueError):
            m.inspect(self.altered(0x143c577), authenticate=False)

    def test_selected_relocation_corruption_rejected(self):
        data = bytearray(self.data)
        off = self.result[5][0x576eb70][0]
        data[off + 16] ^= 1
        with self.assertRaises(ValueError):
            m.relocations(m.View(data))

    def test_template_corruption_rejected(self):
        with self.assertRaises(ValueError):
            m.checked_data(m.View(self.altered(0x1e37d4)))

    def test_callback_copy_and_failure_targets(self):
        rows = self.result[6]
        self.assertEqual([r[2] for r in rows], [616, 616])
        self.assertEqual(rows[0][3:], ['0x143eaf6', '0x143eb03'])
        self.assertEqual(rows[1][3:], ['0x1437dd6', '0x1437de3'])

    def test_graph_positive_and_negative(self):
        graph = {r[0]: r[-1] for r in self.result[8]}
        self.assertEqual(graph['local_skips_publication'], 'false')
        self.assertEqual(graph['sandbox_reaches_publication'], 'true')
        self.assertEqual(graph['publication_can_reach_release'], 'true')

    def test_truncated_instruction_rejected(self):
        with self.assertRaises(ValueError):
            m.decode_body(b'\x48\x8b', 0x1000)

    def test_jump_into_operand_rejected(self):
        with self.assertRaises(ValueError):
            m.decode_body(b'\xeb\xff\xc3', 0x1000)

    def test_unknown_opcode_rejected(self):
        with self.assertRaises(ValueError):
            m.decode_body(b'\x0f\xff\xc3', 0x1000)

    def test_outside_and_nobits_ranges_rejected(self):
        secs = [{'type': 8, 'flags': 2, 'address': 0x1000, 'offset': 0, 'size': 16}]
        view = m.View(bytes(16), secs)
        with self.assertRaises(ValueError):
            view.offset(0x1000, 1)
        with self.assertRaises(ValueError):
            self.view.offset(1 << 63, 1)

    def test_ambiguous_section_rejected(self):
        secs = [{'type': 1, 'flags': 2, 'address': 0x1000, 'offset': 0, 'size': 16}]*2
        with self.assertRaises(ValueError):
            m.View(bytes(16), secs).offset(0x1000, 1)

    def test_reproducible_output_trees(self):
        with tempfile.TemporaryDirectory() as parent:
            one, two = Path(parent)/'a', Path(parent)/'b'
            m.generate(self.data, one)
            m.generate(self.data, two)
            names = sorted(p.name for p in one.iterdir())
            self.assertEqual(names, sorted(p.name for p in two.iterdir()))
            for name in names:
                self.assertEqual((one/name).read_bytes(), (two/name).read_bytes())


if __name__ == '__main__':
    unittest.main()
