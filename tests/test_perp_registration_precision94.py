"""Static, target-bound controls for the node 94 precision evidence."""
import tempfile
from pathlib import Path
import unittest

from tools import perp_registration_precision94 as m


class PrecisionEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = (m.ROOT / m.BINARY).read_bytes()
        cls.image = m.Image(cls.data)
        m.qualify(cls.image)

    def default_case(self, **changes):
        case = dict(name_len=0, count=0, dex=0, precision=0, selector=0,
                    text_len=0, duplicate=False, custom_found=True,
                    parser_tag=0x186, convert_ok=True)
        case.update(changes)
        return case

    def changed_image(self, va):
        altered = bytearray(self.data)
        altered[self.image.offset(va)] ^= 1
        return m.Image(altered, verify=False)

    def test_target_digest_rejects_corruption(self):
        m.check_digest(self.data)
        with self.assertRaises(m.EvidenceError):
            m.check_digest(b'corrupted input')
        with self.assertRaises(m.EvidenceError):
            m.Image(bytearray(self.data[:-1]) + b'X')

    def test_four_fde_extents(self):
        fdes = m.qualify(self.image)
        starts = {f['start']: f['end'] for f in fdes if f['start'] in m.FUNCTIONS}
        self.assertEqual(starts, m.FUNCTIONS)
        self.assertEqual(len(starts), 4)

    def test_all_precision_byte_values(self):
        accepted, rejected = [], []
        for value in range(256):
            decision, target = m.precision_step(self.image, value)
            if decision == 'continue':
                self.assertEqual(target, 0x36f78f3)
                accepted.append(value)
            else:
                self.assertEqual((decision, target), ('refuse', 0x3e))
                rejected.append(value)
        self.assertEqual(accepted, list(range(7)))
        self.assertEqual(rejected, list(range(7, 256)))
        for bad in (-1, 256, True, '6'):
            with self.assertRaises(m.EvidenceError):
                m.precision_step(self.image, bad)

    def test_modified_threshold_and_call_fail_qualification(self):
        for address in (0x36f7847, 0x36f7a1e, 0x342bb71, 0x3c925cf):
            with self.subTest(address=address):
                with self.assertRaises(m.EvidenceError):
                    m.qualify(self.changed_image(address))

    def test_address_checks_exclude_nobits_and_invalid_ranges(self):
        nobits = [s for s in self.image.sections if s['name'] == '.bss' and s['type'] == 8]
        self.assertEqual(len(nobits), 1)
        for address, size in ((nobits[0]['address'], 1), (-1, 1), (0, 0), (1 << 64, 1)):
            with self.subTest(address=address, size=size):
                with self.assertRaises(m.EvidenceError):
                    self.image.offset(address, size)

    def test_field_keys_and_pointer_offsets(self):
        field = m.field(self.image, 0x342bb71, 0x2a, 10, 0x342bb84)
        self.assertEqual(field['key_ascii'], 'szDecimals')
        self.assertEqual(field['key_va'], '0x58d301')
        self.assertEqual(field['call_target'], '0x3c87640')
        self.assertEqual(m.direct(self.image, 0x3c925cf), 0x342bb20)
        self.assertEqual(self.image.read(0x3c92456, 8), bytes.fromhex('498b6f08498b5f10'))
        self.assertEqual(self.image.read(0x3c925dd, 4), bytes.fromhex('4883c530'))
        with self.assertRaises(m.EvidenceError):
            m.field(self.image, 0x342bb71, 0x29, 10, 0x342bb84)
        with self.assertRaises(m.EvidenceError):
            m.field(self.image, 0x342bb71, 0x2a, 11, 0x342bb84)

    def test_relocation_and_bad_call(self):
        for site in (0x273b307, 0x4d4a8c9, 0x4d4ae69):
            self.assertEqual(m.indirect(self.image, site), (0x5774b78, 0x36f7730))
        for site in (0x36f786c, 0x36f7884, 0x36f7ba3, 0x3766020):
            self.assertEqual(m.indirect(self.image, site), (0x576e010, 0x54c8cb0))
        self.assertEqual(m.direct(self.image, 0x36f7a1e), 0x3765fc0)
        symbol = m.comparator_symbol(self.image)
        self.assertEqual((symbol['slot'], symbol['relocation_type'], symbol['symbol_name']),
                         ('0x576e378', 6, 'bcmp'))
        strings = next(s for s in self.image.sections if s['name'] == '.dynstr')
        index = self.data.find(b'bcmp\x00', strings['offset'], strings['offset'] + strings['size'])
        self.assertGreaterEqual(index, strings['offset'])
        corrupted = bytearray(self.data)
        corrupted[index] ^= 1
        with self.assertRaises(m.EvidenceError):
            m.comparator_symbol(m.Image(corrupted, verify=False))
        with self.assertRaises(m.EvidenceError):
            m.direct(self.image, 0x36f7844)
        with self.assertRaises(m.EvidenceError):
            self.image.relative(0)

    def test_identifier_checked_arithmetic_boundaries(self):
        max_dex, remainder = divmod(m.U64, 10000)
        self.assertEqual(m.identifier_step(self.image, max_dex - 1, 9999), ('ok', max_dex * 10000 - 1))
        self.assertEqual(m.identifier_step(self.image, max_dex, remainder), ('ok', m.U64))
        self.assertEqual(m.identifier_step(self.image, max_dex, remainder + 1), ('add-overflow', None))
        self.assertEqual(m.identifier_step(self.image, max_dex, 9999), ('add-overflow', None))
        self.assertEqual(m.identifier_step(self.image, max_dex + 1, 0), ('multiply-overflow', None))
        for bad in (-1, 1 << 64):
            with self.assertRaises(m.EvidenceError):
                m.identifier_step(self.image, bad, 0)

    def test_selected_path_priorities_and_failures(self):
        expectations = [
            (dict(name_len=101, dex=m.U64), ('name-length', 0x143, 'unchanged')),
            (dict(count=10000), ('row-count', 0x60, 'unchanged')),
            (dict(count=1, duplicate=True, precision=7), ('duplicate', 0x3b, 'unchanged')),
            (dict(precision=7, selector=50, custom_found=False), ('precision', 0x3e, 'unchanged')),
            (dict(selector=49, custom_found=False), ('success', 0x186, 'append')),
            (dict(selector=50, custom_found=False), ('custom-missing', 0x154, 'unchanged')),
            (dict(text_len=101), ('text-length', 0x143, 'unchanged')),
            (dict(parser_tag=0xac), ('parse-refusal', 0xac, 'unchanged')),
            (dict(convert_ok=False), ('price-conversion-refusal', 0x13d, 'append-then-pop')),
        ]
        for changes, expected in expectations:
            with self.subTest(changes=changes):
                self.assertEqual(m.model(self.image, self.default_case(**changes))[:3], expected)
        with self.assertRaises(m.EvidenceError):
            m.model(self.image, self.default_case(selector=1 << 32))
        with self.assertRaises(m.EvidenceError):
            m.model(self.image, self.default_case(duplicate=True))

    def test_two_in_process_generations_match(self):
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            a, b = Path(first), Path(second)
            m.generate(self.image, a)
            m.generate(self.image, b)
            self.assertEqual(sorted(p.name for p in a.iterdir()), sorted(p.name for p in b.iterdir()))
            for item in a.iterdir():
                self.assertEqual(item.read_bytes(), (b / item.name).read_bytes(), item.name)


if __name__ == '__main__':
    unittest.main()
