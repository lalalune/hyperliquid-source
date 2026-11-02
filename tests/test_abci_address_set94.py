"""Static extraction and corruption controls for the node 94 set path."""
import struct
import unittest

from tools import abci_address_set94 as m


class PatchedView:
    def __init__(self, original, address, xor=1):
        self.original = original
        self.address = address
        self.xor = xor

    def offset(self, va, length):
        return self.original.offset(va, length)

    def read(self, va, length):
        raw = bytearray(self.original.read(va, length))
        if va <= self.address < va + length:
            raw[self.address - va] ^= self.xor
        return bytes(raw)


def relocation_fixture():
    data = bytearray(256)
    struct.pack_into('<QQq', data, 0, 0x576e488, (1 << 32) | 6, 0)
    struct.pack_into('<QQq', data, 24, 0x57705c0, 8, 0x156e650)
    struct.pack_into('<I', data, 96 + 24, 1)
    data[160:168] = b'\0memcmp\0'
    secs = [
        {'name': '.rela.dyn', 'type': 4, 'offset': 0, 'size': 48},
        {'name': '.dynsym', 'type': 11, 'offset': 96, 'size': 48},
        {'name': '.dynstr', 'type': 3, 'offset': 160, 'size': 8},
    ]
    return data, secs


class AddressSetStaticTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = m.TARGET.read_bytes()
        cls.view = m.View(cls.data)
        cls.result = m.collect(cls.data)

    def test_authentication_and_bad_digest(self):
        self.assertEqual(m.verify_digest(self.data), m.TARGET_SHA256)
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            m.verify_digest(self.data, '0' * 64)
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            m.verify_digest(b'corrupted capture')

    def test_selected_fde_extents_are_independently_indexed(self):
        _, table = m.elf_index.unwind_index(self.data)
        _, records = m.fde_extents.eh_frame_records(self.data, self.view.sections)
        by_va = {row['start']: row for row in records}
        indexed = {row['start']: row['fde'] for row in table}
        self.assertEqual(len(self.result['functions']), 13)
        for item in self.result['functions']:
            start = int(item['start'], 16)
            fde = by_va[start]
            self.assertEqual(item['end_exclusive'], hex(fde['end']))
            self.assertEqual(item['fde'], hex(indexed[start]))
            self.assertGreater(item['bytes'], 0)

    def test_fde_missing_duplicate_and_wrong_index(self):
        row = {'start': 10, 'end': 20, 'fde': 50, 'index': 0}
        index = [{'start': 10, 'fde': 50}]
        self.assertEqual(m.select_fde({10: [row]}, index, 10), row)
        for by_start, table in (({}, index), ({10: [row, row]}, index),
                                ({10: [{**row, 'end': 10}]}, index),
                                ({10: [row]}, [{'start': 11, 'fde': 50}]),
                                ({10: [row]}, [{'start': 10, 'fde': 51}]),
                                ({10: [{**row, 'index': 1}]}, index)):
            with self.subTest(by_start=by_start, table=table), self.assertRaises(ValueError):
                m.select_fde(by_start, table, 10)

    def test_address_mapping_rejects_nobits_and_ambiguity(self):
        f = {'name': 'data', 'type': 1, 'address': 0x100, 'offset': 0, 'size': 4}
        bss = {'name': 'bss', 'type': 8, 'address': 0x100, 'offset': 0, 'size': 4}
        good = m.View(b'abcd', [f, bss])
        self.assertEqual(good.read(0x100, 4), b'abcd')
        for bad, va, length in ((m.View(b'abcd', [bss]), 0x100, 1),
                                (m.View(b'abcd', [f, dict(f)]), 0x100, 1),
                                (good, 0xff, 1), (good, 0x103, 2),
                                (good, 0x100, -1), (m.View(b'a', [f]), 0x100, 4)):
            with self.subTest(va=va, length=length), self.assertRaises(ValueError):
                bad.read(va, length)

    def test_all_window_mutations_fail(self):
        for label, _, va, length in m.WINDOW_RANGES:
            with self.subTest(label=label), self.assertRaises(ValueError):
                m.checked(PatchedView(self.view, va), 'window_' + label, va, length)

    def test_each_call_opcode_and_displacement_corruption_fails(self):
        for va, _ in m.EDGES:
            for offset in (0, 1, 4):
                with self.subTest(va=hex(va), offset=offset), self.assertRaises(ValueError):
                    m.rel_call(PatchedView(self.view, va + offset), va)

    def test_each_branch_opcode_and_displacement_corruption_fails(self):
        for va in m.BRANCHES:
            raw = bytes.fromhex(m.PINS['branch_' + hex(va)])
            for offset in (0, len(raw) - 1):
                with self.subTest(va=hex(va), offset=offset), self.assertRaises(ValueError):
                    m.branch(PatchedView(self.view, va + offset), va)

    def test_decoder_and_writer_connections_from_rel32(self):
        expected = {
            0x2fe808c: 0x308a550, 0x2abb7da: 0x2bfdab0,
            0x308a656: 0x3018f10, 0x3019015: 0x3586f00,
            0x358710c: 0x35c8330, 0x308a684: 0x339ed10,
            0x2bfdcd2: 0x339ed10, 0x2bfe276: 0x339ed10,
            0x27f0670: 0x1e2aad0, 0x4ae4270: 0x4430b20,
            0x1e2ada1: 0x2806b00, 0x1e2ade4: 0x2804dd0,
        }
        for site, target in expected.items():
            raw = self.view.read(site, 5)
            self.assertEqual(raw[0], 0xe8)
            self.assertEqual(site + 5 + struct.unpack_from('<i', raw, 1)[0], target)
            self.assertEqual(m.rel_call(self.view, site), target)

    def test_equal_key_takes_no_increment_branch(self):
        branch = m.branch(self.view, 0x339eda6)
        self.assertEqual(branch['condition_code'], 4)
        self.assertEqual(branch['target'], '0x339edd4')
        self.assertEqual(self.view.read(0x339edd4, 2), b'\xb0\x01')
        self.assertEqual(self.view.read(0x339eee8, 4), bytes.fromhex('48ff4610'))
        self.assertEqual(self.view.read(0x339eeec, 2), b'\x31\xc0')
        for site in (0x308a684, 0x2bfdcd2, 0x2bfe276):
            self.assertEqual(m.rel_call(self.view, site), 0x339ed10)

    def test_messagepack_array_and_json_delimiters(self):
        self.assertEqual(self.view.read(0x2bfe13f, 3), bytes.fromhex('80f9a0'))
        self.assertEqual(self.view.read(0x2bfe148, 3), bytes.fromhex('80e10f'))
        self.assertEqual(self.view.read(0x308a5cd, 3), bytes.fromhex('83ff5b'))
        self.assertEqual(self.view.read(0x3018ff2, 4), bytes.fromhex('4183fa5d'))
        self.assertEqual(m.branch(self.view, 0x2bfe207)['target'], '0x2bfe398')
        self.assertEqual(m.branch(self.view, 0x308a660)['target'], '0x308a68b')

    def test_field_name_and_materialization_coordinates(self):
        self.assertEqual(self.view.read(0x578e9b, 20), b'disabled_precompiles')
        self.assertEqual(self.view.read(0x2fe52dd, 6), bytes.fromhex('4989f64889fb'))
        self.assertEqual(self.view.read(0x2fe9a64, 8), bytes.fromhex('48899c24c0000000'))
        self.assertEqual(self.view.read(0x2ff36e4, 8), bytes.fromhex('4c8bb424c0000000'))
        source = self.view.read(0x37520bc, 7)
        dest = self.view.read(0x3752557, 8)
        self.assertEqual(source[:3], bytes.fromhex('488d83'))
        self.assertEqual(struct.unpack_from('<I', source, 3)[0], 0x1f10)
        self.assertEqual(dest[:4], bytes.fromhex('410f1186'))
        self.assertEqual(struct.unpack_from('<I', dest, 4)[0], 0x3a30)
        self.assertEqual(self.view.read(0x2ff3288, 12)[-4:], b'\0' * 4)
        self.assertEqual(self.view.read(0x2ff3294, 12)[-4:], b'\0' * 4)

    def test_direct_item_mode_and_byte_count(self):
        self.assertEqual(self.view.read(0x2806b1b, 4), bytes.fromhex('807a0a00'))
        self.assertEqual(m.branch(self.view, 0x2806b1f)['target'], '0x2806d98')
        self.assertEqual(self.view.read(0x2806d98, 5), bytes.fromhex('ba14000000'))
        self.assertEqual(m.rel_call(self.view, 0x2806da0), 0x25aa380)
        self.assertEqual(self.view.read(0x28050b7, 4), bytes.fromhex('c6043114'))
        self.assertEqual(self.view.read(0x208620, 16), b'0123456789abcdef')

    def test_gate_address_enumeration_and_negative_controls(self):
        rows = m.gate_cases(self.view)
        accepted = {bytes.fromhex(r['key_hex']) for r in rows if r['accepted']}
        self.assertEqual(len(rows), 30)
        self.assertEqual(len({row['key_hex'] for row in rows}), 30)
        self.assertEqual(len(accepted), 20)
        self.assertEqual(accepted, {i.to_bytes(20, 'big') for i in range(0x800, 0x814)})
        self.assertNotIn((0x7ff).to_bytes(20, 'big'), accepted)
        self.assertNotIn((0x814).to_bytes(20, 'big'), accepted)
        for address in (0x5b2004, 0x3b9d9ca, 0x3b45457,
                        int(rows[0]['arm'], 16), int(rows[0]['head_data'], 16)):
            with self.subTest(address=hex(address)), self.assertRaises(ValueError):
                m.gate_cases(PatchedView(self.view, address))

    def test_indirect_slot_references_and_corruption(self):
        expected = {0x3b453f0: 0x5776280, 0x3b453fc: 0x5776288,
                    0x35c8346: 0x57705c0, 0x339ed3d: 0x576e488}
        for va, size in m.RIP_REFS:
            self.assertEqual(m.rip_reference(self.view, va, size)['target'], hex(expected[va]))
            for offset in (0, size - 1):
                with self.subTest(va=hex(va), offset=offset), self.assertRaises(ValueError):
                    m.rip_reference(PatchedView(self.view, va + offset), va, size)

    def test_selected_relocations_and_negative_controls(self):
        rows = m.selected_relocations(self.view)
        self.assertEqual([(x['slot'], x['type'], x['symbol_name'], x['addend']) for x in rows],
                         [('0x576e488', 6, 'memcmp', '0x0'), ('0x57705c0', 8, '', '0x156e650'),
                          ('0x5773df8', 8, '', '0x3b453d0'), ('0x5776280', 8, '', '0x3b9d9b0'),
                          ('0x5776288', 8, '', '0x3b45470')])
        data, sections = relocation_fixture()
        self.assertEqual(len(m.selected_relocations(m.View(data, sections), (0x576e488, 0x57705c0))), 2)
        controls = []
        bad_type = bytearray(data); struct.pack_into('<Q', bad_type, 32, 7); controls.append((bad_type, sections))
        bad_addend = bytearray(data); struct.pack_into('<q', bad_addend, 40, 0); controls.append((bad_addend, sections))
        bad_symbol = bytearray(data); bad_symbol[161] = ord('M'); controls.append((bad_symbol, sections))
        bad_index = bytearray(data); struct.pack_into('<Q', bad_index, 8, (3 << 32) | 6); controls.append((bad_index, sections))
        duplicate = bytearray(data); duplicate[48:72] = duplicate[:24]
        more = [dict(x) for x in sections]; more[0]['size'] = 72; controls.append((duplicate, more))
        nobits = [dict(x) for x in sections]; nobits[0]['type'] = 8; controls.append((data, nobits))
        for bad_data, bad_secs in controls:
            with self.assertRaises(ValueError):
                m.selected_relocations(m.View(bad_data, bad_secs), (0x576e488, 0x57705c0))

    def test_scoped_counts_and_unique_addresses(self):
        self.assertEqual(len(m.FUNCTIONS), 13)
        self.assertEqual(len(set(va for va, _ in m.FUNCTIONS)), 13)
        self.assertEqual(sum(w['scope'] == 'prior-boundary' for w in self.result['windows']), 15)
        self.assertEqual(len(self.result['direct_edges']), 21)
        self.assertEqual(len(self.result['branches']), 86)
        self.assertEqual(self.result['binary_sha256'], m.TARGET_SHA256)


if __name__ == '__main__':
    unittest.main()
