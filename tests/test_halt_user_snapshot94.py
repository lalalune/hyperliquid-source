"""Controls for node 94 halt-sweep static evidence; no captured code is run."""
import csv
import json
import struct
from pathlib import Path
import tempfile
import unittest

from tools import halt_user_snapshot94 as h


class HaltUserSnapshot94Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = bytearray(h.TARGET.read_bytes())
        cls.sections = h.sections(cls.data)
        cls.functions, cls.context, cls.witnesses, cls.branches, cls.calls, cls.slots, cls.fields = h.collect(cls.data)

    def test_target_identity_and_corruption(self):
        h.authenticate(self.data)
        self.data[0] ^= 1
        try:
            with self.assertRaisesRegex(ValueError, 'SHA-256'):
                h.authenticate(self.data)
        finally:
            self.data[0] ^= 1
        with self.assertRaises(ValueError):
            h.authenticate(b'not an ELF')

    def test_fde_extents_and_full_body_corruption(self):
        self.assertEqual(len(self.functions), len(h.FUNCTIONS))
        for name, start, end, expected in h.FUNCTIONS:
            with self.subTest(name=name):
                raw = h.verify_body(self.data, self.sections, start, end, expected)
                self.assertEqual(len(raw), end - start)
                for pos in (0, len(raw) // 2, len(raw) - 1):
                    off = h.va_offset(self.sections, start + pos)
                    self.data[off] ^= 1
                    try:
                        with self.assertRaisesRegex(ValueError, 'body hash'):
                            h.verify_body(self.data, self.sections, start, end, expected)
                    finally:
                        self.data[off] ^= 1

    def test_fde_record_rejects_corruption(self):
        # This control deliberately bypasses the whole-file digest so the
        # repository's FDE parser must reject the malformed record itself.
        row = self.functions[0]
        fde_va = int(row[4], 16)
        off = h.va_offset(self.sections, fde_va, 4)
        original = bytes(self.data[off:off + 4])
        self.data[off:off + 4] = struct.pack('<I', 0xffffffff)
        try:
            with self.assertRaises(ValueError):
                h.fde_extents(self.data)
        finally:
            self.data[off:off + 4] = original

    def test_context_bytes_reject_mutation(self):
        for name, site, expected in h.CONTEXT:
            with self.subTest(name=name):
                h.check_exact(self.data, self.sections, site, expected)
                off = h.va_offset(self.sections, site + len(expected) // 2)
                self.data[off] ^= 1
                try:
                    with self.assertRaises(ValueError):
                        h.check_exact(self.data, self.sections, site, expected)
                finally:
                    self.data[off] ^= 1

    def test_branches_and_corruption(self):
        for name, site, target in h.BRANCHES:
            with self.subTest(name=name):
                raw = bytearray(h.read_va(self.data, self.sections, site, 6))
                width, actual = h.checked_branch(raw, site, target)
                self.assertEqual(actual, target)
                raw[width - 1] ^= 1
                with self.assertRaises(ValueError):
                    h.checked_branch(raw, site, target)
                raw[0] = 0x90
                with self.assertRaises(ValueError):
                    h.checked_branch(raw, site, target)

    def test_direct_call_targets_and_corruption(self):
        for name, site, target in h.DIRECT:
            with self.subTest(name=name):
                raw = bytearray(h.read_va(self.data, self.sections, site, 5))
                self.assertEqual(h.rel32(raw, site), target)
                raw[1] ^= 1
                self.assertNotEqual(h.rel32(raw, site), target)
                raw[0] = 0x90
                with self.assertRaises(ValueError):
                    h.rel32(raw, site)

    def test_indirect_slots_and_relocations(self):
        relocs = h.relative_relocations(self.data, self.sections)
        for name, site, target in h.INDIRECT:
            with self.subTest(name=name):
                raw = bytearray(h.read_va(self.data, self.sections, site, 6))
                self.assertEqual(h.indirect_slot(raw, site), target)
                raw[2] ^= 1
                self.assertNotEqual(h.indirect_slot(raw, site), target)
                raw[0] = 0x90
                with self.assertRaises(ValueError):
                    h.indirect_slot(raw, site)
        self.assertEqual(relocs[0x576dfd8], 0x54c06b0)
        self.assertEqual(relocs[0x576e010], 0x54c8cb0)
        self.assertNotIn(0x576dfe0, relocs)
        for slot in h.EXPECTED_SLOTS:
            h.checked_slot(relocs, slot)
        damaged = dict(relocs)
        damaged[0x576dfd8] ^= 1
        with self.assertRaisesRegex(ValueError, 'relocation'):
            h.checked_slot(damaged, 0x576dfd8)
        damaged = dict(relocs)
        damaged[0x576dfe0] = 1
        with self.assertRaisesRegex(ValueError, 'relocation'):
            h.checked_slot(damaged, 0x576dfe0)

    def test_each_operand_instruction_rejects_corruption(self):
        for name, site, pattern, position, width in h.FIELDS:
            with self.subTest(name=name):
                expected = bytes.fromhex(pattern)
                actual = h.check_exact(self.data, self.sections, site, expected)
                self.assertLessEqual(position + width, len(actual))
                off = h.va_offset(self.sections, site + position)
                self.data[off] ^= 1
                try:
                    with self.assertRaises(ValueError):
                        h.check_exact(self.data, self.sections, site, expected)
                finally:
                    self.data[off] ^= 1

    def test_mapping_bounds_and_nobits(self):
        bss = next(s for s in self.sections if s['name'] == '.bss' and s['type'] == 8)
        with self.assertRaises(ValueError):
            h.va_offset(self.sections, bss['address'])
        with self.assertRaises(ValueError):
            h.va_offset(self.sections, -1)
        with self.assertRaises(ValueError):
            h.va_offset(self.sections, 1 << 63)
        with self.assertRaises(ValueError):
            h.va_offset(self.sections, h.FUNCTIONS[0][1], 0)
        text = next(s for s in self.sections if s['name'] == '.text')
        with self.assertRaises(ValueError):
            h.va_offset(self.sections, text['address'] + text['size'] - 1, 2)

    def test_node_guard_boundaries(self):
        fields = {name: int(value, 16) for name, _, _, value in self.fields}
        for field, site in (('outer_capacity_bound', 0x49a1bd0),
                            ('set_capacity_bound', 0x497bb88),
                            ('map_capacity_bound', 0x498ab3d)):
            with self.subTest(field=field):
                bound = fields[field]
                raw = h.read_va(self.data, self.sections, site, 2)
                self.assertIn(raw, (b'\x0f\x83', b'\x73\x73'))
                self.assertEqual(bound, 11)
                # The selected instructions compare unsigned and branch at/above.
                self.assertEqual([(n, n >= bound) for n in (0, bound - 1, bound, bound + 1)],
                                 [(0, False), (10, False), (11, True), (12, True)])

    def test_queue_allocation_boundaries(self):
        fields = {name: int(value, 16) for name, _, _, value in self.fields}
        self.assertEqual(fields['queue_size_shift'], 61)
        limit = fields['queue_max_bytes'] // 8
        self.assertEqual(limit, (1 << 60) - 1)
        for count, rejected in ((0, False), (1, False), (limit, False), (limit + 1, True), ((1 << 61), True)):
            with self.subTest(count=count):
                invalid = bool(count >> fields['queue_size_shift']) or (count * 8 & ((1 << 64) - 1)) > fields['queue_max_bytes']
                self.assertEqual(invalid, rejected)

    def test_lsda_cleanup_calls_and_corruption(self):
        _, fdes, _ = h.fde_extents(self.data)
        by_start = {row['start']: row for row in fdes}
        checks = (
            (0x496c1a0, 0x496c1eb, 5, 0x496c284),
            (0x496c1a0, 0x496c209, 5, 0x496c289),
            (0x496c1a0, 0x496c27c, 6, 0x496c289),
            (0x49082e0, 0x49082f0, 5, 0x49083d7),
            (0x49a1a00, 0x49a1b0e, 5, 0x49a1ea2),
            (0x49a1a00, 0x49a1b28, 5, 0x49a1ea7),
            (0x49a1a00, 0x49a1d34, 5, 0x49a1e9d),
        )
        for start, site, width, pad in checks:
            with self.subTest(site=hex(site)):
                _, rows = h.decode_lsda(self.data, self.sections, by_start[start])
                owners = [row for row in rows if row[0] <= site + width - 1 < row[1]]
                self.assertEqual(len(owners), 1)
                self.assertEqual(owners[0][2:4], (pad, 0))
        fde = by_start[0x496c1a0]
        header, rows = h.decode_lsda(self.data, self.sections, fde)
        self.assertEqual(len(rows), 7)
        off = h.va_offset(self.sections, fde['lsda'])
        for offset, replacement in ((0, 0xfe), (len(bytes.fromhex(header)) + 1, 0)):
            original = self.data[off + offset]
            self.data[off + offset] = replacement
            try:
                with self.assertRaises(ValueError):
                    h.decode_lsda(self.data, self.sections, fde)
            finally:
                self.data[off + offset] = original
        bad = dict(fde, lsda=1 << 63)
        with self.assertRaises(ValueError):
            h.decode_lsda(self.data, self.sections, bad)

    def test_emitted_tables_regenerate(self):
        expected_dir = h.ROOT / 'research/work-items/RE-006-halt-user-snapshot-94'
        with tempfile.TemporaryDirectory() as temporary:
            out = Path(temporary)
            result = h.generate(self.data, out)
            self.assertEqual(result['fde_ranges'], len(h.FUNCTIONS))
            self.assertEqual(result['selected_conditional_branches'], len(h.BRANCHES))
            self.assertEqual(result['direct_calls'], len(h.DIRECT))
            for name in ('functions.tsv', 'context.tsv', 'witnesses.tsv', 'branches.tsv', 'calls.tsv',
                         'indirect.tsv', 'fields.tsv', 'lsda.tsv', 'summary.json'):
                self.assertEqual((out / name).read_bytes(), (expected_dir / name).read_bytes(), name)
            with (out / 'fields.tsv').open(newline='', encoding='utf-8') as handle:
                self.assertEqual(len(list(csv.DictReader(handle, delimiter='\t'))), len(h.FIELDS))
            self.assertEqual(json.loads((out / 'summary.json').read_text())['target_sha256'], h.SHA256)


if __name__ == '__main__':
    unittest.main()
