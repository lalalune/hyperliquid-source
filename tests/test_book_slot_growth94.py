"""Static corruption and boundary controls for node 94 slot growth evidence."""
import hashlib
import unittest

from tools import book_slot_growth94 as packet
from tools.fde_extents import eh_frame_records


class SlotGrowthEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = packet.TARGET.read_bytes()
        cls.image = packet.Image(cls.data)
        _, frames = eh_frame_records(cls.data, cls.image.sections)
        cls.frames = {x['start']: x for x in frames}
        cls.rows = packet.make_rows(cls.data)

    def mutated(self, va, value):
        changed = bytearray(self.data)
        changed[self.image.offset(va)] ^= value
        return changed

    def test_identity_and_indexed_extents(self):
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), packet.SHA256)
        expected = [(0x28e0e40, 0x28e0f73), (0x28e0f80, 0x28e10b3),
                    (0x45a4dd0, 0x45a4f03), (0x32d5940, 0x32d59a4)]
        self.assertEqual([(int(x[0], 16), int(x[1], 16)) for x in self.rows['functions']], expected)
        self.assertEqual(len(self.rows['lsda']), 12)
        self.assertEqual([row[2] for row in self.rows['cie']], ['zPLR', 'zPLR', 'zPLR', 'zR'])
        self.assertEqual(len(self.rows['branches']), 19)
        self.assertEqual(len(self.rows['calls']), 26)

    def test_digest_rejects_short_or_changed_input(self):
        with self.assertRaisesRegex(packet.EvidenceError, 'digest'):
            packet.render(b'not the target')
        changed = self.mutated(packet.COPIES[0] + 0x38, 1)
        with self.assertRaisesRegex(packet.EvidenceError, 'digest'):
            packet.render(changed)

    def test_corrupt_opcode_is_rejected_below_digest(self):
        changed = self.mutated(packet.COPIES[0] + 0x38, 1)
        with self.assertRaisesRegex(packet.EvidenceError, 'slot body'):
            packet.make_rows(changed)

    def test_corrupt_masked_displacement_is_rejected_below_digest(self):
        changed = self.mutated(packet.COPIES[1] + packet.MASKS[0], 1)
        # Even a byte intentionally masked in the cross-copy comparison remains
        # protected by its individual full-body hash and resolved edge.
        with self.assertRaisesRegex(packet.EvidenceError, 'slot body'):
            packet.make_rows(changed)

    def test_call_target_and_opcode(self):
        site, expected = packet.CALLERS[0]
        self.assertEqual(self.image.call(site), expected)
        changed = packet.Image(self.mutated(site, 1))
        with self.assertRaisesRegex(packet.EvidenceError, 'opcode'):
            changed.call(site)
        changed = packet.Image(self.mutated(site + 1, 1))
        self.assertNotEqual(changed.call(site), expected)

    def test_exceptions_ranges_and_header_corruption(self):
        frame = self.frames[packet.COPIES[0]]
        _, _, rows = packet.lsda_rows(self.image, frame)
        self.assertEqual(rows[0], (0x28e0e7f, 0x28e0e93, 0x28e0f2f, 0))
        self.assertEqual(rows[2], (0x28e0f14, 0x28e0f2d, 0x28e0f4f, 0))
        bad = packet.Image(self.mutated(frame['lsda'], 1))
        with self.assertRaisesRegex(packet.EvidenceError, 'LSDA encoding'):
            packet.lsda_rows(bad, frame)
        bad = packet.Image(self.mutated(frame['lsda'] + 4, 1))
        with self.assertRaises((packet.EvidenceError, ValueError)):
            packet.lsda_rows(bad, frame)

    def test_relocated_growth_slots_and_corruption(self):
        slots = (0x5774438, 0x57744b8)
        self.assertEqual(packet.relative_relocations(self.image, slots),
                         {slots[0]: (8, packet.GROW), slots[1]: (8, packet.GROW)})
        sec = next(s for s in self.image.sections if s['type'] == 4 and
                   any(self.image.data[o:o + 8] == slots[0].to_bytes(8, 'little')
                       for o in range(s['offset'], s['offset'] + s['size'], 24)))
        offset = next(o for o in range(sec['offset'], sec['offset'] + sec['size'], 24)
                      if self.data[o:o + 8] == slots[0].to_bytes(8, 'little'))
        changed = bytearray(self.data)
        changed[offset + 16] ^= 1
        bad = packet.Image(changed)
        self.assertNotEqual(packet.relative_relocations(bad, slots)[slots[0]], (8, packet.GROW))
        with self.assertRaisesRegex(packet.EvidenceError, 'growth relocation'):
            packet.make_rows(changed)

    def test_file_mapping_rejects_bss_and_outside_image(self):
        bss = next(s for s in self.image.sections if s['name'] == '.bss')
        self.assertEqual(bss['type'], 8)
        with self.assertRaisesRegex(packet.EvidenceError, 'file-backed'):
            self.image.offset(bss['address'])
        with self.assertRaisesRegex(packet.EvidenceError, 'file-backed'):
            self.image.offset(1 << 62)
        with self.assertRaisesRegex(packet.EvidenceError, 'negative'):
            self.image.offset(packet.COPIES[0], -1)

    def test_growth_projection_append_reuse_and_failure(self):
        s = packet.simulate
        self.assertEqual(s(0, 0, 0, 0, 0, False, True, 1, 0), ('append', 1, 4, 1, 1, 0, 0, 0))
        self.assertEqual(s(4, 4, 4, 4, 4, False, True, 1, 2), ('append', 5, 8, 5, 5, 0, 0, 0))
        self.assertEqual(s(3, 3, 8, 3, 0, False, True, 1, 2), ('append', 4, 8, 4, 4, 0, 0, 0))
        self.assertEqual(s(1, 3, 8, 2, 7, True, True, 1, 2), ('reuse', 3, 8, 3, 7, 0, 0, 0))
        self.assertEqual(s(4, 3, 8, 2, 7, True, True, 1, 2), ('invalid-unwind', 3, 8, 3, 4, 1, 16, 0))
        self.assertEqual(s(1, 3, 8, 2, 7, False, True, 1, 2), ('invalid-unwind', 3, 8, 3, 1, 1, 16, 0))
        self.assertEqual(s(4, 4, 4, 4, 4, False, False, 1, 2), ('growth-unwind', 4, 4, 5, 4, 1, 16, 8))

    def test_growth_capacity_boundary_and_wrapping_projection(self):
        self.assertEqual([packet.growth_capacity(x) for x in range(5)], [4, 4, 4, 6, 8])
        self.assertEqual(packet.growth_capacity(1 << 63), 4)
        self.assertEqual(packet.growth_capacity(packet.U64), packet.U64 - 1)
        with self.assertRaisesRegex(packet.EvidenceError, 'outside u64'):
            packet.growth_capacity(packet.U64 + 1)

    def test_fde_start_corruption_is_rejected(self):
        fde = self.frames[packet.COPIES[0]]['fde']
        changed = self.mutated(fde + 8, 1)
        with self.assertRaises((packet.EvidenceError, ValueError)):
            packet.make_rows(changed)

    def test_source_location_path_corruption(self):
        slot = 0x56c73e8
        _, path = packet.relative_relocations(self.image, (slot,))[slot]
        changed = self.mutated(path, 1)
        with self.assertRaisesRegex(packet.EvidenceError, 'source location'):
            packet.make_rows(changed)

    def test_diagnostic_literal_corruption(self):
        literal = self.image.rip(packet.COPIES[0] + 0xd4, b'\x48\x8d\x3d')
        self.assertEqual(self.image.read(literal, 23), b'\x16expected vacant entry ')
        changed = self.mutated(literal + 1, 1)
        with self.assertRaisesRegex(packet.EvidenceError, 'diagnostic literal'):
            packet.make_rows(changed)

    def test_cleanup_gates_and_saturation(self):
        s = packet.simulate
        self.assertEqual(s(4, 4, 4, 4, 4, False, False, 2, 2)[5], 0)
        self.assertEqual(s(4, 4, 4, 4, 4, False, False, 1, 0)[5], 0)
        self.assertEqual(s(4, 3, 8, 2, 7, False, True, 2, 2)[5], 1)
        self.assertEqual(s(1, 3, 8, packet.U64, 7, True, True, 1, 2)[3], packet.U64)
        with self.assertRaisesRegex(packet.EvidenceError, 'outside u64'):
            s(-1, 0, 0, 0, 0, False, True, 1, 0)
        with self.assertRaisesRegex(packet.EvidenceError, 'outside u64'):
            s(0, 0, 0, 0, 0, False, True, 1, packet.U64 + 1)


if __name__ == '__main__':
    unittest.main()
