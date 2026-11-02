"""Controls for the static blob-price lift. No target code is executed."""
import hashlib
from pathlib import Path
import unittest
from unittest.mock import patch

from tools import blob_wei_price as p


class BlobWeiPrice(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = (p.ROOT / p.BINARY).read_bytes()
        cls.sections, cls.fdes = p.validate(cls.data)

    def test_fdes_and_input(self):
        self.assertEqual(p.digest(self.data), p.SHA)
        self.assertEqual(len(self.fdes), 4)
        self.assertEqual({f['start'] for f in self.fdes}, set(p.BODIES))
        self.assertTrue(all(f['end'] > f['start'] for f in self.fdes))

    def test_duplicate_selected_fde_is_rejected(self):
        with patch.object(p.fde_extents, 'eh_frame_records', return_value=({}, [self.fdes[0], self.fdes[0]])):
            with self.assertRaisesRegex(ValueError, 'ambiguous selected FDE'):
                p.image(self.data)

    def test_bad_digest(self):
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            p.validate(self.data, '0' * 64)

    def test_malformed_elf_with_recomputed_digest(self):
        mutated = bytearray(self.data)
        mutated[0] = 0
        with self.assertRaises(ValueError):
            p.validate(mutated, p.digest(mutated))

    def test_body_corruption_even_with_recomputed_digest(self):
        mutated = bytearray(self.data)
        sec = next(s for s in self.sections if s['name'] == '.text')
        pos = sec['offset'] + 0x4ea1e2d - sec['address']
        mutated[pos] ^= 1
        with self.assertRaisesRegex(ValueError, 'function bytes'):
            p.validate(mutated, hashlib.sha256(mutated).hexdigest())

    def test_window_corruption_after_matching_body_hash(self):
        mutated = bytearray(self.data)
        sec = next(s for s in self.sections if s['name'] == '.text')
        mutated[sec['offset'] + 0x4ea1e2d - sec['address']] ^= 1
        fde = next(f for f in self.fdes if f['start'] == 0x4ea1e00)
        newbody = p.at(mutated, self.sections, fde['start'], fde['end'] - fde['start'])
        with patch.dict(p.BODIES, {0x4ea1e00: p.digest(newbody)}):
            with self.assertRaisesRegex(ValueError, 'instruction window'):
                p.validate(mutated, p.digest(mutated))

    def test_unbacked_address(self):
        bss = next(s for s in self.sections if s['name'] == '.bss' and s['type'] == 8 and s['size'])
        with self.assertRaises(ValueError):
            p.at(self.data, self.sections, bss['address'], 1)
        with self.assertRaises(ValueError):
            p.at(self.data, self.sections, 1 << 63, 1)
        with self.assertRaises(ValueError):
            p.at(self.data, self.sections, 0, -1)
        with self.assertRaises(ValueError):
            p.at(self.data, self.sections, 0, 1)

    def test_source_locations(self):
        locs = p.locations(self.data, self.sections)
        self.assertEqual(len(locs), 11)
        self.assertTrue(any(row[-1].endswith('eip4844/mod.rs') for row in locs))
        self.assertTrue(any(row[-1].endswith('revm-primitives-15.1.0/src/utilities.rs') for row in locs))

    def test_handler_location_references(self):
        locs = p.locations(self.data, self.sections)
        handlers = p.handler_rows(self.data, self.sections, locs)
        self.assertEqual(len(handlers), 17)
        self.assertEqual(handlers[0][3], '0x574f898')
        changed = bytearray(self.data)
        text = next(s for s in self.sections if s['name'] == '.text')
        changed[text['offset'] + 0x4ea1fd6 - text['address']] ^= 1
        with self.assertRaisesRegex(ValueError, 'location'):
            p.handler_rows(changed, self.sections, locs)

    def test_limb_multiply(self):
        operands = [0, 1, 2, (1 << 32)-1, (1 << 63), p.MASK, 1 << 64, (1 << 127), p.MAX128]
        multipliers = [0, 1, 2, (1 << 32)-1, 1 << 63, p.MASK]
        for a in operands:
            for x in multipliers:
                expected = a*x if a*x <= p.MAX128 else None
                self.assertEqual(p.checked_mul_128_64(a, x), expected, (a, x))
        for a in range(256):
            for x in range(256):
                self.assertEqual(p.checked_mul_128_64(a, x), a*x)

    def test_checked_add(self):
        values = [0, 1, p.MASK, 1 << 64, 1 << 127, p.MAX128]
        for a in values:
            for b in values:
                self.assertEqual(p.checked_sum(a,b), a+b if a+b <= p.MAX128 else None)

    def test_mismatch_rejected_for_bad_inputs(self):
        for x in (-1, 1 << 64):
            with self.assertRaises(ValueError):
                p.lifted(x, 3338477)
        with self.assertRaises(ValueError):
            p.lifted(1, 0)
        with self.assertRaises(ValueError):
            p.generic(0, 1 << 128, 1)

    def test_byte_walk_and_unknown_instruction(self):
        for d in (3338477, 5007716):
            edge = p.threshold(d)[0]
            for x in (0, 1, d, 3*d, 22*d, edge, edge+1, p.MASK):
                self.assertEqual(p.execute_fixed_loop(self.data, self.sections, x, d), p.specification(x,d))
        mutated = bytearray(self.data)
        sec = next(s for s in self.sections if s['name'] == '.text')
        mutated[sec['offset'] + 0x4ea1f00 - sec['address']] = 0xcc
        with self.assertRaisesRegex(ValueError, 'unmodeled instruction'):
            p.execute_fixed_loop(mutated, self.sections, 1, 3338477)

    def test_boundaries(self):
        expected = {3338477: (192204552, 58), 5007716: (284284038, 57)}
        for d, (limit, iteration) in expected.items():
            a, got, b, refused = p.threshold(d)
            self.assertEqual((a, b), (limit, limit + 1))
            self.assertEqual(got[0], 'ok')
            self.assertEqual(refused[:2], ('term_product_overflow', iteration))
            self.assertEqual(got, p.specification(a, d))
            self.assertEqual(refused, p.specification(b, d))

    def test_generic_and_fixed_agree(self):
        for d in (3338477, 5007716):
            boundary = p.threshold(d)[0]
            for x in (0, 1, d, 3*d, 22*d, boundary, boundary+1, p.MASK):
                actual = p.lifted(x,d)
                generic = p.generic(x,d,1)
                self.assertEqual(generic[0],actual[0])
                if actual[0] == 'ok':
                    self.assertEqual(generic[1],actual[2])
        self.assertEqual(p.generic(0, 0, 1, False), ('absent', None))
        self.assertEqual(p.generic(0, 0, 1, True), ('zero_denominator', None))
        self.assertEqual(p.generic(0, p.MAX128, 2), ('initial_product_overflow', None))
        self.assertEqual(p.generic(0, 3338477, 0), ('ok', 0))

    def test_branch_displacements_and_corruption(self):
        rows = p.branch_rows(self.data, self.sections)
        self.assertEqual(len(rows), 38)
        mutated = bytearray(self.data)
        sec = next(s for s in self.sections if s['name'] == '.text')
        mutated[sec['offset'] + 0x4ea1f6b - sec['address']] ^= 1
        with self.assertRaisesRegex(ValueError, 'branch target'):
            p.branch_rows(mutated, self.sections)

    def test_selector_and_relocation_links(self):
        links = p.call_links(self.data, self.sections)
        self.assertEqual(len(links), 8)
        self.assertEqual(links[0][-1], '0x4ea1e00')
        sel = p.select_excess
        self.assertEqual(sel(17,0,0,False,False,393216,786432), ('call',0,0))
        self.assertEqual(sel(18,0,0,False,False,393216,786432), ('skip',None,1))
        self.assertEqual(sel(18,786432,1,True,True,393216,786432), ('call',1,1))
        self.assertEqual(sel(18,p.MASK,1,True,True,393216,786432), ('addition_overflow',None,1))
        with self.assertRaises(ValueError):
            sel(256,0,0,True,True,393216,786432)

    def test_relocated_call_target_corruption(self):
        changed = bytearray(self.data)
        text = next(s for s in self.sections if s['name'] == '.text')
        changed[text['offset'] + 0x4e4ae93 - text['address']] ^= 1
        with self.assertRaises(ValueError):
            p.call_links(changed, self.sections)

    def test_all_version_and_presence_values(self):
        for version in range(256):
            for a in (False, True):
                for b in (False, True):
                    outcome, amount, flag = p.select_excess(version, 393216, 1, a, b, 393216, 786432)
                    if a and b:
                        self.assertEqual((outcome, amount, flag), ('call', 0 if version >= 18 else 1, int(version >= 18)))
                    elif version == 17:
                        self.assertEqual((outcome, amount, flag), ('call', 0, 0))
                    else:
                        self.assertEqual((outcome, amount, flag), ('skip', None, int(version >= 18)))

    def test_parent_gates(self):
        self.assertEqual(p.parent_excess(1,2,1), ('ok',0))
        self.assertEqual(p.parent_excess(131073,262144,3), ('ok',1))
        self.assertEqual(p.parent_excess(p.MASK,1,0), ('addition_overflow',None))
        self.assertEqual(p.parent_excess(0,0,1 << 47), ('target_product_overflow',None))
        self.assertEqual(p.parent_excess(p.MASK,1,1 << 47,False), ('absent',None))

    def test_saturation_differs_from_checked(self):
        d = 3338477
        edge = p.threshold(d)[0]
        self.assertEqual(p.saturating_comparison(edge, d), p.lifted(edge, d)[2])
        self.assertEqual(p.lifted(edge + 1, d)[0], 'term_product_overflow')
        self.assertEqual(p.saturating_comparison(edge + 1, d), 10079295377470422497392048)

    def test_staged_rounding_differs_from_ideal(self):
        for d, multiple, staged in ((3338477,21,1318815733),(5007716,22,3584912845)):
            x = d*multiple
            self.assertEqual(p.lifted(x,d)[2], staged)
            self.assertEqual(p.exponential_floor(x,d)[0], staged+1)


if __name__ == '__main__':
    unittest.main()
