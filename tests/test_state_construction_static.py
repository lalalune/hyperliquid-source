import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from state_construction_static import (OWNERS, PACKET, SHA, SIZE,
                                       SLOTS, TARGET, analyze,
                                       generate)
from elf_index import sections


def payload(path):
    return json.loads(Path(path).read_text())


class StateConstructionStaticTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not TARGET.exists() or TARGET.stat().st_size != SIZE:
            raise unittest.SkipTest('pinned node115 target is not '
                                    'materialised')
        cls.data = TARGET.read_bytes()
        if hashlib.sha256(cls.data).hexdigest() != SHA:
            raise unittest.SkipTest('target digest is not the '
                                    'pinned node115 distribution')
        cls.retained = payload(PACKET / 'records.json')
        cls.payload = analyze(cls.data)
        cls.regenerated = generate(TARGET, tempfile.mkdtemp())

    def mutated(self, va, delta, value):
        data = bytearray(self.data)
        offset = self.offset_of(va)
        data[offset + delta] = value
        return data

    def offset_of(self, va):
        for s in sections(self.data):
            if (s['type'] != 8 and s['address'] <= va
                    < s['address'] + s['size']):
                return s['offset'] + va - s['address']
        raise AssertionError('unmapped va')

    def test_native_regeneration_matches_retained_packet(self):
        self.assertEqual(self.regenerated, self.retained)
        self.assertEqual(self.payload, self.retained)
        regen_dir = Path(tempfile.mkdtemp())
        generate(TARGET, regen_dir)
        names = ['frames.txt'] + [f'{role}.objdump.txt'
                                  for role in OWNERS]
        for name in names:
            self.assertEqual((regen_dir / name).read_bytes(),
                             (PACKET / name).read_bytes(), name)

    def test_seventeen_owners(self):
        self.assertEqual(len(self.payload['owners']), 17)
        roles = {o['role'] for o in self.payload['owners']}
        self.assertEqual(roles, set(OWNERS))

    def test_mode_is_the_constant_one(self):
        self.assertIn('constant 1', self.payload['mode_value'])
        cons = self.payload['construction']
        for spine in ('bulk_a', 'twin_a', 'twin_b'):
            self.assertIn('constant 1',
                          cons[spine]['constructor']['fields']
                          ['mode'], spine)
        self.assertIn('constant 1',
                      cons['bulk_b']['mode_supplier']
                      ['mode_argument'])
        self.assertIn('rcx argument',
                      cons['bulk_b']['constructor']['fields']
                      ['mode'])
        # Twelve construction sites in total.
        sites = (len(cons['bulk_a']['constructor']['call_sites'])
                 + len(cons['twin_a']['constructor']['call_sites'])
                 + len(cons['twin_b']['constructor']['call_sites'])
                 + len(cons['bulk_b']['mode_supplier']
                       ['call_sites']))
        self.assertEqual(sites, 12)

    def test_charged_starts_at_zero(self):
        self.assertIn('constant 0', self.payload['charged_value'])
        cons = self.payload['construction']
        for spine in ('bulk_a', 'twin_a', 'bulk_b', 'twin_b'):
            self.assertIn('constant 0',
                          cons[spine]['constructor']['fields']
                          ['charged'], spine)

    def test_limit_provenance(self):
        limit = self.payload['limit_value']
        for needle in ('[rbx+0x220]', '[rbx+0x180]', '[rbx+0xa60]',
                       '[[view+0x10]]', 'never a constant'):
            self.assertIn(needle, limit)
        tops = {s: self.payload['construction'][s]['top_caller']
                for s in ('bulk_a', 'twin_a', 'twin_b')}
        self.assertIn('0x220', tops['bulk_a']['limit'])
        self.assertIn('0x180', tops['twin_a']['limit'])
        self.assertIn('0xa60', tops['twin_b']['limit'])
        cons = self.payload['construction']
        self.assertEqual(cons['bulk_b']['view_builder']
                         ['limit_consequence'],
                         cons['twin_b']['view_builder']
                         ['limit_consequence'].replace(
                             'twin-b', 'bulk-b'))

    def test_twin_a_site3_limit_boundary(self):
        fields = (self.payload['construction']['twin_a']
                  ['constructor']['fields'])
        self.assertIn('+0x28', fields['limit'])
        self.assertIn('0x26ff330', fields['limit'])
        self.assertIn('twin_a_site_3_limit',
                      self.payload['boundaries'])

    def test_helper_mechanics(self):
        reg = self.payload['twin_registration']
        for role in ('helper_a', 'helper_b'):
            h = reg[role]
            self.assertEqual(h['element_size'], '0x18')
            self.assertEqual(h['capacity_cap'],
                             '0xaaaa elements')
            self.assertEqual(h['element_call']['form'],
                             'call r14 (the saved rdx)')
            self.assertIn('count * 0x18', h['bulk_charge'])
            self.assertIn('0x18 subtracted',
                          h['element_refund'])
        self.assertEqual(reg['helper_a']['count_call']['target'],
                         '0x2cd7ac0')
        self.assertEqual(reg['helper_b']['count_call']['target'],
                         '0x5821250')
        self.assertEqual(reg['helper_a']['element_call']['site'],
                         '0x232cebc')
        self.assertEqual(reg['helper_b']['element_call']['site'],
                         '0x58252cc')
        self.assertIn('nine 4-byte displacement fields',
                      reg['body_relation'])
        wrap = reg['wrappers']['wrap_twin_a']
        self.assertEqual(wrap['decoder'], '0x26e5710')
        self.assertEqual(wrap['helper'], '0x232cd90')
        wrap_b = reg['wrappers']['wrap_twin_b']
        self.assertEqual(wrap_b['decoder'], '0x5aaa460')
        self.assertEqual(wrap_b['helper'], '0x58251a0')

    def test_call_census_exact(self):
        census = self.payload['call_census']
        self.assertEqual(census['twin_a']['direct_calls'], [])
        self.assertEqual(census['twin_a']['lea_references'],
                         ['0x2dd298e'])
        self.assertEqual(census['twin_b']['lea_references'],
                         ['0x4de621e'])
        for role in OWNERS:
            self.assertEqual(census[role]['lea_references'], [],
                             role)
        self.assertEqual(
         [c['site'] for c in census['ctor_bulk_b']
          ['direct_calls']],
         ['0x4e484a1', '0x4e48516', '0x4e48609'])
        self.assertEqual(
         [c['site'] for c in census['bulk_a']['direct_calls']],
         ['0x2ce1e4d', '0x2ce20e6', '0x2ce230b'])
        self.assertEqual(
         [c['site'] for c in census['bulk_b']['direct_calls']],
         ['0x4e05c56', '0x4e05ca0', '0x4e05ce5'])
        self.assertFalse(self.payload['captured_code_executed'])

    def test_reader_calls_inside(self):
        inside = self.payload['reader_calls_inside']
        self.assertEqual(inside['u64_copy_a']['helper_a'],
                         ['0x232cdac'])
        self.assertEqual(inside['u64_copy_b']['helper_b'],
                         ['0x58251bc'])
        self.assertEqual(inside['u32_copy_b']['ctor_bulk_b'],
                         ['0x5821ae8'])
        self.assertEqual(len(inside['u64_copy_b']
                             ['ctor_bulk_b']), 5)

    def test_slot_relocations(self):
        reloc = self.payload['relocations']
        self.assertEqual(set(reloc), {hex(s) for s in SLOTS})
        for slot, target in SLOTS.items():
            self.assertEqual(reloc[hex(slot)]['type'], 8)
            self.assertEqual(reloc[hex(slot)]['addend_target'],
                             hex(target))

    def test_ctor_bulk_a_mode_counterfactual(self):
        data = self.mutated(0x26fea0b, 5, 0x02)
        with self.assertRaisesRegex(
                ValueError, 'mode store at state \\+0x0 is the '
                            'immediate 1'):
            analyze(data)

    def test_ctor_twin_a_mode_counterfactual(self):
        data = self.mutated(0x26ff5e9, 8, 0x03)
        with self.assertRaisesRegex(ValueError,
                                    'third-site mode store'):
            analyze(data)

    def test_ctor_twin_b_mode_counterfactual(self):
        data = self.mutated(0x4e4673a, 5, 0x02)
        with self.assertRaisesRegex(
                ValueError, 'mode store at state \\+0x0 is the '
                            'immediate 1'):
            analyze(data)

    def test_mode_caller_argument_counterfactual(self):
        data = self.mutated(0x4e4850b, 1, 0x02)
        with self.assertRaisesRegex(
                ValueError, 'site 2 mode argument is the '
                            'immediate 1'):
            analyze(data)

    def test_ctor_bulk_a_limit_store_counterfactual(self):
        data = self.mutated(0x26fea14, 0, 0x4d)
        with self.assertRaisesRegex(ValueError,
                                    'limit store at state \\+0x8'):
            analyze(data)

    def test_helper_charge_size_counterfactual(self):
        data = self.mutated(0x232cdc5, 1, 0x19)
        with self.assertRaisesRegex(ValueError,
                                    'bulk charge element size'):
            analyze(data)

    def test_helper_element_call_register_counterfactual(self):
        data = self.mutated(0x232cebc, 2, 0xd5)
        with self.assertRaisesRegex(
                ValueError, 'element decoder called through '
                            'the saved rdx register'):
            analyze(data)

    def test_helper_u64_target_counterfactual(self):
        data = self.mutated(0x232cdac, 1, 0x0e)
        with self.assertRaisesRegex(ValueError,
                                    'u64 count call target'):
            analyze(data)

    def test_wrap_lea_target_counterfactual(self):
        data = self.mutated(0x2dd298e, 3, 0x7a)
        with self.assertRaisesRegex(ValueError,
                                    'twin lea target changed'):
            analyze(data)

    def test_forwarder_target_counterfactual(self):
        data = self.mutated(0x2ceaf98, 1, 0x22)
        with self.assertRaisesRegex(ValueError,
                                    'downward call target'):
            analyze(data)

    def test_top_caller_target_counterfactual(self):
        data = self.mutated(0x2b688b4, 1, 0x86)
        with self.assertRaisesRegex(ValueError,
                                    'constructor call target'):
            analyze(data)

    def test_helper_twin_diff_counterfactual(self):
        data = self.mutated(0x5825210, 0, 0x0e)
        with self.assertRaisesRegex(
                ValueError, 'helper bodies differ outside the '
                            'displacement fields'):
            analyze(data)

    def test_slot_relocation_counterfactual(self):
        data = bytearray(self.data)
        sec = next(s for s in sections(self.data)
                   if s['name'] == '.rela.dyn')
        for off in range(sec['offset'],
                         sec['offset'] + sec['size'], 24):
            r_offset, _, _ = struct.unpack_from(
             '<QQq', self.data, off)
            if r_offset == 0x64df480:
                struct.pack_into('<q', data, off + 16,
                                 SLOTS[0x64df480] + 1)
        with self.assertRaisesRegex(ValueError,
                                    'slot 0x64df480 relocation'):
            analyze(bytes(data))


if __name__ == '__main__':
    unittest.main()
