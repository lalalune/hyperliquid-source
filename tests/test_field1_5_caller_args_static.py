import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from field1_5_caller_args_static import (MEMCPY_SLOT, OWNERS, PACKET,
                                         SHA, SIZE, TARGET, analyze,
                                         generate)
from elf_index import sections


def payload(path):
    return json.loads(Path(path).read_text())


class Field15CallerArgsStaticTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not TARGET.exists() or TARGET.stat().st_size != SIZE:
            raise unittest.SkipTest('pinned node115 target is not '
                                    'materialised')
        cls.data = TARGET.read_bytes()
        if hashlib.sha256(cls.data).hexdigest() != SHA:
            raise unittest.SkipTest('target digest is not the pinned '
                                    'node115 distribution')
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
        for name in ('frames.txt', 'twin_a.objdump.txt',
                     'twin_b.objdump.txt', 'bulk_a.objdump.txt',
                     'bulk_b.objdump.txt', 'bulk_helper.objdump.txt'):
            self.assertEqual((regen_dir / name).read_bytes(),
                             (PACKET / name).read_bytes(), name)

    def test_six_call_sites_and_state_forwarding(self):
        sites = self.payload['call_sites']
        self.assertEqual(sites['twin_a']['u32_call']['site'], '0x26e5725')
        self.assertEqual(sites['twin_a']['field1_5_call']['site'],
                         '0x26e583f')
        self.assertEqual(sites['twin_b']['u32_call']['site'], '0x5aaa475')
        self.assertEqual(sites['twin_b']['field1_5_call']['site'],
                         '0x5aaa58f')
        bulk_a = [c['site'] for c in sites['bulk_a']['field1_5_calls']]
        bulk_b = [c['site'] for c in sites['bulk_b']['field1_5_calls']]
        self.assertEqual(bulk_a, ['0x2cd9726', '0x2cd9741'])
        self.assertEqual(bulk_b, ['0x5968872', '0x596888a'])
        self.assertEqual(sites['bulk_b']['helper_call']['site'],
                         '0x59688a2')
        census = sites['field1_5_census']
        self.assertEqual(len(census['copy_a']), 3)
        self.assertEqual(len(census['copy_b']), 3)
        self.assertEqual(census['slow'], [])
        # Every field1-5 state argument is the caller's own entry
        # state: the entry register on the first call of a pair, the
        # callee-saved copy of it afterwards.
        for role in ('twin_a', 'twin_b'):
            self.assertIn('entry', sites[role]['u32_call']['state'])
            self.assertIn('entry', sites[role]['field1_5_call']['state'])
        self.assertIn('entry', bulk_a and
                      sites['bulk_a']['field1_5_calls'][0]['state'])

    def test_mode_and_limit_never_written(self):
        access = self.payload['state_field_access']
        for role, inv in access.items():
            self.assertNotIn('+0x0', inv['stores'], role)
            self.assertNotIn('+0x8', inv['stores'], role)
        # bulk_b never touches a state field directly at all: the
        # mode/limit reads for its record happen inside the helper.
        self.assertEqual(access['bulk_b'], {'reads': [], 'stores': []})
        for role in ('twin_a', 'twin_b', 'bulk_a', 'bulk_helper'):
            self.assertIn('+0x0', access[role]['reads'], role)
            self.assertIn('+0x8', access[role]['reads'], role)
            self.assertEqual(access[role]['stores'],
                             ['+0x10', '+0x18', '+0x20'], role)
        state = self.payload['reader_state']
        self.assertIn('written by none', state['mode'])
        self.assertIn('written by none', state['limit'])

    def test_inline_charge_rules(self):
        charges = self.payload['inline_charges']
        self.assertEqual(charges['twin_inline']['amount'], 1)
        self.assertEqual(charges['bulk_a_inline']['amount'], '0x800')
        self.assertEqual(charges['bulk_helper']['amount'], '0x800')
        # The twin compares the OLD charged count (refusal at >=
        # limit after storing +1); the bulk blocks compare the NEW
        # count (refusal at > limit after storing +0x800). Both are
        # the same success bound as the readers' own charges.
        self.assertIn('OLD charged count >= limit',
                      charges['twin_inline']['rule'])
        self.assertIn('NEW charged count > limit',
                      charges['bulk_a_inline']['rule'])
        self.assertIn('new charged count <= limit',
                      charges['uniform_bound'])
        # The twin's four-byte read is committed to the state before
        # its charge is evaluated; the flag byte after it is gated.
        self.assertIn('advanced by four bytes',
                      charges['twin_inline']['committed_before_charge'])

    def test_cross_family_finding(self):
        cross = self.payload['cross_family']
        self.assertEqual(
         cross['u32_inside_owners'],
         [{'site': '0x26e5725', 'containing_fde': '0x26e5710..0x26e58d8'},
          {'site': '0x5aaa475', 'containing_fde': '0x5aaa460..0x5aaa628'}])
        self.assertEqual(cross['u64_inside_owners'], [])
        self.assertIn('field1 5', cross['finding'])

    def test_twin_bodies_differ_only_in_displacements(self):
        def body(va):
            off = self.offset_of(va)
            return self.data[off:off + 456]
        ta, tb = body(0x26e5710), body(0x5aaa460)
        diff = [i for i in range(456) if ta[i] != tb[i]]
        runs = []
        for i in diff:
            if runs and i == runs[-1][1] + 1:
                runs[-1][1] = i
            else:
                runs.append([i, i])
        self.assertEqual([(hex(a), hex(b)) for a, b in runs],
                         [('0x16', '0x19'), ('0x34', '0x37'),
                          ('0x40', '0x43'), ('0x130', '0x133')])

    def test_direct_caller_census(self):
        callers = self.payload['direct_callers']
        self.assertEqual(callers['twin_a']['direct_calls'], [])
        self.assertEqual(callers['twin_a']['lea_references'],
                         ['0x2dd298e'])
        self.assertEqual(callers['twin_b']['lea_references'],
                         ['0x4de621e'])
        self.assertEqual(
         [c['site'] for c in callers['bulk_a']['direct_calls']],
         ['0x2ce1e4d', '0x2ce20e6', '0x2ce230b'])
        self.assertEqual(
         [c['site'] for c in callers['bulk_b']['direct_calls']],
         ['0x4e05c56', '0x4e05ca0', '0x4e05ce5'])
        self.assertFalse(self.payload['captured_code_executed'])

    def test_twin_mode_counterfactual(self):
        data = self.mutated(0x26e57e3, 3, 0x02)
        with self.assertRaisesRegex(ValueError,
                                    'inline charge mode == 1 test'):
            analyze(data)

    def test_twin_charge_increment_counterfactual(self):
        data = self.mutated(0x26e5802, 3, 0x02)
        with self.assertRaisesRegex(ValueError,
                                    'inline charge increment 1'):
            analyze(data)

    def test_twin_field1_5_target_counterfactual(self):
        data = self.mutated(0x26e583f, 1, 0x6d)
        with self.assertRaisesRegex(ValueError,
                                    'field1-5 call target changed'):
            analyze(data)

    def test_twin_b_u32_target_counterfactual(self):
        data = self.mutated(0x5aaa475, 1, 0xd7)
        with self.assertRaisesRegex(ValueError, 'u32 call target changed'):
            analyze(data)

    def test_named_string_counterfactual(self):
        data = self.mutated(0x5f430e, 0, 0x58)
        with self.assertRaisesRegex(ValueError,
                                    'named string bytes changed'):
            analyze(data)

    def test_bulk_a_charge_increment_counterfactual(self):
        data = self.mutated(0x2cd9771, 4, 0x04)
        with self.assertRaisesRegex(ValueError,
                                    'inline charge increment 0x800'):
            analyze(data)

    def test_bulk_b_helper_target_counterfactual(self):
        data = self.mutated(0x59688a2, 1, 0x0a)
        with self.assertRaisesRegex(ValueError,
                                    'helper call target changed'):
            analyze(data)

    def test_helper_mode_counterfactual(self):
        data = self.mutated(0x58214b3, 2, 0x02)
        with self.assertRaisesRegex(ValueError,
                                    'helper charge mode == 1 test'):
            analyze(data)

    def test_memcpy_relocation_counterfactual(self):
        data = bytearray(self.data)
        sec = next(s for s in sections(self.data)
                   if s['name'] == '.rela.dyn')
        for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
            r_offset, _, _ = struct.unpack_from('<QQq', self.data, off)
            if r_offset == MEMCPY_SLOT:
                struct.pack_into('<q', data, off + 16, 1)
                break
        else:
            self.fail('memcpy slot relocation not found')
        with self.assertRaisesRegex(ValueError,
                                    'memcpy slot addend changed'):
            analyze(bytes(data))

    def test_frame_record_counterfactual(self):
        data = self.mutated(0xd45d3c, 24, 0x42)
        with self.assertRaisesRegex(ValueError, 'frame records changed'):
            analyze(data)

    def test_public_identity_rejection(self):
        output = Path(tempfile.mkdtemp()) / 'packet'
        wrong = Path(tempfile.mkdtemp()) / 'wrong'
        wrong.write_bytes(self.data[:SIZE // 2])
        with self.assertRaisesRegex(ValueError, 'pinned node115'):
            generate(wrong, output)
        self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
