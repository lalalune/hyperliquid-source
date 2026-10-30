"""Target-grounded controls for the static staking profiles packet (no node execution)."""
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import staking_profiles_static as sp
from elf_index import sections


class StakingProfilesEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not sp.TARGET.is_file() or sp.TARGET.stat().st_size != 91774280:
            raise unittest.SkipTest('Requires materialized node #94 Git LFS input')
        cls.result = sp.inspect(sp.TARGET)
        cls.data = sp.TARGET.read_bytes()
        cls.sections = sections(cls.data)

    def offset(self, va):
        matches = [s for s in self.sections if s['type'] != 8
                   and s['address'] <= va < s['address'] + s['size']]
        self.assertEqual(len(matches), 1)
        s = matches[0]
        return s['offset'] + va - s['address']

    def mutated(self, va, raw):
        data = bytearray(self.data)
        off = self.offset(va)
        data[off:off + len(raw)] = raw
        return bytes(data)

    def test_retained_record_matches_authenticated_target(self):
        record = sp.ROOT / 'research/work-items/staking-profiles-94/evidence.json'
        self.assertEqual(self.result, json.loads(record.read_text()))

    def test_fde_bounds_and_body_identity(self):
        fn = self.result['function']
        self.assertEqual(fn['start_va'], '0x3366580')
        self.assertEqual(fn['end_va_exclusive'], '0x3366b60')
        self.assertEqual(fn['bytes'], 1504)
        self.assertEqual(fn['sha256'],
                         '00dda1b3f81eb9e94ca1a5730a61df3bd39cf2de26df135a07002e5df4358afe')

    def test_assert_anchor(self):
        panic = self.result['assert_panic']
        self.assertEqual(panic['message'], 'assertion failed: profiles.insert(validator_profile)')
        self.assertEqual(panic['line'], 243)
        self.assertEqual(panic['column'], 17)
        self.assertEqual(panic['path'], 'l1/src/staking.rs')

    def test_rustc_build_hash_and_stdlib_locations(self):
        std = self.result['stdlib_panics']
        self.assertEqual(std['rustc_commit'], 'e408947bfd200af42db322daf0fadfe7e26d3bd1')
        self.assertIn('navigate.rs:534:47', std['navigate']['locations'])
        self.assertIn(':161:36 (x1)', std['navigate']['locations'])
        self.assertIn('accum.rs:204:1', std['accum']['location'])
        self.assertIn('panics on delegator-sum overflow', std['divergence'])

    def test_identity_rejects_truncation_and_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'input'
            path.write_bytes(self.data[:4096])
            with self.assertRaisesRegex(ValueError, 'size/SHA-256'):
                sp.inspect(path)
            path.write_bytes(self.mutated(sp.START, b'\x90'))
            with self.assertRaisesRegex(ValueError, 'size/SHA-256'):
                sp.inspect(path)

    def test_body_and_fde_mutations_rejected(self):
        for va in (sp.START, sp.START + 0xc2, sp.START + 0x54c, sp.START + 0x2f7):
            with self.assertRaisesRegex(ValueError, 'Staking body bytes changed'):
                sp.analyze(self.mutated(va, b'\xcc'))
        with self.assertRaisesRegex(ValueError, 'Staking FDE record changed'):
            sp.analyze(self.mutated(sp.FDE_VA + 8, b'\x33\x33\x33\x33'))

    def test_anchor_mutations_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Assert message changed'):
            sp.analyze(self.mutated(sp.ASSERT_MSG_VA + 10, b'X'))
        with self.assertRaisesRegex(ValueError, 'Assert Location layout changed'):
            sp.analyze(self.mutated(sp.ASSERT_LOC + 8, struct.pack('<I', 244)))
        with self.assertRaisesRegex(ValueError, 'staking path changed'):
            sp.analyze(self.mutated(sp.PATH_VA + 8, b'X'))
        with self.assertRaisesRegex(ValueError, 'Stdlib Location layout changed'):
            sp.analyze(self.mutated(sp.ACCUM_LOC + 8, struct.pack('<I', 205)))

    def test_relocation_mutations_rejected(self):
        rela = next(s for s in self.sections if s['name'] == '.rela.dyn')
        raw = self.data[rela['offset']:rela['offset'] + rela['size']]
        slots = {}
        for off in range(0, len(raw), 24):
            address, info, addend = struct.unpack_from('<QQq', raw, off)
            if info == 8 and address in (sp.GOT_ASSERT_PANIC, sp.GOT_NAV_PANIC,
                                         sp.GOT_ACCUM_PANIC, sp.GOT_SELF,
                                         sp.ASSERT_LOC, sp.ACCUM_LOC):
                slots[address] = (rela['address'] + off, addend)
        self.assertEqual(len(slots), 6)
        messages = {sp.GOT_ASSERT_PANIC: 'Assert panic callee changed',
                    sp.GOT_NAV_PANIC: 'Navigate panic callee changed',
                    sp.GOT_ACCUM_PANIC: 'Accum panic callee changed',
                    sp.GOT_SELF: 'Self GOT slot changed',
                    sp.ASSERT_LOC: 'Assert Location relocation changed',
                    sp.ACCUM_LOC: 'Stdlib Location path changed'}
        for va, (slot_va, addend) in slots.items():
            with self.assertRaisesRegex(ValueError, messages[va]):
                sp.analyze(self.mutated(slot_va + 16, struct.pack('<q', addend + 4)))

    def test_call_census(self):
        census = self.result['call_census']
        self.assertEqual(census['got_indirect'], ['0x3369dd1'])
        self.assertEqual(census['direct_e8'], 0)
        self.assertEqual(census['lea_references'], 0)
        self.assertEqual(census['containing_function'], {'start': '0x3369db0', 'end': '0x336a360'})


if __name__ == '__main__':
    unittest.main()
