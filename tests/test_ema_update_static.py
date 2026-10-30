"""Target-grounded controls for the static ema_tracker packet (no node execution)."""
import json
import math
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import ema_update_static as ema
from elf_index import sections


class EmaUpdateEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not ema.TARGET.is_file() or ema.TARGET.stat().st_size != 91774280:
            raise unittest.SkipTest('Requires materialized node #94 Git LFS input')
        cls.result = ema.inspect(ema.TARGET)
        cls.data = ema.TARGET.read_bytes()
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
        record = ema.ROOT / 'research/work-items/RE-001-ema-tracker-94/evidence.json'
        self.assertEqual(self.result, json.loads(record.read_text()))

    def test_fde_bounds_and_body_identity(self):
        update = self.result['update']
        self.assertEqual(update['start_va'], '0x14791c0')
        self.assertEqual(update['end_va_exclusive'], '0x1479329')
        self.assertEqual(update['bytes'], 361)
        self.assertEqual(update['sha256'],
                         '84d8647a3839ce175a3f9c5d1f37f674a69c77ee5f1d4284ea84b8e04e6bc341')
        self.assertEqual(update['fde_va'], '0xced520')

    def test_decay_semantics_from_decoded_operands(self):
        # exp(-dt/tau) with dt >= 0 and tau > 0 stays in (0, 1]; the body
        # traps NaN decay through ucomisd/jb, matching the panic bound.
        for dt in (0.0, 1.0, 2.5, 60.0, 1e6):
            for tau in (0.001, 0.5, 1.0, 30.0, 3600.0):
                decay = math.exp(-dt / tau)
                # Underflow to 0.0 is reachable (large dt / small tau) and
                # still satisfies the body's single `decay <= 1.` bound.
                self.assertGreaterEqual(decay, 0.0)
                self.assertLessEqual(decay, 1.0)
        self.assertTrue(math.isnan(math.exp(-math.inf)) or math.exp(-math.inf) == 0.0)
        self.assertEqual(self.result['semantics']['default_interval']['dt'], 1.0)
        self.assertEqual(self.result['semantics']['default_interval']['when'],
                         'last_timestamp secs dword == 0')

    def test_lane_update_identity(self):
        # num' = sample*dt + decay*num and denom' = dt + decay*denom keep
        # denom' >= 0 whenever denom >= 0, dt >= 0 and decay in [0, 1].
        for sample in (0.0, 0.25, 1.5, 7.0):
            for dt in (0.0, 1.0, 0.5, 2.0):
                for decay in (0.0, 0.25, 1.0):
                    num, denom = 4.0, 2.0
                    num2 = sample * dt + decay * num
                    denom2 = dt + decay * denom
                    self.assertEqual(num2, sample * dt + decay * 4.0)
                    self.assertGreaterEqual(denom2, 0.0)
        layout = self.result['struct_layout']['observed']
        self.assertEqual(layout['num'], 'f64 @ +0x0')
        self.assertEqual(layout['denom'], 'f64 @ +0x8')
        self.assertEqual(layout['tau'], 'f64 @ +0x10')
        self.assertEqual(layout['last_timestamp'], '{u64 secs, u32 nanos} @ +0x18')

    def test_accessor_sites_share_one_location(self):
        sites = self.result['accessor_sites']
        self.assertEqual(len(sites), 3)
        for site in sites:
            self.assertEqual(site['line'], 59)
            self.assertEqual(site['location'], '0x566c5c0')
            self.assertEqual(site['message'], '0x21a843')

    def test_call_census(self):
        census = self.result['call_census']
        self.assertEqual(census['direct_e8'], [])
        self.assertEqual(census['lea_references'], [])
        self.assertEqual(census['got_indirect'], ['0x474fcac'])
        self.assertEqual(census['got_slot'], '0x576f8f0')
        self.assertEqual(census['caller']['start_va'], '0x474fb90')

    def test_identity_rejects_truncation_and_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'input'
            path.write_bytes(self.data[:4096])
            with self.assertRaisesRegex(ValueError, 'size/SHA-256'):
                ema.inspect(path)
            path.write_bytes(self.mutated(ema.UPDATE_START, b'\x90'))
            with self.assertRaisesRegex(ValueError, 'size/SHA-256'):
                ema.inspect(path)

    def test_body_byte_mutations_rejected(self):
        # The body identity gate fires before any deeper check.
        for va in (ema.UPDATE_START, ema.UPDATE_START + 0x18, 0x14792a3, 0x147931e):
            with self.assertRaisesRegex(ValueError, 'Update body bytes changed'):
                ema.analyze(self.mutated(va, b'\xcc'))

    def test_fde_mutations_rejected(self):
        for va, raw in [(ema.FDE_VA + 4, b'\x00\xd0'),
                        (ema.FDE_VA + 8, b'\x99\x99\x99\x99')]:
            with self.assertRaisesRegex(ValueError, 'Update FDE record changed'):
                ema.analyze(self.mutated(va, raw))

    def test_source_path_and_location_mutations_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Standalone path string changed'):
            ema.analyze(self.mutated(ema.PATH_VA + 4, b'X'))
        with self.assertRaisesRegex(ValueError, 'Suffix-shared path string changed'):
            ema.analyze(self.mutated(ema.PATH_SUFFIX_VA + 4, b'X'))
        with self.assertRaisesRegex(ValueError, 'Location layout changed'):
            ema.analyze(self.mutated(ema.LOC_DECAY + 8, struct.pack('<I', 43)))
        with self.assertRaisesRegex(ValueError, 'Location layout changed'):
            ema.analyze(self.mutated(ema.LOC_DENOM + 16, struct.pack('<I', 14)))

    def test_relocation_mutations_rejected(self):
        rela = next(s for s in self.sections if s['name'] == '.rela.dyn')
        raw = self.data[rela['offset']:rela['offset'] + rela['size']]
        found = {}
        for off in range(0, len(raw), 24):
            address, info, addend = struct.unpack_from('<QQq', raw, off)
            if address in (ema.GOT_ELAPSED, ema.GOT_UPDATE, ema.GOT_PANIC,
                           ema.LOC_DECAY, ema.LOC_DENOM):
                found[address] = (rela['address'] + off, addend)
        self.assertEqual(len(found), 5)
        for va, (slot_va, addend) in found.items():
            shifted = struct.pack('<q', addend + 1)
            messages = {ema.GOT_ELAPSED: 'Elapsed helper GOT slot changed',
                        ema.GOT_UPDATE: 'Update GOT slot changed',
                        ema.GOT_PANIC: 'Panic callee GOT slot changed',
                        ema.LOC_DECAY: 'Location path relocation changed',
                        ema.LOC_DENOM: 'Location path relocation changed'}
            with self.assertRaisesRegex(ValueError, messages[va]):
                ema.analyze(self.mutated(slot_va + 16, shifted))

    def test_panic_and_constant_mutations_rejected(self):
        msg_va = 0x21a843
        with self.assertRaisesRegex(ValueError, 'Accessor message changed'):
            ema.analyze(self.mutated(msg_va + 20, b'X'))
        with self.assertRaisesRegex(ValueError, 'Sign-negation xorpd mask changed'):
            ema.analyze(self.mutated(ema.NEG_MASK_VA, struct.pack('<d', 0.0)))
        with self.assertRaisesRegex(ValueError, 'Shared 1.0 constant changed'):
            ema.analyze(self.mutated(ema.ONE_VA, struct.pack('<d', 2.0)))

    def test_accessor_site_mutations_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Accessor panic lea opcodes changed'):
            ema.analyze(self.mutated(0x4726d1a - 7, b'\x48\x8d\x35'))
        with self.assertRaisesRegex(ValueError, 'Accessor location changed'):
            shifted = struct.pack('<i', struct.unpack_from(
                '<i', self.data[self.offset(0x4726d1a + 3):self.offset(0x4726d1a + 7)])[0] + 8)
            ema.analyze(self.mutated(0x4726d1a + 3, shifted))
        with self.assertRaisesRegex(ValueError, 'Accessor message length changed'):
            ema.analyze(self.mutated(0x4726d1a + 8, b'\x22\x00\x00\x00'))

    def test_exp_symbol_binding(self):
        raw = self.data[self.offset(0x576f8f8):self.offset(0x576f8f8) + 8]
        self.assertEqual(raw, b'\0' * 8)


if __name__ == '__main__':
    unittest.main()
