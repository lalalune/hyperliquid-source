"""Target-grounded controls for the static vault guard packet (no node execution)."""
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import vault_guard_static as vg
from elf_index import sections


class VaultGuardEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not vg.TARGET.is_file() or vg.TARGET.stat().st_size != 91774280:
            raise unittest.SkipTest('Requires materialized node #94 Git LFS input')
        cls.result = vg.inspect(vg.TARGET)
        cls.data = vg.TARGET.read_bytes()
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
        record = vg.ROOT / 'research/work-items/vault-guard-94/evidence.json'
        self.assertEqual(self.result, json.loads(record.read_text()))

    def test_fde_bounds_and_body_identity(self):
        fn = self.result['function']
        self.assertEqual(fn['start_va'], '0x395b3a0')
        self.assertEqual(fn['end_va_exclusive'], '0x395bdc3')
        self.assertEqual(fn['bytes'], 2595)
        self.assertEqual(fn['sha256'],
                         'bc6d0672a761b1929e1abbe5d5ecbc93395c37e756d602426f47ae092a86de4f')

    def test_location_anchors(self):
        locs = self.result['locations']
        self.assertEqual((locs['vault']['line'], locs['vault']['column']), (407, 58))
        self.assertEqual(locs['vault']['path'], 'l1/src/vault/mod.rs')
        self.assertEqual(locs['stdlib']['rustc_commit'],
                         'e408947bfd200af42db322daf0fadfe7e26d3bd1')
        self.assertIn('navigate.rs:161:36', locs['stdlib']['path'])

    def test_identity_rejects_truncation_and_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'input'
            path.write_bytes(self.data[:4096])
            with self.assertRaisesRegex(ValueError, 'size/SHA-256'):
                vg.inspect(path)
            path.write_bytes(self.mutated(vg.START, b'\x90'))
            with self.assertRaisesRegex(ValueError, 'size/SHA-256'):
                vg.inspect(path)

    def test_body_fde_and_window_mutations_rejected(self):
        for va in (vg.START, vg.START + 0x77c, vg.START + 0x7f4, vg.START + 0x9c7):
            with self.assertRaisesRegex(ValueError, 'Vault guard body bytes changed'):
                vg.analyze(self.mutated(va, b'\xcc'))
        with self.assertRaisesRegex(ValueError, 'Vault guard FDE record changed'):
            vg.analyze(self.mutated(vg.FDE_VA + 8, b'\x44\x44\x44\x44'))

    def test_anchor_mutations_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Vault Location layout changed'):
            vg.analyze(self.mutated(vg.VAULT_LOC + 8, struct.pack('<I', 408)))
        with self.assertRaisesRegex(ValueError, 'vault path changed'):
            vg.analyze(self.mutated(vg.VAULT_PATH_VA + 6, b'X'))
        with self.assertRaisesRegex(ValueError, 'Navigate Location layout changed'):
            vg.analyze(self.mutated(vg.NAVIGATE_LOC + 8, struct.pack('<I', 162)))
        with self.assertRaisesRegex(ValueError, 'i64::MIN f64 constant changed'):
            vg.analyze(self.mutated(vg.MIN_F64_VA, struct.pack('<d', -1.0)))
        with self.assertRaisesRegex(ValueError, 'Shared 1e6 constant changed'):
            vg.analyze(self.mutated(vg.ONE_E6_VA, struct.pack('<d', 2e6)))

    def test_relocation_mutations_rejected(self):
        rela = next(s for s in self.sections if s['name'] == '.rela.dyn')
        raw = self.data[rela['offset']:rela['offset'] + rela['size']]
        slots = {}
        for off in range(0, len(raw), 24):
            address, info, addend = struct.unpack_from('<QQq', raw, off)
            if info == 8 and address in (vg.GOT_PANIC_DISPLAY, vg.GOT_PANIC_FMT,
                                         vg.GOT_SELF, vg.VAULT_LOC, vg.NAVIGATE_LOC):
                slots[address] = (rela['address'] + off, addend)
        self.assertEqual(len(slots), 5)
        messages = {vg.GOT_PANIC_DISPLAY: 'Panic display callee changed',
                    vg.GOT_PANIC_FMT: 'Panic fmt callee changed',
                    vg.GOT_SELF: 'Self GOT slot changed',
                    vg.VAULT_LOC: 'Vault Location relocation changed',
                    vg.NAVIGATE_LOC: 'Navigate Location relocation missing|Navigate path changed'}
        for va, (slot_va, addend) in slots.items():
            with self.assertRaisesRegex(ValueError, messages[va]):
                vg.analyze(self.mutated(slot_va + 16, struct.pack('<q', addend + 4)))

    def test_call_census(self):
        census = self.result['call_census']
        self.assertEqual(census['got_indirect'],
                         ['0x2736819', '0x395b1dc', '0x4d4275c', '0x4d46699'])
        self.assertEqual(census['direct_e8'], 0)


if __name__ == '__main__':
    unittest.main()
