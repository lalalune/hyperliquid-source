import hashlib
import json
import math
from pathlib import Path
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

import vault_lifecycle_path as tool  # noqa: E402

FOLDER = ROOT / 'research/work-items/vaults-lifecycle-path-94'


class Patched(tool.Image):
    """The image with bytes replaced at virtual addresses, for negative controls."""

    def __init__(self, data, patches):
        super().__init__(data)
        blob = bytearray(data)
        for va, raw in patches.items():
            i = tool.bisect.bisect_right(self.starts, va) - 1
            addr, _, off, _ = self.mapped[i]
            blob[off + va - addr:off + va - addr + len(raw)] = raw
        self.data = bytes(blob)


class VaultLifecyclePath(unittest.TestCase):
    def setUpClass(cls):
        cls.data = tool.load()
        cls.img = tool.Image(cls.data)
        cls.rel = cls.img.relative()

    setUpClass = classmethod(setUpClass)

    def test_binary_digest_is_checked(self):
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), tool.SHA256)
        real = tool.ROOT
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / tool.BINARY
            bad.parent.mkdir(parents=True)
            bad.write_bytes(b'\x7fELF not the target')
            tool.ROOT = Path(tmp)
            try:
                with self.assertRaises(SystemExit):
                    tool.load()
            finally:
                tool.ROOT = real

    def test_pins_decode(self):
        self.assertEqual(len(tool.check_pins(self.img)), len(tool.PINS))
        self.assertEqual(len(tool.check_layout(self.img)), len(tool.LAYOUT))

    def test_flipped_branch_fails_the_pin(self):
        bad = Patched(self.data, {0x395bd77: b'\x0f\x87'})  # jbe -> ja
        with self.assertRaises(ValueError):
            tool.check_pins(bad)

    def test_changed_code_immediate_fails_the_pin(self):
        bad = Patched(self.data, {0x395b3fc: b'\x17'})  # code 22 -> 23
        with self.assertRaises(ValueError):
            tool.check_pins(bad)

    def test_layout_rejects_changed_displacement(self):
        worse = Patched(self.data, {0x395b406: b'\xae'})  # +0xad -> +0xae
        with self.assertRaises(ValueError):
            tool.check_layout(worse)

    def test_walk_claims(self):
        walk = tool.walks(self.img)
        self.assertEqual(walk['post_drain_walk']['memory_stores'], 0)
        self.assertEqual(walk['post_drain_walk']['calls'], 0)
        self.assertEqual(walk['recomputed_sum']['stores_of_r15'], 0)
        store = tool.decode(lambda va, n: bytes.fromhex('4c897c2408') + b'\0' * 11, 0)  # mov [rsp+8],r15
        self.assertTrue(tool.is_store(store))
        self.assertEqual(store.args[1][:2], ('r', 15))
        self.assertFalse(tool.is_store(tool.decode(lambda va, n: bytes.fromhex('4c8b7c2408') + b'\0' * 11, 0)))

    def test_address_outside_file_sections(self):
        with self.assertRaises(ValueError):
            self.img.rd(0x10, 1)
        bss = self.img.section('.bss')
        with self.assertRaises(ValueError):
            self.img.rd(bss['address'] + 16, 8)

    def test_unknown_encoding_is_refused(self):
        with self.assertRaises(ValueError):
            tool.decode(lambda va, n: b'\x0f\x0b' + b'\0' * 14, 0)

    def test_unmodelled_call_is_refused(self):
        m = tool.Machine(self.img.rd, self.img.rd, lambda target, machine: False)
        tool.stack(m)
        m.r[1], m.r[2], m.r[14] = (1 << 63) - 1, 1, 1
        with self.assertRaises(ValueError):
            m.run(0x395a2e7, {0x395a2fc})

    def test_gate_boundary(self):
        self.assertEqual(tool.span_gate(self.img, self.rel, 100_000000, 5_000000, 0.0525)[0], 'pass')
        self.assertEqual(tool.span_gate(self.img, self.rel, 100_000000, 5_000000, 0.0524999)[0], 'fraction<0.05')
        self.assertEqual(tool.span_gate(self.img, self.rel, 0, 5_000000, 0.5)[0], 'equity<1e-7')
        got, records = tool.span_gate(self.img, self.rel, 1_000000, (1 << 64) - 1, 0.5)
        self.assertEqual(got, 'fraction<0.05')
        self.assertEqual(records and tool.location(self.img, self.rel, 0x5714d18)[:2], ('l1/src/qtys/impl_ntl.rs', 26))

    def test_constant_mutation_changes_the_gate(self):
        bad = Patched(self.data, {0x20a4c0: struct.pack('<d', 0.04)})
        self.assertEqual(tool.span_gate(self.img, self.rel, 100_000000, 5_000000, 0.045)[0], 'fraction<0.05')
        self.assertEqual(tool.span_gate(bad, self.rel, 100_000000, 5_000000, 0.045)[0], 'pass')

    def test_grid_detects_mutated_span(self):
        bad = Patched(self.data, {0x20adf8: struct.pack('<d', 1e-6)})  # the 1e-7 threshold
        grid = tool.grid_checks(bad, self.rel, 64)
        self.assertLess(grid['share']['agree'], 64)

    def test_stale_sum_cannot_reach_the_shares(self):
        one = tool.span_usd(self.img, self.rel, 7_000000, 9_000000, 9_000000, 0)
        two = tool.span_usd(self.img, self.rel, 7_000000, 9_000000, 9_000000, 123456789)
        self.assertEqual(one, two)
        self.assertEqual(one, (9.0, 7.0))
        self.assertEqual(tool.span_usd(self.img, self.rel, -7_000000, -2_000000, 0, 5), (0.0, -7.0))

    def test_saturating_cast_model(self):
        self.assertEqual(tool.sat_cast(math.nan), 0)
        self.assertEqual(tool.sat_cast(math.inf), 0)
        self.assertEqual(tool.sat_cast(2.0 ** 70), (1 << 63) - 1)
        self.assertEqual(tool.sat_cast(-2.0 ** 70), -(1 << 63))
        self.assertEqual(tool.sat_cast(-1.5), -1)

    def test_lists_have_eight_distinct_addresses_each(self):
        rows = tool.lists(self.img)
        self.assertEqual(sum(r[0] == 'A' for r in rows), 8)
        self.assertEqual(sum(r[0] == 'B' for r in rows), 8)
        self.assertEqual(len({r[2] for r in rows}), 16)

    def test_create_boundaries(self):
        good = tool.run_create(self.img, 3, 10, 100_000_000, 3, 0)
        self.assertEqual(good['code'], 'deposit')
        self.assertEqual((good['tag'], good['commission'], good['lockup'], good['flags']), (0, 0.1, 86400.0, '00010000'))
        child = tool.run_create(self.img, 50, 250, 100_000_000, 2, 1)
        self.assertEqual((child['tag'], child['commission'], child['lockup']), (1, 0.0, 20.0))
        self.assertEqual(tool.run_create(self.img, 3, 10, 99_999_999, 3, 0), {'code': 1, 'tag': 3})
        self.assertEqual(tool.run_create(self.img, 51, 10, 100_000_000, 3, 0), {'code': 4, 'tag': 3})
        self.assertEqual(tool.run_create(self.img, 3, 251, 100_000_000, 3, 0), {'code': 0x143, 'tag': 3})

    def test_mutated_create_minimum_is_seen(self):
        bad = Patched(self.data, {0x395af9c: struct.pack('<I', 50_000_000)})
        with self.assertRaises(ValueError):
            tool.check_pins(bad)
        self.assertEqual(tool.run_create(bad, 3, 10, 60_000_000, 3, 0)['code'], 'deposit')
        self.assertEqual(tool.run_create(self.img, 3, 10, 60_000_000, 3, 0)['code'], 1)

    def plain(self, **change):
        return dict({'same_vault': True, 'make_parent': 0, 'name': None, 'desc': None, 'lockup': None,
                     'commission': None, 'allow': 2, 'always': 2, 's': 2}, **change)

    def test_modify_rules(self):
        st = tool.vault_state(0)
        code, after = tool.run_modify(self.img, st, self.plain(make_parent=1), 0, None, None)
        self.assertEqual((code, after['tag'], after['root'], after['count']), (0x186, 2, 0, 0))
        code, after = tool.run_modify(self.img, st, self.plain(lockup=4_000_001, name=10), 0, None, None)
        self.assertEqual((code, after['name_len'], after['lockup']), (0x186, 10, st['lockup']))
        code, after = tool.run_modify(self.img, tool.vault_state(1), self.plain(s=1), 0, 0, 0)
        self.assertEqual((code, after['s']), (0x186, 1))
        code, after = tool.run_modify(self.img, tool.vault_state(1), self.plain(s=1), 0, 3, None)
        self.assertEqual((code, after['s']), (0x186, 0))

    def test_mutated_commission_cap_is_seen(self):
        bad = Patched(self.data, {0x3959d53: struct.pack('<I', 2000)})
        act = self.plain(commission=1500)
        st = tool.vault_state(0)
        self.assertEqual(tool.run_modify(self.img, st, act, 0, None, None)[1]['commission'], st['commission'])
        self.assertEqual(tool.run_modify(bad, st, act, 0, None, None)[1]['commission'], 0.15)

    def test_life_grid_detects_mutation(self):
        bad = Patched(self.data, {0x20a880: struct.pack('<d', 0.2)})  # 0.1 commission
        self.assertLess(tool.life_checks(bad, 64)['create_body']['agree'], 64)

    def test_named_tables(self):
        rows = tool.vault_fields(self.img)
        self.assertEqual(len(rows), 13)
        self.assertEqual([r[1] for r in rows][:2], ['name', 'description'])
        self.assertEqual(rows[12][1], 's')
        self.assertEqual([r[1] for r in tool.variant_rows(self.img, self.rel)], ['normal', 'child', 'parent'])
        saved = tool.VAULT_KEYS
        tool.VAULT_KEYS = [(0x2340bc2, 0x2340bc2)]
        try:
            with self.assertRaises(ValueError):
                tool.vault_fields(self.img)
        finally:
            tool.VAULT_KEYS = saved

    def test_location_refuses_plain_data(self):
        with self.assertRaises(ValueError):
            tool.location(self.img, self.rel, 0x570d9e8 + 1)

    def test_generated_files_match_the_packet(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(tool.main(['--out', tmp]), 0)
            produced = sorted(p.name for p in Path(tmp).iterdir())
            self.assertEqual(produced, sorted(list(n for n in (
                'address_lists.tsv', 'callees.tsv', 'callers.tsv', 'evidence.json', 'functions.tsv', 'layout.tsv',
                'locations.tsv', 'outcomes.tsv', 'pins.tsv', 'vault_fields.tsv', 'vectors.tsv'))))
            for name in produced:
                self.assertEqual((Path(tmp) / name).read_bytes(), (FOLDER / name).read_bytes(), name)
        summary = json.loads((FOLDER / 'evidence.json').read_text())
        for row in summary['grid'].values():
            self.assertEqual(row['agree'], row['vectors'])

    def test_manifest_lists_every_file(self):
        names = sorted(p.name for p in FOLDER.iterdir() if p.name != 'MANIFEST.sha256')
        lines = (FOLDER / 'MANIFEST.sha256').read_text().splitlines()
        self.assertEqual(sorted(line.split('  ', 1)[1] for line in lines), names)
        for line in lines:
            digest, name = line.split('  ', 1)
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest)


if __name__ == '__main__':
    unittest.main()
