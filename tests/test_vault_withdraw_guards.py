"""Tests for tools/vault_withdraw_guards.py.  Runs on the real node #94 binary and needs no binutils."""

import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
FOLDER = ROOT / 'research/work-items/vaults-withdraw-guards-94'
SPEC = importlib.util.spec_from_file_location('vault_withdraw_guards', ROOT / 'tools/vault_withdraw_guards.py')
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)
DATA = tool.load()
IMG = tool.Image(DATA)


def patched(*edits):
    """Return an Image with bytes replaced at virtual addresses."""
    data = bytearray(DATA)
    for va, hexbytes in edits:
        raw = bytes.fromhex(hexbytes)
        addr, size, off, _ = next(m for m in IMG.mapped if m[0] <= va < m[0] + m[1])
        data[off + va - addr:off + va - addr + len(raw)] = raw
    return tool.Image(bytes(data))


def disagreements(img):
    return len(tool.evaluate(img, 200)[1])


class Baseline(unittest.TestCase):
    def test_vectors_agree(self):
        counts, bad = tool.evaluate(IMG, 400)
        self.assertEqual(bad, [])
        self.assertEqual(sum(counts.values()), 600)

    def test_named_cases(self):
        rows = tool.named_cases(IMG)
        self.assertEqual(len(rows), 25)
        self.assertTrue(all(r[-1] == 'same' for r in rows))

    def test_tables(self):
        pins, layout = tool.check_tables(IMG)
        self.assertEqual(len(pins), len(tool.PINS))
        self.assertEqual(len(layout), len(tool.LAYOUT_ROWS))

    def test_hlp_address_in_both_layouts(self):
        for layout in ('A', 'B'):
            self.assertEqual(tool.special_address(IMG, 3, layout).hex(), 'dfc24b077bc1425ad1dea75bcb6f8158e10df303')
            self.assertEqual(tool.special_address(IMG, 2, layout).hex(), 'a15099a30bbf2e68942d6f4c43d70d04faeab0a0')

    def test_state_field_names(self):
        names = {r[1] for r in tool.field_rows(IMG)}
        self.assertEqual(names, {'max_hlp_withdraw_fraction_per_day', 'hlp_start_of_day_account_value', 'last_hlp_cancel_time'})

    def test_snapshot_only_on_a_new_date(self):
        sp = tool.special_address(IMG, 3)
        now = (tool.date_word(2026, 300), 1, 1)
        c = dict(fn=0x2702e80, chain=3, keys=[sp], now=now, prev=(tool.date_word(2026, 299), 0, 0), total=9, snap=(0, 0))
        self.assertEqual(tool.run_snapshot(IMG, c)['snap'], (1, 9))
        self.assertEqual(tool.run_snapshot(IMG, dict(c, prev=now))['snap'], (0, 0))

    def test_sell_adds_a_tick_on_a_multiple(self):
        c = tool.base(best=[(2500000, 2500000)])
        ins = [r[2] for r in tool.run_close(IMG, c)['log'] if r[0] == 'insert']
        self.assertEqual(ins[0]['limit'], 2425100)

    def test_order_user_is_the_vault(self):
        c = tool.base()
        ins = [r[2] for r in tool.run_close(IMG, c)['log'] if r[0] == 'insert']
        self.assertEqual(ins[0]['user'], c['user'].hex())
        self.assertEqual((ins[0]['w70'], ins[0]['tif']), (6, 1))

    def test_evidence_has_no_absolute_paths(self):
        for f in FOLDER.iterdir():
            if f.suffix in ('.tsv', '.json', '.md'):
                text = f.read_text(encoding='utf-8')
                for root in ('home', 'tmp', 'srv', 'mnt'):
                    self.assertNotIn('/'.join(('', root, '')), text)


class Negative(unittest.TestCase):
    def test_wrong_hash_fails(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'hl-node'
            p.write_bytes(b'not the node')
            saved = tool.ROOT, tool.BINARY
            tool.ROOT, tool.BINARY = Path(d), 'hl-node'
            try:
                with self.assertRaises(SystemExit):
                    tool.load()
            finally:
                tool.ROOT, tool.BINARY = saved

    def test_address_outside_file_backed_sections(self):
        bss = next(s for s in IMG.secs if s['name'] == '.bss')
        with self.assertRaises(ValueError):
            IMG.rd(bss['address'] + 16, 4)
        with self.assertRaises(ValueError):
            IMG.rd(0x10, 4)

    def test_pin_catches_changed_byte(self):
        with self.assertRaises(ValueError):
            tool.check_tables(patched((0x26f74b2, '80969800')))

    def test_layout_catches_changed_offset(self):
        rows = tool.LAYOUT_ROWS
        tool.LAYOUT_ROWS = [(s, o, w, va, '[r13+0x77]:64', n) for s, o, w, va, _, n in rows[:1]]
        try:
            with self.assertRaises(ValueError):
                tool.check_tables(IMG)
        finally:
            tool.LAYOUT_ROWS = rows

    def test_field_table_catches_changed_string(self):
        with self.assertRaises(ValueError):
            tool.field_rows(patched((0x3ef44f, '58')))

    def test_unknown_encoding_raises(self):
        with self.assertRaises(ValueError):
            tool.decode(lambda va, n: bytes.fromhex('d9e8' + '90' * 14), 0x1000)

    def test_unmodelled_call_raises(self):
        c = tool.base()
        w = tool.World(IMG, c)
        del w.stubs[0x57748c8]
        tool.fixture(w, c)
        w.m.r[4] -= 8
        tool.q(w.m, w.m.r[4], tool.SENT)
        w.m.r[7], w.m.r[6] = tool.EX, tool.USER
        with self.assertRaises(ValueError):
            w.m.run(0x26f7280, {tool.SENT}, 2000)

    def test_function_start_is_an_fde_start(self):
        table = tool.fdes(DATA)
        saved = tool.FUNCS
        tool.FUNCS = [(0x26f7281, 'not a start')]
        try:
            with self.assertRaises(ValueError):
                tool.function_rows(IMG, table)
        finally:
            tool.FUNCS = saved

    def test_generated_files_match(self):
        with tempfile.TemporaryDirectory() as d:
            tool.generate(d)
            for f in sorted(Path(d).iterdir()):
                self.assertEqual(hashlib.sha256(f.read_bytes()).hexdigest(),
                                 hashlib.sha256((FOLDER / f.name).read_bytes()).hexdigest(), f.name)


class Mutants(unittest.TestCase):
    """Each edit changes one behaviour; the fixed models must then disagree with the bytes."""

    def check(self, *edits):
        self.assertGreater(disagreements(patched(*edits)), 0)

    def test_snapshot_date_gate(self):
        self.check((0x2702e96, '909090909090'))

    def test_snapshot_chain_limit(self):
        self.check((0x2702ea5, '03'))

    def test_snapshot_floor(self):
        self.check((0x270300c, '4889c190'))

    def test_snapshot_tag(self):
        self.check((0x2703017, '02'))

    def test_snapshot_address_tail(self):
        self.check((0x2702ee3, 'e2'))

    def test_snapshot_layout_b_tag(self):
        self.check((0x4cf02c7, '02'))

    def test_snapshot_second_copy_tag(self):
        self.check((0x4cf04c7, '02'))

    def test_none_word_gate(self):
        self.check((0x26f7304, '909090909090'))

    def test_hash_flag(self):
        self.check((0x26f7347, '9090'))

    def test_side_two(self):
        self.check((0x26f7412, '909090909090'))

    def test_oracle_bound(self):
        self.check((0x26f744b, '909090909090'))

    def test_notional_floor(self):
        self.assertGreater(len([1 for c in [tool.base(rows=[(0, 1, 2000)], prices=[5000])] if not tool.same(tool.run_close(patched((0x26f74b2, '80969800')), c), tool.model_close(c))]), 0)

    def test_midpoint_shift(self):
        self.check((0x26f7641, '909090'))

    def test_factor_branch(self):
        self.check((0x26f76a2, 'eb'))

    def test_sell_factor_constant(self):
        self.check((0x20ac58, '7b14ae47e17aee3f'))

    def test_buy_keeps_quotient(self):
        self.check((0x26f7787, '90909090'))

    def test_zero_limit(self):
        self.check((0x26f7798, '90909090'))

    def test_record_tag(self):
        self.check((0x26f78c0, '07'))

    def test_record_tif(self):
        self.check((0x26f7905, '04'))

    def test_final_step(self):
        self.check((0x26f73f4, '9090909090'))

    def test_error_free_gate(self):
        self.check((0x26f7aa1, '909090909090'))

    def test_oracle_drop(self):
        self.check((0x26f7b7a, '9090909090'))

    def test_dex_bound(self):
        self.check((0x26f7527, '909090909090'))


if __name__ == '__main__':
    unittest.main()
