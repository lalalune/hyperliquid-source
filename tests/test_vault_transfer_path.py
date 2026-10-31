"""Tests for tools/vault_transfer_path.py.  Runs on the real node #94 binary and needs no binutils."""

import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
FOLDER = ROOT / 'research/work-items/vaults-transfer-path-94'
SPEC = importlib.util.spec_from_file_location('vault_transfer_path', ROOT / 'tools/vault_transfer_path.py')
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)
DATA = tool.load()
IMG = tool.Image(DATA)
U, T = tool.addr(1), tool.addr(2)


def patched(*edits):
    """Return an Image with bytes replaced at virtual addresses."""
    data = bytearray(DATA)
    for va, hexbytes in edits:
        raw = bytes.fromhex(hexbytes)
        addr, size, off, _ = next(m for m in IMG.mapped if m[0] <= va < m[0] + m[1])
        data[off + va - addr:off + va - addr + len(raw)] = raw
    return tool.Image(bytes(data))


def disagreements(img):
    return len(tool.evaluate(img, 320, 256, 32)[1])


class Baseline(unittest.TestCase):
    def test_vectors_agree(self):
        counts, bad = tool.evaluate(IMG, 128, 128, 32)
        self.assertEqual(bad, [])
        self.assertEqual(sum(counts.values()), 288)

    def test_named_cases(self):
        rows = tool.named_cases(IMG)
        self.assertEqual(len(rows), 21)
        self.assertTrue(all(r[-1] == 'same' for r in rows))

    def test_tables(self):
        pins, layout = tool.check_tables(IMG)
        self.assertEqual(len(pins), len(tool.PINS))
        self.assertEqual(len(layout), len(tool.LAYOUT_ROWS))

    def test_mainnet_special_vault_bytes(self):
        self.assertEqual(tool.special_address(IMG, 3).hex(), 'dfc24b077bc1425ad1dea75bcb6f8158e10df303')

    def test_failed_gate_still_stores_time(self):
        c = tool.base(usd=tool.CUT, now=(100, 5, 300000000), last=(100, 5, 0))
        self.assertEqual(tool.run_body(IMG, c)['last'], tool.time_bytes((100, 5, 300000000)).hex())

    def test_deposit_sums(self):
        got = tool.run_body(IMG, tool.base())
        self.assertEqual(got['accounts'], sorted(((U.hex(), 0, -1000), (T.hex(), 1000, 1000))))

    def test_withdraw_leader_event_first(self):
        c = tool.base(deposit=0, withdraw=dict(word=0x8000000000000005, p1=1, amount=30000, word2=0x8000000000000007, p2=2))
        events = [x for x in tool.run_body(IMG, c)['log'] if x[0] == 'event']
        self.assertEqual([e[6] for e in events], [0x8000000000000007, 0x8000000000000005])

    def test_exit_settlement_failure_is_dropped(self):
        c = dict(user=U, cls=3, g4=0, g3=0, switch=0, count=0, flag=0, key=0, row50=0, windows=[1, 0], settle=[0x33, tool.OK], body=tool.OK)
        got = tool.run_router(IMG, c)
        self.assertEqual(got['out'], tool.OK)
        self.assertEqual([x[0] for x in got['log']][-2:], ['settle', 'drop'])

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
            tool.check_tables(patched((0x27363fb, 'cdcccccccccccc0c')))

    def test_layout_catches_changed_offset(self):
        rows = tool.LAYOUT_ROWS
        tool.LAYOUT_ROWS = [(s, o, w, va, '[r13+0x77]:64', n) for s, o, w, va, _, n in rows[:1]]
        try:
            with self.assertRaises(ValueError):
                tool.check_tables(IMG)
        finally:
            tool.LAYOUT_ROWS = rows

    def test_unknown_encoding_raises(self):
        with self.assertRaises(ValueError):
            tool.decode(lambda va, n: bytes.fromhex('d9e8' + '90' * 14), 0x1000)

    def test_unmodelled_call_raises(self):
        w = tool.World(IMG)
        del w.stubs[0x5774b48]
        c = tool.base()
        tool.exchange(w, c)
        w.m.store(tool.USER, U)
        tool.q(w.m, tool.ACTION, 10000000)
        w.m.store(tool.ACTION + 8, T)
        w.m.store(tool.ACTION + 0x1c, bytes((1,)))
        with self.assertRaises(ValueError):
            tool.call(w, 0x27362b0, tool.OUT, tool.USER, tool.ACTION, tool.EX)

    def test_function_start_is_an_fde_start(self):
        table = tool.fdes(DATA)
        saved = tool.FUNCS
        tool.FUNCS = [(0x27362b1, 'not a start')]
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

    def differs(self, case, *edits):
        self.assertEqual(tool.run_body(IMG, case), tool.model_body(IMG, case))
        self.assertNotEqual(tool.run_body(patched(*edits), case), tool.model_body(IMG, case))

    def special(self, **k):
        sp = tool.special_address(IMG, 3)
        return tool.base(deposit=0, vaults={sp: tool.vault(sp)}, target=sp, **k)

    def test_window(self):
        self.check((0x273632f, '01a3e111'))

    def test_time_store(self):
        self.check((0x27363bf, '90909090909090'))

    def test_usd_cut(self):
        self.check((0x27363fb, 'cdcccccccccccc0c'))

    def test_code_31(self):
        self.check((0x273650e, '20'))

    def test_tag_gate(self):
        self.differs(tool.base(vaults={T: tool.vault(T), U: tool.vault(U, tag=1, children=[T])}), (0x273652c, '01'))

    def test_code_25(self):
        self.check((0x27365fa, '1a'))

    def test_code_7(self):
        self.check((0x27366cd, '06'))

    def test_closed_offset(self):
        self.check((0x27366d6, 'ad'))

    def test_deposit_minimum(self):
        self.differs(tool.base(usd=5000000), (0x2736747, '414b4c00'))

    def test_code_41(self):
        self.check((0x2736755, '2a'))

    def test_chain_branch(self):
        self.differs(self.special(cap_on=1, cap_base=1000000, chain=1), (0x2736789, '909090909090'))

    def test_cap_switch(self):
        self.differs(self.special(cap_on=0, cap_base=1000000), (0x2736932, '9090'))

    def test_cap_formula(self):
        self.differs(self.special(cap_on=1, cap_base=1000000, cap_frac=0.25), (0x26f6066, '90909090'))

    def test_leader_event_gate(self):
        self.check((0x2736b70, '909090909090'))

    def test_none_word_gate(self):
        self.check((0x2736b47, '909090909090'))

    def test_post_step_gate(self):
        self.check((0x2736a85, 'eb'))

    def test_vault_sign(self):
        self.check((0x2736fb3, '909090'))

    def test_user_sum_flag(self):
        self.check((0x273700b, '00'))

    def test_sum_selector(self):
        self.check((0x2712a51, '90909090'))

    def test_sum_divide(self):
        self.check((0x2712a3d, '0a'))

    def test_clamp(self):
        self.check((0x370c26d, 'afe147ae147ae101'))

    def test_scale_offset(self):
        self.check((0x370c1e9, 'a8'))

    def test_depth_counter(self):
        self.check((0x27362d2, '909090'))

    def test_router_class_limit(self):
        self.check((0x2731317, '03'))

    def test_router_count_limit(self):
        c = dict(user=U, cls=2, g4=0, g3=0, switch=1, count=2, flag=0, key=1, row50=0, windows=[0, 0], settle=[tool.OK, tool.OK], body=tool.OK)
        self.assertTrue(tool.same_router(tool.run_router(IMG, c), tool.model_router(c)))
        self.assertFalse(tool.same_router(tool.run_router(patched((0x273132e, '03')), c), tool.model_router(c)))

    def test_router_high_class_bit(self):
        self.check((0x2731504, 'eb'))

    def test_router_code_368(self):
        self.check((0x27315d0, '71'))

    def test_router_window_gate(self):
        self.check((0x27315c0, '9090'))

    def test_router_exit_gate(self):
        self.check((0x27316b9, 'eb'))

    def test_router_stride(self):
        self.check((0x273164c, 'f8'))

    def test_wrapper_code(self):
        self.check((0x1e5fb82, '87'))

    def test_nanosecond_compare(self):
        self.check((0x27363b9, '909090909090'))


if __name__ == '__main__':
    unittest.main()
