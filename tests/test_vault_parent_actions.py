"""Tests for tools/vault_parent_actions.py.  Runs on the real node #94 binary and needs no binutils."""

import hashlib
import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
FOLDER = ROOT / 'research/work-items/vaults-parent-actions-94'
SPEC = importlib.util.spec_from_file_location('vault_parent_actions', ROOT / 'tools/vault_parent_actions.py')
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


def disagreements(img, sizes=(64, 64, 64)):
    return len(tool.evaluate(img, *sizes)[1])


class Baseline(unittest.TestCase):
    def test_vectors_agree(self):
        counts, bad = tool.evaluate(IMG, 96, 96, 96)
        self.assertEqual(bad, [])
        self.assertEqual(sum(counts.values()), 288)

    def test_named_cases(self):
        rows = tool.named_cases(IMG)
        self.assertEqual(len(rows), 19)
        self.assertTrue(all(r[-1] == 'same' for r in rows))

    def test_tables(self):
        pins, layout = tool.check_tables(IMG)
        self.assertEqual(len(pins), len(tool.PINS))
        self.assertEqual(len(layout), len(tool.LAYOUT_ROWS))

    def test_first_child_is_the_counterparty(self):
        a, b, c = tool.addr(60), tool.addr(61), tool.addr(62)
        case = tool.net_base([a, b, c], {(a, 0): 0, (b, 0): 100, (c, 0): 201}, [0])
        got = tool.run_net(IMG, case)
        self.assertEqual(len(got['fills']), 1)
        fill = got['fills'][0]
        self.assertEqual((fill[0], fill[1], fill[4], fill[8]), (a.hex(), c.hex(), 101, 1))

    def test_ids_spent_on_refusal(self):
        a, b = tool.addr(60), tool.addr(61)
        case = tool.net_base([a, b], {(a, 0): 10, (b, 0): -10}, [0])
        case['margin'] = [0x100]
        got = tool.run_net(IMG, case)
        self.assertEqual((got['fills'], got['tid']), ([], 1002))

    def test_scale_truncates(self):
        v = tool.addr(1)
        vaults = {v: tool.vault(v, tool.addr(2))}
        args = (vaults, tool.addr(2), v, 10000000, 10000000, (tool.OK, 0), [(tool.addr(3), 19999)], 0.5, {})
        got = tool.run_distribute(IMG, *args)
        self.assertEqual(got['accounts'], [(tool.addr(3).hex(), 0, 0)])
        self.assertEqual(got['events'][0][1], f'{tool.f2i(9999 / 1e6):016x}')

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
            tool.check_tables(patched((0x26f6b97, '12')))

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
        del w.stubs[0x5774660]
        v = tool.addr(1)
        e, ch = tool.exchange(w, {v: tool.vault(v, tool.addr(2))})
        w.m.store(0x7830000, tool.addr(2))
        w.m.store(0x7810008, v)
        tool.q(w.m, 0x7810000, 10000000)
        with self.assertRaises(ValueError):
            tool.call(w, 0x1e60020, 0x7820000, 0x7810000, 0x7830000, e)

    def test_function_start_is_an_fde_start(self):
        table = tool.fdes(DATA)
        saved = tool.FUNCS
        tool.FUNCS = [(0x26f6a81, 'not a start')]
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

    def test_modify_code_17(self):
        self.check((0x26f6b97, '12'))

    def test_modify_keep_value(self):
        self.check((0x26f6be6, '03'))

    def test_modify_store_offset(self):
        self.check((0x26f6bec, '2a'))

    def test_modify_skips_vault_user_compare(self):
        self.check((0x26f6bdb, '9090'))

    def test_distribute_cut(self):
        self.check((0x1e6003f, 'cdcccccccccccc0c'))

    def test_distribute_closed_ignored(self):
        self.check((0x26f61f7, '9090'))

    def test_distribute_code_18(self):
        a = tool.addr(1)
        args = ({a: tool.vault(a, tool.addr(2))}, tool.addr(2), a, 10, 5, (tool.OK, 0), [], 1.0, {})
        self.assertEqual(tool.run_distribute(IMG, *args)['code'], 18)
        self.assertEqual(tool.run_distribute(patched((0x26f62f2, '13')), *args)['code'], 19)

    def test_distribute_usd_zero_flag(self):
        self.check((0x26f62f9, '89ed'))

    def test_distribute_clamp(self):
        self.check((0x26f65b3, 'afe147ae147ae101'), (0x26f65eb, 'afe147ae147ae101'), (0x26f6613, 'afe147ae147ae101'), (0x26f6622, 'afe147ae147ae101'))

    def test_distribute_divisor(self):
        self.check((0x26f66ad, '0a'), (0x26f673c, '0a'))

    def test_distribute_two_sum_arm(self):
        self.check((0x26f665b, '90e9'))

    def test_distribute_event_scale(self):
        self.check((0x26f6442 + 2, struct.pack('<i', struct.unpack('<i', IMG.rd(0x26f6444, 4))[0] + 8).hex()))

    def test_net_limit_assets(self):
        a, b = tool.addr(60), tool.addr(61)
        case = tool.net_base([a, b], {}, [])
        case['wire_len'] = 10000
        self.assertEqual(tool.run_net(IMG, case)['code'], tool.OK)
        self.assertNotEqual(tool.run_net(patched((0x27e8cdd, '1027')), case)['code'], tool.OK)

    def test_net_limit_children(self):
        a, b = tool.addr(60), tool.addr(61)
        case = tool.net_base([a, b], {}, [])
        case['child_len'] = 10001
        self.assertEqual(tool.run_net(IMG, case)['code'], 0x143)
        self.assertNotEqual(tool.run_net(patched((0x27e8f93, '1227')), case)['code'], 0x143)

    def test_net_spot_code(self):
        self.check((0x27e9012, '5f01'))

    def test_net_ready_byte(self):
        self.check((0x27e8f36, '02'))

    def test_net_tag_gate(self):
        a, b = tool.addr(60), tool.addr(61)
        case = tool.net_base([a, b], {}, [])
        case['vaults'][case['caller']]['tag'] = 1
        self.assertEqual(tool.run_net(IMG, case)['code'], 24)
        self.assertEqual(tool.run_net(patched((0x26f6d32, '01')), case)['code'], 27)

    def test_net_single_child_gate(self):
        self.check((0x3707c3e, '02'))

    def test_net_first_child_moves(self):
        self.check((0x37083c1, '9090'))

    def test_net_weight(self):
        self.check((0x20a730, '000000000000e03f'))

    def test_net_oracle_field(self):
        self.check((0x3708354, '28'))

    def test_net_side(self):
        self.check((0x3708621, '00'))

    def test_net_skip_margin(self):
        self.check((0x370879c, '909090909090'))

    def test_net_chain_gate(self):
        self.check((0x37083cc, '03'))

    def test_net_position_field(self):
        self.check((0x3707e44, 'c0'))

    def test_closure_counter_step(self):
        self.check((0x3c18ac7 + 3, '02'))

    def test_closure_side_swap(self):
        self.check((0x3c189fa, '0f95c0'))


if __name__ == '__main__':
    unittest.main()
