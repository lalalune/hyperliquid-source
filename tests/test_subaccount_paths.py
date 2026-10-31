"""Tests for tools/subaccount_paths.py.  Runs on the real node #94 binary and needs no binutils."""

import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
FOLDER = ROOT / 'research/work-items/vaults-subaccount-paths-94'
SPEC = importlib.util.spec_from_file_location('subaccount_paths', ROOT / 'tools/subaccount_paths.py')
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
    return len(tool.evaluate(img, 128, 96, 32, 32, 48)[1])


M, S, X = tool.addr(1), tool.addr(2), tool.addr(3)


def transfer(img, usd=25000, deposit=1, links=None, users=None, gates=(1, 1), balance=25000, **k):
    args = (M, S, usd, deposit, {S: M} if links is None else links, users or {}, gates, balance)
    return tool.run_transfer(img, *args, **k)


class Baseline(unittest.TestCase):
    def test_vectors_agree(self):
        counts, bad = tool.evaluate(IMG, 128, 128, 32, 32, 32)
        self.assertEqual(bad, [])
        self.assertEqual(sum(counts.values()), 352)

    def test_named_cases(self):
        rows = tool.named_cases(IMG)
        self.assertEqual(len(rows), 28)
        self.assertTrue(all(r[-1] == 'same' for r in rows))

    def test_tables(self):
        pins, layout = tool.check_tables(IMG)
        self.assertEqual(len(pins), len(tool.PINS))
        self.assertEqual(len(layout), len(tool.LAYOUT_ROWS))

    def test_preimage_is_160_abi_bytes(self):
        got = tool.run_encode(IMG, IMG.rd(0x2035a0, 16), M, 3)
        self.assertEqual(len(got), 160)
        self.assertEqual(got[:32], (0x60).to_bytes(32, 'big'))
        self.assertEqual(got[44:64], M)
        self.assertEqual(got[64:96], (3).to_bytes(32, 'big'))
        self.assertEqual(got[96:128], (16).to_bytes(32, 'big'))
        self.assertEqual(got[128:144], b'createSubAccount')

    def test_withdrawal_token_shape(self):
        got = tool.run_tokens(IMG, [(6, b'x' * 17), (0, M), (0, S), (4, 7), (4, 9)])
        self.assertEqual(len(got), 224)
        self.assertEqual(got[:32], (0xa0).to_bytes(32, 'big'))
        self.assertEqual(got[160:192], (17).to_bytes(32, 'big'))

    def test_transfer_truncates_row_step(self):
        got = transfer(IMG, usd=19999, balance=19999)
        self.assertEqual(sorted(a[1:] for a in got['accounts']), [(-1, -1), (1, 1)])
        self.assertEqual(len(got['events']), 1)

    def test_event_user_order_keeps_master_first(self):
        got = transfer(IMG, deposit=0)
        self.assertEqual(got['events'][0][3], (M + S).hex())
        self.assertEqual(got['events'][0][8:], (S.hex(), M.hex()))

    def test_code_51_changes_nothing(self):
        got = transfer(IMG, balance=24999)
        self.assertEqual(got['code'], 51)
        self.assertEqual((got['events'], got['accounts']), ([], []))

    def test_none_name_reaches_the_helper(self):
        got = tool.run_modify(IMG, M, S, None, 0xdc, bytes(22))
        self.assertEqual(got['log'], [('modify', tool.EX + 0x37e0, M.hex(), None, S.hex())])
        self.assertEqual((got['tag'], got['word']), (14, 0xdc))

    def test_census_tables(self):
        table = tool.fdes(DATA)
        status = tool.status_rows(IMG, table)
        self.assertIn(('222', 'SelfTransfer', '0x27108ce', '0x2710530', 'reference hint: usdSend core'), status)
        self.assertFalse([r for r in status if r[3] == '0x27148e0' and r[0] == '222'])
        self.assertTrue(all('0x3828' in r[2] for r in tool.reader_rows(IMG, table)))

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
            tool.check_tables(patched((0x27148f6, 'cdcccccccccccc0c')))

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
        tool.exchange(w, {S: M}, {}, (1, 1))
        w.m.store(tool.USER, M)
        tool.q(w.m, tool.ACTION, 5)
        w.m.store(tool.ACTION + 8, S)
        with self.assertRaises(ValueError):
            tool.call(w, 0x1e60d00, tool.OUT, tool.ACTION, tool.USER, tool.EX)

    def test_function_start_is_an_fde_start(self):
        table = tool.fdes(DATA)
        saved = tool.FUNCS
        tool.FUNCS = [(0x27148e1, 'not a start')]
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

    def test_gate_code(self):
        self.check((0x1e60d83, '7001'))

    def test_gate_class_limit(self):
        self.check((0x1e60d33, '04'))

    def test_gate_byte_offset(self):
        self.check((0x1e60d49, 'b1'))

    def test_second_gate_skip(self):
        self.check((0x1e60d72, 'eb'))

    def test_usd_cut(self):
        self.check((0x27148f6, 'cdcccccccccccc0c'))

    def test_zero_code(self):
        self.check((0x2714a66, '32'))

    def test_legs_swapped(self):
        self.check((0x2714935, '44'), (0x2714939, '45'))

    def test_master_compare_gone(self):
        self.check((0x2714ac1, 'eb'))

    def test_link_code(self):
        self.check((0x2714b15, 'db'))

    def test_balance_compare(self):
        self.check((0x2714bd5, '77'))

    def test_balance_code(self):
        self.check((0x2714bdf, '34'))

    def test_event_divisor(self):
        self.check((0x20ae60, '000000000088c340'))

    def test_event_tag(self):
        self.check((0x2714c55, '0f'))

    def test_row_step_shift(self):
        self.check((0x2714d8f, '0a'))

    def test_sender_step_sign(self):
        self.check((0x2714d93, '909090'))

    def test_row_field(self):
        self.check((0x2714dc0, '20'))

    def test_credit_goes_to_sender(self):
        self.check((0x2714bfb, '70000000'))

    def test_hash_gate(self):
        self.check((0x2714cc9, '00'))

    def test_event_user_slot(self):
        self.check((0x2714c94, '15'))

    def test_create_code(self):
        self.check((0x27e3362, 'd9'))

    def test_create_user_table_test_gone(self):
        self.check((0x27e3284, '909090909090'))

    def test_create_equity_argument(self):
        self.check((0x27e33b6, '18'))

    def test_create_settings_word_ignored(self):
        self.check((0x27e344c, '909090909090'), (0x27e3452, '909090909090'))

    def test_create_row_flag(self):
        self.check((0x27e3671, '02'))

    def test_create_tag(self):
        self.check((0x27e371e, '07'))

    def test_create_u32_gate(self):
        same = bytearray(0x78)
        same[0x68] = 1
        case = dict(master=M, sub=S, users=[M], derive=tool.OK, inner=tool.OK, payload=bytes(0x56), equity=10 ** 7, name=b'desk',
                    settings={M: bytes(same), S: bytes(same)})
        self.assertEqual(tool.run_create(IMG, case)['copied'], {})
        self.assertNotEqual(tool.run_create(patched((0x27e3507, '9090')), case)['copied'], {})

    def test_modify_none_word(self):
        self.check((0x22cdfd3, '0000000000000000'))

    def test_modify_code_word(self):
        self.check((0x22ce063, '87'))

    def test_address_token_tag(self):
        self.check((0x3c97960, '04'))

    def test_uint_token_tag(self):
        self.check((0x3c97974, '00'))

    def test_count_field(self):
        self.check((0x3c9793f, '28'))

    def test_dynamic_pad_rounding(self):
        self.check((0x1591ab3, '1e'))

    def test_fixed_pad_rounding(self):
        self.check((0x1591b0a, '1e'))

    def test_head_offset_word_order(self):
        self.check((0x1591fc5, '9090'))


if __name__ == '__main__':
    unittest.main()
