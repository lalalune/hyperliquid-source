"""Tests for tools/vault_equity_views.py.  Runs on the real node #94 binary and needs no binutils."""

import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
FOLDER = ROOT / 'research/work-items/vaults-equity-views-94'
SPEC = importlib.util.spec_from_file_location('vault_equity_views', ROOT / 'tools/vault_equity_views.py')
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)
DATA = tool.load()
IMG = tool.Image(DATA)
U, A, B = tool.addr(1), tool.addr(2), tool.addr(3)


def patched(*edits):
    """Return an Image with bytes replaced at virtual addresses."""
    data = bytearray(DATA)
    for va, hexbytes in edits:
        raw = bytes.fromhex(hexbytes)
        addr, size, off, _ = next(m for m in IMG.mapped if m[0] <= va < m[0] + m[1])
        data[off + va - addr:off + va - addr + len(raw)] = raw
    return tool.Image(bytes(data))


def disagreements(img):
    """A wild read from a changed stride also counts as a disagreement."""
    try:
        return len(tool.evaluate(img, 24)[1])
    except ValueError:
        return 1


class Baseline(unittest.TestCase):
    def test_vectors_agree(self):
        counts, bad = tool.evaluate(IMG, 48)
        self.assertEqual(bad, [])
        self.assertEqual(sum(counts.values()), 240)

    def test_named_cases(self):
        rows = tool.named_cases(IMG)
        self.assertEqual(len(rows), 12)
        self.assertTrue(all(r[-1] == 'same' for r in rows))

    def test_tables(self):
        pins, layout = tool.check_tables(IMG)
        self.assertEqual(len(pins), len(tool.PINS))
        self.assertEqual(len(layout), len(tool.LAYOUT_ROWS))

    def test_json_keys(self):
        self.assertEqual([r[2] for r in tool.key_rows(IMG)][:3], ['vaultAddress', 'equity', 'lockedUntilTimestamp'])

    def test_negative_equity_rounds_to_zero_for_a_user(self):
        c = dict(vault=tool.vault(A, users={U: 0.5}), u=U, eq={A: -5000000})
        self.assertEqual(tool.run_user(IMG, c)['equity'], 0)

    def test_tvl_keeps_a_negative_total(self):
        c = dict(vaults={A: tool.vault(A, name=b'x')}, eq={A: -2500000})
        self.assertEqual(tool.run_summary(IMG, c)['rows'][0]['tvl'], -2.5)

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
            tool.check_tables(patched((0x3957be6, '90909090')))

    def test_layout_catches_changed_offset(self):
        rows = tool.LAYOUT_ROWS
        tool.LAYOUT_ROWS = [(s, o, w, va, '[r13+0x77]:64', n) for s, o, w, va, _, n in rows[:1]]
        try:
            with self.assertRaises(ValueError):
                tool.check_tables(IMG)
        finally:
            tool.LAYOUT_ROWS = rows

    def test_key_table_catches_changed_string(self):
        with self.assertRaises(ValueError):
            tool.key_rows(patched((0x420210, '58')))

    def test_unknown_encoding_raises(self):
        with self.assertRaises(ValueError):
            tool.decode(lambda va, n: bytes.fromhex('d9e8' + '90' * 14), 0x1000)

    def test_unmodelled_call_raises(self):
        w = tool.World(IMG)
        del w.stubs[0x3955e80]
        p = w.alloc(0xb0)
        w.m.store(p, tool.vault_bytes(w, tool.vault(A)))
        with self.assertRaises(ValueError):
            tool.call(w, 0x3957bc0, p, tool.CTX)

    def test_function_start_is_an_fde_start(self):
        table = tool.fdes(DATA)
        saved = tool.FUNCS
        tool.FUNCS = [(0x3957bc1, 'not a start')]
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

    def test_total_tag(self):
        self.check((0x3957be9, '02'))

    def test_total_saturation(self):
        self.check((0x3957e32, '90909090'))

    def test_total_recorder(self):
        self.check((0x3957e3f, '909090909090'))

    def test_user_tag(self):
        self.check((0x3957f95, '03'))

    def test_user_floor(self):
        self.check((0x395828c, '90909090'))

    def test_user_non_finite(self):
        self.check((0x395823a, '9090'))

    def test_list_zero_skip_first(self):
        self.check((0x25814b5, '909090909090'))

    def test_list_zero_skip_later(self):
        self.check((0x25818ae, '909090909090'))

    def test_million_constant(self):
        self.check((0x20ae60, '000000000000f03f'))

    def test_summary_tag(self):
        self.check((0x2a35fcc, '03'))

    def test_summary_time_clamp(self):
        self.check((0x2a360cc, '4889ca90'))

    def test_summary_stride(self):
        self.check((0x26b2d8f, '70'))

    def test_fold_stride(self):
        self.check((0x26b162a, 'a8'))

    def test_iterator_stride(self):
        self.check((0x27e13d2, 'a8'))


if __name__ == '__main__':
    unittest.main()
