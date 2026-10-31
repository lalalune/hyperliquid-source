"""Tests for tools/vault_subaccount_spot.py.  Runs on the real node #94 binary and needs no binutils."""

import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
FOLDER = ROOT / 'research/work-items/vaults-subaccount-spot-transfer-94'
SPEC = importlib.util.spec_from_file_location('vault_subaccount_spot', ROOT / 'tools/vault_subaccount_spot.py')
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)
DATA = tool.load()
IMG = tool.Image(DATA)
A, B = tool.addr(1), tool.addr(2)
MUTANTS = [
    ('class gate fields swapped', 0x1e64469, '4180bfb105000000', '4180bfb005000000'),
    ('deposit direction swapped', 0x2717aa5, '480f45ca', '480f44ca'),
    ('is_deposit offset', 0x2717a99, '80794400', '80794500'),
    ('token text limit 99', 0x2717c98, '4983f965', '4983f964'),
    ('amount text limit 99', 0x2717ca9, '49837e2865', '49837e2864'),
    ('record kind 4', 0x27146ef, '48c78424a800000003000000', '48c78424a800000004000000'),
    ('self transfer status', 0x2712f67, '66b9de00', '66b9dd00'),
    ('vault status', 0x27130c7, '66b91c00', '66b91d00'),
    ('skip bit test', 0x2712fa8, 'f644247001', 'f644247002'),
    ('kinds 3 and 4 widened', 0x271316f, '4883f802', '4883f803'),
    ('USDC limit becomes strict', 0x27133a3, '0f8701ffffff', '0f8301ffffff'),
    ('chain byte 3 branch', 0x271356a, '4180bc24f208000003', '4180bc24f208000002'),
    ('route 1 branch', 0x27135c9, '0f85aa000000', '0f84aa000000'),
    ('route 0 compare', 0x2713670, '743e', '753e'),
    ('route 2 compare', 0x27136ae, '74c2', '75c2'),
    ('cost selector', 0x2713d14, '4c0f43ac2460020000', '4c0f42ac2460020000'),
    ('sign test on the value', 0x2713d56, '0f880d070000', '0f890d070000'),
    ('event kind', 0x2713f3c, '83bc246002000003', '83bc246002000004'),
    ('free balance equal case', 0x371b93f, '0f96c0', '0f92c0'),
    ('free balance carry test', 0x371b939, '0f93c1', '0f92c1'),
    ('second word store', 0x371b368, '4c897108', '4c897100'),
    ('system range top inclusive', 0x37e51ad, '0f9ec0', '0f9cc0'),
    ('system range top word', 0x37e5189, '48b8000000000000270f', '48b8000000000000270e'),
    ('system range bottom', 0x37e5171, '784b', '794b'),
    ('value cap', 0x371fd42, '48b90000c16ff2862300', '48b90000c16ff2862400'),
    ('token 1 cap exemption', 0x371fd0e, '7446', '7546'),
    ('merge first test', 0x2712b0b, '7716', '7316'),
    ('credit route test', 0x2716fcd, '0f82dd000000', '0f83dd000000'),
    ('gas tree byte test', 0x2717276, '753b', '743b'),
    ('100x gate constant', 0x27172ca, '48b9cb10c7bab88d0600', '48b9ca10c7bab88d0600'),
    ('fee at the amount', 0x2717300, '7321', '7721'),
    ('row flag store', 0x271702b, 'c6403d01', 'c6403d00'),
    ('fee value sign', 0x27173ef, '48f7da', '4889d2'),
]


def patched(*edits):
    """Return an Image with bytes replaced at virtual addresses, checking the old bytes first."""
    data = bytearray(DATA)
    for va, old, new in edits:
        raw = bytes.fromhex(new)
        addr, size, off, _ = next(m for m in IMG.mapped if m[0] <= va < m[0] + m[1])
        at = off + va - addr
        assert data[at:at + len(raw)].hex() == old, hex(va)
        data[at:at + len(raw)] = raw
    return tool.Image(bytes(data))


def disagreements(img):
    """A wild read or a panic from changed bytes also counts as a disagreement."""
    try:
        bad = len(tool.evaluate(img, 120)[1])
        return bad + sum(r[-1] != 'same' for r in tool.named_cases(img))
    except (ValueError, tool.Panic):
        return 1


class Baseline(unittest.TestCase):
    def test_vectors_agree(self):
        counts, bad = tool.evaluate(IMG, 200)
        self.assertEqual(bad, [])
        self.assertEqual(sum(counts.values()), 500)

    def test_every_route_is_reached(self):
        counts = tool.evaluate(IMG)[0]
        labels = {k[1] for k in counts}
        for want in ('status 390 receiver fee', 'status 390 sink', 'status 390 into system', 'status 390 gas step', 'status 390 system sender',
                     'status 28', 'status 38', 'status 222', 'status 247', 'status 330', 'status 344', 'status 347', 'status 356', 'panic unwrap'):
            self.assertIn(want, labels)

    def test_named_cases(self):
        rows = tool.named_cases(IMG)
        self.assertGreater(len(rows), 50)
        self.assertTrue(all(r[-1] == 'same' for r in rows))

    def test_tables(self):
        pins, layout = tool.check_tables(IMG)
        self.assertEqual(len(pins), len(tool.PINS))
        self.assertEqual(len(layout), len(tool.LAYOUT_ROWS))

    def test_gate_rows_decode(self):
        for row in tool.GATES:
            self.assertEqual(tool.decode(IMG.rd, int(row[3], 16)).text(), row[4])

    def test_status_text(self):
        rows = {int(r[0]): r[4] for r in tool.status_rows(IMG)}
        self.assertEqual(rows[28], 'Vault cannot receive spot.')
        self.assertEqual(rows[222], 'Cannot self-transfer.')
        self.assertEqual(rows[38], 'Error transferring to EVM. Use Arbitrum bridge instead.')
        self.assertIn('Invalid sub-account transfer from', rows[218])

    def test_functions_are_fde_starts(self):
        rows = tool.function_rows(IMG, tool.fdes(DATA))
        self.assertEqual(len(rows), len(tool.FUNCS))

    def test_caller_census(self):
        rows = tool.caller_rows(IMG, tool.fdes(DATA))
        sites = {(r[0], r[1]) for r in rows}
        self.assertIn(('0x2712ce0', '0x271470b'), sites)
        self.assertIn(('0x2714570', '0x2717ccc'), sites)
        self.assertIn(('0x2714570', '0x1f6615d'), sites)
        self.assertIn(('0x1e64420', '0x2759e1d'), sites)

    def test_generated_files(self):
        with tempfile.TemporaryDirectory() as d:
            tool.generate(d)
            for f in sorted(Path(d).iterdir()):
                self.assertEqual(f.read_bytes(), (FOLDER / f.name).read_bytes(), f.name)

    def test_manifest(self):
        rows = [line.split('  ') for line in (FOLDER / 'MANIFEST.sha256').read_text().splitlines()]
        names = {r[1] for r in rows}
        self.assertEqual(names, {f.name for f in FOLDER.iterdir() if f.name != 'MANIFEST.sha256'})
        for digest, name in rows:
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest)


class Controls(unittest.TestCase):
    def test_wrong_hash_is_refused(self):
        import unittest.mock as mock
        with mock.patch.object(tool, 'SHA256', '0' * 64):
            with self.assertRaises(SystemExit):
                tool.load()

    def test_read_outside_mapped_bytes(self):
        with self.assertRaises(ValueError):
            IMG.rd(0x7fffffff, 8)

    def test_unknown_encoding_fails_closed(self):
        with self.assertRaises(ValueError):
            tool.decode(lambda va, n: bytes.fromhex('0f05') + bytes(14), 0x1000)

    def test_changed_pin_fails(self):
        img = patched((0x2712f67, '66b9de00', '66b9dd00'))
        with self.assertRaises(ValueError):
            tool.check_tables(img)

    def test_changed_function_changes_hash(self):
        img = patched((0x27130c7, '66b91c00', '66b91d00'))
        table = tool.fdes(DATA)
        self.assertNotEqual(tool.function_rows(img, table)[3][3], tool.function_rows(IMG, table)[3][3])

    def test_wrong_model_is_seen(self):
        c = tool.base_case(vaults=[B])
        want = tool.want_core(c)
        want['status'] = 390
        self.assertFalse(tool.same(tool.run_core(IMG, c), want))

    def test_changed_log_is_seen(self):
        c = tool.base_case()
        want = tool.want_core(c)
        want['log'] = want['log'][1:]
        self.assertFalse(tool.same(tool.run_core(IMG, c), want))

    def test_bad_status_arm(self):
        va = tool.TEXT_TABLE + 4 * 28
        raw = tool.struct.pack('<i', 0).hex()
        img = patched((va, IMG.rd(va, 4).hex(), raw))
        with self.assertRaises((ValueError, UnicodeDecodeError)):
            tool.status_rows(img)


def add(name, va, old, new):
    def test(self):
        self.assertGreater(disagreements(patched((va, old, new))), 0, name)
    setattr(Controls, 'test_mutant_' + name.replace(' ', '_'), test)


for row in MUTANTS:
    add(*row)


if __name__ == '__main__':
    unittest.main()
