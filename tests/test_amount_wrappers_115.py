import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import amount_wrappers_115 as aw  # noqa: E402

IMAGE = None


def image():
    global IMAGE
    if IMAGE is None:
        data = aw.TARGET.read_bytes()
        IMAGE = (aw.cpu.Image(data), data)
    return IMAGE


class ScalerModel(unittest.TestCase):
    def test_exact_scaling(self):
        self.assertEqual(aw.scaler_model(3 << 16, 1234567, 0, 0, 2, 6), ('ok', 1234567000))

    def test_half_even_ties(self):
        # 0.5 -> 0, 1.5 -> 2, 2.5 -> 2 at zero digits
        self.assertEqual(aw.scaler_model(1 << 16, 5, 0, 0, 2, 0), ('ok', 0))
        self.assertEqual(aw.scaler_model(1 << 16, 15, 0, 0, 2, 0), ('ok', 2))
        self.assertEqual(aw.scaler_model(1 << 16, 25, 0, 0, 2, 0), ('ok', 2))

    def test_negative_rounding_to_zero_is_accepted(self):
        self.assertEqual(aw.scaler_model(0x80000000 | 18 << 16, 1, 0, 0, 2, 6), ('ok', 0))
        self.assertEqual(aw.scaler_model(0x80000000, 1, 0, 0, 2, 0), ('err',))

    def test_bound_and_digits(self):
        self.assertEqual(aw.scaler_model(0, aw.BOUND, 0, 0, 2, 0)[0], 'ok')
        self.assertEqual(aw.scaler_model(0, aw.BOUND + 1, 0, 0, 2, 0), ('err',))
        self.assertEqual(aw.scaler_model(0, 1, 0, 0, 2, 20), ('err',))

    def test_noncanonical_decimals_are_rejected(self):
        for flags in (29 << 16, 1, 0xff << 16, 0x40000000):
            with self.assertRaises(aw.Error):
                aw.scaler_model(flags, 1, 0, 0, 2, 6)


class WrapperRuns(unittest.TestCase):
    def test_every_wrapper_matches_its_model(self):
        img, _ = image()
        for name, entry, kind in aw.WRAPPERS:
            for case in aw.cases(kind, 150, 99):
                self.assertEqual(aw.execute(img, entry, kind, case), aw.model(kind, case), (name, case['dec']))

    def test_twin_bodies_agree(self):
        img, _ = image()
        for (a, ea, kind), (b, eb, kind_b) in (aw.WRAPPERS[1:3], aw.WRAPPERS[3:5], aw.WRAPPERS[5:7]):
            self.assertEqual(kind, kind_b)
            for case in aw.cases(kind, 120, 31):
                self.assertEqual(aw.execute(img, ea, kind, case), aw.execute(img, eb, kind, case), (a, b))

    def test_wrappers_lie_inside_one_fde_each(self):
        img, _ = image()
        for name, entry, kind in aw.WRAPPERS:
            start, end = img.fde_of(entry)
            self.assertEqual(start, entry, name)
            self.assertGreater(end - start, 100)

    def test_slot_names_scaler(self):
        img, _ = image()
        self.assertEqual(img.slots[aw.SLOT], 0x421e9d0)
        for slot in aw.PANIC_SLOTS:
            self.assertIn(slot, img.slots)

    def test_const_wrapper_passes_error_tag(self):
        img, _ = image()
        case = dict(dec=(0x80000000, 7, 0, 0))
        self.assertEqual(aw.execute(img, 0x46aa250, 'const6', case), (aw.SCALE_ERR, None))

    def test_digits_wrapper_collapses_zero_and_errors(self):
        img, _ = image()
        zero = dict(dec=(0, 0, 0, 0), digits=6)
        self.assertEqual(aw.execute(img, 0x274b760, 'digits', zero), (aw.WRAP_ERR, None))
        bad = dict(dec=(0, 5, 0, 0), digits=20)
        self.assertEqual(aw.execute(img, 0x274b760, 'digits', bad), (aw.WRAP_ERR, None))
        fine = dict(dec=(0, 5, 0, 0), digits=2)
        self.assertEqual(aw.execute(img, 0x274b760, 'digits', fine), (aw.OK, 500))

    def test_asset_wrapper_panics(self):
        img, _ = image()
        sizes = [0] * aw.ARRAY_LEN
        sizes[2] = 7
        base = dict(dec=(0, 5, 0, 0), sizes=sizes)
        self.assertEqual(aw.execute(img, 0x3be28a0, 'asset', dict(base, asset=30001)), (aw.OK, 5000000))
        for asset in (30002 + 10000, 30000 + aw.ARRAY_LEN, 30002 - 0):
            want = aw.model('asset', dict(base, asset=asset))
            self.assertEqual(aw.execute(img, 0x3be28a0, 'asset', dict(base, asset=asset)), want)
        self.assertEqual(aw.model('asset', dict(base, asset=30002)), 'panic')

    def test_record_wrapper_echoes_asset_id_and_value(self):
        img, _ = image()
        base = dict(dec=(0, 5, 0, 0), sizes=[1] * aw.ARRAY_LEN)
        case = dict(base, asset=30007)
        self.assertEqual(aw.execute(img, 0x3c42660, 'assetrec', case), (aw.OK, 500000))
        self.assertEqual(aw.execute(img, 0x3c42660, 'assetrec', dict(base, asset=40007)), 'panic')
        zero = dict(case, dec=(0, 0, 0, 0))
        self.assertEqual(aw.execute(img, 0x3c42660, 'assetrec', zero)[0], aw.WRAP_ERR)

    def test_record_wrapper_matches_asset_wrapper_values(self):
        img, _ = image()
        for case in aw.cases('asset', 150, 61):
            a = aw.execute(img, 0x3be28a0, 'asset', case)
            b = aw.execute(img, 0x3c42660, 'assetrec', case)
            self.assertEqual(a if a == 'panic' else a[0], b if b == 'panic' else b[0])
            if a != 'panic' and a[0] == aw.OK:
                self.assertEqual(a, b)

    def test_pair_wrapper_borrow_panics(self):
        img, _ = image()
        pairs = [(0, 1)] * aw.ARRAY_LEN
        table = [(3, 2)] * aw.TABLE_LEN
        case = dict(dec=(0, 5, 0, 0), index=1, pairs=pairs, table=table)
        self.assertEqual(aw.execute(img, 0x2891af0, 'pair', case), 'panic')
        table = [(1, 4)] * aw.TABLE_LEN
        case = dict(case, table=table)
        self.assertEqual(aw.execute(img, 0x2891af0, 'pair', case), (aw.OK, 5000))


class Controls(unittest.TestCase):
    def test_model_mutants_are_caught(self):
        img, _ = image()
        for mut, kind, entry in (('mode_half_up', 'const6', 0x46aa250), ('digits7', 'const6', 0x46aa250),
                                 ('swap_pair', 'pair', 0x2891af0), ('div_1000', 'asset', 0x3be28a0),
                                 ('zero_pass', 'digits', 0x274b760)):
            hit = any(aw.model(kind, c, mut) != aw.execute(img, entry, kind, c) for c in aw.battery(kind, 400))
            self.assertTrue(hit, mut)

    def test_byte_mutants_are_caught(self):
        img, data = image()
        rows = aw.byte_mutants(img)
        self.assertGreaterEqual(len(rows), 30)
        for label, entry, kind, edits in rows:
            bad = aw.cpu.Image(aw.patch_bytes(data, img, edits))
            caught = False
            for case in aw.battery(kind, 400):
                try:
                    got = aw.execute(bad, entry, kind, case)
                except (aw.cpu.ToolError, aw.Error, ValueError, KeyError, IndexError):
                    caught = True
                    break
                if got != aw.model(kind, case):
                    caught = True
                    break
            self.assertTrue(caught, label)

    def test_patch_precondition_guards_wrong_byte(self):
        img, data = image()
        with self.assertRaises(aw.Error):
            aw.patch_bytes(data, img, [(0x46aa25c, 0x77, 0x78)])

    def test_range_controls_reject(self):
        self.assertTrue(all(bad for _, bad in aw.range_controls()))


def packed_controls():
    folder = ROOT / 'research/work-items/l1-shared-amount-wrappers-115'
    return json.loads((folder / 'measure.json').read_text())['negative_controls']


class Evidence(unittest.TestCase):
    def test_packaged_measure_matches_tool_numbers(self):
        folder = ROOT / 'research/work-items/l1-shared-amount-wrappers-115'
        packed = json.loads((folder / 'measure.json').read_text())
        self.assertEqual(packed['cases'], 24000)
        self.assertEqual(packed['negative_controls'], packed['negative_detected'])
        self.assertGreaterEqual(packed['negative_controls'], 30)
        rows = (folder / 'wrapper-cases.tsv').read_text().splitlines()
        self.assertEqual(sum(int(r.split('\t')[3]) for r in rows[1:]), packed['cases'])

    def test_sample_file_and_controls_are_consistent(self):
        folder = ROOT / 'research/work-items/l1-shared-amount-wrappers-115'
        samples = (folder / 'wrapper-samples.tsv').read_text().splitlines()
        self.assertEqual(len(samples) - 1, 8 * 150)
        controls = (folder / 'controls.tsv').read_text().splitlines()[1:]
        self.assertEqual(len(controls), packed_controls())
        self.assertTrue(all(row.endswith('\t1') for row in controls))


if __name__ == '__main__':
    unittest.main()
