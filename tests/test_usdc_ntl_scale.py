"""Tests for tools/usdc_ntl_scale.py: field binding, whole-domain pieces and damaged copies of node #94."""

import filecmp
import importlib.util
import json
import math
from pathlib import Path
import struct
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
FOLDER = ROOT / 'research/work-items/RE-004-usdc-ntl-scale-94'
spec = importlib.util.spec_from_file_location('usdc_ntl_scale', ROOT / 'tools/usdc_ntl_scale.py')
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)


SHARED = {}


def set_up_class(cls):
    if not SHARED:
        SHARED['image'] = tool.Image(tool.load_target(ROOT / tool.BINARY))
        SHARED['result'] = tool.analyse(SHARED['image'])
        SHARED['controls'] = tool.control_rows(SHARED['image'])
    cls.image, cls.result, cls.controls = SHARED['image'], SHARED['result'], SHARED['controls']


def tsv(name):
    lines = (FOLDER / name).read_text(encoding='ascii').splitlines()
    head = lines[0].split('\t')
    return [dict(zip(head, line.split('\t'))) for line in lines[1:]]


class Binding(unittest.TestCase):
    setUpClass = classmethod(set_up_class)

    def test_all_serializers_name_the_field(self):
        rows = self.result['binding']
        self.assertEqual(len(rows), 3)
        for row in rows:
            self.assertEqual(row[5], 'usdc_ntl_scale')
            self.assertEqual(row[6:10], (0x2e0, 'last_set_global_time', 0x2a8, 'isolated_external'))
        self.assertEqual([row[12] for row in rows], ['-', 'collateralToken', '-'])

    def test_wrong_key_is_refused(self):
        address = self.result['binding'][1][4]
        damaged = self.image.patched([(address, b'x')])
        with self.assertRaises(tool.EvidenceError):
            tool.binding_rows(damaged)

    def test_wrong_token_key_is_refused(self):
        row = self.result['binding'][1]
        damaged = self.image.patched([(row[11], b'x')])
        with self.assertRaises(tool.EvidenceError):
            tool.binding_rows(damaged)

    def test_census_has_no_unclassified_row(self):
        self.assertNotIn('unclassified', self.result['classes'])
        self.assertEqual(sum(1 for row in self.result['uses'] if row[1] == 'mulsd'), 25)
        self.assertEqual(sum(1 for c in self.result['classes'] if c == 'clamp site, proved'), 6)
        self.assertEqual(sum(1 for c in self.result['classes'] if c == 'writer store, proved'), 3)
        self.assertEqual(sum(1 for c in self.result['classes'] if c == 'serializer load, key read'), 3)

    def test_callers(self):
        rows = self.result['callers']
        self.assertEqual(sum(1 for r in rows if r[0] == 'indirect' and r[2] == 0x370c100), 3)
        self.assertEqual(sum(1 for r in rows if r[0] == 'indirect' and r[2] == 0x370c1e0), 3)
        self.assertEqual(sum(1 for r in rows if r[0] == 'direct'), 6)

    def test_slot_with_a_foreign_target_is_refused(self):
        relocs = dict(self.image.relocs)
        relocs[0x5774cd8] = 0x370c1e0
        with self.assertRaises(tool.EvidenceError):
            tool.slot_callers(tool.Image(self.image.data, self.image.fdes, relocs))


class Pieces(unittest.TestCase):
    setUpClass = classmethod(set_up_class)

    def test_each_site_covers_all_bit_patterns(self):
        for site in self.result['clamps']:
            rows = sorted((lo, hi) for lo, hi, _a, _b in site['pieces'])
            self.assertEqual(rows[0][0], 0)
            self.assertEqual(rows[-1][1], tool.U64)
            for left, right in zip(rows, rows[1:]):
                self.assertEqual(left[1] + 1, right[0])

    def test_six_sites_agree(self):
        signed = [site for site in self.result['clamps'] if not site['nonneg']]
        self.assertEqual(len(signed), 5)
        shapes = {tuple((lo, hi, a[1][0]) for lo, hi, a, _b in site['pieces']) for site in signed}
        self.assertEqual(len(shapes), 1)

    def test_writer_rule(self):
        self.assertEqual(len(self.result['writers']), 3)
        for writer in self.result['writers']:
            for status, lo, hi, kind, _first, _last in writer['table']:
                self.assertEqual(kind == 'scaled', bool(status & 1) and hi < tool.SCALE_GATE)
            self.assertEqual(writer['vectors'], 2066)

    def test_writer_compare_forms(self):
        self.assertEqual([w['shape'] for w in self.result['writers']], ['jb', 'jae', 'jae'])

    def test_gate_boundary(self):
        rows = self.result['gate']
        multiplied = [hi for _lo, hi, first, _last in rows if first[1][0] == 'multiplied']
        returned = [lo for lo, _hi, first, _last in rows if first[1][0] == 'returned']
        self.assertEqual(max(multiplied), tool.SCALE_GATE)
        self.assertEqual(min(returned), tool.SCALE_GATE + 1)

    def test_interior_points_match_the_model(self):
        points = [tool.to_bits(float(tool.CLAMP) + delta) for delta in (-64.0, -32.0, -16.0, 0.0, 16.0, 32.0)]
        points += [tool.to_bits(-float(tool.CLAMP) + delta) for delta in (-32.0, -16.0, 0.0, 16.0, 32.0)]
        points += [tool.to_bits(value) for value in (0.5, -0.5, 1.0, -1.0, 2.0 ** 62, -2.0 ** 62, 1e300, -1e300, 5e-324)]
        state = 0x2545f4914f6cdd1d
        for _ in range(3000):
            state = (state * 0xd1342543de82ef95 + 1) & tool.U64
            points.append(state)
            points.append((0x4300000000000000 | (state >> 8)) ^ (state << 63 & tool.U64))
        for mulsd, nonneg, seeds in tool.CONSUMERS:
            evaluate = tool.clamp_evaluator(self.image, mulsd, seeds)[0]
            for bits in points:
                self.assertEqual(evaluate(bits)[1], tool.clamp_model(bits, nonneg), (hex(mulsd), hex(bits)))

    def test_constants_are_bare(self):
        self.assertEqual(tool.SCALE_GATE, tool.U64 // 100)
        self.assertEqual(tool.CLAMP, (tool.SIGN - 1) // 100)

    def test_clamp_model_edges(self):
        bits = tool.to_bits
        two63 = 2.0 ** 63
        self.assertEqual(tool.clamp_model(bits(two63), False), ('const', tool.CLAMP))
        self.assertEqual(tool.clamp_model(bits(-two63), False), ('panic', tool.ABS_OVERFLOW_LOCATION))
        self.assertEqual(tool.clamp_model(bits(-two63), True), ('panic', tool.ABS_OVERFLOW_LOCATION))
        self.assertEqual(tool.clamp_model(bits(math.inf), False), ('const', 0))
        self.assertEqual(tool.clamp_model(bits(-math.inf), True), ('const', 0))
        self.assertEqual(tool.clamp_model(tool.INF_BITS + 1, False), ('const', 0))
        self.assertEqual(tool.clamp_model(bits(-1.5), False), ('trunc', tool.U64))
        self.assertEqual(tool.clamp_model(bits(-1.5), True), ('const', 0))
        self.assertEqual(tool.clamp_model(bits(0.9), True), ('const', 0))
        self.assertEqual(tool.clamp_model(bits(1.5), True), ('trunc', 1))

    def test_derived_range(self):
        derived = tool.derived_range()
        self.assertTrue(derived['product_is_finite'])
        self.assertTrue(derived['product_is_at_least_2_pow_63'])


class Machine(unittest.TestCase):
    setUpClass = classmethod(set_up_class)

    def test_refine_finds_a_threshold(self):
        def evaluate(u):
            return [('cmp', u < 12345)], ('kind', u)
        pieces, runs = tool.refine(evaluate, [(0, tool.U64)])
        rows = tool.merged(pieces)
        self.assertEqual([(lo, hi) for lo, hi, _a, _b in rows], [(0, 12344), (12345, tool.U64)])
        self.assertGreater(runs, 2)

    def test_refine_splits_on_output_form(self):
        def evaluate(u):
            return [], ('low' if u < 5 else 'high', u)
        rows = tool.merged(tool.refine(evaluate, [(0, 9)])[0])
        self.assertEqual([(lo, hi) for lo, hi, _a, _b in rows], [(0, 4), (5, 9)])

    def test_two_moving_operands_are_refused(self):
        run = tool.Run(self.image, {}, {}, {})
        with self.assertRaises(tool.EvidenceError):
            run.compare_int(0, (1, 1, 'a'), (2, 1, 'b'))
        with self.assertRaises(tool.EvidenceError):
            run.compare_float(0, (0, 0, 1, 'a'), (0, 0, 1, 'b'), False)

    def test_carried_value_cannot_be_compared(self):
        run = tool.Run(self.image, {}, {}, {})
        with self.assertRaises(tool.EvidenceError):
            run.compare_float(0, (0, 0, 2, 'a'), (0, 0, 0, 'const'), False)

    def test_branch_without_flags_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.Run(self.image, {}, {}, {}).condition(2)

    def test_unknown_instruction_is_refused(self):
        damaged = self.image.patched([(0x370c120, bytes.fromhex('0fa290909090'))])
        with self.assertRaises(tool.EvidenceError):
            tool.analyse_clamp(damaged, 0x370c118, True, {})

    def test_wrong_floor_claim_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.analyse_clamp(self.image, 0x370c118, False, {})
        with self.assertRaises(tool.EvidenceError):
            tool.analyse_clamp(self.image, 0x370c1e5, True, {})

    def test_site_must_be_a_field_multiply(self):
        with self.assertRaises(tool.EvidenceError):
            tool.analyse_clamp(self.image, 0x370c120, True, {})
        damaged = self.image.patched([(0x370c11c, b'\xa8')])
        with self.assertRaises(tool.EvidenceError):
            tool.analyse_clamp(damaged, 0x370c118, True, {})

    def test_writer_needs_its_function(self):
        with self.assertRaises(tool.EvidenceError):
            tool.analyse_writer(self.image, 0x4ce4d00, *tool.WRITERS[0][1:])

    def test_r13_write_in_the_loop_is_refused(self):
        rows = tool.sweep(self.image, *self.image.fde_of(0x26fd900))
        store, tail, cap_row = tool.WRITERS[0][1:]
        tool.writer_row_facts(self.image, rows, store, tail, cap_row)
        damaged = self.image.patched([(0x26fd9c9, bytes.fromhex('4d89d5'))])
        rows = tool.sweep(damaged, *damaged.fde_of(0x26fd900))
        with self.assertRaises(tool.EvidenceError):
            tool.writer_row_facts(damaged, rows, store, tail, cap_row)


class Target(unittest.TestCase):
    setUpClass = classmethod(set_up_class)

    def test_wrong_digest_is_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'hl-node'
            path.write_bytes(b'not the binary')
            with self.assertRaises(tool.EvidenceError):
                tool.load_target(path)

    def test_nobits_section_has_no_bytes(self):
        table = tool.elf_index.sections(self.image.data)
        bss = next(s for s in table if s['name'] == '.bss')
        with self.assertRaises(tool.EvidenceError):
            self.image.file_offset(bss['address'])

    def test_address_outside_every_fde(self):
        with self.assertRaises(tool.EvidenceError):
            self.image.fde_of(0x10)

    def test_panic_location_text(self):
        self.assertEqual(self.result['panic'], ('rustc/library/core/src/num/mod.rs', 320, 5))

    def test_no_external_program(self):
        source = (ROOT / 'tools/usdc_ntl_scale.py').read_text(encoding='utf-8')
        self.assertNotIn('subprocess', source)
        self.assertNotIn('objdump -', source)


class Evidence(unittest.TestCase):
    setUpClass = classmethod(set_up_class)

    def test_every_control_is_rejected(self):
        self.assertTrue(self.controls)
        survivors = [row[0] for row in self.controls if row[1] != 'rejected']
        self.assertEqual(survivors, [])

    def test_controls_fail_by_behaviour(self):
        refused = [row for row in self.controls if 'outside the model' in row[2]]
        self.assertEqual(refused, [])

    def test_stored_summary(self):
        summary = json.loads((FOLDER / 'evidence.json').read_text(encoding='ascii'))
        self.assertEqual(summary['sha256'], tool.SHA256)
        self.assertEqual(summary['field_uses'], len(self.result['uses']))
        self.assertEqual(summary['controls'], summary['controls_rejected'])

    def test_stored_tables(self):
        self.assertEqual(len(tsv('clamp-sites.tsv')), 6)
        self.assertEqual(len(tsv('writer-copies.tsv')), 3)
        self.assertEqual({row['key'] for row in tsv('field-binding.tsv')}, {'usdc_ntl_scale'})

    def test_tool_regenerates_the_evidence_byte_for_byte(self):
        with tempfile.TemporaryDirectory() as folder:
            out = Path(folder)
            self.assertEqual(tool.main(['--out', str(out)]), 0)
            names = sorted(p.name for p in out.iterdir())
            self.assertEqual(names, sorted(p.name for p in FOLDER.iterdir()
                                           if p.name not in ('README.md', 'MANIFEST.sha256')))
            for name in names:
                self.assertTrue(filecmp.cmp(out / name, FOLDER / name, shallow=False), name)

    def test_manifest_matches(self):
        import hashlib
        lines = (FOLDER / 'MANIFEST.sha256').read_text(encoding='ascii').splitlines()
        rows = dict(reversed(line.split('  ')) for line in lines)
        self.assertEqual(sorted(rows), sorted(p.name for p in FOLDER.iterdir() if p.name != 'MANIFEST.sha256'))
        for name, digest in rows.items():
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest)

    def test_float_helpers_round_trip(self):
        self.assertEqual(tool.to_float(struct.unpack('<Q', struct.pack('<d', 1.5))[0]), 1.5)
        self.assertEqual(tool.to_bits(1.0), tool.ONE_BITS)


if __name__ == '__main__':
    unittest.main()
