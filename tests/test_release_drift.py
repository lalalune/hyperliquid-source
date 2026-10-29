from pathlib import Path
import os
import shutil
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
sys.path.insert(0, str(ROOT / 'research/work-items/RE-014-release-drift'))
from release_drift import classify, fingerprint, monotonic_anchors, normalize, path_strings, require_pie_without_textrel, tsv_bytes
import mutation_controls

PLT, STARTS = (0x900, 0x980), {0x2000}


def norm(text, start=0x1000, end=0x1100):
    return normalize(text, start, end, STARTS, PLT)


def row(start, raw, masked, size=16, callees=()):
    return {'start': start, 'size': size, 'raw': raw, 'norm': masked, 'callees': list(callees)}


@unittest.skipUnless(shutil.which('objdump'), 'GNU objdump not installed')
class MutationControls(unittest.TestCase):
    def test_each_mutation_gets_its_expected_class(self):
        for name, mutation, expected in mutation_controls.CASES:
            with self.subTest(name):
                self.assertEqual(mutation_controls.classes(**mutation), expected)


class Normalize(unittest.TestCase):
    def test_masks_only_address_like_operands(self):
        self.assertEqual(norm('call   2000 <foo>'), ('call @fde', ('branch_fde',), 0x2000))
        self.assertEqual(norm('call   910 <x@plt>'), ('call @plt', ('branch_plt',), None))
        self.assertEqual(norm('jmp    3000'), ('jmp @unknown', ('branch_unknown',), None))
        self.assertEqual(norm('jne    1010'), ('jne +0x10', (), None))
        self.assertEqual(norm('lea    0x1234(%rip),%rax        # 5678 <bar>'), ('lea RIP,%rax', ('rip',), None))

    def test_negative_control_immediates_and_displacements_are_never_masked(self):
        # PIE without text relocations: an immediate that falls inside the image range is still a constant.
        self.assertEqual(norm('mov    $0x2000,%edi')[0], 'mov $0x2000,%edi')
        self.assertNotEqual(norm('sub    $0x348,%rsp')[0], norm('sub    $0x3d8,%rsp')[0])
        self.assertNotEqual(norm('movb   $0x0,0x340(%rsp)')[0], norm('movb   $0x0,0x3c8(%rsp)')[0])
        self.assertEqual(norm('mov    $0x2a,%eax')[0], 'mov $0x2a,%eax')
        self.assertEqual(norm('mov    0x18(%rsp),%rax')[0], 'mov 0x18(%rsp),%rax')
        self.assertNotEqual(norm('mov    $0x2a,%eax')[0], norm('mov    $0x2b,%eax')[0])
        self.assertNotEqual(norm('call   2000')[0], norm('call   910')[0])

    def test_intra_function_branch_offsets_are_compared(self):
        self.assertNotEqual(norm('jmp    1010')[0], norm('jmp    1020')[0])


class Fingerprint(unittest.TestCase):
    LINES = ['\n', '    1000:\tpush   %rbp\n', '    1001:\tcall   1010 <f>\n', '    1006:\tret\n',
             '    1010:\tret\n']

    def run_fp(self, spans, lines=None):
        return fingerprint(spans, lambda s, e: bytes(e - s), lines or self.LINES, PLT)

    def test_records_call_sites_and_masks(self):
        rows = self.run_fp([(0x1000, 0x1007), (0x1010, 0x1011)])
        self.assertEqual([r['insns'] for r in rows], [3, 1])
        self.assertEqual(rows[0]['callees'], [0x1010])
        self.assertEqual(dict(rows[0]['masks']), {'branch_fde': 1})

    def test_fails_closed_on_an_extent_with_no_decoded_instructions(self):
        with self.assertRaisesRegex(ValueError, 'No instructions decoded inside extent 0x1020'):
            self.run_fp([(0x1000, 0x1007), (0x1020, 0x1030)])


class Classify(unittest.TestCase):
    def test_raw_and_masked_verdicts_are_reported_separately(self):
        old = [row(0x10, 'r1', 'm1'), row(0x20, 'r2', 'm2')]
        new = [row(0x110, 'r1', 'm1'), row(0x120, 'r9', 'm2')]
        table = classify(old, new)
        self.assertEqual([r[:3] for r in table], [['identical', 'true', 'true'], ['moved_only', 'false', 'true']])

    def test_negative_control_duplicate_hashes_never_get_a_hash_match_class(self):
        old = [row(0x10, 'a', 'm'), row(0x20, 'b', 'm')]
        new = [row(0x110, 'c', 'm'), row(0x120, 'd', 'm'), row(0x130, 'e', 'x')]
        rows = classify(old, new)
        self.assertEqual(sorted(r[0] for r in rows), ['duplicate_ordered', 'duplicate_ordered', 'unmatched_115'])
        self.assertTrue(all(r[7].startswith('duplicate-order-gap-') for r in rows if r[0] == 'duplicate_ordered'))
        three = classify(old + [row(0x30, 'f', 'm')], new)
        self.assertEqual(sorted(r[0] for r in three), ['equivalent_unpaired'] * 5 + ['unmatched_115'])

    def test_callee_position_pairs_changed_code_only_within_size_bound(self):
        old = [row(0x10, 'p', 'P', callees=[0x20]), row(0x20, 'x', 'X', size=100)]
        near = [row(0x110, 'p', 'P', callees=[0x120]), row(0x120, 'y', 'Y', size=150)]
        far = [row(0x110, 'p', 'P', callees=[0x120]), row(0x120, 'y', 'Y', size=201)]
        self.assertEqual([r[0] for r in classify(old, near)], ['identical', 'changed'])
        self.assertEqual([r[0] for r in classify(old, far)], ['unmatched_115', 'identical', 'unmatched_94'])

    def test_negative_control_callee_position_never_claims_a_body_with_a_twin(self):
        old = [row(0x10, 'p', 'P', callees=[0x20]), row(0x20, 'x', 'X')]
        new = [row(0x110, 'p', 'P', callees=[0x120]), row(0x120, 'y', 'Y'), row(0x130, 'x2', 'X'), row(0x140, 'q', 'X')]
        self.assertEqual([r[0] for r in classify(old, new)],
                         ['unmatched_115', 'equivalent_unpaired', 'equivalent_unpaired', 'identical', 'equivalent_unpaired'])

    def test_duplicates_pair_by_order_only_within_one_anchor_gap(self):
        anchors_old = [row(0x10, 'a', 'A'), row(0x100, 'b', 'B')]
        anchors_new = [row(0x110, 'a', 'A'), row(0x200, 'b', 'B')]
        old = anchors_old + [row(0x20, 'd', 'D'), row(0x30, 'd', 'D')]
        new = anchors_new + [row(0x150, 'd', 'D'), row(0x160, 'd', 'D')]
        rows = {r[3]: r for r in classify(old, new)}
        self.assertEqual(rows['0x20'][0], 'duplicate_ordered')
        self.assertEqual(rows['0x20'][5], '0x150')
        self.assertEqual(rows['0x30'][5], '0x160')
        self.assertEqual(rows['0x20'][1:3], ['true', 'true'])

    def test_negative_control_duplicates_split_across_gaps_stay_unpaired(self):
        old = [row(0x10, 'a', 'A'), row(0x100, 'b', 'B'), row(0x20, 'd', 'D'), row(0x30, 'd', 'D')]
        new = [row(0x110, 'a', 'A'), row(0x200, 'b', 'B'), row(0x150, 'd', 'D'), row(0x250, 'd', 'D')]
        self.assertEqual(sorted(r[0] for r in classify(old, new))[:2], ['equivalent_unpaired'] * 2)
        self.assertNotIn('duplicate_ordered', [r[0] for r in classify(old, new)])

    def test_a_leftover_copy_of_a_paired_body_is_equivalent_not_unmatched(self):
        old = [row(0x10, 'x1', 'X'), row(0x20, 'x2', 'X')]
        new = [row(0x110, 'x1', 'X'), row(0x120, 'y', 'Y')]
        self.assertEqual([r[0] for r in classify(old, new)], ['unmatched_115', 'identical', 'equivalent_unpaired'])

    def test_anchor_chain_drops_crossing_pairs(self):
        pairs = {0x10: (0x110, ''), 0x20: (0x300, ''), 0x30: (0x120, ''), 0x40: (0x130, '')}
        self.assertEqual(monotonic_anchors(pairs), [(0x10, 0x110), (0x30, 0x120), (0x40, 0x130)])

    def test_output_is_independent_of_input_order(self):
        old = [row(0x10, 'p', 'P', callees=[0x20, 0x30]), row(0x20, 'x', 'X'), row(0x30, 'z', 'Z')]
        new = [row(0x110, 'p', 'P', callees=[0x120, 0x130]), row(0x120, 'y', 'Y'), row(0x130, 'z2', 'Z')]
        self.assertEqual(tsv_bytes(classify(old, new)), tsv_bytes(classify(old[::-1], new[::-1])))


class PieGuard(unittest.TestCase):
    @staticmethod
    def elf(e_type, dynamic):
        data = bytearray(b'\x7fELF\x02\x01' + bytes(58) + dynamic)
        data[16:18] = e_type.to_bytes(2, 'little')
        return bytes(data), {'.dynamic': {'offset': 64, 'size': len(dynamic)}}

    @staticmethod
    def dyn(*entries):
        return b''.join(t.to_bytes(8, 'little') + v.to_bytes(8, 'little') for t, v in entries)

    def test_accepts_pie_without_text_relocations(self):
        require_pie_without_textrel(*self.elf(3, self.dyn((30, 8), (0, 0))))

    def test_fails_closed_on_non_pie_or_text_relocations(self):
        for e_type, dynamic in ((2, self.dyn((0, 0))), (3, self.dyn((22, 0), (0, 0))), (3, self.dyn((30, 4), (0, 0))),
                                (3, self.dyn((30, 8)))):
            with self.subTest(e_type=e_type, dynamic=dynamic.hex()):
                with self.assertRaises(ValueError):
                    require_pie_without_textrel(*self.elf(e_type, dynamic))


class PathStrings(unittest.TestCase):
    def test_matches_only_at_a_path_boundary(self):
        datas = {'94': b'\0/home/u/code/l1/src/time.rs\0', '115': b'\0/rustc/x/library/std/src/time.rs\0xl1/src/time.rs'}
        out = path_strings(datas, {'absent115': ['l1/time.rs'], 'added115': []})
        self.assertEqual(out, [{'catalogue_list': 'absent115', 'path': 'l1/time.rs',
                                'string_in_94': True, 'string_in_115': False}])


class Determinism(unittest.TestCase):
    def test_classification_bytes_do_not_depend_on_hash_seed(self):
        code = ('import sys; sys.path[:0] = [sys.argv[1]]; from test_release_drift import Classify, row; '
                'from release_drift import classify, tsv_bytes; import hashlib; '
                'old = [row(i, f"r{i}", f"m{i % 7}", callees=[i + 1]) for i in range(60)]; '
                'new = [row(i + 5, f"s{i}", f"m{i % 7}", callees=[i + 6]) for i in range(60)]; '
                'print(hashlib.sha256(tsv_bytes(classify(old, new))).hexdigest())')
        outs = {subprocess.run([sys.executable, '-c', code, str(ROOT / 'tests')], capture_output=True, text=True,
                               check=True, env={**os.environ, 'PYTHONHASHSEED': seed}).stdout for seed in ('0', '1', '4242')}
        self.assertEqual(len(outs), 1)


if __name__ == '__main__':
    unittest.main()
