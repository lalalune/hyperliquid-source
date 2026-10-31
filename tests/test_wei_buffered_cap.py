"""Controls for tools/wei_buffered_cap.py (RE-004, node #94)."""

import filecmp
import importlib.util
import math
import struct
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / 'tools' / 'wei_buffered_cap.py'
PACKET = ROOT / 'research' / 'work-items' / 'RE-004-wei-buffered-cap-94'

spec = importlib.util.spec_from_file_location('wei_buffered_cap', TOOL)
wbc = importlib.util.module_from_spec(spec)
sys.modules['wei_buffered_cap'] = wbc
spec.loader.exec_module(wbc)

BINARY = ROOT / wbc.BINARY
CACHE = {}
FN = (0x2723c70, 0x27240a3)
AMOUNTS = [0, 1, 10 ** 8, 10 ** 15, 2 ** 53 + 1, 2 ** 63, 2 ** 64 - 1]
FACTORS = [0, 10 ** 8, wbc.MAX_FACTOR_INT, wbc.MAX_FACTOR_INT + 1]


def mutate(insns, va, mnemonic=None, ops=None):
    out = []
    for ins in insns:
        if ins[0] == va:
            ins = (ins[0], mnemonic or ins[1], ops if ops is not None else ins[2], ins[3])
        out.append(ins)
    return out


class Fixture(unittest.TestCase):
    def set_up_class(cls):
        if not CACHE:
            data = BINARY.read_bytes()
            CACHE['data'] = data
            CACHE['analysis'] = wbc.analyse(BINARY, data)
            CACHE['img'] = wbc.Image(data)
            CACHE['insns'] = wbc.parse_listing(wbc.disassemble(BINARY, *FN))
        cls.data = CACHE['data']
        cls.result, cls.rows, cls.details = CACHE['analysis']
        cls.img = CACHE['img']
        cls.insns = CACHE['insns']
        cls.tail = wbc.find_tail(cls.insns)

    setUpClass = classmethod(set_up_class)

    def differs(self, insns):
        machine = wbc.Machine(insns, self.img, {wbc.DROP_A, wbc.DROP_B}, 0x5773190)
        for a in AMOUNTS:
            for f in FACTORS:
                if wbc.run_cap(machine, self.tail, a, f) != wbc.cap_model(a, f):
                    return True
        return False

    def find(self, mn, pred=lambda ins: True):
        lo, hi = self.tail['indices']
        return next(ins for ins in self.insns[lo:hi] if ins[1] == mn and pred(ins))


class Results(Fixture):
    def test_counts(self):
        s = self.result['summary']
        self.assertEqual((s['sse_refs'], s['lea_refs'], s['movabs_refs'], s['functions']), (5, 0, 0, 5))
        self.assertEqual(s['distinct_tail_forms'], 1)
        self.assertEqual(s['limit_1_01_sse_refs'], 36)
        self.assertEqual(s['direct_refs_total'], 1)
        self.assertEqual(s['ratio_flag_one_sites'], 5)
        self.assertEqual(s['grid_mismatches'], 0)
        self.assertEqual(s['factor_window_mismatches'], 0)
        self.assertEqual(s['clamp_mismatches'], 0)
        self.assertEqual(s['lead_grid_mismatches'], 0)
        self.assertEqual(s['lead_clamp_differences'], 1)
        self.assertTrue(s['reciprocal_exact'])
        self.assertFalse(s['nan_or_inf_reachable'])

    def test_lead_difference_is_positive_infinity_only(self):
        self.assertEqual(self.result['lead']['clamp_bits_differing'], ['0x7ff0000000000000'])

    def test_every_site_read_by_mulsd(self):
        for site in self.result['sites']:
            insns = wbc.parse_listing(wbc.disassemble(BINARY, int(site['ref_va'], 16), int(site['ref_va'], 16) + 8))
            self.assertEqual(insns[0][1], 'mulsd')

    def test_rounding_example(self):
        self.assertEqual(wbc.cap_model(10 ** 8, 10 ** 8), (wbc.OK_TAG, 101099999, False))

    def test_saturation(self):
        self.assertEqual(wbc.cap_model(wbc.MASK, 10 ** 8), (wbc.OK_TAG, wbc.MASK, True))
        self.assertIsNone(wbc.saturation_threshold(50_000_000))
        t = wbc.saturation_threshold(10 ** 8)
        self.assertLess(wbc.cap_model(t - 1, 10 ** 8)[1], wbc.MASK)
        self.assertEqual(wbc.cap_model(t, 10 ** 8)[1], wbc.MASK)

    def test_regeneration_is_byte_identical(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            wbc.write(out, self.result, self.rows, self.details)
            names = sorted(p.name for p in out.iterdir())
            self.assertEqual(names, ['boundaries.tsv', 'evidence.json', 'sites.tsv', 'tail-bytes.txt'])
            match, mismatch, errors = filecmp.cmpfiles(out, PACKET, names, shallow=False)
            self.assertEqual((sorted(match), mismatch, errors), (names, [], []))
            for path in out.iterdir():
                self.assertNotIn(chr(64), path.read_text())


class Models(unittest.TestCase):
    def test_factor_bound(self):
        self.assertEqual(wbc.cap_model(1, wbc.MAX_FACTOR_INT)[0], wbc.OK_TAG)
        self.assertEqual(wbc.cap_model(1, wbc.MAX_FACTOR_INT + 1)[0], wbc.ERR_FACTOR)

    def test_clamp_values(self):
        self.assertEqual(wbc.sat(math.inf), 0)
        self.assertEqual(wbc.sat(math.nan), 0)
        self.assertEqual(wbc.sat(-1.5), 0)
        self.assertEqual(wbc.sat(2.0 ** 64), wbc.MASK)
        self.assertEqual(wbc.sat(math.nextafter(2.0 ** 64, 0.0)), (1 << 64) - 2048)
        self.assertEqual(wbc.lead_saturating(math.inf), wbc.MASK)

    def test_reciprocal_controls(self):
        self.assertTrue(wbc.reciprocal_exact(wbc.RECIPROCAL, 75, 10000))
        self.assertFalse(wbc.reciprocal_exact(wbc.RECIPROCAL + 1, 75, 10000))
        self.assertFalse(wbc.reciprocal_exact(wbc.RECIPROCAL, 75, 10001))
        self.assertFalse(wbc.reciprocal_exact(wbc.RECIPROCAL, 74, 10000))

    def test_double_grid_includes_bounds(self):
        grid = set(wbc.double_grid())
        self.assertIn(wbc.d2u(math.inf), grid)
        self.assertIn(wbc.d2u(2.0 ** 64), grid)
        self.assertIn(wbc.d2u(math.nextafter(2.0 ** 63, 0.0)), grid)


class InputControls(Fixture):
    def test_digest_rejects_tampering(self):
        with self.assertRaises(wbc.EvidenceError):
            wbc.check_digest(self.data[:-1])

    def test_absent_constant_rejected(self):
        with self.assertRaises(wbc.EvidenceError):
            wbc.find_constant(self.img, 1.23456789012345)

    def test_address_outside_sections_rejected(self):
        with self.assertRaises(wbc.EvidenceError):
            self.img.read(0x7fffffff0000, 8)

    def test_fde_rejects_low_address(self):
        with self.assertRaises(wbc.EvidenceError):
            wbc.Fdes(self.img).range_of(0x10)


class InstructionControls(Fixture):
    def test_unchanged_is_clean(self):
        self.assertFalse(self.differs(self.insns))

    def test_add_immediate(self):
        ins = self.find('add', lambda i: i[2][1] == ('i', 0xf4240))
        self.assertTrue(self.differs(mutate(self.insns, ins[0], ops=(ins[2][0], ('i', 0xf4241)))))

    def test_factor_branch_inverted(self):
        ins = self.find('jae')
        self.assertTrue(self.differs(mutate(self.insns, ins[0], 'jb')))

    def test_buffer_constant_swapped(self):
        ins = self.find('mulsd', lambda i: i[2][1][0] == 'a')
        self.assertTrue(self.differs(mutate(self.insns, ins[0], ops=(ins[2][0], ('a', 8, 0x20a528)))))

    def test_clamp_bound_swapped(self):
        ins = self.find('movsd', lambda i: i[3].startswith('movsd  xmm1'))
        changed = mutate(self.insns, ins[0], ops=(ins[2][0], ('a', 8, 0x20a7f0)))
        self.assertTrue(self.differs(changed))

    def test_high_half_conversion_removed(self):
        ins = self.find('subpd')
        self.assertTrue(self.differs(mutate(self.insns, ins[0], ops=(ins[2][0], ('a', 16, 0x203e80)))))

    def test_overflow_compare_changed(self):
        ins = self.find('cmp')
        changed = mutate(self.insns, ins[0], ops=(ins[2][0], ('i', 0xfffffffffff0bdc1 - 4096)))
        machine = wbc.Machine(changed, self.img, {wbc.DROP_A, wbc.DROP_B}, 0x5773190)
        got = wbc.run_cap(machine, self.tail, 18428315757950602239, 10 ** 8)
        self.assertNotEqual(got, wbc.cap_model(18428315757950602239, 10 ** 8))


class EvaluatorControls(unittest.TestCase):
    def machine(self, text):
        insns = wbc.parse_listing(text)
        return wbc.Machine(insns, None), insns[0][0]

    def test_unknown_call_stops(self):
        m, start = self.machine('  10:\tcall   20 <x>\n')
        with self.assertRaises(wbc.Unmodelled):
            m.run(start)

    def test_poisoned_xmm_stops(self):
        m, start = self.machine('  10:\taddsd  xmm0,xmm1\n')
        with self.assertRaises(wbc.Unmodelled):
            m.run(start)

    def test_unknown_mnemonic_stops(self):
        m, start = self.machine('  10:\troundsd xmm0,xmm1,0x1\n')
        with self.assertRaises(wbc.Unmodelled):
            m.run(start)

    def test_cvttsd2si_indefinite(self):
        self.assertEqual(wbc.cvttsd2si(2.0 ** 63), 1 << 63)
        self.assertEqual(wbc.cvttsd2si(math.nan), 1 << 63)
        self.assertEqual(wbc.cvttsd2si(-1.5), wbc.MASK)


def elf_with_names(inside, outside=b'', extra_name_off=None):
    """ELF64 whose .shstrtab is `inside` and whose next file bytes are `outside`."""
    shstr_off = 64
    labels = [b'', b'.text', b'.shstrtab', b'.extra']
    shoff = shstr_off + len(inside) + len(outside)

    def name_off(label):
        if label == b'':
            return 0
        return inside.index(label)

    headers = b''
    for label in labels:
        off, size = (shstr_off, len(inside)) if label == b'.shstrtab' else (0, 0)
        off_name = extra_name_off if (label == b'.extra' and extra_name_off is not None) else name_off(label)
        headers += struct.pack('<IIQQQQIIQQ', off_name, 3 if label == b'.shstrtab' else 1,
                               0, 0, off, size, 0, 0, 1, 0)
    header = bytearray(64)
    header[0:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<Q', header, 40, shoff)
    struct.pack_into('<HHH', header, 58, 64, len(labels), labels.index(b'.shstrtab'))
    return bytes(header) + inside + outside + headers


NAMES = b'\0.text\0.shstrtab\0'


class SectionNameBoundsTests(unittest.TestCase):
    def test_name_terminated_inside_shstrtab_is_kept(self):
        self.assertIn('.extra', wbc.sections(elf_with_names(NAMES + b'.extra\0')))

    def test_name_finished_outside_shstrtab_is_rejected(self):
        # '.extra' has no NUL inside .shstrtab; its terminator lives in the
        # following bytes, which the old unbounded search accepted as
        # '.extra_name'.
        with self.assertRaisesRegex(wbc.EvidenceError, 'unterminated section name'):
            wbc.sections(elf_with_names(NAMES + b'.extra', b'_name\0'))

    def test_unterminated_name_is_rejected(self):
        with self.assertRaisesRegex(wbc.EvidenceError, 'unterminated section name'):
            wbc.sections(elf_with_names(NAMES + b'.extra'))

    def test_name_offset_outside_shstrtab_is_rejected(self):
        # The offset points at 'bogus' in the bytes after .shstrtab; on base
        # it was read as a section name instead of being rejected.
        inside = NAMES + b'.extra\0'
        with self.assertRaisesRegex(wbc.EvidenceError, 'section name offset outside .shstrtab'):
            wbc.sections(elf_with_names(inside, b'bogus\0', extra_name_off=len(inside)))


if __name__ == '__main__':
    unittest.main()
