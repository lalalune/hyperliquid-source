import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('guard', ROOT / 'tools/owned_db_dir_guard.py')
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)
PACKET = ROOT / 'research/work-items/RE-009-owned-db-dir-guard-94'
DATA = guard.load_binary()
VIEW = guard.View(DATA)
CONSTANTS = guard.loop_constants(VIEW)


class Patched(guard.View):
    """A view with a VA byte overlay, so controls never copy the whole binary."""

    def __init__(self, base, patch):
        self.__dict__.update(base.__dict__)
        self.patch = patch

    def mem(self, va, size):
        raw = bytearray(super().mem(va, size))
        for where, byte in self.patch.items():
            if va <= where < va + size:
                raw[where - va] = byte
        return bytes(raw)


class Report(unittest.TestCase):
    report = guard.build(DATA)

    def test_identity(self):
        self.assertEqual(self.report['binary_sha256'], guard.SHA256)

    def test_needle_and_panic(self):
        self.assertEqual(self.report['needle'], 'checkpoint')
        self.assertEqual(self.report['panic']['pieces'], ['OwnedDbDir invalid dir ', None])
        self.assertEqual(self.report['panic']['location']['file'], 'db/src/owned_db_home.rs')
        self.assertEqual(self.report['panic']['location']['line'], 21)

    def test_singleton_key(self):
        self.assertEqual(self.report['singleton']['kind'], 'OwnedDbDir')
        self.assertEqual(self.report['singleton']['key_pieces'], [None, '::', None])

    def test_constructor_reached_by_slot_only(self):
        self.assertEqual(self.report['constructor']['direct_rel32_calls'], 0)
        self.assertEqual([c['site'] for c in self.report['callers']],
                         ['0x257399e', '0x4872579', '0x4883953'])

    def test_every_caller_builds_dir_slash_name(self):
        self.assertEqual(self.report['path_template']['pieces'], [None, '/', None])
        self.assertEqual([c['compares_bundle_with_3'] for c in self.report['callers']],
                         [True, False, True])

    def test_search_coverage_is_exact(self):
        result = self.report['search_coverage']
        self.assertEqual(result['lengths'], 513)
        self.assertEqual(result['missing_starts'], 0)
        self.assertEqual(result['starts_past_end'], 0)

    def test_no_absolute_paths_in_report(self):
        text = json.dumps(self.report)
        self.assertNotIn('ubuntu', text)
        self.assertNotIn('code_Mainnet', text)

    def test_outputs_match_packet(self):
        with tempfile.TemporaryDirectory() as tmp:
            guard.write_outputs(self.report, Path(tmp))
            name = guard.JSON_NAME
            self.assertEqual((Path(tmp) / name).read_bytes(), (PACKET / name).read_bytes())


class SearchModel(unittest.TestCase):
    def test_short_lengths(self):
        self.assertEqual(guard.covered_starts(9, CONSTANTS), set())
        self.assertEqual(guard.covered_starts(10, CONSTANTS), {0})
        self.assertEqual(guard.covered_starts(11, CONSTANTS), {0, 1})
        self.assertEqual(guard.covered_starts(24, CONSTANTS), set(range(15)))
        self.assertEqual(guard.covered_starts(25, CONSTANTS), set(range(16)))

    def test_regime_edges(self):
        for length in (73, 74, 137, 138, 139, 201, 202):
            self.assertEqual(guard.covered_starts(length, CONSTANTS), set(range(length - 9)))

    def control(self, **change):
        return guard.coverage({**CONSTANTS, **change})

    def test_shorter_window_opens_a_gap(self):
        self.assertGreater(self.control(window_step=8)['missing_starts'], 0)

    def test_shorter_tail_opens_a_gap(self):
        self.assertGreater(self.control(tail_back=24)['starts_past_end'], 0)

    def test_longer_tail_changes_coverage(self):
        result = self.control(tail_back=41)
        self.assertGreater(result['missing_starts'] + result['starts_past_end'], 0)

    def test_wrong_scalar_stop_is_caught(self):
        self.assertGreater(self.control(scalar_stop=12)['missing_starts'], 0)

    def test_wrong_exact_length_is_caught(self):
        result = guard.coverage({**CONSTANTS, 'exact': 11})
        self.assertGreater(result['missing_starts'], 0)

    def test_longer_needle_is_not_covered_exactly(self):
        self.assertGreater(guard.coverage(CONSTANTS, needle_len=11)['starts_past_end'], 0)


class Controls(unittest.TestCase):
    def test_wrong_digest_rejected(self):
        with self.assertRaisesRegex(ValueError, 'sha256'):
            guard.load_binary(expected='0' * 64)

    def test_every_rip_pin_holds(self):
        for pin in guard.RIP_PINS:
            guard.check_rip_pin(VIEW, pin)

    def test_every_byte_pin_holds(self):
        for pin in guard.BYTE_PINS:
            guard.check_byte_pin(VIEW, pin)

    def test_panic_pin_rejects_nop(self):
        pin = next(p for p in guard.RIP_PINS if p[0] == 0x158e923)
        with self.assertRaisesRegex(ValueError, 'differ'):
            guard.check_rip_pin(Patched(VIEW, {0x158e923: 0x90}), pin)

    def test_panic_pin_rejects_other_slot(self):
        pin = next(p for p in guard.RIP_PINS if p[0] == 0x158e923)
        with self.assertRaisesRegex(ValueError, 'targets'):
            guard.check_rip_pin(Patched(VIEW, {0x158e925: 0x00}), pin)

    def test_hit_branch_pin_rejects_other_target(self):
        pin = next(p for p in guard.RIP_PINS if p[0] == 0x158ea10)
        with self.assertRaisesRegex(ValueError, 'targets'):
            guard.check_rip_pin(Patched(VIEW, {0x158ea12: 0x00}), pin)

    def test_ud2_pin_rejects_change(self):
        pin = next(p for p in guard.BYTE_PINS if p[0] == 0x158edb3)
        with self.assertRaises(ValueError):
            guard.check_byte_pin(Patched(VIEW, {0x158edb3: 0x90}), pin)

    def test_needle_rejects_changed_immediate(self):
        with self.assertRaisesRegex(ValueError, 'needle'):
            guard.needle(Patched(VIEW, {0x158e89e: 0x43}))

    def test_needle_rejects_changed_length_ten_form(self):
        with self.assertRaisesRegex(ValueError, 'length-10'):
            guard.needle(Patched(VIEW, {0x158e8df: 0x43}))

    def test_needle_rejects_changed_vector(self):
        with self.assertRaisesRegex(ValueError, 'vector'):
            guard.needle(Patched(VIEW, {guard.LAST_VECTOR + 15: 0x54}))

    def test_needle_rejects_changed_verifier_text(self):
        with self.assertRaisesRegex(ValueError, 'vector'):
            guard.needle(Patched(VIEW, {guard.TAIL_NEEDLE + 2: 0x43}))

    def test_template_rejects_unknown_tag(self):
        with self.assertRaisesRegex(ValueError, 'tag'):
            guard.decode_template(Patched(VIEW, {guard.PANIC_TEMPLATE: 0xc1}), guard.PANIC_TEMPLATE)

    def test_out_of_range_address_rejected(self):
        with self.assertRaisesRegex(ValueError, 'outside'):
            VIEW.mem(0x7fff00000000, 4)

    def test_nobits_is_not_readable(self):
        bss = next(s for s in VIEW.sections if s['name'] == '.bss')
        with self.assertRaisesRegex(ValueError, 'outside'):
            VIEW.mem(bss['address'] + 8, 8)

    def test_location_rejects_foreign_path(self):
        with self.assertRaisesRegex(ValueError, 'Location'):
            guard.location(VIEW, 0x5675500)

    def test_relative_rejects_unknown_slot(self):
        with self.assertRaisesRegex(ValueError, 'RELATIVE'):
            VIEW.relative(0x10)

    def test_caller_row_rejects_changed_template(self):
        row = {'start': 0x2573900, 'end': 0x2573a11}
        guard.caller_row(VIEW, 0x257399e, row)
        with self.assertRaisesRegex(ValueError, 'template'):
            guard.caller_row(Patched(VIEW, {0x2573985: 0x00}), 0x257399e, row)

    def test_fde_lookup_rejects_gap(self):
        with self.assertRaisesRegex(ValueError, 'outside'):
            guard.fde_for([0x10], [{'start': 0x10, 'end': 0x20}], 0x20)


if __name__ == '__main__':
    unittest.main()
