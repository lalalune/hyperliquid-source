import importlib.util
import json
import struct
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('cbm', ROOT / 'tools/checkpoint_bundle_markers.py')
cbm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cbm)
PACKET = ROOT / 'research/work-items/RE-009-checkpoint-bundle-markers-94'
DATA = cbm.load_binary()
VIEW = cbm.View(DATA)


class Patched(cbm.View):
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
    report = cbm.build(DATA)

    def test_identity(self):
        self.assertEqual(self.report['binary_sha256'], cbm.SHA256)

    def test_marker_files(self):
        self.assertEqual([row['marker_file'] for row in self.report['bundle_names']],
                         ['CHECKPOINT_COMPLETE_EXCHANGE', 'CHECKPOINT_COMPLETE_RPC',
                          'CHECKPOINT_COMPLETE_EVMSTATE'])

    def test_names_are_built_not_stored(self):
        counts = self.report['file_backed_literal_counts']
        self.assertEqual(counts['CHECKPOINT_COMPLETE_EVMSTATE'], 0)
        self.assertEqual(counts['CHECKPOINT_COMPLETE_EvmState'], 0)
        self.assertEqual(counts['/CHECKPOINT_COMPLETE'], 2)

    def test_site_census(self):
        self.assertEqual(self.report['site_counts'],
                         {'total': 11, 'touch': 6, 'probe': 5, 'immediate_2': 8, 'stack_byte': 3})
        self.assertEqual([s['site'] for s in self.report['sites'] if s['bundle_argument'] == 'stack_byte'],
                         ['0x1589a38', '0x332d6fd', '0x332d77f'])

    def test_plain_template_has_only_reader_sites(self):
        sites = self.report['templates']['plain']['lea_sites']
        self.assertEqual(sites, ['0x28d1ace', '0x332e4d9', '0x459ac6e'])
        self.assertEqual([r['plain_lea'] for r in self.report['plain_or_evmstate_readers']], sites)
        touches = {s['fde_start'] for s in self.report['sites'] if s['use'] == 'touch'}
        readers = {s['fde_start'] for s in self.report['sites'] if s['site'] in
                   {r['marker_call'] for r in self.report['plain_or_evmstate_readers']}}
        self.assertFalse(touches & readers)

    def test_readers_join_both_hits(self):
        for row in self.report['plain_or_evmstate_readers']:
            self.assertNotEqual(row['both_hits_join'], row['marker_miss'])

    def test_touch_and_save_locations(self):
        self.assertEqual(self.report['touch']['location']['file'], 'base/src/fu.rs')
        self.assertEqual(self.report['touch']['location']['line'], 254)
        self.assertEqual([x['line'] for x in self.report['bundle_save']['unwrap_locations']], [72, 74])
        self.assertEqual(self.report['bundle_save']['direct_callers'], ['0x1589e19', '0x326af78'])

    def test_no_absolute_paths_in_report(self):
        text = json.dumps(self.report)
        self.assertNotIn('ubuntu', text)
        self.assertNotIn('code_Mainnet', text)

    def test_outputs_match_packet(self):
        with tempfile.TemporaryDirectory() as tmp:
            cbm.write_outputs(self.report, Path(tmp))
            for name in (cbm.JSON_NAME, cbm.TSV_NAME):
                self.assertEqual((Path(tmp) / name).read_bytes(), (PACKET / name).read_bytes())

    def test_tsv_rows_follow_json(self):
        rows = (PACKET / cbm.TSV_NAME).read_text().splitlines()
        self.assertEqual(len(rows), 1 + self.report['site_counts']['total'])


class Controls(unittest.TestCase):
    def test_wrong_digest_rejected(self):
        with self.assertRaisesRegex(ValueError, 'sha256'):
            cbm.load_binary(expected='0' * 64)

    def test_every_rip_pin_holds(self):
        for pin in cbm.RIP_PINS:
            cbm.check_rip_pin(VIEW, pin)

    def test_every_byte_pin_holds(self):
        for pin in cbm.BYTE_PINS:
            cbm.check_byte_pin(VIEW, pin)

    def test_rip_pin_rejects_changed_opcode(self):
        view = Patched(VIEW, {0x1586869: 0x90})
        with self.assertRaises(ValueError):
            cbm.check_rip_pin(view, cbm.RIP_PINS[6])

    def test_rip_pin_rejects_changed_target(self):
        view = Patched(VIEW, {0x158686c: 0x00})
        with self.assertRaisesRegex(ValueError, 'targets'):
            cbm.check_rip_pin(view, cbm.RIP_PINS[6])

    def test_rip_pin_rejects_wrong_expectation(self):
        pin = (0x1586869, '488d35', cbm.TEMPLATE_PLAIN, 'wrong template')
        with self.assertRaisesRegex(ValueError, 'targets'):
            cbm.check_rip_pin(VIEW, pin)

    def test_byte_pin_rejects_changed_mask(self):
        pin = next(p for p in cbm.BYTE_PINS if p[0] == 0x144a772)
        cbm.check_byte_pin(VIEW, pin)
        view = Patched(VIEW, {0x144a774: 0x40})
        with self.assertRaises(ValueError):
            cbm.check_byte_pin(view, pin)

    def test_out_of_range_address_rejected(self):
        with self.assertRaisesRegex(ValueError, 'outside'):
            VIEW.mem(0x7fff00000000, 4)

    def test_nobits_is_not_readable(self):
        bss = next(s for s in VIEW.sections if s['name'] == '.bss')
        with self.assertRaisesRegex(ValueError, 'outside'):
            VIEW.mem(bss['address'] + 8, 8)

    def test_template_shape(self):
        self.assertEqual(cbm.decode_template(VIEW, cbm.TEMPLATE_BUNDLE),
                         [None, '/CHECKPOINT_COMPLETE_', None])
        self.assertEqual(cbm.decode_template(VIEW, cbm.TEMPLATE_PLAIN), [None, '/CHECKPOINT_COMPLETE'])

    def test_template_rejects_unknown_tag(self):
        view = Patched(VIEW, {cbm.TEMPLATE_BUNDLE: 0xc1})
        with self.assertRaisesRegex(ValueError, 'tag'):
            cbm.decode_template(view, cbm.TEMPLATE_BUNDLE)

    def test_name_table_stops_at_text_row(self):
        names, end = cbm.bundle_names(VIEW)
        self.assertEqual(len(names), 3)
        self.assertEqual(end['row'], 3)

    def test_name_table_rejects_short_length(self):
        view = Patched(VIEW, {cbm.NAME_LENGTHS + 16: 0})
        names, end = cbm.bundle_names(view)
        self.assertEqual(len(names), 2)
        self.assertEqual(end['row'], 2)

    def test_uppercase_rule_model(self):
        self.assertEqual(cbm.ascii_uppercase('EvmState'), 'EVMSTATE')
        self.assertEqual(cbm.ascii_uppercase('Rpc'), 'RPC')
        self.assertEqual(cbm.ascii_uppercase('a0`z{'), 'A0`Z{')

    def test_uppercase_rejects_changed_scalar(self):
        view = Patched(VIEW, {cbm.UPPERCASE_SCALAR_VA + 3: 0xbf})
        with self.assertRaisesRegex(ValueError, 'scalar'):
            cbm.uppercase_rule(view)

    def test_uppercase_rejects_changed_vector(self):
        view = Patched(VIEW, {0x2092e0: 0x21})
        with self.assertRaisesRegex(ValueError, 'vector'):
            cbm.uppercase_rule(view)

    def test_classify_real_sites(self):
        self.assertEqual(cbm.classify_argument(VIEW, 0x28d1b3e), 'immediate_2')
        self.assertEqual(cbm.classify_argument(VIEW, 0x332d6fd), 'stack_byte')
        self.assertEqual(cbm.classify_use(VIEW, 0x28d1b3e), 'probe')
        self.assertEqual(cbm.classify_use(VIEW, 0x226521a), 'touch')

    def test_classify_rejects_other_bytes(self):
        view = Patched(VIEW, {0x332e546: 0x90})
        with self.assertRaisesRegex(ValueError, 'argument'):
            cbm.classify_argument(view, 0x332e54b)

    def test_classify_use_rejects_no_slot(self):
        with self.assertRaisesRegex(ValueError, 'use'):
            cbm.classify_use(VIEW, 0x15867a0)

    def test_reader_join_detects_changed_branch(self):
        cbm.reader_join(VIEW, 0x332e4d9, 0x332e54b)
        view = Patched(VIEW, {0x332e51b: 0x40})
        with self.assertRaisesRegex(ValueError, 'differs'):
            cbm.reader_join(view, 0x332e4d9, 0x332e54b)

    def test_fde_lookup_rejects_gap(self):
        rows = [{'start': 0x10, 'end': 0x20}]
        with self.assertRaisesRegex(ValueError, 'outside'):
            cbm.fde_for([0x10], rows, 0x20)

    def test_location_rejects_foreign_path(self):
        slot = 0x5675500  # a std library Location
        with self.assertRaisesRegex(ValueError, 'Location'):
            cbm.location(VIEW, slot)

    def test_relative_rejects_unknown_slot(self):
        with self.assertRaisesRegex(ValueError, 'RELATIVE'):
            VIEW.relative(0x10)

    def test_rel32_is_little_endian_signed(self):
        rel = struct.unpack('<i', VIEW.mem(0x1586869 + 3, 4))[0]
        self.assertLess(rel, 0)


if __name__ == '__main__':
    unittest.main()
