"""Negative controls and regeneration checks of tools/fees_request_budget.py."""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

import fees_request_budget as tool  # noqa: E402

FOLDER = ROOT / 'research' / 'work-items' / 'fees-request-budget-94'
DATA = (ROOT / tool.BINARY).read_bytes()
BUILT = tool.build(DATA)
IMG, CODE, FDES, SLOTS, GOT = BUILT
CTX = (IMG, CODE, SLOTS, GOT)
tool.TABLE_ROWS = tool.weight_table(IMG)['rows']
VECTORS = tool.all_vectors()
EVIDENCE = json.loads((FOLDER / 'evidence.json').read_text())


def patched(*pairs):
    """A context with the bytes in `pairs` replaced, decoded again for every subject they touch."""
    patch = {}
    for va, raw in pairs:
        for i, b in enumerate(raw):
            patch[va + i] = b
    img = tool.Image(DATA, patch)
    code = dict(CODE)
    for s in tool.RANGES:
        code.update({i.va: i for i in tool.decode_subject(img, s)})
    return img, code, SLOTS, GOT


def first_failure(ctx, vectors):
    for v in vectors:
        try:
            msg = tool.check(ctx, v)
        except (tool.Unmodelled, tool.EvidenceError, tool.Stop, KeyError) as exc:
            msg = f'fault {type(exc).__name__}'
        if msg:
            return msg
    return None


def of_group(*names):
    return [v for v in VECTORS if v['group'] in names]


class Binding(unittest.TestCase):
    def test_digest_passes(self):
        self.assertEqual(tool.check_digest(DATA), tool.SHA256)

    def test_wrong_digest_fails(self):
        spoiled = bytearray(DATA[:4096])
        with self.assertRaises(tool.EvidenceError):
            tool.check_digest(bytes(spoiled))

    def test_address_outside_every_section_fails(self):
        with self.assertRaises(tool.EvidenceError):
            IMG.off(0x7fff_0000_0000)

    def test_no_fde_at_middle_of_function(self):
        with self.assertRaises(tool.EvidenceError):
            FDES.range_of(tool.HANDLER + 1)

    def test_nobits_is_not_file_bytes(self):
        addr, _, size, _ = IMG.sec['.bss']
        with self.assertRaises(tool.EvidenceError):
            IMG.read(addr + size // 2, 8)

    def test_wrong_pinned_byte_fails(self):
        img = tool.Image(DATA, {tool.PINNED[0][0]: 0})
        with self.assertRaises(tool.EvidenceError):
            tool.pinned(img)

    def test_decoder_must_land_on_the_end(self):
        with self.assertRaises(tool.EvidenceError):
            tool.decode_range(IMG, tool.HANDLER, tool.HANDLER + 2 + 2)


class Vectors(unittest.TestCase):
    def test_all_vectors_agree(self):
        self.assertIsNone(first_failure(CTX, VECTORS))

    def test_vector_count_matches_evidence(self):
        self.assertEqual(len(VECTORS), EVIDENCE['vectors'])

    def test_every_status_is_met(self):
        self.assertEqual(set(EVIDENCE['outcomes']) & {'0x186', '0x13f', '0x34', 'panic', 'expired', 'charged', 'other'}, {'0x186', '0x13f', '0x34', 'panic', 'expired', 'charged', 'other'})


class Corruption(unittest.TestCase):
    def test_cap_base_is_seen(self):
        self.assertIsNotNone(first_failure(patched((0x21e2acc, b'\x11\x27')), of_group('cap')))

    def test_unit_cost_is_seen(self):
        self.assertIsNotNone(first_failure(patched((0x2758b24, b'\xf5\x01')), of_group('reserve balance')))

    def test_copy_unit_cost_is_seen(self):
        self.assertIsNotNone(first_failure(patched((0x4d821d4, b'\xf5\x01')), [v for v in of_group('reserve balance') if v['entry'] == tool.COPY_A]))

    def test_cost_cap_is_seen(self):
        self.assertIsNotNone(first_failure(patched((0x2758b51, b'\x0d')), of_group('reserve weight')))

    def test_times_five_is_seen(self):
        self.assertIsNotNone(first_failure(patched((0x220871e, b'\x04')), of_group('entry charge')))

    def test_times_four_is_seen(self):
        self.assertIsNotNone(first_failure(patched((0x27585ae, b'\x03')), of_group('inner charge')))

    def test_batch_times_four_is_seen(self):
        self.assertIsNotNone(first_failure(patched((0x24bcd95, b'\x03')), of_group('batch charge')))

    def test_divisor_of_twenty_is_seen(self):
        self.assertIsNotNone(first_failure(patched((0x336332b, b'\x05')), of_group('fields')))


class Model(unittest.TestCase):
    def test_cap_floor(self):
        v = dict(dexes=[], base=(199, 0), rows={}, user=b'a', row_cell=dict(t=0, r=0, time=tool.FRESH_TIME), tree=None, tree_cell=tool.FRESH_TIME)
        self.assertEqual(tool.view_model(v)['cap'], 10001)

    def test_used_and_surplus_exclude_each_other(self):
        v = dict(dexes=[], base=(0, 0), user=b'a', rows={b'a': dict(t=3, r=8, time=tool.FRESH_TIME)}, row_cell=None, tree=None, tree_cell=tool.FRESH_TIME)
        got = tool.view_model(v)
        self.assertEqual((got['used'], got['surplus']), (0, 5))

    def test_sum_saturates_once_per_add(self):
        v = dict(dexes=[(tool.U64, tool.U64)], base=(1, 0))
        self.assertEqual(tool.sum_model(v), (tool.U64, tool.U64, 1))

    def test_days_from_epoch(self):
        self.assertEqual(tool.days_from_epoch(1970, 1), 0)
        self.assertEqual(tool.days_from_epoch(1972, 61), 790)
        self.assertEqual(tool.days_from_epoch(1969, 365), -1)

    def test_clock_floors_at_zero(self):
        self.assertEqual(tool.now_ms(dict(date=tool.date_word(1969, 365), secs=86399, frac=0)), 0)

    def test_nested_weight(self):
        self.assertEqual(tool.weight_model(tool.action(0xa8, f18=0, inner=tool.action(0x8b, f18=40))), 3)

    def test_nested_weight_saturates(self):
        self.assertEqual(tool.weight_model(tool.action(0xa8, f18=2, inner=tool.action(0x76, f18=tool.U64))), tool.U64)


class Regeneration(unittest.TestCase):
    def test_dry_run_matches_the_packet(self):
        with tempfile.TemporaryDirectory() as tmp:
            ev = tool.generate(DATA, tmp, with_survey=False)
            for name in ('vectors.tsv', 'instructions.tsv', 'reference-diff.tsv'):
                self.assertEqual(Path(tmp, name).read_bytes(), (FOLDER / name).read_bytes(), name)
        for key in ('vectors', 'groups', 'outcomes', 'cap_scan', 'charge_sites', 'weight_table', 'status', 'strings', 'pinned'):
            self.assertEqual(ev[key], EVIDENCE[key], key)

    def test_no_survivor_outside_the_list(self):
        rows = (FOLDER / 'mutations.tsv').read_text().splitlines()[1:]
        survivors = {r.split('\t')[2] for r in rows if r.split('\t')[4] == 'equivalent'}
        self.assertEqual(survivors, set(EVIDENCE['equivalent']))
        self.assertEqual(len(rows), EVIDENCE['mutants'])

    def test_packet_has_no_external_program(self):
        text = (ROOT / 'tools' / 'fees_request_budget.py').read_text()
        self.assertNotIn('subprocess', text)
        self.assertNotIn('os.system', text)

    def test_manifest_lists_every_file(self):
        names = {line.split()[1] for line in (FOLDER / 'MANIFEST.sha256').read_text().splitlines()}
        self.assertEqual(names, {p for p in os.listdir(FOLDER) if p != 'MANIFEST.sha256'})


if __name__ == '__main__':
    unittest.main()
