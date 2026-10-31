"""Tests of tools/fees_schedule_vote.py: digest binding, real outcomes, corrupted bytes and the packet files."""

import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
SPEC = importlib.util.spec_from_file_location('fees_schedule_vote', ROOT / 'tools' / 'fees_schedule_vote.py')
tool = importlib.util.module_from_spec(SPEC)
sys.modules['fees_schedule_vote'] = tool
SPEC.loader.exec_module(tool)
FOLDER = ROOT / 'research' / 'work-items' / 'fees-schedule-vote-94'


class Base(unittest.TestCase):
    data = (ROOT / tool.BINARY).read_bytes()
    built = tool.build(data)
    ctx = (built[0], built[1], built[3], built[4], built[5], built[6])

    def passes(self, doc, **kw):
        self.assertIsNone(tool.check(self.ctx, dict(kind='decode', group='t', doc=doc, **kw)))

    def seen(self, doc):
        m, res = tool.run_decode(self.ctx, doc.encode())
        return tool.observe(m, res)[0]

    def broken(self, doc, patch):
        """True when the corrupted image no longer matches the model on `doc`."""
        img, code, _, slots, got, real, stops = self.built
        mimg = tool.Image(self.data, patch)
        mcode = dict(code)
        for s in tool.RANGES:
            mcode.update({i.va: i for i in tool.decode_subject(mimg, s)})
        try:
            return tool.check((mimg, mcode, slots, got, real, stops), dict(kind='decode', group='t', doc=doc)) is not None
        except (tool.Unmodelled, tool.Panicked, KeyError):
            return True


class Digest(Base):
    def test_digest_accepted(self):
        self.assertEqual(tool.check_digest(self.data), tool.SHA256)

    def test_wrong_digest_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.check_digest(self.data[:-1] + bytes([self.data[-1] ^ 1]))

    def test_wrong_binary_refused_by_build(self):
        with self.assertRaises(tool.EvidenceError):
            tool.build(self.data[:100] + bytes([self.data[100] ^ 1]) + self.data[101:])


class Model(unittest.TestCase):
    def test_empty_object_is_an_empty_patch(self):
        self.assertEqual(tool.expected(tool.model(b'{}')), {})

    def test_null_equals_absent(self):
        self.assertEqual(tool.expected(tool.model(b'{"rates":null}')), {})

    def test_trailing_text(self):
        self.assertEqual(tool.model(b'{} x'), ('trailing characters', 1, 4))

    def test_position_counts_lines(self):
        self.assertEqual(tool.position(b'a\nbc', 3), (2, 1))

    def test_number_uses_the_reader_rule(self):
        self.assertEqual(tool.Reader(b'1.5').number(True), ('float', 1.5))
        self.assertEqual(tool.Reader(b'18446744073709551615').number(True), ('uint', (1 << 64) - 1))
        self.assertEqual(tool.Reader(b'18446744073709551616').number(True)[0], 'float')

    def test_address_prefix_optional(self):
        a = b'"0102030405060708090a0b0c0d0e0f1011121314"'
        self.assertEqual(tool.spec_address(tool.Reader(a)), tool.spec_address(tool.Reader(a[:1] + b'0x' + a[1:])))


class Bytes(Base):
    def test_full_object(self):
        self.passes(tool.full())

    def test_positional_form(self):
        self.passes(tool.seq())

    def test_object_and_array_build_the_same_patch(self):
        self.assertEqual(self.seen(tool.full()), self.seen(tool.seq()))

    def test_rates_refuse_an_object(self):
        self.assertEqual(self.seen('{"rates":{}}')[0], 'invalid type')

    def test_top_refuses_unknown_key(self):
        self.assertEqual(self.seen('{"x":1}')[0], 'unknown field `x`, expected {}')

    def test_nested_skips_unknown_key(self):
        self.assertEqual(self.seen('{"tiers":{"vip":[],"mm":[],"x":1}}')['tiers'], ([], []))

    def test_vip_row_field_order(self):
        row = self.seen(tool.vip_doc('[9,[1,2,3,4],0.5]'))['tiers'][0][0]
        self.assertEqual(row['ntl'], 9)
        self.assertEqual(row['keep'], tool.f2b(0.5))

    def test_negative_cutoff_refused_by_text(self):
        self.assertEqual(self.seen(tool.vip_doc('[-1,[1,2,3,4],0.5]'))[0], 'invalid value {} for NtlPriv when visiting i64')

    def test_float_cutoff_refused(self):
        self.assertEqual(self.seen(tool.vip_doc('[1.0,[1,2,3,4],0.5]'))[0], 'invalid type')

    def test_null_then_value_is_a_duplicate(self):
        self.assertEqual(self.seen('{"referrerKeep":null,"referrerKeep":1}')[0], 'duplicate field `referrerKeep`')

    def test_map_refuses_equal_keys_after_the_closer(self):
        k = '0x' + '11' * 20
        doc = '{"extraDestinationFractions":[["%s",0.5],["%s",0.25]]}' % (k, k)
        self.assertEqual(self.seen(doc), ('duplicate key', 1, len(doc) - 1))

    def test_map_of_forty_needs_inner_nodes(self):
        self.passes(tool.map_docs()[27])

    def test_second_decoder_matches(self):
        self.passes(tool.full(), root=tool.DECODE_B)

    def test_depth_limit(self):
        self.passes(tool.full(), depth=2)

    def test_every_vector_group_has_a_rejection_and_a_patch(self):
        names = {tool.outcome_name(v).split(' ')[0] for v in tool.all_vectors() if v['group'] == 'field'}
        self.assertIn('patch', names)


class Corrupted(Base):
    def test_depth_constant(self):
        self.assertTrue(self.broken(tool.full(), {0x1b2c526: 0x01}))

    def test_key_identifier(self):
        self.assertTrue(self.broken('{"rates":null}', {0x1e6e3f2: 0x73}))

    def test_trailing_code(self):
        self.assertTrue(self.broken('{} x', {0x1b2c5ad: 0x17}))

    def test_uncorrupted_control(self):
        self.assertFalse(self.broken(tool.full(), {}))


class Static(Base):
    def test_key_table_reads_the_binary(self):
        self.assertEqual(len(tool.key_table(self.built[0])), 22)

    def test_key_table_refuses_a_wrong_address(self):
        rows = tool.KEY_ROWS
        try:
            tool.KEY_ROWS = rows[:1] + (rows[1][:2] + (rows[1][2] + 1,) + rows[1][3:],)
            with self.assertRaises(tool.EvidenceError):
                tool.key_table(self.built[0])
        finally:
            tool.KEY_ROWS = rows

    def test_pins_hold(self):
        self.assertEqual(len(tool.pins(self.built[0])), len(tool.PINS))

    def test_pin_refused_on_other_bytes(self):
        pins = tool.PINS
        try:
            tool.PINS = ((pins[0][0], 'c6442450ff', pins[0][2]),)
            with self.assertRaises(tool.EvidenceError):
                tool.pins(self.built[0])
        finally:
            tool.PINS = pins

    def test_vectors_are_sorted_stable(self):
        self.assertEqual([v['doc'] for v in tool.all_vectors()[:50]], [v['doc'] for v in tool.all_vectors()[:50]])


class Packet(unittest.TestCase):
    def test_evidence(self):
        ev = json.loads((FOLDER / 'evidence.json').read_text())
        self.assertEqual(ev['sha256'], tool.SHA256)
        self.assertEqual(ev['mismatches'], 0)
        self.assertEqual(ev['mutants'], ev['killed'] + ev['survived'])

    def test_every_survivor_has_a_reason(self):
        for line in (FOLDER / 'mutations.tsv').read_text().splitlines()[1:]:
            cells = line.split('\t')
            self.assertTrue(cells[6], line)

    def test_manifest(self):
        for line in (FOLDER / 'MANIFEST.sha256').read_text().splitlines():
            digest, name = line.split('  ')
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest)

    def test_vectors_file_matches_the_list(self):
        rows = (FOLDER / 'vectors.tsv').read_text().splitlines()[1:]
        self.assertEqual(len(rows), len(tool.all_vectors()))

    def test_schema_file_matches_the_binary(self):
        rows = (FOLDER / 'schedule-schema.tsv').read_text().splitlines()[1:]
        self.assertEqual(rows, ['\t'.join(r) for r in tool.key_table(Base.built[0])])


if __name__ == '__main__':
    unittest.main()
