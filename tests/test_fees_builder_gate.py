"""Tests of tools/fees_builder_gate.py: digest binding, real outcomes, corrupted bytes and the packet files."""

import hashlib
import importlib.util
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
SPEC = importlib.util.spec_from_file_location('fees_builder_gate', ROOT / 'tools' / 'fees_builder_gate.py')
gate = importlib.util.module_from_spec(SPEC)
sys.modules['fees_builder_gate'] = gate
SPEC.loader.exec_module(gate)
FOLDER = ROOT / 'research' / 'work-items' / 'fees-builder-gate-94'


class Base(unittest.TestCase):
    data = (ROOT / gate.BINARY).read_bytes()
    built = gate.build(data)
    ctx = (built[0], built[1], built[3], built[4])

    def status(self, v, ctx=None):
        gate.GOLD.clear()
        msg = gate.check(ctx or self.ctx, v)
        self.assertIsNone(msg)
        return gate.model(v)['status']

    def patched(self, patch):
        """The same run on an image with `patch` VA -> byte applied; subjects decoded again."""
        img, code, _, slots, got = self.built
        mimg = gate.Image(self.data, patch)
        mcode = dict(code)
        for s in gate.RANGES:
            mcode.update({i.va: i for i in gate.decode_subject(mimg, s)})
        return (mimg, mcode, slots, got)

    def broken(self, v, patch):
        """True when the corrupted image no longer matches the model on `v`."""
        try:
            return gate.check(self.patched(patch), v) is not None
        except gate.Unmodelled:
            return True


class Digest(Base):
    def test_digest_accepted(self):
        self.assertEqual(gate.check_digest(self.data), gate.SHA256)

    def test_wrong_digest_refused(self):
        with self.assertRaises(gate.EvidenceError):
            gate.check_digest(self.data[:-1] + bytes([self.data[-1] ^ 1]))

    def test_outside_address_refused(self):
        with self.assertRaises(gate.EvidenceError):
            self.built[0].read(0x7fff0000, 8)

    def test_no_fde_refused(self):
        with self.assertRaises(gate.EvidenceError):
            self.built[2].range_of(gate.PERP + 1)


class Outcomes(Base):
    def test_cap_edges(self):
        for entry, cap in ((gate.PERP, 100), (gate.SPOT, 1000)):
            limits = {gate.ME: {gate.CODER: gate.U64}}
            self.assertEqual(self.status(gate.vec('t', entry, rate=cap, rows=limits)), gate.OK)
            self.assertEqual(self.status(gate.vec('t', entry, rate=cap + 1, rows=limits)), gate.TOO_HIGH)

    def test_the_cap_reads_the_rate_not_the_order_count(self):
        many = [gate.LIMIT] * 101
        limits = {gate.ME: {gate.CODER: 50}}
        self.assertEqual(self.status(gate.vec('t', gate.PERP, rate=5, rows=limits, orders=many, cap=101)), gate.OK)

    def test_rate_above_the_limit_of_the_builder(self):
        for entry in (gate.PERP, gate.SPOT):
            limits = {gate.ME: {gate.CODER: 9}}
            self.assertEqual(self.status(gate.vec('t', entry, rate=9, rows=limits)), gate.OK)
            self.assertEqual(self.status(gate.vec('t', entry, rate=10, rows=limits)), gate.NOT_APPROVED)

    def test_rate_zero_still_needs_a_row(self):
        for entry in (gate.PERP, gate.SPOT):
            self.assertEqual(self.status(gate.vec('t', entry, rate=0, rows={})), gate.NOT_APPROVED)
            self.assertEqual(self.status(gate.vec('t', entry, rate=0, rows={gate.ME: None})), gate.OK)
            self.assertEqual(self.status(gate.vec('t', entry, rate=0, rows={gate.ME: {gate.OTHER: 1}})), gate.OK)

    def test_rate_zero_on_a_row_of_someone_else(self):
        self.assertEqual(self.status(gate.vec('t', gate.SPOT, rate=0, rows={gate.OTHER: {gate.CODER: 9}})), gate.NOT_APPROVED)

    def test_approval_is_read_on_the_master(self):
        for entry in (gate.PERP, gate.SPOT):
            self.assertEqual(self.status(gate.vec('t', entry, rate=3, masters={gate.ME: gate.BOSS}, rows={gate.BOSS: {gate.CODER: 9}})), gate.OK)
            self.assertEqual(self.status(gate.vec('t', entry, rate=3, masters={gate.ME: gate.BOSS}, rows={gate.ME: {gate.CODER: 9}})), gate.NOT_APPROVED)

    def test_no_flag_no_gate(self):
        self.assertEqual(self.status(gate.vec('t', gate.PERP, flag=0, rate=gate.U64, rows={})), gate.OK)
        self.assertEqual(self.status(gate.vec('t', gate.PERP, flag=2, rate=gate.U64, rows={})), gate.OK)

    def test_order_of_rejects(self):
        self.assertEqual(self.status(gate.vec('t', gate.PERP, rate=gate.U64, rows={}, orders=[], cap=0)), gate.NO_ORDERS)
        self.assertEqual(self.status(gate.vec('t', gate.PERP, rate=gate.U64, rows={}, kind=3, index=gate.MAX_PRIORITY + 1)), gate.BAD_PRIORITY)
        self.assertEqual(self.status(gate.vec('t', gate.SPOT, rate=gate.U64, rows={}, orders=[gate.trig()])), gate.NOT_ENABLED)
        self.assertEqual(self.status(gate.vec('t', gate.SPOT, rate=gate.U64, rows={}, kind=1)), gate.NOT_ENABLED)
        self.assertEqual(self.status(gate.vec('t', gate.PERP, rate=101, rows={}, kind=1, orders=[gate.trig()])), gate.TOO_HIGH)

    def test_spot_texts(self):
        self.assertEqual(self.built[0].read(*gate.TEXT_TPSL), b'TP/SL')
        self.assertEqual(self.built[0].read(*gate.TEXT_TRIGGER), b'Placing trigger orders')

    def test_status_texts(self):
        self.assertEqual(self.built[0].read(*gate.STATUS_TEXT[gate.NOT_APPROVED]), b'Builder fee has not been approved.')
        self.assertEqual(self.built[0].read(*gate.STATUS_TEXT[gate.TOO_HIGH]), b'Builder fee is too high.')


class Census(Base):
    def test_six_gates_with_their_caps(self):
        starts = sorted(f['start'] for f in gate.eh_frame_records(self.data)[1])
        pairs, alone = gate.gate_pairs(self.built[0], starts)
        self.assertEqual({int(p['function'], 16): p['cap'] for p in pairs}, gate.CAP)
        self.assertEqual([x['site'] for x in alone], ['0x44d21ae'])

    def test_census_notices_a_changed_cap(self):
        starts = sorted(f['start'] for f in gate.eh_frame_records(self.data)[1])
        pairs, _ = gate.gate_pairs(self.built[0], starts)
        mutated = bytearray(self.data)
        off = self.built[0].off(0x1ea3a35)
        mutated[off] = 0x65
        changed, _ = gate.gate_pairs(gate.Image(bytes(mutated)), starts)
        self.assertNotEqual(pairs, changed)


class Corrupted(Base):
    def test_perp_cap_byte(self):
        v = gate.vec('t', gate.PERP, rate=100, rows={gate.ME: {gate.CODER: 500}})
        self.assertTrue(self.broken(v, {0x1ea3a35: 0x63}))

    def test_spot_cap_byte(self):
        v = gate.vec('t', gate.SPOT, rate=1001, rows={gate.ME: {gate.CODER: 5000}})
        self.assertTrue(self.broken(v, {0x1ea472b: 0x07}))

    def test_limit_compare_flipped(self):
        v = gate.vec('t', gate.PERP, rate=9, rows={gate.ME: {gate.CODER: 9}})
        self.assertTrue(self.broken(v, {0x1ea3b53: 0x8e}))

    def test_flag_test_flipped(self):
        v = gate.vec('t', gate.SPOT, flag=0, rows={})
        self.assertTrue(self.broken(v, {0x1ea466a: 0x85}))

    def test_tree_value_stride(self):
        limits = {gate.ME: {gate.CODER: 5, gate.OTHER: 5}}
        self.assertTrue(any(self.broken(gate.vec('t', gate.SPOT, rate=6, builder=who, rows=limits), {0x284ba77: 0x10}) for who in (gate.CODER, gate.OTHER)))

    def test_decoder_ends_on_fde(self):
        with self.assertRaises((gate.EvidenceError, gate.Unmodelled, IndexError)):
            gate.decode_range(self.built[0], gate.PERP, gate.FDE_END[gate.PERP] - 1)


class Packet(Base):
    evidence = json.loads((FOLDER / 'evidence.json').read_text())

    def test_manifest(self):
        lines = (FOLDER / 'MANIFEST.sha256').read_text().splitlines()
        listed = {}
        for line in lines:
            digest, name = line.split('  ')
            listed[name] = digest
        self.assertEqual(set(listed), {p.name for p in FOLDER.iterdir() if p.name != 'MANIFEST.sha256'})
        for name, digest in listed.items():
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest)

    def test_counts(self):
        ev = self.evidence
        self.assertEqual(ev['sha256'], gate.SHA256)
        self.assertEqual(ev['mismatches'], 0)
        rows = (FOLDER / 'mutations.tsv').read_text().splitlines()[1:]
        self.assertEqual(len(rows), ev['mutants'])
        self.assertEqual(sum('\tkilled\t' in r for r in rows), ev['killed'])

    def test_vectors_match(self):
        vecs = gate.all_vectors()
        rows = (FOLDER / 'vectors.tsv').read_text().splitlines()[1:]
        self.assertEqual(len(rows), self.evidence['vectors'])
        self.assertEqual(rows[:len(vecs)], [f"{v['group']}\t{v['entry']:#x}\t{gate.digest_of(v)}\t{gate.model(v)['status']:#x}" for v in vecs])

    def test_every_vector_of_a_sample(self):
        for v in gate.all_vectors()[::37]:
            gate.GOLD.clear()
            self.assertIsNone(gate.check(self.ctx, v))

    def test_unexecuted_ranges_are_listed(self):
        self.assertEqual([(int(u['start'], 16), int(u['end'], 16)) for u in self.evidence['unexecuted']], [(a, b) for a, b, _ in gate.UNEXECUTED])

    def test_no_external_program(self):
        text = (ROOT / 'tools' / 'fees_builder_gate.py').read_text()
        for word in ('subprocess', 'os.system', 'objdump', 'readelf'):
            if word in ('objdump', 'readelf'):
                text = text.replace('no objdump, readelf or\nother external program', '')
            self.assertNotIn(word, text)


if __name__ == '__main__':
    unittest.main()
