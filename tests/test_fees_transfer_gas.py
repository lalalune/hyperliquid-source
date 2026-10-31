"""Tests for tools/fees_transfer_gas.py on node #94 bytes."""

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

import fees_transfer_gas as t  # noqa: E402

FOLDER = ROOT / 'research/work-items/fees-transfer-gas-94'
DATA = (ROOT / t.BINARY).read_bytes()
IMG, CODE, FDES, SLOTS, GOT = t.build(DATA)
FAULTS = (t.Unmodelled, t.Panicked, t.EvidenceError, KeyError, ValueError, TypeError, StopIteration, IndexError)
MILLION = (1000000, 0)
FREE = (0, 0)
SYN = t.synth


def gas(entry=t.GAS, **kw):
    v = t.vec('test', entry=entry, **kw)
    rax, rdx, _ = t.run(IMG, CODE, SLOTS, GOT, v)
    return rax, rdx & 0xff


def passes(v, img=IMG, code=CODE):
    return t.check(img, code, SLOTS, GOT, v) is None


def mutate(fn, patch):
    img = t.Image(DATA, patch)
    code = dict(CODE)
    code.update({i.va: i for i in t.decode_range(img, fn, t.FDE_END[fn])})
    return img, code


def fails(fn, patch, vectors):
    img, code = mutate(fn, patch)
    for v in vectors:
        try:
            if not passes(v, img, code):
                return True
        except FAULTS:
            return True
    return False


def flip(fn, va, vectors, bit=1):
    return fails(fn, {va: IMG.read(va, 1)[0] ^ bit}, vectors)


VECTORS = t.all_vectors()
FIRST = [v for v in VECTORS if v['entry'] == t.GAS and v['group'] != 'random']


class Digest(unittest.TestCase):
    def test_binary(self):
        self.assertEqual(hashlib.sha256(DATA).hexdigest(), t.SHA256)

    def test_wrong_digest_rejected(self):
        with self.assertRaises(t.EvidenceError):
            t.check_digest(DATA[:-1] + bytes([DATA[-1] ^ 1]))

    def test_build_rejects_other_bytes(self):
        with self.assertRaises(t.EvidenceError):
            t.build(b'\0' + DATA[1:])


class Boundaries(unittest.TestCase):
    def test_fde_ends(self):
        self.assertEqual(t.FDE_END[t.GAS], 0x2710523)
        self.assertEqual(t.FDE_END[t.COPY_A], 0x4d00e93)
        self.assertEqual(t.FDE_END[t.COPY_B], 0x4d01233)
        self.assertEqual(t.FDE_END[t.SPECIAL], 0x37e5346)

    def test_decoder_lands_on_each_fde_end(self):
        for fn in t.SUBJECTS + t.HELPERS:
            rows = t.decode_range(IMG, fn, t.FDE_END[fn])
            self.assertEqual(rows[-1].va + rows[-1].size, t.FDE_END[fn])

    def test_out_of_range_address(self):
        with self.assertRaises(t.EvidenceError):
            IMG.read(0x7fff0000, 4)

    def test_no_fde_inside_a_body(self):
        with self.assertRaises(t.EvidenceError):
            FDES.range_of(t.GAS + 1)

    def test_nobits_is_not_read(self):
        addr, _, size, kind = IMG.sec['.bss']
        self.assertEqual(kind, 8)
        with self.assertRaises(t.EvidenceError):
            IMG.read(addr + size // 2, 1)

    def test_pinned_bytes_checked(self):
        t.pinned(IMG)
        bad = t.Image(DATA, {t.PINNED[0][0]: 0})
        with self.assertRaises(t.EvidenceError):
            t.pinned(bad)


class Rules(unittest.TestCase):
    def test_plain_transfer_pays(self):
        for e in t.ENTRIES:
            self.assertEqual(gas(e), MILLION)

    def test_destination_known_to_a_dex_is_free(self):
        for e in t.ENTRIES:
            self.assertEqual(gas(e, dexes=[dict(keys=(t.OTHER,)), dict(keys=(t.YOU,))]), FREE)

    def test_stale_key_with_zero_items_is_not_read(self):
        self.assertEqual(gas(dexes=[dict(keys=(t.YOU,), items=0)]), MILLION)
        self.assertEqual(gas(spot=dict(keys=(t.YOU,), items=0)), MILLION)

    def test_destination_known_to_the_second_table_is_free(self):
        self.assertEqual(gas(spot=dict(keys=(t.YOU,))), FREE)

    def test_flagged_sender_skips_the_destination_lists(self):
        for e in t.ENTRIES:
            self.assertEqual(gas(e, rows={t.ME: 1}, dexes=[dict(keys=(t.YOU,))]), MILLION)
        self.assertEqual(gas(rows={t.ME: 1}, spot=dict(keys=(t.YOU,))), MILLION)
        self.assertEqual(gas(rows={t.ME: 1}, dest=bytes([0x22]) * 20), MILLION)
        self.assertEqual(gas(rows={t.ME: 2}, dest=SYN(0x20, 1)), MILLION)

    def test_flagged_sender_skips_the_token_row(self):
        self.assertEqual(gas(rows={t.ME: 1}, tag=1, first=t.ME), MILLION)

    def test_special_destination_wins_over_flag(self):
        self.assertEqual(gas(rows={t.ME: 1}, dest=SYN(0x31, 5)), FREE)

    def test_special_sender_never_pays(self):
        s = SYN(0x32, 7)
        self.assertEqual(gas(sender=s, rows={s: 0}), FREE)
        self.assertEqual(gas(sender=s, rows={s: 1}), FREE)

    def test_range_tops(self):
        self.assertEqual(gas(dest=SYN(0x30, 19999)), FREE)
        self.assertEqual(gas(dest=SYN(0x30, 20000)), MILLION)
        self.assertEqual(gas(dest=SYN(0x31, 9999)), FREE)
        self.assertEqual(gas(dest=SYN(0x31, 10000)), MILLION)
        self.assertEqual(gas(dest=SYN(0x32, 9999)), FREE)
        self.assertEqual(gas(dest=SYN(0x32, 10000)), MILLION)

    def test_tail_lives_in_the_last_bytes(self):
        raw = bytearray(SYN(0x31, 0))
        raw[8] = 1
        self.assertEqual(gas(dest=bytes(raw)), MILLION)

    def test_block_20(self):
        self.assertEqual(gas(dest=SYN(0x20, 0)), FREE)
        self.assertEqual(gas(dest=SYN(0x20, 9999)), FREE)
        self.assertEqual(gas(dest=SYN(0x20, 10000)), MILLION)

    def test_block_20_does_not_cover_a_sender(self):
        s = SYN(0x20, 5)
        self.assertEqual(gas(sender=s, rows={s: 0}), MILLION)

    def test_all_22(self):
        self.assertEqual(gas(dest=bytes([0x22]) * 20), FREE)
        self.assertEqual(gas(dest=bytes([0x22]) * 19 + bytes([0x23])), MILLION)

    def test_token_row_gives_second_result(self):
        for e in t.ENTRIES:
            self.assertEqual(gas(e, tag=1, first=t.ME), (0, 1))

    def test_token_row_needs_tag_one(self):
        self.assertEqual(gas(tag=2, first=t.ME), MILLION)
        self.assertEqual(gas(tag=0, first=t.ME), MILLION)

    def test_no_row_uses_default_flag_zero(self):
        self.assertEqual(gas(rows={}), MILLION)
        self.assertEqual(gas(rows={t.OTHER: 1}), MILLION)

    def test_default_flag_is_read(self):
        self.assertEqual(gas(rows={}, default_flag=1, spot=dict(keys=(t.YOU,))), MILLION)

    def test_empty_tokens_panic(self):
        with self.assertRaises(t.Panicked):
            gas(tokens=0)

    def test_no_token_panic_when_a_list_answers(self):
        self.assertEqual(gas(tokens=0, spot=dict(keys=(t.YOU,))), FREE)

    def test_no_state_is_written(self):
        for v in FIRST[:60]:
            self.assertTrue(passes(v))


class Model(unittest.TestCase):
    def test_model_and_bytes_on_the_small_set(self):
        for v in FIRST[:200]:
            self.assertTrue(passes(v), v['group'])

    def test_wrong_model_is_noticed(self):
        real = t.GAS_UNITS
        try:
            t.GAS_UNITS = real + 1
            self.assertFalse(passes(t.vec('test', entry=t.GAS)))
        finally:
            t.GAS_UNITS = real

    def test_groups_cover_each_outcome(self):
        seen = {str(t.gas_model(v)) for v in VECTORS}
        self.assertEqual(seen, {str(MILLION), str(FREE), str((0, 1)), 'panic'})


class Controls(unittest.TestCase):
    def test_flag_branch(self):
        self.assertTrue(flip(t.GAS, 0x27101d9, FIRST))

    def test_setle_to_setl(self):
        self.assertTrue(fails(t.SPECIAL, {0x37e5336: 0x9c}, FIRST))

    def test_top_0x30(self):
        self.assertTrue(flip(t.SPECIAL, 0x37e5229, FIRST, 1))

    def test_top_0x31(self):
        self.assertTrue(flip(t.SPECIAL, 0x37e52a3, FIRST, 1))

    def test_amount_immediate(self):
        self.assertTrue(flip(t.GAS, 0x27101e9, FIRST))

    def test_token_tag_compare(self):
        self.assertTrue(flip(t.GAS, 0x27104d2, FIRST))

    def test_second_result(self):
        self.assertTrue(flip(t.GAS, 0x271050e, FIRST))

    def test_copy_field(self):
        at = next(i.va for i in t.decode_range(IMG, t.COPY_A, t.FDE_END[t.COPY_A]) if '0x1048' in t.show(i))
        scope = [v for v in VECTORS if v['entry'] == t.COPY_A and v['group'] != 'random']
        self.assertTrue(flip(t.COPY_A, at + 3, scope, 8))


class Packet(unittest.TestCase):
    def test_manifest(self):
        rows = [ln.split('  ', 1) for ln in (FOLDER / 'MANIFEST.sha256').read_text().splitlines()]
        names = sorted(p.name for p in FOLDER.iterdir() if p.name != 'MANIFEST.sha256')
        self.assertEqual(sorted(n for _, n in rows), names)
        for digest, name in rows:
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest)

    def test_evidence_numbers(self):
        ev = json.loads((FOLDER / 'evidence.json').read_text())
        self.assertEqual(ev['sha256'], t.SHA256)
        self.assertEqual(ev['vectors'], len(VECTORS))
        self.assertEqual(ev['mismatches'], 0)
        self.assertEqual(ev['mutants'], len((FOLDER / 'mutations.tsv').read_text().splitlines()) - 1)
        self.assertEqual(ev['killed'] + sum(1 for ln in (FOLDER / 'mutations.tsv').read_text().splitlines() if '\tequivalent\t' in ln), ev['mutants'])
        self.assertEqual(ev['unexecuted'], [])

    def test_static_files_rebuild(self):
        with tempfile.TemporaryDirectory() as d:
            t.generate(DATA, d, with_survey=False)
            for name in ('vectors.tsv', 'instructions.tsv', 'reference-diff.tsv'):
                self.assertEqual((Path(d) / name).read_bytes(), (FOLDER / name).read_bytes(), name)

    def test_reference_rows_have_a_verdict(self):
        for row in t.REFERENCE_ROWS:
            self.assertIn(row[0], ('same', 'differs'))
            self.assertEqual(len(row), 4)


if __name__ == '__main__':
    unittest.main()
