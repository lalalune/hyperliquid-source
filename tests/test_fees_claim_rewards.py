"""Tests for tools/fees_claim_rewards.py on node #94 bytes."""

import hashlib
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

import fees_claim_rewards as t  # noqa: E402

FOLDER = ROOT / 'research/work-items/fees-claim-rewards-94'
DATA = (ROOT / t.BINARY).read_bytes()
IMG, CODE, FDES, SLOTS, GOT = t.build(DATA)
FAULTS = (t.Unmodelled, t.Panicked, t.EvidenceError, KeyError, ValueError, TypeError, struct.error, StopIteration, IndexError)
USD = t.USD


def result(v, img=IMG, code=CODE):
    return t.run(img, code, SLOTS, GOT, v)


def status(v):
    return t.read(result(v)[0], 0, 2)


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


def writer(ledger, **kw):
    return t.vec('test', ledger, entry='writer', **kw)


def handler(ledger, **kw):
    return t.vec('test', ledger, entry='handler', **kw)


def words_after(v):
    return t.ledger_words(result(v)[1].parts[0])


class Input(unittest.TestCase):
    def test_digest(self):
        self.assertEqual(t.check_digest(DATA), t.SHA256)
        with self.assertRaises(t.EvidenceError):
            t.check_digest(DATA[:-1] + bytes([DATA[-1] ^ 1]))

    def test_decoder_lands_on_each_end(self):
        for fn in t.SUBJECTS + t.HELPERS:
            listing = t.decode_range(IMG, fn, t.FDE_END[fn])
            self.assertEqual(listing[-1].va + listing[-1].size, t.FDE_END[fn])

    def test_decoder_rejects_cut_range(self):
        with self.assertRaises((t.EvidenceError, IndexError, struct.error)):
            t.decode_range(IMG, t.WRITER, t.WRITER + 0x15)

    def test_outside_address_refused(self):
        with self.assertRaises(t.EvidenceError):
            IMG.read(0x7fffffff0000, 4)

    def test_nobits_section_has_no_bytes(self):
        addr, _, size, typ = IMG.sec['.bss']
        self.assertEqual(typ, 8)
        with self.assertRaises(t.EvidenceError):
            IMG.read(addr + size // 2, 8)

    def test_no_fde_refused(self):
        with self.assertRaises(t.EvidenceError):
            FDES.range_of(t.WRITER + 1)

    def test_pinned_bytes(self):
        self.assertEqual(len(t.pinned(IMG)), len(t.PINNED))
        va = t.PINNED[1][0]
        with self.assertRaises(t.EvidenceError):
            t.pinned(t.Image(DATA, {va: IMG.read(va, 1)[0] ^ 1}))


class Rows(unittest.TestCase):
    def test_empty_table(self):
        self.assertEqual(status(writer([(0, USD, 0)], rows=[])), t.NOTHING)

    def test_missing_user(self):
        self.assertEqual(status(writer([(0, USD, 0)], rows=[(t.YOU, 'ledger')])), t.NOTHING)

    def test_no_root_and_no_items(self):
        self.assertEqual(status(writer([], rows=[(t.ME, 'no-root')])), t.NOTHING)
        self.assertEqual(status(writer([(0, USD, 0)], rows=[(t.ME, 'no-items')])), t.NOTHING)

    def test_last_four_key_bytes_are_compared(self):
        other = t.ME[:16] + t.YOU[16:]
        v = writer([(0, USD, 0)], rows=[(other, 'ledger')], hashes={other: t.key_hash(t.ME)})
        self.assertEqual(status(v), t.NOTHING)


class Floor(unittest.TestCase):
    def test_usdc_is_one_unit(self):
        self.assertEqual(status(writer([(0, USD, 0)])), t.OK)
        self.assertEqual(status(writer([(0, USD - 1, 0)])), t.TOO_SMALL)

    def test_whole_token_for_each_decimals(self):
        for wei in (0, 5, 8, 12, 18):
            meta = (t.USDC, dict(name=b'T', sz=0, wei=wei))
            need = 10 ** wei
            self.assertEqual(t.floor_of(meta, 1), need)
            self.assertEqual(status(writer([(1, need, 0)], meta=meta)), t.OK)
            if need > 1:
                self.assertEqual(status(writer([(1, need - 1, 0)], meta=meta)), t.TOO_SMALL)

    def test_floor_ignores_the_mark(self):
        for mark in (0, 1, 10 ** 12):
            v = handler([(3, USD - 1, 0)], marks={3: mark})
            self.assertEqual(status(v), t.TOO_SMALL)
            self.assertFalse(result(v)[1].calls)

    def test_floor_follows_token_zero_decimals(self):
        meta = (dict(name=b'USDC', sz=2, wei=6), dict(name=b'T', sz=2, wei=8))
        self.assertEqual(t.floor_of(meta, 1), 10 ** 10)
        self.assertEqual(status(writer([(1, 10 ** 10 - 1, 0)], meta=meta)), t.TOO_SMALL)
        self.assertEqual(status(writer([(1, 10 ** 10, 0)], meta=meta)), t.OK)

    def test_quotient_past_64_bits_never_claims(self):
        meta = (dict(name=b'USDC', sz=0, wei=0), dict(name=b'T', sz=0, wei=19))
        self.assertIsNone(t.floor_of(meta, 1))
        self.assertEqual(status(writer([(1, t.U64, 0)], meta=meta)), t.TOO_SMALL)

    def test_exponent_of_20_panics(self):
        meta = (t.USDC, dict(name=b'T', sz=0, wei=20))
        with self.assertRaises(t.Panicked):
            result(writer([(1, t.U64, 0)], meta=meta))
        self.assertTrue(passes(writer([(1, t.U64, 0)], meta=meta)))

    def test_size_decimals_above_token_zero_wei_panic(self):
        meta = (t.USDC, dict(name=b'T', sz=9, wei=9))
        with self.assertRaises(t.Panicked) as ctx:
            result(writer([(1, USD, 0)], meta=meta))
        self.assertEqual(str(ctx.exception), 'subtract')

    def test_status_text(self):
        self.assertEqual(t.format_text(IMG, t.STATUS_FORMAT), 'Must have at least {} of a reward token to claim')
        self.assertEqual(t.status_text(IMG, t.NOTHING), 'No rewards to claim')
        self.assertEqual(struct.unpack('<d', IMG.read(t.STATUS_ARM + 2, 8))[0], 1.0)


class Writer(unittest.TestCase):
    def test_u_moves_to_c_and_others_stay(self):
        before = (0, USD + 5, 7, 11, 13, 17)
        after = words_after(writer([before]))
        self.assertEqual(after, [(0, 0, USD + 12)])
        m = result(writer([before]))[1]
        at = m.parts[0].places[0]
        blob = m.parts[0].snapshot()
        self.assertEqual((t.read(blob, at), t.read(blob, at + 0x18), t.read(blob, at + 0x20)), (11, 13, 17))

    def test_small_tokens_keep_their_u(self):
        v = writer([(0, USD, 1), (1, USD - 1, 2), (3, 2 * USD, 3)])
        self.assertEqual(words_after(v), [(0, 0, USD + 1), (1, USD - 1, 2), (3, 0, 2 * USD + 3)])

    def test_zero_u_sets_no_seen(self):
        self.assertEqual(status(writer([(0, 0, 9), (1, 0, 9)])), t.NOTHING)

    def test_add_saturates_and_reports(self):
        v = writer([(0, USD, t.U64)])
        res, m = result(v)
        self.assertEqual(t.read(res, 0, 2), t.OK)
        self.assertEqual(t.ledger_words(m.parts[0]), [(0, 0, t.U64)])
        self.assertEqual(m.reports, 1)
        self.assertEqual(result(writer([(0, USD, t.U64 - USD)]))[1].reports, 0)

    def test_vector_order_is_key_order(self):
        items = [(i + 1, USD + i, 0) for i in range(30)]
        meta = tuple(dict(name=b'T', sz=0, wei=8) for _ in range(40))
        res, m = result(writer(items, meta=meta, fan=2))
        cap, ptr, n = t.read(res, 8), t.read(res, 0x10), t.read(res, 0x18)
        self.assertEqual(n, 30)
        self.assertGreaterEqual(cap, 30)
        self.assertEqual([m.load(ptr + 16 * i, 8) for i in range(30)], [i + 1 for i in range(30)])

    def test_tall_tree_descents(self):
        meta = tuple(dict(name=b'T', sz=0, wei=8) for _ in range(2000))
        items = [(i + 1, USD, 0) for i in range(1023)]
        v = writer(items, meta=meta, fan=1, height=9)
        self.assertTrue(passes(v))
        self.assertEqual(t.read(result(v)[0], 0x18), 1023)

    def test_length_above_the_tree_panics(self):
        v = writer([(0, USD, 0)], length_lie=1, panic='bound')
        self.assertTrue(passes(v))


class Handler(unittest.TestCase):
    def test_error_copy(self):
        v = handler([(0, USD - 1, 0)])
        res, m = result(v)
        self.assertEqual(t.read(res, 0, 2), t.TOO_SMALL)
        self.assertEqual(res[2:], bytes(m.stack.mem[t.FRAME + 0xc2:t.FRAME + 0xc0 + 0x60]))

    def test_token_zero_value_and_units(self):
        rows = t.pay_model(handler([], account=0), [(0, 12345 * USD + 77)])
        self.assertEqual(rows[0]['usd'], (12345 * USD + 77) // 100)
        self.assertEqual(rows[0]['units'], 12345 * 100)
        self.assertEqual(rows[0]['px'], 0)
        v = handler([(0, 12345 * USD + 77, 0)])
        self.assertEqual(t.read(result(v)[1].account.mem, 0x10), 12345 * 100)

    def test_mark_zero_gives_no_units(self):
        v = handler([(3, USD, 0)], marks={})
        self.assertEqual(t.read(result(v)[1].account.mem, 0x10), 0)

    def test_cap_on_other_tokens_only(self):
        wei, mark = 10 ** 16, 10 ** 9
        fake = handler([(3, wei, 0)], marks={3: mark})
        self.assertEqual(t.read(result(fake)[1].account.mem, 0x10), t.CAP // 10000)
        hype = handler([(1, wei, 0)], marks={1: mark})
        self.assertEqual(t.read(result(hype)[1].account.mem, 0x10), wei * mark // 10 ** 8 // 10000)
        named = handler([(5, 10 ** 22 // 10 ** 4, 0)], marks={5: 10 ** 12})
        self.assertTrue(passes(named))

    def test_name_needs_length_four(self):
        v = handler([(4, 10 ** 9, 0)], marks={4: 10 ** 15})
        self.assertTrue(passes(v))

    def test_value_past_the_limit_is_zero(self):
        v = handler([(3, 10 ** 16, 0)], marks={3: 10 ** 10})
        self.assertEqual(t.read(result(v)[1].account.mem, 0x10), 0)

    def test_account_word_saturates(self):
        top = (1 << 63) - 1
        v = handler([(0, 10 ** 9, 0)], account=top - 1)
        res, m = result(v)
        self.assertEqual(t.read(m.account.mem, 0x10), top)
        self.assertEqual(m.reports, 1)

    def test_scale_tree_value_goes_to_the_balance_call(self):
        v = handler([(3, USD, 0)], scales={3: 4242})
        calls = result(v)[1].calls
        self.assertEqual(calls[0], ('apply', t.ME, 3, USD, 4242))
        v = handler([(3, USD, 0)], scales={2: 4242})
        self.assertEqual(result(v)[1].calls[0], ('apply', t.ME, 3, USD, 10 ** 6))

    def test_event_amount(self):
        v = handler([(0, 3 * USD + USD // 2, 0)])
        ev = [c for c in result(v)[1].calls if c[0] == 'event'][0]
        self.assertEqual(t.b2f(ev[4][4]), 3.5)
        self.assertEqual(ev[4][0], t.EVENT_TAG)
        self.assertEqual(ev[1], t.ME)

    def test_block_record_flag(self):
        self.assertTrue(any(c[0] == 'block' for c in result(handler([(0, USD, 0)], block=2))[1].calls))
        self.assertFalse(any(c[0] == 'block' for c in result(handler([(0, USD, 0)]))[1].calls))

    def test_failed_allocation_panics(self):
        self.assertTrue(passes(handler([(0, USD, 0)], no_alloc=True, panic='allocation')))


class Mutants(unittest.TestCase):
    def test_floor_compare_flip(self):
        self.assertTrue(flip(t.WRITER, 0x3743cbd, [writer([(0, USD, 0)]), writer([(0, USD - 1, 0)])]))

    def test_floor_immediate(self):
        self.assertTrue(fails(t.WRITER, {0x3743c94: 1}, [writer([(0, USD, 0)]), writer([(0, USD - 1, 0)])]))

    def test_cap_flip(self):
        self.assertTrue(flip(t.HANDLER, 0x27110da + 2, [handler([(3, 10 ** 16, 0)], marks={3: 10 ** 9})]))

    def test_hype_name_compare(self):
        self.assertTrue(fails(t.HANDLER, {0x27110cb: 0x75}, [handler([(3, 10 ** 16, 0)], marks={3: 10 ** 9})]))

    def test_model_rejects_a_wrong_expectation(self):
        v = writer([(0, USD, 0)])
        real = t.writer_model
        t.writer_model = lambda x: dict(real(x), status=t.NOTHING)
        try:
            self.assertFalse(passes(v))
        finally:
            t.writer_model = real


class Packet(unittest.TestCase):
    def test_folder_matches_a_fresh_run(self):
        with tempfile.TemporaryDirectory() as d:
            ev = t.generate(DATA, d, with_survey=False)
            old = json.loads((FOLDER / 'evidence.json').read_text())
            for k in ('functions', 'vectors', 'groups', 'outcomes', 'writer_callers', 'handler_copies', 'status_arm', 'pinned'):
                self.assertEqual(json.loads(json.dumps(ev[k])), old[k], k)
            for name in ('vectors.tsv', 'instructions.tsv', 'reference-diff.tsv'):
                self.assertEqual((Path(d) / name).read_bytes(), (FOLDER / name).read_bytes(), name)

    def test_manifest(self):
        rows = (FOLDER / 'MANIFEST.sha256').read_text().split('\n')
        names = set()
        for row in rows:
            if row:
                digest, name = row.split('  ')
                names.add(name)
                self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest)
        self.assertEqual(names, {p.name for p in FOLDER.iterdir()} - {'MANIFEST.sha256'})

    def test_mutants_all_accounted(self):
        ev = json.loads((FOLDER / 'evidence.json').read_text())
        rows = (FOLDER / 'mutations.tsv').read_text().splitlines()[1:]
        self.assertEqual(len(rows), ev['mutants'])
        self.assertEqual(sum(r.split('\t')[4] == 'killed' for r in rows), ev['killed'])
        self.assertEqual(ev['mismatches'], 0)

    def test_binutils_not_used(self):
        text = (ROOT / 'tools/fees_claim_rewards.py').read_text()
        self.assertNotIn('subprocess', text)
        self.assertNotIn('os.system', text)


if __name__ == '__main__':
    unittest.main()
