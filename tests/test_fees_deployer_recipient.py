"""Tests of tools/fees_deployer_recipient.py: digest binding, real outcomes, corrupted bytes and the packet files."""

import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
SPEC = importlib.util.spec_from_file_location('fees_deployer_recipient', ROOT / 'tools' / 'fees_deployer_recipient.py')
tool = importlib.util.module_from_spec(SPEC)
sys.modules['fees_deployer_recipient'] = tool
SPEC.loader.exec_module(tool)
FOLDER = ROOT / 'research' / 'work-items' / 'fees-deployer-recipient-94'
COPY = 0x273e080
SETTER = 0x27512f0
ARM = 0x23e8066


class Base(unittest.TestCase):
    data = (ROOT / tool.BINARY).read_bytes()
    built = tool.build(data)
    ctx = (built[0], built[1], built[3], built[4])

    def setUp(self):
        tool.GOLD.clear()

    def passes(self, v, ctx=None):
        self.assertIsNone(tool.check(ctx or self.ctx, v))

    def patched(self, patch):
        """The same run on an image with `patch` VA -> byte applied; subjects decoded again."""
        img, code, _, slots, got, _ = self.built
        mimg = tool.Image(self.data, patch)
        mcode = dict(code)
        for s in tool.RANGES:
            mcode.update({i.va: i for i in tool.decode_subject(mimg, s)})
        for e in tool.ACTIONS:
            mcode.update({i.va: i for i in tool.walk_action(mimg, e)[0]})
        for e in tool.SHARE_ARMS:
            mcode.update({i.va: i for i in tool.walk_share(mimg, e)[0]})
        return (mimg, mcode, slots, got)

    def broken(self, v, patch):
        """True when the corrupted image no longer matches the model on `v`."""
        try:
            return tool.check(self.patched(patch), v) is not None
        except (tool.Unmodelled, tool.Panicked):
            return True


def act(**kw):
    return tool.act(COPY, 't', **kw)


def setter(token=5, count=tool.COUNT, mode=0, old=7, share=3, fn=SETTER):
    return dict(kind='setter', group='t', fn=fn, token=token, count=count, mode=mode, old=old, share=share)


def arm(token=3, count=tool.COUNT, mode=0, old=7, text=b'1%', parsed=5, at=ARM):
    return dict(kind='share_arm', group='t', arm=at, token=token, count=count, mode=mode, old=old, text=text, parsed=parsed)


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
    def test_gate_order(self):
        a, b = tool.addr(1), tool.addr(2)
        self.assertEqual(tool.gate_rule(3, a, {}, 3, a), tool.BAD_DEPLOYER)
        self.assertEqual(tool.gate_rule(3, a, {}, 0xe, a), tool.GONE)
        self.assertEqual(tool.gate_rule(0, a, {}, 0xe, a), tool.OK)
        self.assertEqual(tool.gate_rule(0, a, {0xe: [b]}, 0xe, b), tool.GONE)
        self.assertEqual(tool.gate_rule(0, a, {3: [b]}, 3, b), tool.OK)
        self.assertEqual(tool.gate_rule(0, a, {2: [b]}, 3, b), tool.BAD_DEPLOYER)

    def test_share_rule_table(self):
        self.assertEqual(tool.share_rule(1, 2, 0, 5, 100001)[1], tool.TEXT_OVER)
        self.assertEqual(tool.share_rule(1, 2, 0, 5, 5)[1], tool.TEXT_RAISE)
        self.assertEqual(tool.share_rule(1, 2, 0, 0, 0)[1], tool.TEXT_RAISE)
        self.assertEqual(tool.share_rule(1, 2, 3, 0, 9)[0], tool.OK)
        self.assertEqual(tool.share_rule(1, 2, 3, 0, 0)[0], tool.OK)
        self.assertEqual(tool.share_rule(1, 2, 3, 5, 0)[1], tool.TEXT_RESET)
        self.assertEqual(tool.share_rule(0xc4, 0xc8, 3, 0, 9)[1], tool.TEXT_RAISE)
        self.assertEqual(tool.share_rule(3, 3, 3, 0, 0), ('panic',))


class Action(Base):
    def test_every_copy_writes(self):
        for c in tool.ACTIONS:
            v = tool.act(c, 't', dexes=[tool.dex(users=[tool.A], old=(1, tool.addr(91)))])
            self.assertEqual(tool.action_rule(v)['stage'], 'write')
            self.passes(v)

    def test_unknown_address_refused(self):
        v = act(dexes=[tool.dex()])
        self.assertEqual(tool.action_rule(v)['status'], tool.BAD_RECIPIENT)
        self.passes(v)

    def test_fallback_map_admits(self):
        self.passes(act(dexes=[tool.dex()], known=True))

    def test_item_count_zero_keeps_table_unread(self):
        self.passes(act(dexes=[tool.dex(), tool.dex(users=[tool.A])]))

    def test_address_in_set_refused(self):
        v = act(vaults=[tool.A])
        self.assertEqual(tool.action_rule(v)['status'], tool.BAD_RECIPIENT)
        self.passes(v)

    def test_abstraction_message(self):
        v = act(mode=2)
        self.assertEqual(tool.action_rule(v)['status'], tool.MESSAGE)
        self.passes(v)

    def test_abstraction_flag_passes(self):
        self.passes(act(mode=3, f1=2))
        self.passes(act(mode=4, f0=1))

    def test_flag_two_is_not_one(self):
        v = act(mode=4, f0=2)
        self.assertEqual(tool.action_rule(v)['status'], tool.MESSAGE)
        self.passes(v)

    def test_sub_deployer(self):
        self.passes(act(sender=tool.OTHER, dexes=[tool.dex(users=[tool.A], subs={3: [tool.OTHER]})]))

    def test_other_kind_is_no_right(self):
        v = act(sender=tool.OTHER, dexes=[tool.dex(users=[tool.A], subs={2: [tool.OTHER]})])
        self.assertEqual(tool.action_rule(v)['status'], tool.BAD_DEPLOYER)
        self.passes(v)

    def test_name_limit(self):
        self.passes(act(name=b'x' * 100, cap=100))
        v = act(name=b'x' * 101, cap=101)
        self.assertEqual(tool.action_rule(v)['status'], tool.TOO_LONG)
        self.passes(v)

    def test_tombstones_and_clashes(self):
        decoys = [(tool.addr(300 + i), tool.A) if i else (tool.flip(tool.A, 19), tool.A) for i in range(34)]
        self.passes(act(dexes=[tool.dex(decoys=decoys, users=[tool.A])]))
        self.passes(act(dexes=[tool.dex(decoys=decoys, users=[])]))

    def test_recipient_tag_corrupted(self):
        self.assertTrue(self.broken(act(dexes=[tool.dex()]), {0x274016e: 0x64}))

    def test_option_store_corrupted(self):
        self.assertTrue(self.broken(act(), {0x27413dd: 0}))

    def test_address_store_corrupted(self):
        self.assertTrue(self.broken(act(), {0x27413eb: 0x9f}))

    def test_set_test_corrupted(self):
        self.assertTrue(self.broken(act(vaults=[tool.A]), {0x2740160: 0x85}))

    def test_abstraction_bound_corrupted(self):
        self.assertTrue(self.broken(act(mode=3, f1=1), {0x2745eca: 2}))

    def test_kind_byte_corrupted(self):
        v = act(sender=tool.OTHER, dexes=[tool.dex(users=[tool.A], subs={3: [tool.OTHER]})])
        self.assertTrue(self.broken(v, {0x273ef57: 2}))


class Gate(Base):
    def test_direct_values(self):
        d = tool.dex(subs={3: [tool.OTHER]})
        self.passes(dict(kind='gate', group='t', dex=d, kind_byte=3, sender=tool.OTHER))
        self.passes(dict(kind='gate', group='t', dex=d, kind_byte=0xe, sender=tool.OTHER))
        self.passes(dict(kind='gate', group='t', dex=d, kind_byte=3, sender=tool.addr(9)))

    def test_owner_compare_corrupted(self):
        d = tool.dex()
        self.assertTrue(self.broken(dict(kind='gate', group='t', dex=d, kind_byte=3, sender=tool.addr(9)), {0x37190a0: 0x85}))


class Find(Base):
    def test_pointer_of_value(self):
        items = tool.spread(30, 1)
        for fn in tool.FINDS:
            self.passes(dict(kind='find', group='t', fn=fn, items=items, height=1, key=items[7]))
            self.passes(dict(kind='find', group='t', fn=fn, items=items, height=1, key=tool.addr(13)))

    def test_value_stride_corrupted(self):
        items = tool.spread(5, 1)
        self.assertTrue(self.broken(dict(kind='find', group='t', fn=tool.FINDS[0], items=items, height=0, key=items[3]), {0x284bca7: 0xb8}))


class Setter(Base):
    def test_each_copy(self):
        for fn in tool.SETTERS:
            self.passes(setter(fn=fn))
            self.passes(setter(fn=fn, mode=3, token=0xc3, old=0, share=9))
            self.passes(setter(fn=fn, mode=3, token=0xc3, old=9, share=0))
            self.passes(setter(fn=fn, token=tool.COUNT))

    def test_equal_share_refused(self):
        v = setter(old=7, share=7)
        self.assertEqual(tool.share_rule(5, tool.COUNT, 0, 7, 7)[1], tool.TEXT_RAISE)
        self.passes(v)

    def test_cap_corrupted(self):
        self.assertTrue(self.broken(setter(share=100001, old=0), {0x2751300: 0xa1}))

    def test_legacy_bound_corrupted(self):
        self.assertTrue(self.broken(setter(mode=3, token=0xc4, old=0, share=5), {0x275133b: 0xc4}))

    def test_mode_corrupted(self):
        self.assertTrue(self.broken(setter(mode=3, token=1, old=0, share=5), {0x2751347: 2}))

    def test_write_offset_corrupted(self):
        self.assertTrue(self.broken(setter(), {0x275137f: 0xb0}))

    def test_token_past_end_panics(self):
        self.passes(setter(token=tool.COUNT, count=tool.COUNT))


class ShareArm(Base):
    def test_each_copy(self):
        for at in tool.SHARE_ARMS:
            self.passes(arm(at=at))
            self.passes(arm(at=at, parsed=None))
            self.passes(arm(at=at, token=tool.COUNT))
            self.passes(arm(at=at, text=b'1' * 101))
            self.passes(arm(at=at, parsed=8))

    def test_length_corrupted(self):
        self.assertTrue(self.broken(arm(text=b'1' * 101), {0x23e807e: 0x66}))


class Walk(Base):
    def test_every_arm_has_ends(self):
        for e in tool.ACTIONS:
            self.assertEqual(len(tool.STOPS[e]) >= 2, True)
        for e in tool.SHARE_ARMS:
            self.assertEqual(len(tool.ARM_STOPS[e]), 2)

    def test_walk_refuses_a_return(self):
        with self.assertRaises(tool.EvidenceError):
            tool.walk(self.built[0], SETTER, (tool.OUTER_OK,), False)

    def test_range_outside_any_fde_refused(self):
        with self.assertRaises(Exception):
            self.built[2].range_of(0x10)

    def test_wrong_table_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.table_jump(self.built[0], {}, COPY)


class Static(Base):
    def test_pins_read_back(self):
        rows = tool.pins(self.built[0])
        keys = [r['key'] for r in rows if 'key' in r]
        self.assertEqual(keys, ['oracle_updater', 'fee_recipient'])

    def test_corrupted_pin_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.pins(tool.Image(self.data, {0x233b588: 0}))

    def test_variant_rows(self):
        rows = tool.variant_rows(self.built[0])
        by = {r[1]: r for r in rows}
        self.assertEqual(by['setFeeRecipient'][0], 5)
        self.assertEqual(by['setFeeRecipient'][4], 3)
        self.assertEqual(by['setFeeScale'][5], 'setFeeScale')
        self.assertEqual(by['setSubDeployers'][4], 0xe)

    def test_status_text(self):
        self.assertEqual(tool.status_text(self.built[0], 0x163), 'Invalid perp DEX fee recipient')

    def test_census_finds_the_store_of_each_copy(self):
        starts = sorted(f['start'] for f in tool.eh_frame_records(self.data)[1])
        rows = tool.recipient_sites(self.built[0], starts)
        stores = [r for r in rows if r[1] == 'store']
        self.assertEqual({r[2] for r in stores}, set(tool.ACTIONS))


class Packet(Base):
    folder = FOLDER

    def test_regenerated_files_match(self):
        with tempfile.TemporaryDirectory() as t:
            tool.generate(self.data, t, with_survey=False)
            for name in ('vectors.tsv', 'instructions.tsv', 'reference-diff.tsv', 'variants.tsv', 'recipient-sites.tsv'):
                self.assertEqual((Path(t) / name).read_bytes(), (self.folder / name).read_bytes(), name)

    def test_evidence_numbers(self):
        ev = json.loads((self.folder / 'evidence.json').read_text())
        self.assertEqual(ev['sha256'], tool.SHA256)
        self.assertEqual(ev['mismatches'], 0)
        self.assertEqual(ev['mutants'], ev['killed'] + len([1 for line in (self.folder / 'mutations.tsv').read_text().splitlines()[1:] if line.split('\t')[4] == 'equivalent']))

    def test_manifest(self):
        for line in (self.folder / 'MANIFEST.sha256').read_text().splitlines():
            digest, name = line.split('  ')
            self.assertEqual(hashlib.sha256((self.folder / name).read_bytes()).hexdigest(), digest, name)

    def test_tool_runs_no_external_program(self):
        src = (ROOT / 'tools' / 'fees_deployer_recipient.py').read_text()
        self.assertNotIn('subprocess', src)
        self.assertNotIn('os.system', src)


if __name__ == '__main__':
    unittest.main()
