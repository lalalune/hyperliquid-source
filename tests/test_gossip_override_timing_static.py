"""Controls for tools/gossip_override_timing_static.py (node #94 timed gossip-override snapshot)."""
import contextlib
import io
import json
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import gossip_override_timing_static as ot  # noqa: E402
from artifacts import check  # noqa: E402

BINARY = ROOT / ot.TARGET
PACKET = ROOT / 'research/work-items/gossip-override-timing-94/records.json'
CACHE = {}


def load():
    if not CACHE:
        identity = next(i for i in json.loads((ROOT / 'provenance/artifacts.json').read_text())['files']
                        if i['path'] == ot.TARGET)
        check(BINARY, identity)
        CACHE['data'] = BINARY.read_bytes()
        CACHE['img'] = ot.Image(CACHE['data'])
        CACHE['result'] = ot.analyse(CACHE['data'])
        CACHE['sha256'] = identity['sha256']
    return CACHE


def patched(*edits):
    c = load()
    data = bytearray(c['data'])
    for va, new in edits:
        off = c['img'].offset(va, len(new))
        data[off:off + len(new)] = new
    return bytes(data)


def relative_edit(slot, addend):
    c = load()
    img = c['img']
    rela = next(s for s in img.secs if s['name'] == '.rela.dyn')
    data = bytearray(c['data'])
    for pos in range(rela['offset'], rela['offset'] + rela['size'], 24):
        where, info, _ = struct.unpack_from('<QQq', data, pos)
        if where == slot and info & 0xffffffff == 8:
            struct.pack_into('<q', data, pos + 16, addend)
            return bytes(data)
    raise AssertionError(f'no RELATIVE entry at {slot:#x}')


class Models(unittest.TestCase):
    def test_seconds(self):
        self.assertEqual(ot.seconds((5, 500_000_000), (3, 250_000_000)), 2.25)
        self.assertEqual(ot.seconds((5, 100_000_000), (3, 600_000_000)), 1.5)
        self.assertEqual(ot.seconds((3, 0), (5, 0)), 0.0)

    def test_durations_differ_from_lead(self):
        events = dict(call=0.0, locked=0.4, refreshed=0.7, cloned=0.75, unlocked=0.8)
        wait, hold = ot.binary_durations(events)
        update, clone = ot.lead_durations(events)
        self.assertAlmostEqual(wait, 0.4)
        self.assertAlmostEqual(hold, 0.4)
        self.assertAlmostEqual(update, 0.3)
        self.assertAlmostEqual(clone, 0.05)

    def test_uncontended_lock(self):
        events = dict(call=0.0, locked=0.0, refreshed=0.3, cloned=0.35, unlocked=0.35)
        self.assertEqual(ot.binary_durations(events)[0], 0.0)
        self.assertAlmostEqual(ot.binary_durations(events)[1], sum(ot.lead_durations(events)))

    def test_snapshot(self):
        self.assertEqual(ot.snapshot(0, 0, 3, 1), 'None')
        self.assertEqual(ot.snapshot(0, 2, 3, 1), 'None')
        self.assertEqual(ot.snapshot(0, 1, 0, 0), 'Some(empty)')
        self.assertEqual(ot.snapshot(1, 0, 3, 1), 'Some(clone)')
        self.assertEqual(ot.snapshot(1, 0, 3, 0), 'panic')


@unittest.skipUnless(BINARY.exists(), 'pinned node #94 binary not present')
class Results(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = load()['result']

    def test_clock(self):
        c = self.result['clock']
        self.assertEqual((c['source'], c['divisor'], c['err_value']),
                         ('clock_gettime(1 = CLOCK_MONOTONIC)', '0x20a220', 0.0))

    def test_timing(self):
        t = self.result['timing']
        self.assertEqual(t['first'], 't1 - t0: waiting for the lock')
        self.assertEqual(t['output']['+0x20'], 't1 - t0')
        self.assertEqual(t['output']['+0x28'], 't2 - t1')

    def test_body(self):
        b = self.result['body']
        self.assertEqual((b['lock'], b['tracker'], b['include']),
                         ('base+0x2a0', 'base+0x2a8', '[base+0x2d8] != 0 or ([rcx] & 1)'))
        self.assertTrue(b['tracker_refresh']['location'].endswith('node/src/connections.rs:163:45'))
        self.assertEqual((b['extra']['argument'], b['extra']['target']), (50, '0x13c9e20'))

    def test_caller(self):
        c = self.result['caller']
        self.assertEqual((c['call'], c['stack_argument'], c['name_args']),
                         ('0x4740670', 1, 'update_and_get_overrides'))
        self.assertEqual(self.result['callers'], {'relative_slots': [], 'direct_call': '0x4740670'})

    def test_packet_matches_regeneration(self):
        expected = json.loads(PACKET.read_text())
        got = dict(self.result, target_sha256=load()['sha256'])
        self.assertEqual(json.loads(json.dumps(got, sort_keys=True)), expected)

    def test_cli(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(ot.main([]), 0)
        self.assertIn('t1 - t0: waiting for the lock', out.getvalue())


@unittest.skipUnless(BINARY.exists(), 'pinned node #94 binary not present')
class Corruptions(unittest.TestCase):
    def refuses(self, data, pattern):
        with self.assertRaisesRegex(ot.EvidenceError, pattern):
            ot.analyse(data)

    def test_clock_id(self):
        self.refuses(patched((0x45281de + 1, struct.pack('<I', 0))), 'snapshot at 0x45281c0: bytes changed')

    def test_operand_swap(self):
        self.refuses(patched((0x4528236 + 4, b'\x40'), (0x452823b + 4, b'\x60')), 'snapshot at 0x45281c0: bytes changed')

    def test_divisor(self):
        self.refuses(patched((ot.NANOS_PER_SEC, struct.pack('<d', 1e6))), 'nanos divisor is')

    def test_clock_symbol(self):
        c = load()
        img = c['img']
        rela = next(s for s in img.secs if s['name'] == '.rela.dyn')
        data = bytearray(c['data'])
        for pos in range(rela['offset'], rela['offset'] + rela['size'], 24):
            where, info, _ = struct.unpack_from('<QQq', data, pos)
            if where == 0x576ea88:
                struct.pack_into('<Q', data, pos, 0x576ea90)
        self.refuses(bytes(data), 'clock slot fills None')

    def test_tracker_location(self):
        self.refuses(patched((0x572e8a8 + 16, struct.pack('<I', 64))), 'tracker error Location is')

    def test_tracker_template(self):
        self.refuses(patched((0x1f3bf3 + 5, b'X')), 'tracker template changed')

    def test_name(self):
        self.refuses(patched((0x6fb471 + 3, b'X')), 'names are')

    def test_extra_slot(self):
        c = load()
        img = c['img']
        rela = next(s for s in img.secs if s['name'] == '.rela.dyn')
        data = bytearray(c['data'])
        for pos in range(rela['offset'], rela['offset'] + rela['size'], 24):
            where, info, _ = struct.unpack_from('<QQq', data, pos)
            if where == 0x576e8f8:
                struct.pack_into('<Q', data, pos, 0x576e900)
        self.refuses(bytes(data), 'extra call slot has no RELATIVE target')

    def test_new_relative_caller(self):
        self.refuses(relative_edit(0x57735f8, ot.SNAPSHOT_FDE), 'RELATIVE slots holding')

    def test_fact_outside_window(self):
        saved = dict(ot.FACTS)
        try:
            ot.FACTS['stray'] = (0x4528490, '48')
            self.refuses(load()['data'], 'fact stray at 0x4528490 is outside every window')
        finally:
            ot.FACTS.clear()
            ot.FACTS.update(saved)


if __name__ == '__main__':
    unittest.main()
