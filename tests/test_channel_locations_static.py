"""Controls for tools/channel_locations_static.py (node #94 net_utils/src/channel.rs panic Locations)."""
import contextlib
import io
import json
import struct
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import channel_locations_static as ch  # noqa: E402
from artifacts import check  # noqa: E402

BINARY = ROOT / ch.TARGET
PACKET = ROOT / 'research/work-items/channel-locations-94/records.json'
PAD = 0x157b559  # seven int3 bytes between the two const panic functions, outside every window
CACHE = {}


def load():
    if not CACHE:
        identity = next(i for i in json.loads((ROOT / 'provenance/artifacts.json').read_text())['files']
                        if i['path'] == ch.TARGET)
        check(BINARY, identity)
        CACHE['data'] = BINARY.read_bytes()
        CACHE['img'] = ch.Image(CACHE['data'])
        CACHE['result'] = ch.analyse(CACHE['data'])
        CACHE['sha256'] = identity['sha256']
    return CACHE


def patched(*edits, data=None):
    c = load()
    data = bytearray(data or c['data'])
    for va, new in edits:
        off = c['img'].offset(va, len(new))
        data[off:off + len(new)] = new
    return bytes(data)


def rela_edit(slot, new):
    """Rewrite the addend of the RELATIVE .rela.dyn entry for `slot`."""
    c = load()
    rela = next(s for s in c['img'].secs if s['name'] == '.rela.dyn')
    data = bytearray(c['data'])
    for pos in range(rela['offset'], rela['offset'] + rela['size'], 24):
        where, info, _ = struct.unpack_from('<QQq', data, pos)
        if where == slot and info & 0xffffffff == 8:
            struct.pack_into('<q', data, pos + 16, new)
            return bytes(data)
    raise AssertionError(f'no RELATIVE entry at {slot:#x}')


def rel32(va, length, target):
    return struct.pack('<i', target - (va + length))


@contextlib.contextmanager
def rewrite(va, new, length=None, target=None):
    """Patch window bytes and re-pin the window and operand tables, so only the semantic checks can object."""
    data = patched((va, new))
    name = ch.window_of(va)
    fde, start, hexs = ch.WINDOWS[name]
    raw = bytearray(bytes.fromhex(hexs))
    raw[va - start:va - start + len(new)] = new
    ops = {va: (length, target)} if length else {}
    with mock.patch.dict(ch.WINDOWS, {name: (fde, start, raw.hex())}), mock.patch.dict(ch.OPERANDS, ops):
        yield data


@unittest.skipUnless(BINARY.exists(), 'pinned node #94 binary not present')
class Models(unittest.TestCase):
    def test_blocking_recv(self):
        self.assertEqual(ch.blocking_recv([7], senders=1), 7)
        self.assertIsNone(ch.blocking_recv([], senders=0))
        self.assertEqual(ch.blocking_recv([], senders=1), 'blocked')

    def test_blocking_panics_carry_117_30(self):
        with self.assertRaisesRegex(ch.Panic, 'Cannot block.*117:30'):
            ch.blocking_recv([1], senders=1, in_runtime=True)
        with self.assertRaisesRegex(ch.Panic, 'Result::unwrap.*117:30'):
            ch.blocking_recv([1], senders=1, parker=False)

    def test_receive_loop_returns_on_none(self):
        self.assertEqual(ch.receive_loop([1, 2], senders=0), [1, 2])
        self.assertEqual(ch.receive_loop([], senders=0), [])

    def test_lead_recv_panics_on_none(self):
        self.assertEqual(ch.lead_recv([3], senders=0), 3)
        with self.assertRaisesRegex(ch.Panic, 'Option::unwrap.*93:47'):
            ch.lead_recv([], senders=0)


@unittest.skipUnless(BINARY.exists(), 'pinned node #94 binary not present')
class Results(unittest.TestCase):
    def setUp(self):
        self.result = load()['result']

    def test_locations(self):
        locs = self.result['locations']
        self.assertEqual(sorted(locs.values()), ['117:30'] * 2 + ['93:47'] * 5)
        self.assertEqual(self.result['path']['va'], '0x1e9781')

    def test_census(self):
        c = self.result['census']
        self.assertEqual((c['references'], c['references_93_47'], c['references_117_30']), (47, 42, 5))
        self.assertEqual(c['helper_callers'], {'0x437f970': ['0x432e597'], '0x437f580': ['0x432f6c9'],
                                               '0x437fdb0': ['0x474c0dc']})

    def test_async_fn_pairs(self):
        resume = self.result['async_fn_93_47']
        self.assertEqual(len(resume), 21)
        for rec in resume.values():
            self.assertEqual(sorted(rec['panics']), ['completion', 'panicking'])

    def test_const_panics(self):
        for rec in self.result['const_panics'].values():
            self.assertEqual(rec['esi'], 2 * len(rec['message']) + 1)
        self.assertEqual(self.result['const_panics']['0x576f040']['message'], '`async fn` resumed after completion')

    def test_blocking(self):
        b = self.result['blocking_117_30']
        self.assertEqual(b['callers']['fast']['sampler'], dict(constructor='0x3d22aa0', name='node_fast', f64=0.25))
        self.assertEqual(b['callers']['slow']['sampler'], dict(constructor='0x3d22aa0', name='node_slow', f64=0.5))
        self.assertNotIn('sampler', b['callers']['plain'])
        for h in b['helpers'].values():
            self.assertTrue(h['future_resume'].endswith('sync/mpsc/unbounded.rs:167:47'))
        self.assertEqual(b['inline']['location'], '0x56a0a88')

    def test_lead(self):
        lead = self.result['lead']
        self.assertEqual(len(lead['seeds_with_93_47']), 15)
        self.assertEqual(lead['seeds_with_117_30'], ['0x2017c80', '0x432e4d0', '0x432f680', '0x474bfa0'])
        self.assertEqual(len(lead['not_seeds_with_93_47']), 6)

    def test_packet_matches_regeneration(self):
        expected = json.loads(PACKET.read_text())
        got = dict(self.result, target_sha256=load()['sha256'])
        self.assertEqual(json.loads(json.dumps(got, sort_keys=True)), expected)

    def test_cli(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(ch.main([]), 0)
        self.assertIn('93:47: async fn resume panics in 21 FDEs', out.getvalue())


@unittest.skipUnless(BINARY.exists(), 'pinned node #94 binary not present')
class Corruptions(unittest.TestCase):
    def refuses(self, data, pattern):
        with self.assertRaisesRegex(ch.EvidenceError, pattern):
            ch.analyse(data)

    def test_location_line(self):
        self.refuses(patched((0x572fcc8 + 16, struct.pack('<I', 94))), 'channel.rs Locations are')

    def test_foreign_location_retargeted(self):
        self.refuses(rela_edit(0x5692d28, ch.PATH_VA), 'Location 0x5692d28 has a different length or path')

    def test_slot_holds_location(self):
        self.refuses(rela_edit(ch.SAMPLER_NEW_SLOT, 0x572fcc8), 'hold a channel.rs Location')

    def test_path_not_unique(self):
        self.refuses(patched((ch.PATH_VA + 0x200, b'/net_utils/src/channel.rs')), 'path is not unique')

    def test_planted_reference(self):
        lea = b'\x48\x8d\x3d' + rel32(PAD, 7, 0x572fcc8)
        self.refuses(patched((PAD, lea)), '93:47 references outside the resume pairs')

    def test_planted_helper_call(self):
        self.refuses(patched((PAD, b'\xe8' + rel32(PAD, 5, 0x437f970))), 'helper 0x437f970 callers are')

    def test_window_bytes(self):
        self.refuses(patched((0x437f9be, bytes.fromhex('4989c7'))), 'block_slow at 0x437f970: bytes changed')

    def test_const_message(self):
        self.refuses(patched((0x25d282 + 1, b'A')), 'message at 0x25d282 changed')

    def test_tokio_location(self):
        self.refuses(patched((ch.TOKIO_RECV[0] + 16, struct.pack('<I', 168))), 'Location 0x571e8c0 changed')

    def test_sampler_name(self):
        self.refuses(patched((0x6fb7d1 + 6, b'i')), 'fast: sampler name changed')

    def test_resume_pair_same_panic(self):
        ref = 0x47b070b + 7
        new = b'\xff\x15' + rel32(ref, 6, ch.PANICKING_SLOT)
        with rewrite(ref, new, 6, ch.PANICKING_SLOT) as data:
            self.refuses(data, '0x47b05f0: 93:47 goes to')

    def test_expect_length(self):
        with rewrite(0x437fa6d, bytes.fromhex('beb7000000')) as data:
            self.refuses(data, 'instruction at 0x437fa6d is not beb8000000')

    def test_unwrap_location_register(self):
        with rewrite(0x437faa7, bytes.fromhex('4d89e0')) as data:
            self.refuses(data, 'instruction at 0x437faa7 is not 4d89f8')

    def test_none_branch(self):
        new = b'\x0f\x84' + rel32(0x432e5a4, 6, 0x432e5aa)
        with rewrite(0x432e5a4, new, 6, 0x432e5aa) as data:
            self.refuses(data, 'does not pin 0x432e833')

    def test_none_path_panics(self):
        new = b'\xff\x15' + rel32(0x432e84f, 6, ch.UNWRAP_SLOT)
        with rewrite(0x432e84f, new, 6, ch.UNWRAP_SLOT) as data:
            self.refuses(data, 'slow: None path reaches a panic')

    def test_window_outside_fde(self):
        fde, va, hexs = ch.WINDOWS['inline_select']
        with mock.patch.dict(ch.WINDOWS, {'inline_select': (0x432e4d0, va, hexs)}):
            self.refuses(load()['data'], 'inline_select window 0x201889d is outside FDE 0x432e4d0')

    def test_lead_seed_without_location(self):
        with mock.patch.object(ch, 'LEAD_SEEDS', ch.LEAD_SEEDS + [0x3d21990]):
            self.refuses(load()['data'], 'a lead seed has no channel.rs Location')


if __name__ == '__main__':
    unittest.main()
