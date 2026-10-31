"""Controls for tools/gossip_peer_cap_static.py (node #94 gossip peer cap in `maybe_reject_peer_reason`)."""
import contextlib
import io
import json
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import gossip_peer_cap_static as pc  # noqa: E402
from artifacts import check  # noqa: E402

BINARY = ROOT / pc.TARGET
PACKET = ROOT / 'research/work-items/gossip-peer-cap-94/records.json'
CACHE = {}
LOCALHOST = 0x7f000001


def load():
    if not CACHE:
        identity = next(i for i in json.loads((ROOT / 'provenance/artifacts.json').read_text())['files']
                        if i['path'] == pc.TARGET)
        check(BINARY, identity)
        CACHE['data'] = BINARY.read_bytes()
        CACHE['img'] = pc.Image(CACHE['data'])
        CACHE['result'] = pc.analyse(CACHE['data'])
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
    def test_peer_limit(self):
        self.assertEqual(pc.peer_limit(None), (8, False))
        self.assertEqual(pc.peer_limit(0), (8, True))
        self.assertEqual(pc.peer_limit(1), (8, True))
        self.assertEqual(pc.peer_limit(7), (8, True))
        self.assertEqual(pc.peer_limit(8), (8, False))
        self.assertEqual(pc.peer_limit(16), (16, False))
        self.assertEqual(pc.peer_limit(100), (100, False))
        self.assertEqual(pc.peer_limit(101), (100, True))
        self.assertEqual(pc.peer_limit(2 ** 64 - 1), (100, True))

    def test_lead_differs_below_eight(self):
        diff = [v for v in range(0, 120) if pc.lead_limit(v) != pc.peer_limit(v)[0]]
        self.assertEqual(diff, list(range(0, 8)))

    def test_counted_peers(self):
        peers = [(0, 0x0a000001), (0, 0x0a000002), (1, 0), (0, LOCALHOST)]
        self.assertEqual(pc.counted_peers(peers, set()), 4)
        self.assertEqual(pc.counted_peers(peers, {0x0a000001}), 3)
        self.assertEqual(pc.counted_peers(peers, {LOCALHOST}), 2)

    def test_cap_code(self):
        peers = [(0, ip) for ip in range(0x0a000001, 0x0a000009)]
        self.assertEqual(pc.cap_code(peers[:7], set(), 8, (0, 0x0b000001)), 3)
        self.assertEqual(pc.cap_code(peers, set(), 8, (0, 0x0b000001)), 0)
        self.assertEqual(pc.cap_code(peers, {0x0b000001}, 8, (0, 0x0b000001)), 3)
        self.assertEqual(pc.cap_code(peers, {LOCALHOST}, 8, (1, 0)), 3)
        self.assertEqual(pc.cap_code(peers, {peers[0][1]}, 8, (0, 0x0b000001)), 3)


@unittest.skipUnless(BINARY.exists(), 'pinned node #94 binary not present')
class Results(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = load()['result']

    def test_limit(self):
        lm = self.result['limit']
        self.assertEqual((lm['low'], lm['high'], lm['none_default']), (8, 100, 8))
        self.assertEqual(pc.peer_limit(5, lm['low'], lm['high'], lm['none_default']), pc.peer_limit(5))

    def test_clip_log(self):
        cl = self.result['limit']['clip_log']
        self.assertEqual((cl['template'], cl['text'], cl['formatter'], cl['argument']),
                         ('0x1e8c2b', 'n_gossip_peers clipped to {}', '0x1570900', '&[rsp+0xe0]'))
        self.assertTrue(cl['location'].endswith('node/src/connections.rs:513:13'))

    def test_tracker(self):
        t = self.result['tracker']
        self.assertEqual(t['config'], {'unlocked': '0x18', 'locked': '0x20'})
        self.assertTrue(t['error_log']['location'].endswith('file_mod_time_tracker.rs:63:13'))

    def test_census(self):
        self.assertEqual(self.result['census']['[rsp+0xe0]'],
                         ['0x473f648', '0x473f71c', '0x473f886', '0x473f8a9', '0x473f8fa', '0x473fcc9'])

    def test_callers(self):
        self.assertEqual(self.result['callers'], ['0x57735f8'])

    def test_flow(self):
        fl = self.result['flow']
        self.assertEqual((fl['none_to_default'], fl['below_limit_else'], fl['incoming_miss']),
                         ('0x473f8f8', '0x473fd06', '0x4740051'))

    def test_packet_matches_regeneration(self):
        expected = json.loads(PACKET.read_text())
        got = dict(self.result, target_sha256=load()['sha256'])
        self.assertEqual(json.loads(json.dumps(got, sort_keys=True)), expected)

    def test_cli(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(pc.main([]), 0)
        self.assertIn('Some(v) -> min(max(v, 8), 100)', out.getvalue())


@unittest.skipUnless(BINARY.exists(), 'pinned node #94 binary not present')
class Corruptions(unittest.TestCase):
    def refuses(self, data, pattern):
        with self.assertRaisesRegex(pc.EvidenceError, pattern):
            pc.analyse(data)

    def test_low_bound(self):
        self.refuses(patched((0x473f86e + 1, struct.pack('<I', 1))), 'limit at 0x473f853: bytes changed')

    def test_high_bound(self):
        self.refuses(patched((0x473f87b + 1, struct.pack('<I', 200))), 'limit at 0x473f853: bytes changed')

    def test_gate(self):
        self.refuses(patched((0x473fccf, b'\x72')), 'count at 0x473f97e: bytes changed')

    def test_clip_template(self):
        self.refuses(patched((0x1e8c2b + 3, b'X')), 'clip template 0x1e8c2b changed')

    def test_clip_location(self):
        self.refuses(patched((0x1f0c72 + 40, b'X')), 'clip Location is')

    def test_tracker_template(self):
        self.refuses(patched((0x1f3bf3 + 5, b'X')), 'tracker template 0x1f3bf3 changed')

    def test_formatter_relocation(self):
        self.refuses(relative_edit(0x576e090, 0x1570960), 'clip formatter slot resolves to')

    def test_caller_slot(self):
        self.refuses(relative_edit(pc.CALLER_SLOT, pc.FDE + 1), 'RELATIVE slots holding')

    def test_limit_read_planted(self):
        self.refuses(patched((pc.FDE + 0x100, bytes.fromhex('488b8424e0000000'))), r'\[rsp\+0xe0\] operands are')

    def test_fact_outside_window(self):
        saved = dict(pc.FACTS)
        try:
            pc.FACTS['stray'] = (0x473f396, '00')
            self.refuses(load()['data'], 'fact stray at 0x473f396 is outside every window')
        finally:
            pc.FACTS.clear()
            pc.FACTS.update(saved)


if __name__ == '__main__':
    unittest.main()
