"""Controls for tools/gossip_connect_stagger_static.py (node #94 gossip connect deadlines in 0x4740490)."""
import contextlib
import io
import json
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import gossip_connect_stagger_static as cs  # noqa: E402
from artifacts import check  # noqa: E402

BINARY = ROOT / cs.TARGET
PACKET = ROOT / 'research/work-items/gossip-connect-stagger-94/records.json'
CACHE = {}


def load():
    if not CACHE:
        identity = next(i for i in json.loads((ROOT / 'provenance/artifacts.json').read_text())['files']
                        if i['path'] == cs.TARGET)
        check(BINARY, identity)
        CACHE['data'] = BINARY.read_bytes()
        CACHE['img'] = cs.Image(CACHE['data'])
        CACHE['result'] = cs.analyse(CACHE['data'])
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
    def test_k_value(self):
        self.assertEqual(cs.k_value(7, 2, 9), 7)
        self.assertEqual(cs.k_value(None, 2, 9), 2)
        self.assertEqual(cs.k_value(None, None, 9), 9)
        self.assertEqual(cs.k_value(0, 2, 9), 0)

    def test_delay(self):
        self.assertEqual(cs.delay(False, 50, 3), 0.0)
        self.assertAlmostEqual(cs.delay(True, 10, 3), 0.03)
        self.assertEqual(cs.delay(True, 10, 100), 0.07)
        self.assertEqual(cs.delay(True, 0, 100), 0.0)

    def test_stagger_shape(self):
        delays = [cs.delay(True, 20, k) for k in range(6)]
        self.assertEqual([round(d, 3) for d in delays], [0.0, 0.02, 0.04, 0.06, 0.07, 0.07])


@unittest.skipUnless(BINARY.exists(), 'pinned node #94 binary not present')
class Results(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = load()['result']

    def test_constants(self):
        d = self.result['deadline']
        self.assertEqual((d['cap'], self.result['factor']['some'], d['add']['seconds_to_nanos']),
                         (0.07, 'X * 0.001', 1e9))
        self.assertEqual(d['now']['clock'], 'clock_gettime(0 = CLOCK_REALTIME)')

    def test_locked_copy(self):
        lc = self.result['locked_copy']
        self.assertEqual((lc['lock'], lc['list']['element'], lc['output']['+0x18']), ('+0x2a0', 5, 'X'))

    def test_durations_unread(self):
        d = self.result['durations']
        self.assertEqual((d['touching'], d['after_call']), (['0x47404fe'], 'none'))
        self.assertEqual(len(d['eight_byte_below_0x1a0']), 4)

    def test_factor_census(self):
        self.assertEqual(self.result['factor']['census'],
                         {'0x47406b9': '0x168', '0x4740725': '0x170', '0x4740751': '0x170', '0x4740e43': '0x170'})

    def test_names(self):
        self.assertEqual(self.result['names'], {'locked_copy': 'clone', 'snapshot': 'update_and_get_overrides'})

    def test_packet_matches_regeneration(self):
        expected = json.loads(PACKET.read_text())
        got = dict(self.result, target_sha256=load()['sha256'])
        self.assertEqual(json.loads(json.dumps(got, sort_keys=True)), expected)

    def test_cli(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(cs.main([]), 0)
        self.assertIn('min(0.07, k * X * 0.001)', out.getvalue())


@unittest.skipUnless(BINARY.exists(), 'pinned node #94 binary not present')
class Corruptions(unittest.TestCase):
    def refuses(self, data, pattern):
        with self.assertRaisesRegex(cs.EvidenceError, pattern):
            cs.analyse(data)

    def test_cap_constant(self):
        self.refuses(patched((0x20ac80, struct.pack('<d', 0.7))), 'cap constant is 0.7')

    def test_factor_constant(self):
        self.refuses(patched((0x20afb8, struct.pack('<d', 0.01))), 'factor constant is 0.01')

    def test_nanos_constant(self):
        self.refuses(patched((0x20a220, struct.pack('<d', 1e6))), 'seconds multiplier is')

    def test_none_branch(self):
        self.refuses(patched((0x4740d09, b'\x74')), 'deadline at 0x4740cf0: bytes changed')

    def test_wall_clock(self):
        self.refuses(patched((0x151cbad, bytes.fromhex('b001'))), 'wall_now at 0x151cba0: bytes changed')

    def test_add_slot(self):
        self.refuses(relative_edit(0x576efb8, cs.ADD_SECS + 1), 'add slot resolves to')

    def test_now_slot(self):
        self.refuses(relative_edit(0x576e8a0, cs.WALL_NOW + 1), 'now slot resolves to')

    def test_duration_read_planted(self):
        self.refuses(patched((0x4740f61, bytes.fromhex('488b8424a8010000'))), r'\[rsp\+0x191\.\.0x1b0\) operands are')

    def test_factor_read_planted(self):
        self.refuses(patched((0x4740f61, bytes.fromhex('488b842470010000'))), r'\[rsp\+0x170\] operands are')

    def test_snapshot_name(self):
        self.refuses(patched((0x6fb471 + 2, b'X')), 'names are')

    def test_enumerate_location(self):
        self.refuses(patched((0x572d9e8 + 16, struct.pack('<I', 1))), 'enumerate Location is')


if __name__ == '__main__':
    unittest.main()
