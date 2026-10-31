"""Controls for tools/height_retry_static.py (node #94 `gossip rpc height` retry loop)."""
import contextlib
import io
import json
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import height_retry_static as hr  # noqa: E402
from artifacts import check  # noqa: E402

BINARY = ROOT / hr.TARGET
PACKET = ROOT / 'research/work-items/height-retry-94/records.json'
CACHE = {}


def load():
    if not CACHE:
        identity = next(i for i in json.loads((ROOT / 'provenance/artifacts.json').read_text())['files']
                        if i['path'] == hr.TARGET)
        check(BINARY, identity)
        CACHE['data'] = BINARY.read_bytes()
        CACHE['img'] = hr.Image(CACHE['data'])
        CACHE['result'] = hr.analyse(CACHE['data'])
        CACHE['sha256'] = identity['sha256']
    return CACHE


def patched(*edits):
    c = load()
    data = bytearray(c['data'])
    for va, new in edits:
        off = c['img'].offset(va, len(new))
        data[off:off + len(new)] = new
    return bytes(data)


class Models(unittest.TestCase):
    def test_max_one(self):
        self.assertEqual(hr.max_one(0), 1)
        self.assertEqual(hr.max_one(1), 1)
        self.assertEqual(hr.max_one(10), 10)
        self.assertEqual(hr.max_one(2 ** 64 - 1), 2 ** 64 - 1)

    def test_attempts(self):
        self.assertEqual(hr.attempts(10, 3), ([0, 1, 2], False))
        self.assertEqual(hr.attempts(2, 5), ([0, 1], True))
        logged, exhausted = hr.attempts(hr.max_one(2 ** 64 - 1), 1000)
        self.assertEqual((logged[0], logged[-1], len(logged), exhausted), (0, 999, 1000, False))


@unittest.skipUnless(BINARY.exists(), 'pinned node #94 binary not present')
class Results(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = load()['result']

    def test_record(self):
        f = self.result['record']['fields']
        self.assertEqual((f['+0x10'], f['+0x18'], f['+0x20']), (17, 10, 2.0))
        self.assertIn('"gossip rpc height"', f['+0x8'])

    def test_bound(self):
        b = self.result['bound']
        self.assertEqual((b['raw_tries'], b['bound'], b['counter_start']),
                         ('0xffffffffffffffff', '0xffffffffffffffff', 0))

    def test_logs(self):
        lg = self.result['logs']
        self.assertEqual((lg['retry_template'], lg['retry_ntries_arg_index'], lg['ntries_formatter']),
                         ('0x1f2256', 1, '0x1570900'))
        self.assertEqual((lg['exhausted_template'], lg['exhausted_n_retries_index']), ('0x1ebd40', 1))

    def test_tries_field_never_read(self):
        c = self.result['census']
        self.assertEqual(c['[rbx+0x3bb0]'], ['0x2268bb6'])
        self.assertEqual(c['[rbx+0x3c30]'], ['0x2268c65', '0x2269c65', '0x226a79d', '0x226a897'])
        self.assertEqual(c['[rbx+0x3bd0]'], ['0x2268c8d', '0x2269c43'])

    def test_all_record_sites(self):
        sites = self.result['sites']
        self.assertEqual(sorted(sites), sorted(['0x22c54a0', '0x438ed70', '0x47b4950', '0x2039060', '0x4387f40',
                                                '0x439fa90', '0x4b399a0', '0x22689f0']))
        self.assertEqual(sites['0x2039060']['census']['count_slot'],
                         ['0x20391a8', '0x20392bc', '0x20399cc', '0x2039bd6', '0x2039bfb'])
        self.assertEqual(sites['0x439fa90']['census']['count_slot'], ['0x439fb56', '0x439fb77'])
        self.assertEqual({k: len(v['pointer_loads']) for k, v in sites.items()},
                         {'0x22c54a0': 3, '0x438ed70': 5, '0x47b4950': 5, '0x2039060': 3, '0x4387f40': 3,
                          '0x439fa90': 3, '0x4b399a0': 3, '0x22689f0': 3})
        self.assertIsNone(sites['0x22c54a0']['census']['pointer_slot'])
        self.assertEqual(sites['0x22689f0']['pointer_loads'], ['0x2269c63', '0x226a79b', '0x226a895'])

    def test_flow(self):
        fl = self.result['flow']
        self.assertEqual((fl['bound_reached_to_exhausted'], fl['failure_to_sleep'], fl['first_attempt']),
                         ('0x2268c9d', '0x2269bcc', '0x2269c51'))

    def test_packet_matches_regeneration(self):
        expected = json.loads(PACKET.read_text())
        got = dict(self.result, target_sha256=load()['sha256'])
        self.assertEqual(json.loads(json.dumps(got, sort_keys=True)), expected)

    def test_cli(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(hr.main([]), 0)
        self.assertIn('max(0xffffffffffffffff, 1) = 0xffffffffffffffff', out.getvalue())


@unittest.skipUnless(BINARY.exists(), 'pinned node #94 binary not present')
class Corruptions(unittest.TestCase):
    def refuses(self, data, pattern):
        with self.assertRaisesRegex(hr.EvidenceError, pattern):
            hr.analyse(data)

    def test_bound_constant(self):
        self.refuses(patched((0x2268c53 + 3, struct.pack('<i', 10))), 'init at 0x2268c15: bytes changed')

    def test_tries_field(self):
        self.refuses(patched((0x2268bb4 + 7, struct.pack('<i', 3))), 'record at 0x2268b78: bytes changed')

    def test_descriptor_text(self):
        self.refuses(patched((0x3d7953 + 4, b'X')), 'descriptor at 0x3d7953 changed')

    def test_tries_field_read_planted(self):
        site = hr.STARTUP_FDE + 0x100
        self.refuses(patched((site, bytes.fromhex('488b83b03b0000'))), r'\[rbx\+0x3bb0\] operands are')

    def test_record_pointer_read_planted(self):
        site = hr.STARTUP_FDE + 0x100
        self.refuses(patched((site, bytes.fromhex('488b83303c0000'))), r'\[rbx\+0x3c30\] operands are')

    def test_retry_template(self):
        self.refuses(patched((0x1f2256 + 35, b'X')), 'retry template head changed')

    def test_exhausted_template(self):
        self.refuses(patched((0x1ebd40 + 5, b'X')), 'exhausted template changed')

    def test_formatter_relocation(self):
        c = load()
        img = c['img']
        rela = next(s for s in img.secs if s['name'] == '.rela.dyn')
        data = bytearray(c['data'])
        for pos in range(rela['offset'], rela['offset'] + rela['size'], 24):
            where, info, _ = struct.unpack_from('<QQq', data, pos)
            if where == hr.NTRIES_FORMATTER_SLOT and info & 0xffffffff == 8:
                struct.pack_into('<q', data, pos + 16, 0x1570960)
        self.refuses(bytes(data), 'n_tries formatter slot resolves to')

    def test_sleep_skip_branch(self):
        self.refuses(patched((0x2269bde + 1, b'\x41')), 'sleep at 0x2269bcc: bytes changed')

    def test_rpc_connect_bound(self):
        self.refuses(patched((0x2039321 + 3, struct.pack('<i', 10))), '0x2039060 bound at 0x2039321: bytes changed')

    def test_rpc_connect_pointer_read_planted(self):
        self.refuses(patched((0x2039060 + 0x40, bytes.fromhex('488b83a8010000'))), r'0x2039060 \[rbx\+0x1a8\] operands are')


if __name__ == '__main__':
    unittest.main()
