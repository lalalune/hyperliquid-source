"""Controls for tools/firewall_mismatch_static.py (node #94 firewall/validator mismatch log gate in 0x4b28ff0)."""
import contextlib
import io
import json
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import firewall_mismatch_static as fm  # noqa: E402
from artifacts import check  # noqa: E402

BINARY = ROOT / fm.TARGET
PACKET = ROOT / 'research/work-items/firewall-mismatch-94/records.json'
CACHE = {}


def load():
    if not CACHE:
        identity = next(i for i in json.loads((ROOT / 'provenance/artifacts.json').read_text())['files']
                        if i['path'] == fm.TARGET)
        check(BINARY, identity)
        CACHE['data'] = BINARY.read_bytes()
        CACHE['img'] = fm.Image(CACHE['data'])
        CACHE['result'] = fm.analyse(CACHE['data'])
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
    def test_small_firewall_surplus_is_silent(self):
        for n in range(7):
            self.assertFalse(fm.logs(0, n))
        self.assertTrue(fm.logs(0, 7))

    def test_any_missing_validator_logs(self):
        self.assertTrue(fm.logs(1, 0))

    def test_throttle(self):
        self.assertTrue(fm.logs(1, 0, None, 60.0))
        self.assertFalse(fm.logs(1, 0, 60.0, 60.0))
        self.assertTrue(fm.logs(1, 0, 60.000001, 60.0))
        self.assertFalse(fm.logs(1, 0, float('nan'), 60.0))

    def test_elapsed_seconds(self):
        self.assertEqual(fm.elapsed_seconds(3, 250_000_999), 3.250000)
        self.assertEqual(fm.elapsed_seconds(0, 999), 0.0)
        self.assertEqual(fm.elapsed_seconds(-1, 500_000_000), -0.5)


@unittest.skipUnless(BINARY.exists(), 'pinned node #94 binary not present')
class Results(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = load()['result']

    def test_gate(self):
        self.assertEqual(self.result['gate']['skip'], 'len(abci_minus_firewall) == 0 and len(firewall_minus_abci) <= 6')

    def test_difference_order(self):
        d = self.result['difference']
        self.assertEqual((d['self_is'], d['other_is']), ('rsi', 'rdx'))
        self.assertTrue(d['firewall_minus_abci'].startswith('[rsp+0xb0] = [rsp+0x128] - [rsp+0x140]'))

    def test_log(self):
        log = self.result['log']
        self.assertTrue(log['location'].endswith('node/src/firewall_ips.rs:65:13'))
        self.assertEqual((log['first_byte'], log['template'][0][:8]), ('0x3c', 'firewall'))

    def test_level_gate(self):
        self.assertEqual(self.result['level_gate']['returns_early_for'], [1, 2, 15, 17])

    def test_caller(self):
        c = self.result['caller']
        self.assertEqual((c['call'], c['args']['r8']), ('0x45250d1', '[r13+0x18] (throttle state)'))
        self.assertTrue(c['result'].startswith('unused'))

    def test_packet_matches_regeneration(self):
        expected = json.loads(PACKET.read_text())
        got = dict(self.result, target_sha256=load()['sha256'])
        self.assertEqual(json.loads(json.dumps(got, sort_keys=True)), expected)

    def test_cli(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(fm.main([]), 0)
        self.assertIn('len(firewall_minus_abci) <= 6', out.getvalue())


@unittest.skipUnless(BINARY.exists(), 'pinned node #94 binary not present')
class Corruptions(unittest.TestCase):
    def refuses(self, data, pattern):
        with self.assertRaisesRegex(fm.EvidenceError, pattern):
            fm.analyse(data)

    def test_bound(self):
        self.refuses(patched((0x4b293e6, b'\x07')), 'body at 0x4b29098: bytes changed')

    def test_swapped_difference(self):
        self.refuses(patched((0x4b292fd, struct.pack('<I', 0x128)), (0x4b29305, struct.pack('<I', 0x140))),
                     'body at 0x4b29098: bytes changed')

    def test_tipping_shift(self):
        self.refuses(patched((0x44c202c, b'\x05')), 'tipping at 0x44c201e: bytes changed')

    def test_million(self):
        self.refuses(patched((0x20ae60, struct.pack('<d', 1e3))), 'elapsed divisor is 1000.0')

    def test_template(self):
        self.refuses(patched((0x1fa618 + 1, b'F')), 'template is')

    def test_location(self):
        self.refuses(patched((0x5738490 + 16, struct.pack('<I', 66))), 'Location is')

    def test_elapsed_slot(self):
        self.refuses(relative_edit(0x576e8c0, fm.ELAPSED + 1), 'elapsed_slot resolves to')

    def test_level_slot(self):
        self.refuses(relative_edit(0x576e928, fm.LEVEL_STATIC + 8), 'level_slot resolves to')

    def test_caller_rax_kept(self):
        self.refuses(patched((0x45250d6, bytes.fromhex('90' * 7))), 'caller at 0x452502e: bytes changed')

    def test_time_sub_template(self):
        self.refuses(patched((0x1f9cb6 + 1, b'X')), 'Time Sub template is')

    def test_raw_mdg_path(self):
        self.refuses(patched((0x216f6d + 0x2f, b'x')), 'elapsed path is')


if __name__ == '__main__':
    unittest.main()
