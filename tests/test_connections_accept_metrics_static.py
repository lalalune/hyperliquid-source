"""Controls for tools/connections_accept_metrics_static.py (node #94 instrumented accept loops 0x203f3e0 / 0x2041c60)."""
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
import connections_accept_metrics_static as am  # noqa: E402
from artifacts import check  # noqa: E402

BINARY = ROOT / am.TARGET
PACKET = ROOT / 'research/work-items/connections-accept-metrics-94/records.json'
CACHE = {}


def load():
    if not CACHE:
        identity = next(i for i in json.loads((ROOT / 'provenance/artifacts.json').read_text())['files']
                        if i['path'] == am.TARGET)
        check(BINARY, identity)
        CACHE['data'] = BINARY.read_bytes()
        CACHE['img'] = am.Image(CACHE['data'])
        CACHE['result'] = am.analyse(CACHE['data'])
        CACHE['sha256'] = identity['sha256']
    return CACHE


def patched(*edits):
    c = load()
    data = bytearray(c['data'])
    for va, new in edits:
        off = c['img'].offset(va, len(new))
        data[off:off + len(new)] = new
    return bytes(data)


def rela_edit(slot, kind, new):
    """Rewrite the addend (RELATIVE) or symbol index (GLOB_DAT) of the .rela.dyn entry for `slot`."""
    c = load()
    rela = next(s for s in c['img'].secs if s['name'] == '.rela.dyn')
    data = bytearray(c['data'])
    for pos in range(rela['offset'], rela['offset'] + rela['size'], 24):
        where, info, _ = struct.unpack_from('<QQq', data, pos)
        if where == slot and info & 0xffffffff == kind:
            if kind == 8:
                struct.pack_into('<q', data, pos + 16, new)
            else:
                struct.pack_into('<Q', data, pos + 8, (new << 32) | kind)
            return bytes(data)
    raise AssertionError(f'no type {kind} entry at {slot:#x}')


class Models(unittest.TestCase):
    MS = 1_000_000

    def test_first_poll(self):
        inc, last = am.poll_metrics(True, 5 * self.MS, 0, 0, 5 * self.MS, 6 * self.MS, self.MS, 50 * self.MS)
        self.assertEqual(inc, {0x18: 1, 0x58: 5 * self.MS, 0x30: 1, 0x70: self.MS})
        self.assertEqual(last, 6 * self.MS)

    def test_idle_then_short_delay(self):
        inc, _ = am.poll_metrics(False, 30 * self.MS, 29 * self.MS, 10 * self.MS, 30 * self.MS, 31 * self.MS,
                                 2 * self.MS, 50 * self.MS)
        self.assertEqual((inc[0x20], inc[0x60]), (1, 19 * self.MS))
        self.assertEqual((inc[0x28], inc[0x68], inc[0x48], inc[0x80]), (1, self.MS, 1, self.MS))
        self.assertNotIn(0x40, inc)

    def test_delay_at_threshold_is_long(self):
        inc, _ = am.poll_metrics(False, 12, 10, 20, 12, 12, 2, 50)
        self.assertNotIn(0x20, inc)
        self.assertEqual((inc[0x40], inc[0x88]), (1, 2))

    def test_no_wake_no_schedule(self):
        inc, _ = am.poll_metrics(False, 100, 0, 50, 100, 100, 1, 1)
        self.assertEqual(set(inc), {0x30, 0x70})

    def test_slow_poll(self):
        inc, _ = am.poll_metrics(False, 0, 0, 0, 0, 50, 1, 50)
        self.assertEqual((inc[0x38], inc[0x78]), (1, 50))


@unittest.skipUnless(BINARY.exists(), 'pinned node #94 binary not present')
class Results(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = load()['result']

    def test_metrics(self):
        m = self.result['metrics']
        self.assertEqual(m['monitor'], '[[state]+0x30]')
        self.assertEqual(m['poll']['split']['below'], {'count': '0x30', 'ns': '0x70'})
        self.assertEqual(m['scheduled']['split']['at_or_above'], {'count': '0x40', 'ns': '0x88'})

    def test_locations(self):
        locs = self.result['operands']['locations']
        self.assertTrue(locs['0x5691708'].endswith('tokio-metrics-0.3.1/src/task.rs:2483:23'))
        self.assertTrue(locs['0x5692c80'].endswith('node/src/connections.rs:186:84'))

    def test_twins(self):
        t = self.result['twins']
        self.assertEqual((t['shift'], t['window_pairs'], t['compared_bytes'], t['rel_operands']),
                         ('0x2880', 8, 1777, 66))

    def test_error_arm(self):
        e = self.result['loop']['error']
        self.assertEqual(e['format'], '{} ERROR >>> {} @@ node failed to accept {} connection: {}\n\n')
        self.assertIn('no return, no sleep', e['after'])

    def test_accept(self):
        a = self.result['accept']
        self.assertIn('"ip not v4"', a['ipv6_peer'])
        self.assertTrue(a['listener_fd_minus_one'].endswith('poll_evented.rs:288:26'))

    def test_callers(self):
        c = self.result['callers']['accept_poll']
        self.assertEqual((c['0x203f3e0'], c['0x2041c60'], len(c['0x2032ae0'])), (['0x203fbac'], ['0x204242c'], 9))

    def test_packet_matches_regeneration(self):
        expected = json.loads(PACKET.read_text())
        got = dict(self.result, target_sha256=load()['sha256'])
        self.assertEqual(json.loads(json.dumps(got, sort_keys=True)), expected)

    def test_cli(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(am.main([]), 0)
        self.assertIn('monitor+0x90', out.getvalue())


@unittest.skipUnless(BINARY.exists(), 'pinned node #94 binary not present')
class Corruptions(unittest.TestCase):
    def refuses(self, data, pattern):
        with self.assertRaisesRegex(am.EvidenceError, pattern):
            am.analyse(data)

    def test_slow_threshold_offset(self):
        self.refuses(patched((0x203fd87, b'\x88')), 'pending_a at 0x203fc82: bytes changed')

    def test_counter_offset(self):
        self.refuses(patched((0x203f4b4, b'\x50')), 'entry_a at 0x203f3e0: bytes changed')

    def test_error_arm_returns(self):
        self.refuses(patched((0x203ff80, bytes.fromhex('b001c39090'))), 'dispatch_a at 0x203fe36: bytes changed')

    def test_v4_gate_removed(self):
        self.refuses(patched((0x204967c, b'\x90\xe9')), 'v4_check at 0x204962a: bytes changed')

    def test_template(self):
        self.refuses(patched((am.TEMPLATE + 3, b'W')), 'template 0x1fb0d4 is')

    def test_ip_not_v4_text(self):
        self.refuses(patched((0x3c4be5, b'IP')), 'string at 0x3c4be5 changed')

    def test_jump_table(self):
        self.refuses(patched((am.JUMP_TABLE, struct.pack('<i', 0x20495a5 - am.JUMP_TABLE))), 'io::Error repr table is')

    def test_metrics_location(self):
        self.refuses(patched((0x5691708 + 16, struct.pack('<I', 2484))), 'Location 0x5691708 is')

    def test_waker_vtable(self):
        self.refuses(rela_edit(am.WAKER_VTABLE + 8, 8, 0x219a6d1), 'waker vtable')

    def test_print_slot(self):
        self.refuses(rela_edit(0x576e968, 8, am.PRINT + 1), 'std print to stdout slot 0x576e968')

    def test_close_symbol(self):
        memcpy = load()['img'].glob_dat[0x576dfe0]
        self.refuses(rela_edit(0x576e708, 6, memcpy), r'close\(2\) slot 0x576e708 holds memcpy')

    def test_twins_diverge(self):
        va = 0x203fd87 + am.TWIN
        data = patched((va, b'\x88'))
        fde, start, hexs = am.WINDOWS['pending_b']
        raw = bytearray.fromhex(hexs)
        raw[va - start] = 0x88
        with mock.patch.dict(am.WINDOWS, {'pending_b': (fde, start, raw.hex())}):
            self.refuses(data, 'pending_a twins differ outside rel operands')

    def test_extra_accept_caller(self):
        pad = 0x22c0d40
        self.refuses(patched((pad, b'\xe8' + struct.pack('<i', am.ACCEPT - (pad + 5)))), 'accept poll callers live in')


if __name__ == '__main__':
    unittest.main()
