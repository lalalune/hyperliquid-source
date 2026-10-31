"""Controls for tools/lz4_stats_report_static.py (node #94 LZ4 stats report loops 0x3d21990 / 0x3d12780)."""
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
import lz4_stats_report_static as lz  # noqa: E402
from artifacts import check  # noqa: E402

BINARY = ROOT / lz.TARGET
PACKET = ROOT / 'research/work-items/lz4-stats-report-94/records.json'
CACHE = {}


def load():
    if not CACHE:
        identity = next(i for i in json.loads((ROOT / 'provenance/artifacts.json').read_text())['files']
                        if i['path'] == lz.TARGET)
        check(BINARY, identity)
        CACHE['data'] = BINARY.read_bytes()
        CACHE['img'] = lz.Image(CACHE['data'])
        CACHE['result'] = lz.analyse(CACHE['data'])
        CACHE['facts'] = lz.facts(CACHE['img'])
        CACHE['sha256'] = identity['sha256']
    return CACHE


def patched(*edits):
    c = load()
    data = bytearray(c['data'])
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


class Drain(unittest.TestCase):
    def test_totals_cover_both_directions(self):
        rows, totals = lz.drain([(0, 100, 40, 2), (1, 300, 90, 3)])
        self.assertEqual(totals, [400, 130, 5])
        self.assertEqual([r['tag'] for r in rows], [0, 1])
        self.assertEqual(lz.tick([(0, 100, 40, 2), (1, 300, 90, 3)])[1],
                         ('total', dict(input=400, samples=5, ratio=130 / 400)))

    def test_zero_input_entry_still_counts(self):
        rows, totals = lz.drain([(0, 0, 7, 1), (1, 10, 5, 1)])
        self.assertEqual(len(rows), 1)
        self.assertEqual(totals, [10, 12, 2])

    def test_tag_two_skipped_but_counted(self):
        rows, totals = lz.drain([(2, 10, 5, 1)])
        self.assertEqual((rows, totals), ([], [10, 5, 1]))
        self.assertEqual(lz.tick([(2, 10, 5, 1)]), [('total', dict(input=10, samples=1, ratio=0.5))])

    def test_row_fields(self):
        rows, _ = lz.drain([(1, 8, 2, 4)])
        self.assertEqual(rows, [dict(tag=1, input=8, samples=4, ratio=0.25)])

    def test_empty_tick(self):
        self.assertEqual(lz.tick([]), [])
        self.assertEqual(lz.tick([(0, 0, 0, 0)]), [])

    def test_overflow_order(self):
        with self.assertRaisesRegex(OverflowError, 'lz4_stats.rs:97:21'):
            lz.drain([(0, 1, 2 ** 64 - 1, 0), (0, 1, 1, 0)])
        with self.assertRaisesRegex(OverflowError, 'lz4_stats.rs:96:21'):
            lz.drain([(0, 2 ** 64 - 1, 2 ** 64 - 1, 0), (0, 1, 1, 0)])


class Append(unittest.TestCase):
    def state(self, **kw):
        s = dict(writer=True, hourly=False, day=None, hour=None, flush_flag=False, root='root', last=None)
        s.update(kw)
        return s

    def test_no_writer(self):
        s = self.state(writer=False)
        self.assertEqual(lz.append(s, (10, 921600, 0)), dict(path=None, written=False, helper_calls=0))

    def test_daily_and_hourly(self):
        s = self.state(day=9)
        self.assertEqual(lz.append(s, (10, 5, 0))['path'], 'root/10')
        self.assertIsNone(lz.append(s, (10, 6, 0))['path'])
        h = self.state(hourly=True, day=10, hour=0)
        self.assertEqual(lz.append(h, (10, 7200, 0))['path'], 'root/hourly/10/2')

    def test_helper_once(self):
        self.assertEqual(lz.append(self.state(flush_flag=True), (10, 5, 0), True)['helper_calls'], 1)
        self.assertEqual(lz.append(self.state(flush_flag=True), (10, 5, 0), False)['helper_calls'], 0)

    def test_panics(self):
        with self.assertRaisesRegex(ValueError, 'base/src/hour.rs:12:13'):
            lz.append(self.state(), (10, 90000, 0))


@unittest.skipUnless(BINARY.exists(), 'pinned node #94 binary not present')
class Results(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = load()['result']

    def test_loops(self):
        self.assertEqual(self.result['report']['loop']['totals'], ['0x8', '0x10', '0x18'])
        self.assertEqual(self.result['metrics']['totals'], ['0x80', '0x88', '0x90'])
        self.assertEqual(self.result['metrics']['period'], 300.0)

    def test_drain(self):
        d = self.result['drain']
        self.assertEqual(d['overflow'][2], 'net_utils/src/tcp/lz4_stats.rs:98:21')
        self.assertIn('then filter', d['order'])

    def test_writers(self):
        w = self.result['writers']
        self.assertEqual((w['rows']['serializer'], w['total']['serializer']), ('0x3d24610', '0x3d24130'))
        self.assertTrue(w['rows']['none'].startswith('free the rows'))

    def test_callers(self):
        c = self.result['callers']['direct']
        self.assertEqual(c['0x3d21990'], {'0x3d1323c': '0x3d12f20'})
        self.assertEqual(c['0x3d27940'], {'slot': '0x5786520'})

    def test_templates(self):
        t = self.result['operands']['templates']
        self.assertEqual(t['0x1e938e'], dict(pieces=[None, '/', None], end='0x1e9393'))

    def test_packet_matches_regeneration(self):
        expected = json.loads(PACKET.read_text())
        got = dict(self.result, target_sha256=load()['sha256'])
        self.assertEqual(json.loads(json.dumps(got, sort_keys=True)), expected)

    def test_cli(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(lz.main([]), 0)
        self.assertIn('every 300.0 s', out.getvalue())


@unittest.skipUnless(BINARY.exists(), 'pinned node #94 binary not present')
class Corruptions(unittest.TestCase):
    def refuses(self, data, pattern):
        with self.assertRaisesRegex(lz.EvidenceError, pattern):
            lz.analyse(data)

    def semantic(self, fn, pattern, facts=None, operands=None):
        f = dict(load()['facts'])
        f.update(facts or {})
        with mock.patch.dict(lz.OPERANDS, operands or {}):
            with self.assertRaisesRegex(lz.EvidenceError, pattern):
                fn(f)

    def test_period(self):
        self.refuses(patched((0x3d21c18, struct.pack('<d', 60.0))), 'report_loop at 0x3d21a6f: bytes changed')

    def test_filter_removed(self):
        self.refuses(patched((0x3d231ca, b'\x90\x90')), 'drain_entry at 0x3d23159: bytes changed')

    def test_template(self):
        self.refuses(patched((0x1e9396, b'H')), 'template 0x1e9393 is')

    def test_overflow_location(self):
        self.refuses(patched((0x57199c0 + 16, struct.pack('<I', 95))), 'Location 0x57199c0 is')

    def test_reporter_name(self):
        self.refuses(patched((0x5bd05b, b'udp')), 'string at 0x5bd05b changed')

    def test_conversion_constant(self):
        self.refuses(patched((0x202ea0, struct.pack('<d', 1.0))), 'f64 at 0x202ea0 is 1.0')

    def test_entry_slot(self):
        self.refuses(rela_edit(lz.ENTRY_SLOT, lz.ENTRY + 1), 'entry point slot 0x5786520')

    def test_extra_caller(self):
        pad = 0x22c0d40
        self.refuses(patched((pad, b'\xe8' + struct.pack('<i', lz.TOTAL_WRITER - (pad + 5)))), '0x3d1e500 is called from')

    def test_filter_target(self):
        self.semantic(lambda f: lz.check_drain(f), 'filter is not counter0',
                      operands={0x3d231ca: (2, 0x3d231cc)})

    def test_total_gate(self):
        self.semantic(lambda f: lz.check_loop(f, 'report'), 'total row is not total1 / total0',
                      operands={0x3d21b87: (2, 0x3d21b89)})

    def test_twin_totals(self):
        self.semantic(lambda f: lz.check_loop(f, 'metrics'), 'total at rsp\\+0x88 is not zeroed',
                      facts={0x3d12b42: bytes.fromhex('48c784248000000000000000')})

    def test_second_helper(self):
        with mock.patch.dict(lz.OPERANDS, {0x3d1e7cf: (6, 0x576eaa8)}):
            with self.assertRaisesRegex(lz.EvidenceError, 'panic blocks changed|writer helper is called from'):
                lz.check_writer(load()['facts'], 'total')

    def test_fact_outside_windows(self):
        with mock.patch.dict(lz.FACTS, {0x3d219fe: ('4989c7', 'unwind')}):
            self.refuses(load()['data'], 'fact unwind at 0x3d219fe is outside every window')


if __name__ == '__main__':
    unittest.main()
