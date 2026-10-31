"""Controls for tools/abci_latency_sampler_static.py (node #94 ABCI latency sampler 0x3d22aa0 / 0x3d22920 / 0x3d22500)."""
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
import abci_latency_sampler_static as ls  # noqa: E402
from artifacts import check  # noqa: E402

BINARY = ROOT / ls.TARGET
PACKET = ROOT / 'research/work-items/abci-latency-sampler-94/records.json'
CACHE = {}


def load():
    if not CACHE:
        identity = next(i for i in json.loads((ROOT / 'provenance/artifacts.json').read_text())['files']
                        if i['path'] == ls.TARGET)
        check(BINARY, identity)
        CACHE['data'] = BINARY.read_bytes()
        CACHE['img'] = ls.Image(CACHE['data'])
        CACHE['result'] = ls.analyse(CACHE['data'])
        CACHE['facts'] = ls.facts(CACHE['img'])
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


class Elapsed(unittest.TestCase):
    def test_earlier_now_is_zero(self):
        self.assertEqual(ls.elapsed((10, 5, 0), (10, 6, 0)), 0.0)
        self.assertEqual(ls.elapsed((9, 86399, 999_999_999), (10, 0, 0)), 0.0)
        self.assertEqual(ls.elapsed((10, 5, 10), (10, 5, 11)), 0.0)

    def test_equal_is_zero(self):
        self.assertEqual(ls.elapsed((10, 5, 7), (10, 5, 7)), 0.0)

    def test_whole_microseconds(self):
        self.assertEqual(ls.elapsed((10, 6, 1999), (10, 5, 0)), 1.000001)
        self.assertEqual(ls.elapsed((10, 5, 999), (10, 5, 0)), 0.0)

    def test_nanos_borrow_and_days(self):
        self.assertEqual(ls.elapsed((11, 0, 0), (10, 86399, 500_000_000)), 0.5)


class Begin(unittest.TestCase):
    def test_first_begin_samples_only_backlog(self):
        s = ls.new_state()
        self.assertEqual(ls.begin(s, (10, 0, 0), True, (10, 120, 0)), [(0x260, 120.0)])
        self.assertEqual(s['last'], ((10, 0, 0), (10, 120, 0)))

    def test_block_duration_capped_backlog_not(self):
        s = ls.new_state()
        ls.begin(s, (10, 0, 0), False, (10, 100, 0))
        self.assertEqual(ls.begin(s, (10, 90, 0), True, (10, 200, 0)), [(0x000, 60.0), (0x260, 110.0)])

    def test_backwards_clock_samples_zero(self):
        s = ls.new_state()
        ls.begin(s, (10, 0, 0), False, (10, 100, 0))
        self.assertEqual(ls.begin(s, (10, 200, 0), True, (10, 50, 0)), [(0x000, 0.0), (0x260, 0.0)])


class Commit(unittest.TestCase):
    def started(self, **kw):
        s = ls.new_state(**kw)
        ls.begin(s, (10, 0, 0), False, (10, 100, 0))
        return s

    def test_no_begin(self):
        self.assertEqual(ls.commit(ls.new_state(), 1, (10, 5, 0)),
                         dict(samples=[], path=None, row=None, writer_calls=0))

    def test_row_apply_is_uncapped(self):
        out = ls.commit(self.started(day=10), 7, (10, 175, 0))
        self.assertEqual(out['samples'], [(0x4c0, 60.0)])
        self.assertEqual(out['row']['apply_duration'], 75.0)
        self.assertEqual(out['row']['height'], 7)

    def test_backwards_clock_still_writes(self):
        out = ls.commit(self.started(day=10), 7, (10, 50, 0))
        self.assertEqual(out['samples'], [(0x4c0, 0.0)])
        self.assertEqual(out['row']['apply_duration'], 0.0)

    def test_no_writer_returns_after_sample(self):
        s = self.started(writer=False)
        out = ls.commit(s, 7, (10, 101, 0))
        self.assertEqual((out['samples'], out['row'], out['writer_calls']), ([(0x4c0, 1.0)], None, 0))
        self.assertIsNone(s['last_commit'])

    def test_daily_rotation(self):
        s = self.started(day=9)
        self.assertEqual(ls.commit(s, 1, (10, 101, 0))['path'], 'root/10')
        self.assertIsNone(ls.commit(s, 2, (10, 102, 0))['path'])
        self.assertEqual(s['last_commit'], (10, 102, 0))

    def test_hourly_rotation(self):
        s = self.started(hourly=True, day=10, hour=0)
        self.assertIsNone(ls.commit(s, 1, (10, 3599, 0))['path'])
        self.assertEqual(ls.commit(s, 2, (10, 3600, 0))['path'], 'root/hourly/10/1')
        self.assertEqual(ls.commit(s, 3, (11, 3600, 0))['path'], 'root/hourly/11/1')

    def test_second_of_day_panics(self):
        with self.assertRaisesRegex(ValueError, 'base/src/hour.rs:12:13'):
            ls.commit(self.started(), 1, (10, 90000, 0))
        with self.assertRaisesRegex(ValueError, 'base/src/time.rs:62:44'):
            ls.commit(self.started(), 1, (10, 921600, 0))

    def test_panics_only_with_writer(self):
        self.assertEqual(ls.commit(self.started(writer=False), 1, (10, 921600, 0))['row'], None)

    def test_writer_calls(self):
        self.assertEqual(ls.commit(self.started(flush_flag=False), 1, (10, 101, 0), True)['writer_calls'], 1)
        self.assertEqual(ls.commit(self.started(flush_flag=True), 1, (10, 101, 0), False)['writer_calls'], 1)
        self.assertEqual(ls.commit(self.started(flush_flag=True), 1, (10, 101, 0), True)['writer_calls'], 2)


@unittest.skipUnless(BINARY.exists(), 'pinned node #94 binary not present')
class Results(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = load()['result']

    def test_ctor(self):
        c = self.result['ctor']
        self.assertEqual([(s['name'], s['constant'], s['esi']) for s in c['samplers']],
                         [('_block_duration', 1.0, 0), ('_backlog_from_node', 1.0, 1), ('_begin_block_to_commit', 0.06, 0)])
        self.assertEqual(c['arguments'], 'rdi out, rsi/rdx prefix, xmm0 f64')

    def test_templates(self):
        t = self.result['operands']['templates']
        self.assertEqual(t['0x1e938e'], dict(pieces=[None, '/', None], end='0x1e9393'))
        self.assertEqual(t['0x1e9393']['pieces'], [None, '/hourly/', None, '/', None])
        self.assertEqual(t['0x1f9cb6']['pieces'], ['Time Sub ', None, ' ', None])

    def test_locations(self):
        locs = self.result['operands']['locations']
        self.assertTrue(locs['0x57193a0'].endswith('net_utils/src/abci_latency_sampler.rs:67:48'))
        self.assertTrue(locs['0x5666dd8'].endswith('base/src/hour.rs:12:13'))

    def test_callsite_lines(self):
        self.assertEqual(self.result['begin']['callsite_lines'], dict(block_duration=54, backlog=58))

    def test_row(self):
        r = self.result['row']
        self.assertEqual(r['keys'], ['height', 'block_time', 'begin_block_wall_time', 'apply_duration'])
        self.assertEqual(r['offsets']['apply_duration'], 8)

    def test_callers(self):
        e = self.result['callers']['entry']
        self.assertEqual(e['0x3d22500']['calls'], {'0x4678b5f': '0x4677fd0', '0x474d4af': '0x474bfa0'})
        self.assertEqual(e['0x3d22aa0']['slot'], '0x5776560')

    def test_packet_matches_regeneration(self):
        expected = json.loads(PACKET.read_text())
        got = dict(self.result, target_sha256=load()['sha256'])
        self.assertEqual(json.loads(json.dumps(got, sort_keys=True)), expected)

    def test_cli(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(ls.main([]), 0)
        self.assertIn('raw elapsed (no cap)', out.getvalue())


@unittest.skipUnless(BINARY.exists(), 'pinned node #94 binary not present')
class Corruptions(unittest.TestCase):
    def refuses(self, data, pattern):
        with self.assertRaisesRegex(ls.EvidenceError, pattern):
            ls.analyse(data)

    def semantic(self, check, pattern, facts=None, operands=None):
        f = dict(load()['facts'])
        f.update(facts or {})
        with mock.patch.dict(ls.OPERANDS, operands or {}):
            with self.assertRaisesRegex(ls.EvidenceError, pattern):
                check(f)

    def test_commit_cap_removed(self):
        self.refuses(patched((0x3d225e5, b'\x90' * 4)), 'commit at 0x3d22500: bytes changed')

    def test_cap_constant(self):
        self.refuses(patched((0x20abf8, struct.pack('<d', 61.0))), 'f64 at 0x20abf8 is 61.0')

    def test_daily_template(self):
        self.refuses(patched((0x1e9390, b'-')), 'template 0x1e938e is')

    def test_record_location(self):
        self.refuses(patched((0x57193a0 + 16, struct.pack('<I', 68))), 'Location 0x57193a0 is')

    def test_hour_assert_text(self):
        self.refuses(patched((0x216f29 + 25, b'3')), 'string at 0x216f29 changed')

    def test_global_flag_slot(self):
        self.refuses(rela_edit(0x576ef18, 8, 0x5788313), 'global flag byte slot 0x576ef18')

    def test_entry_slot(self):
        self.refuses(rela_edit(0x5776550, 8, ls.COMMIT + 1), 'entry point slot 0x5776550')

    def test_extra_direct_caller(self):
        pad = 0x22c0d40
        self.refuses(patched((pad, b'\xe8' + struct.pack('<i', ls.BEGIN - (pad + 5)))), 'gained a direct call')

    def test_extra_indirect_caller(self):
        pad = 0x22c0d40
        self.refuses(patched((pad, b'\xff\x15' + struct.pack('<i', 0x5776558 - (pad + 6)))), '0x3d22920 is called from')

    def test_row_apply_source(self):
        self.semantic(ls.check_commit, 'row apply_duration is not the raw',
                      facts={0x3d22609: bytes.fromhex('f20f118424a0000000')})

    def test_writer_gate(self):
        self.semantic(ls.check_commit, 'first writer call is not gated', operands={0x3d2285b: (2, 0x3d22873)})

    def test_error_arm_nonzero(self):
        self.semantic(ls.check_elapsed, 'error arm no longer returns 0.0', facts={0x1447237: bytes.fromhex('660f57c9')})

    def test_ctor_constant(self):
        self.semantic(ls.check_ctor, 'samplers are', operands={0x3d22bb6: (8, 0x20a730)})

    def test_fact_outside_windows(self):
        with mock.patch.dict(ls.FACTS, {0x3d228d9: ('cc', 'padding')}):
            self.refuses(load()['data'], 'fact padding at 0x3d228d9 is outside every window')


if __name__ == '__main__':
    unittest.main()
