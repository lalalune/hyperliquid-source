"""Controls for tools/firewall_update_cycle_static.py (node #94 firewall IP update cycle in 0x28f6960)."""
import contextlib
import io
import json
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import firewall_update_cycle_static as uc  # noqa: E402
from artifacts import check  # noqa: E402

BINARY = ROOT / uc.TARGET
PACKET = ROOT / 'research/work-items/firewall-update-cycle-94/records.json'
CACHE = {}


def load():
    if not CACHE:
        identity = next(i for i in json.loads((ROOT / 'provenance/artifacts.json').read_text())['files']
                        if i['path'] == uc.TARGET)
        check(BINARY, identity)
        CACHE['data'] = BINARY.read_bytes()
        CACHE['img'] = uc.Image(CACHE['data'])
        CACHE['result'] = uc.analyse(CACHE['data'])
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
    def test_changed(self):
        self.assertFalse(uc.changed(True, True, True))
        for args in ((False, True, True), (True, False, True), (True, True, False)):
            self.assertTrue(uc.changed(*args))

    def test_skip(self):
        self.assertEqual(uc.cycle(True, is_changed=True),
                         dict(maybe_update=False, compute=False, check=False, update=False, loader_flag=0))

    def test_throttle(self):
        self.assertTrue(uc.cycle(False)['maybe_update'])
        self.assertFalse(uc.cycle(False, True, 5.0, 5.0)['maybe_update'])
        self.assertTrue(uc.cycle(False, True, 5.5, 5.0)['maybe_update'])
        self.assertFalse(uc.cycle(False, True, float('nan'), 5.0)['maybe_update'])

    def test_check_runs_even_when_throttled(self):
        got = uc.cycle(False, True, 1.0, 5.0, is_changed=True)
        self.assertEqual((got['maybe_update'], got['check'], got['update']), (False, True, True))


@unittest.skipUnless(BINARY.exists(), 'pinned node #94 binary not present')
class Results(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = load()['result']

    def test_names(self):
        self.assertEqual(self.result['names'], {'maybe': 'firewall_ips_maybe_update', 'check': 'check_computed_ips',
                                                'update': 'update_computed_ips'})

    def test_slow(self):
        s = self.result['slow']
        self.assertEqual((s['threshold'], s['location'].rsplit('/', 1)[-1]), (3.0, 'once.rs:219:20'))

    def test_no_log(self):
        self.assertEqual(self.result['no_log']['hits'], [])

    def test_locks(self):
        s = self.result['sections']
        self.assertEqual((s['check_computed_ips']['lock'], s['update_computed_ips']['lock']),
                         ('read, +0x568 (+0x10)', 'write, +0x568 (0 -> 8)'))

    def test_packet_matches_regeneration(self):
        expected = json.loads(PACKET.read_text())
        got = dict(self.result, target_sha256=load()['sha256'])
        self.assertEqual(json.loads(json.dumps(got, sort_keys=True)), expected)

    def test_cli(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(uc.main([]), 0)
        self.assertIn('log calls in FDE: 0', out.getvalue())


@unittest.skipUnless(BINARY.exists(), 'pinned node #94 binary not present')
class Corruptions(unittest.TestCase):
    def refuses(self, data, pattern):
        with self.assertRaisesRegex(uc.EvidenceError, pattern):
            uc.analyse(data)

    def test_slow_constant(self):
        self.refuses(patched((0x20aab8, struct.pack('<d', 1.0))), 'slow threshold is')

    def test_skip_value(self):
        self.refuses(patched((0x28f6990, b'\x00')), 'entry at 0x28f6960: bytes changed')

    def test_update_gate(self):
        self.refuses(patched((0x28f6c2d, b'\x85')), 'sections at 0x28f6b31: bytes changed')

    def test_check_not(self):
        self.refuses(patched((0x27cdff3, b'\x00')), 'check_section at 0x27cdf00: bytes changed')

    def test_map_eq_length(self):
        self.refuses(patched((0x28a73cf, b'\x18')), 'map_eq at 0x28a73c0: bytes changed')

    def test_names(self):
        self.refuses(patched((0x3f6a88, b'C')), 'check_name is')

    def test_lazy_location(self):
        self.refuses(patched((0x5669f50 + 16, struct.pack('<I', 220))), 'lazy Location is')

    def test_compute_slot(self):
        self.refuses(relative_edit(0x5773b50, 0x45c42b0 + 1), 'compute_slot resolves to')

    def test_lazy_vtable(self):
        self.refuses(relative_edit(0x5669f80, uc.LAZY_INIT + 1), 'lazy vtable call resolves to')

    def test_planted_log_call(self):
        site = 0x28f72f9
        rel = struct.pack('<i', uc.LOG_EMIT - (site + 5))
        self.refuses(patched((site, b'\xe8' + rel)), r'log calls at \[.0x28f72f9.\]')


if __name__ == '__main__':
    unittest.main()
