"""Controls for tools/connections_accept_loop_static.py (node #94 accept loops 0x22c0d30 / 0x22c15e0, poll 0x22c47a0)."""
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
import connections_accept_loop_static as al  # noqa: E402
from artifacts import check  # noqa: E402

BINARY = ROOT / al.TARGET
PACKET = ROOT / 'research/work-items/connections-accept-loop-94/records.json'
CACHE = {}


def load():
    if not CACHE:
        identity = next(i for i in json.loads((ROOT / 'provenance/artifacts.json').read_text())['files']
                        if i['path'] == al.TARGET)
        check(BINARY, identity)
        CACHE['data'] = BINARY.read_bytes()
        CACHE['img'] = al.Image(CACHE['data'])
        CACHE['result'] = al.analyse(CACHE['data'])
        CACHE['sha256'] = identity['sha256']
    return CACHE


def patched(*edits, data=None):
    c = load()
    data = bytearray(c['data'] if data is None else data)
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
    def test_accept_result(self):
        self.assertEqual(al.accept_result(), 0)
        self.assertEqual(al.accept_result('WouldBlock'), 3)
        self.assertEqual(al.accept_result('ConnectionAborted'), 2)
        self.assertEqual(al.accept_result(peer='v6'), 2)
        self.assertEqual(al.accept_result(registered=False), 2)

    def test_binary_survives_errors_lead_does_not(self):
        for tag in (2,):
            self.assertEqual(al.loop_step(tag), 'print-stdout-continue')
            self.assertEqual(al.lead_step(tag), 'return-err')
        for tag in (0, 1, 3):
            self.assertEqual(al.loop_step(tag), al.lead_step(tag))

    def test_ipv6_peer_is_an_accept_error(self):
        self.assertEqual(al.loop_step(al.accept_result(peer='v6')), 'print-stdout-continue')


@unittest.skipUnless(BINARY.exists(), 'pinned node #94 binary not present')
class Results(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = load()['result']

    def test_error_arm(self):
        e = self.result['error_arm']
        self.assertEqual(e['format'], '{} ERROR >>> {} @@ node failed to accept {} connection: {}\n\n')
        self.assertTrue(e['sink'].startswith('stdout'))
        self.assertIn('no return, no sleep', e['after'])

    def test_twins(self):
        t = self.result['twins']
        self.assertEqual((t['shift'], t['compared_bytes'], t['rel_operands']), ('0x8b0', 708, 34))
        self.assertIn('0x225e860 (validator)', t['only_difference'])

    def test_spawn_labels(self):
        labels = self.result['spawn_arm']['labels']
        self.assertEqual(labels[hex(al.SPAWN_V)], dict(label='validator', task='handle_stream_connection', flag=0))
        self.assertEqual(labels[hex(al.SPAWN_G)], dict(label='gossip', task='handle_stream_connection', flag=1))

    def test_kind(self):
        self.assertEqual(self.result['kind'], {'1': 'gossip', 'other': 'validator'})

    def test_accept(self):
        a = self.result['accept']
        self.assertIn('"ip not v4"', a['ipv6_peer'])
        self.assertTrue(a['listener_fd_minus_one'].endswith('poll_evented.rs:288:26'))
        self.assertEqual(a['pending'], 'tag 3')

    def test_callers(self):
        c = self.result['callers']
        self.assertEqual(c['accept_poll'], ['0x22c11e6', '0x22c1a96'])
        self.assertIn('0x22c14c6', c['spawn_validator'])
        self.assertIn('0x22c1d76', c['spawn_gossip'])

    def test_packet_matches_regeneration(self):
        expected = json.loads(PACKET.read_text())
        got = dict(self.result, target_sha256=load()['sha256'])
        self.assertEqual(json.loads(json.dumps(got, sort_keys=True)), expected)

    def test_cli(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(al.main([]), 0)
        self.assertIn('no return, no sleep', out.getvalue())


@unittest.skipUnless(BINARY.exists(), 'pinned node #94 binary not present')
class Corruptions(unittest.TestCase):
    def refuses(self, data, pattern):
        with self.assertRaisesRegex(al.EvidenceError, pattern):
            al.analyse(data)

    def test_error_arm_returns(self):
        self.refuses(patched((0x22c146e, bytes.fromhex('b001c39090'))), 'dispatch_a at 0x22c1337: bytes changed')

    def test_v4_gate_removed(self):
        self.refuses(patched((0x22c4eea, b'\xeb')), 'v4_check at 0x22c4e98: bytes changed')

    def test_kind_compare(self):
        self.refuses(patched((0x4b6f895, b'\x02')), 'kind_fmt at 0x4b6f890: bytes changed')

    def test_template(self):
        self.refuses(patched((al.TEMPLATE + 3, b'W')), 'template 0x1fb0d4 is')

    def test_ip_not_v4_text(self):
        self.refuses(patched((0x3d8342, b'IP')), 'string at 0x3d8342 changed')

    def test_jump_table(self):
        self.refuses(patched((al.JUMP_TABLE, struct.pack('<i', 0x22c4e13 - al.JUMP_TABLE))), 'io::Error repr table is')

    def test_panic_location(self):
        self.refuses(patched((al.PANIC_LOCATION + 16, struct.pack('<I', 289))), 'fd -1 panic Location is')

    def test_print_slot(self):
        self.refuses(rela_edit(0x576e968, 8, al.PRINT + 1), 'std print to stdout slot 0x576e968')

    def test_lazy_prefix_slot(self):
        self.refuses(rela_edit(al.LAZY_PREFIX, 8, 0x143ed41), 'lazy prefix initialiser slot')

    def test_close_symbol(self):
        memcpy = load()['img'].glob_dat[0x576dfe0]
        self.refuses(rela_edit(0x576e708, 6, memcpy), r'close\(2\) slot 0x576e708 holds memcpy')

    def test_twins_diverge(self):
        va = 0x22c1ce4 + 2
        data = patched((va, b'\x8d'))
        name, (fde, start, hexs) = 'dispatch_b', al.WINDOWS['dispatch_b']
        raw = bytearray.fromhex(hexs)
        raw[va - start] = 0x8d
        with mock.patch.dict(al.WINDOWS, {name: (fde, start, raw.hex())}):
            self.refuses(data, 'dispatch_a twins differ outside rel operands')

    def test_extra_accept_caller(self):
        pad = 0x22c15d9
        self.refuses(patched((pad, b'\xe8' + struct.pack('<i', al.ACCEPT - (pad + 5)))), 'callers of accept poll are')


if __name__ == '__main__':
    unittest.main()
