"""Controls for tools/socket_calls_static.py (node #94 socket/setsockopt/listen/accept4 census)."""
import json
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import socket_calls_static as sc  # noqa: E402
from artifacts import check  # noqa: E402

BINARY = ROOT / sc.TARGET
PACKET = ROOT / 'research/work-items/transport-socket-calls-94/records.json'
CACHE = {}


def load():
    if not CACHE:
        identity = next(i for i in json.loads((ROOT / 'provenance/artifacts.json').read_text())['files']
                        if i['path'] == sc.TARGET)
        check(BINARY, identity)
        CACHE['data'] = BINARY.read_bytes()
        CACHE['img'] = sc.Image(CACHE['data'])
        CACHE['result'] = sc.analyse(CACHE['data'])
        CACHE['sha256'] = identity['sha256']
    return CACHE


@unittest.skipUnless(BINARY.exists(), 'pinned node #94 binary not present')
class Results(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = load()['result']

    def test_counts(self):
        self.assertEqual(self.result['call_counts'], sc.EXPECTED_CALLS)
        self.assertEqual(self.result['setsockopt_by_option'],
                         {'SO_KEEPALIVE': 2, 'SO_RCVBUF': 1, 'SO_REUSEADDR': 4, 'SO_SNDBUF': 1, 'TCP_KEEPCNT': 2,
                          'TCP_KEEPIDLE': 2, 'TCP_KEEPINTVL': 2, 'TCP_NODELAY': 4})

    def test_backlogs_and_accept4(self):
        self.assertEqual([(r['fde'], r['value']) for r in self.result['listen']], [('0x3cd6690', 1024), ('0x4ee12c0', 128)])
        self.assertEqual(self.result['accept4'][0]['value'], sc.SOCK_NONBLOCK | sc.SOCK_CLOEXEC)

    def test_socket_types(self):
        types = {r['call']: (r['nonblock'], r['cloexec'], r['protocol']) for r in self.result['socket']}
        self.assertEqual(types, {'0x29c333e': (False, True, 6), '0x3cd6353': (True, True, 0), '0x3cd66b3': (True, True, 0),
                                 '0x4ee12e4': (False, True, 0), '0x4ee134f': (False, True, 0)})

    def test_constant_one_options(self):
        ones = sorted(r['option'] for r in self.result['setsockopt'] if r['optval'] and r['optval']['constant'] == 1)
        self.assertEqual(ones, ['SO_KEEPALIVE', 'SO_KEEPALIVE', 'SO_REUSEADDR', 'SO_REUSEADDR', 'SO_REUSEADDR', 'SO_REUSEADDR'])

    def test_node_port_connect_chain(self):
        c = self.result['node_port_connect']
        self.assertEqual((c['helper'], c['socket_type']), ('0x3cd6330', '0x80801'))
        self.assertEqual([r['node_port_fde'] for r in c['callers']], ['0x2037ac0', '0x43831e0'])

    def test_node_port_listen_chain(self):
        c = self.result['node_port_listen']
        self.assertEqual([r['fde'] for r in c['node_port_calls']], ['0x22c54a0', '0x438ed70', '0x47b4950'])
        self.assertEqual((c['wrapper'], c['node_port_backlog']), ('0x4f78960', 1024))
        self.assertEqual(c['helpers']['0x4ee12c0']['caller_fde'], '0x29ae8f0')

    def test_packet_matches_regeneration(self):
        result = dict(load()['result'])
        result['target_sha256'] = load()['sha256']
        self.assertEqual(PACKET.read_text(), json.dumps(result, indent=2, sort_keys=True) + '\n')


@unittest.skipUnless(BINARY.exists(), 'pinned node #94 binary not present')
class CorruptionControls(unittest.TestCase):
    """Each control flips the bytes behind one claim; the analysis must refuse."""

    def mutated(self, va, new):
        c = load()
        data = bytearray(c['data'])
        off = c['img'].offset(va, len(new))
        data[off:off + len(new)] = new
        return bytes(data)

    def refuses(self, va, new, pattern):
        with self.assertRaisesRegex(sc.EvidenceError, pattern):
            sc.analyse(self.mutated(va, new))

    def test_unknown_option(self):
        self.refuses(0x29c3887 + 1, b'\x29', 'unexpected option')

    def test_optlen(self):
        self.refuses(0x4ecda20 + 2, b'\x08', 'arguments are not mov esi,L')

    def test_listen_backlog_load_removed(self):
        self.refuses(0x4ee13ce, b'\x90' * 5, 'listen 0x4ee13d3: constant argument')

    def test_socket_type(self):
        self.refuses(0x3cd634c + 1, b'\x02', 'socket 0x3cd6353: type')

    def test_injected_setsockopt_call(self):
        va = 0x3723000
        img = load()['img']
        slot = sc.libc_slot(img, 'setsockopt')
        self.refuses(va, b'\xff\x15' + struct.pack('<i', slot - (va + 6)), 'setsockopt: 19 call sites')

    def test_connect_helper_slot(self):
        img = load()['img']
        rela = next(s for s in img.secs if s['name'] == '.rela.dyn')
        for pos in range(rela['offset'], rela['offset'] + rela['size'], 24):
            where, info, addend = struct.unpack_from('<QQq', img.data, pos)
            if where == sc.CONNECT_HELPER_SLOT:
                data = bytearray(img.data)
                data[pos + 16:pos + 24] = struct.pack('<q', addend + 16)
                with self.assertRaisesRegex(sc.EvidenceError, 'connect helper slot relocation changed'):
                    sc.analyse(bytes(data))
                return
        self.fail('connect helper slot relocation not found')

    def test_node_port_call_retarget(self):
        self.refuses(0x2037d9b + 1, b'\x51', 'NodePort site call 0x2037d9b retargeted')

    def test_listen_wrapper_slot_retarget(self):
        self.refuses(0x4f78970 + 2, struct.pack('<i', 0x57751c8 - (0x4f78970 + 6)), 'listen helper slot 0x5776490: 0 callers|backlog-1024 helper')

    def test_injected_listen_wrapper_call(self):
        va = 0x3723000
        self.refuses(va, b'\xff\x15' + struct.pack('<i', sc.LISTEN_WRAPPER_SLOT - (va + 6)), 'listen wrapper callers')

    def test_injected_direct_listen_helper_call(self):
        va = 0x3723000
        self.refuses(va, b'\xe8' + struct.pack('<i', 0x4ee12c0 - (va + 5)), 'has direct callers')

    def test_truncated_elf(self):
        with self.assertRaises(ValueError):
            sc.analyse(load()['data'][:4096])


if __name__ == '__main__':
    unittest.main()
