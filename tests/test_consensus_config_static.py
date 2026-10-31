"""Controls for tools/consensus_config_static.py (node #94 node/consensus/config.rs validator and public-IP checks)."""
import contextlib
import io
import ipaddress
import json
import struct
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import consensus_config_static as cf  # noqa: E402
from artifacts import check  # noqa: E402

BINARY = ROOT / cf.TARGET
PACKET = ROOT / 'research/work-items/consensus-config-94/records.json'
PAD = 0x157b559  # seven int3 bytes between two const panic functions, outside every window
CACHE = {}

WALLET = 'w'
IP = ipaddress.IPv4Address('10.0.0.1')


def load():
    if not CACHE:
        identity = next(i for i in json.loads((ROOT / 'provenance/artifacts.json').read_text())['files']
                        if i['path'] == cf.TARGET)
        check(BINARY, identity)
        CACHE['data'] = BINARY.read_bytes()
        CACHE['img'] = cf.Image(CACHE['data'])
        CACHE['result'] = cf.analyse(CACHE['data'])
        CACHE['sha256'] = identity['sha256']
    return CACHE


def patched(*edits, data=None):
    c = load()
    data = bytearray(data or c['data'])
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


def rel32(va, length, target):
    return struct.pack('<i', target - (va + length))


@contextlib.contextmanager
def rewrite(va, new, length=None, target=None):
    """Patch window bytes and re-pin the window and operand tables, so only the semantic checks can object."""
    data = patched((va, new))
    name = cf.window_of(va)
    fde, start, hexs = cf.WINDOWS[name]
    raw = bytearray(bytes.fromhex(hexs))
    raw[va - start:va - start + len(new)] = new
    ops = {va: (length, target)} if length else {}
    with mock.patch.dict(cf.WINDOWS, {name: (fde, start, raw.hex())}), mock.patch.dict(cf.OPERANDS, ops):
        yield data


def run(**kw):
    args = dict(items=[(WALLET, 0, IP)], wallet=WALLET, second_set=set(), validate=True, public_ip='10.0.0.1',
                node_ips={WALLET: (0, IP)})
    args.update(kw)
    return cf.build(**args)


@unittest.skipUnless(BINARY.exists(), 'pinned node #94 binary not present')
class Models(unittest.TestCase):
    def test_ok(self):
        self.assertEqual(run(), dict(node_ip=(0, IP), log=None))

    def test_wallet_missing_is_30_17(self):
        with self.assertRaisesRegex(cf.Panic, 'running with wallet that is not a validator.*30:17'):
            run(items=[('other', 0, IP)])
        with self.assertRaisesRegex(cf.Panic, 'not a validator'):
            run(items=[])

    def test_last_match_wins(self):
        items = [(WALLET, 1, 7), (WALLET, 0, IP)]
        self.assertEqual(run(items=items)['node_ip'], (0, IP))
        with self.assertRaisesRegex(cf.Panic, r'abci_node_ip=LocalNode\(7\) @ 44:25'):
            run(items=list(reversed(items)))

    def test_local_node_tag_mismatches(self):
        with self.assertRaisesRegex(cf.Panic, r'public_ip=10.0.0.1 abci_node_ip=LocalNode\(1\)'):
            run(items=[(WALLET, 1, 1)])

    def test_validate_off_skips_ip(self):
        self.assertEqual(run(validate=False, public_ip='10.9.9.9')['log'], None)

    def test_parse_error_logs_and_continues(self):
        for text in ('10.0.0.1\n', '0000010.000.0.1', 'not-an-ip'):
            log = run(public_ip=text)['log']
            self.assertIn('invalid IPv4 address syntax', log)
            self.assertTrue(log.endswith('51:21'))

    def test_second_set_skips_compare_and_node_ips(self):
        self.assertEqual(run(second_set={WALLET}, public_ip='10.9.9.9', node_ips={})['log'], None)

    def test_node_ips_60_13(self):
        with self.assertRaisesRegex(cf.Panic, 'validator is not in node_ips.*60:13'):
            run(node_ips={})
        with self.assertRaisesRegex(cf.Panic, 'not in node_ips'):
            run(node_ips={WALLET: (2, 0)})
        self.assertEqual(run(node_ips={WALLET: (1, 3)})['log'], None)

    def test_lead_differs(self):
        with self.assertRaisesRegex(cf.Panic, '^validator is not in node_ips'):
            cf.lead_build([], WALLET, True, '10.0.0.1')
        with self.assertRaisesRegex(cf.Panic, r'abci_node_ip=Error\(1\)'):
            cf.lead_build([(WALLET, 1, 1)], WALLET, True, '10.0.0.1')
        self.assertEqual(cf.node_ip_debug(1, 1), 'LocalNode(1)')


@unittest.skipUnless(BINARY.exists(), 'pinned node #94 binary not present')
class Results(unittest.TestCase):
    def setUp(self):
        self.result = load()['result']

    def test_locations_and_census(self):
        self.assertEqual(sorted(self.result['strings']['locations'].values()),
                         ['30:17', '44:25', '51:21', '60:13', '71:32'])
        self.assertEqual(self.result['census']['references'],
                         {'0x284abd8': '44:25', '0x284ac96': '51:21', '0x284ae41': '71:32',
                          '0x284b07d': '30:17', '0x284b0da': '60:13'})

    def test_templates(self):
        t = self.result['strings']['templates']
        self.assertEqual(t['0x1dedcc'], '{}: running with wallet that is not a validator, address={}')
        self.assertEqual(t['0x20210b'], '{}: validator is not in node_ips: {}')
        self.assertEqual(self.result['strings']['prefix'], 'CONFIGURATION ERROR')

    def test_node_ip_debug(self):
        d = self.result['node_ip_debug']
        self.assertEqual((d['1']['name'], d['other']['name']), ('LocalNode', 'Ip'))

    def test_packet_matches_regeneration(self):
        expected = json.loads(PACKET.read_text())
        got = dict(self.result, target_sha256=load()['sha256'])
        self.assertEqual(json.loads(json.dumps(got, sort_keys=True)), expected)

    def test_cli(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(cf.main([]), 0)
        self.assertIn('node IP Debug: tag 1 = LocalNode, other = Ip', out.getvalue())


@unittest.skipUnless(BINARY.exists(), 'pinned node #94 binary not present')
class Corruption(unittest.TestCase):
    def rejects(self, data, pattern):
        with self.assertRaisesRegex(cf.EvidenceError, pattern):
            cf.analyse(data)

    def test_window_bytes(self):
        self.rejects(patched((0x284a5b1, b'\x90')), 'scan at 0x284a5a0: bytes changed')

    def test_first_match_exit(self):
        with rewrite(0x284a827, b'\xe9' + rel32(0x284a827, 5, 0x284a842), 5, 0x284a842) as data:
            self.rejects(data, '0x284a827 goes to 0x284a842, not 0x284a620|does not pin 0x284a620')

    def test_sentinel_tag(self):
        with rewrite(0x284a60b, bytes.fromhex('b103')) as data:
            self.rejects(data, '0x284a60b is not b102')

    def test_validate_offset(self):
        with rewrite(0x284a867, bytes.fromhex('410fb6aef3080000')) as data:
            self.rejects(data, '0x284a867 is not')

    def test_validate_branch(self):
        with rewrite(0x284aaae, b'\x0f\x84' + rel32(0x284aaae, 6, 0x284ab62), 6, 0x284ab62) as data:
            self.rejects(data, 'does not pin 0x284acca')

    def test_parse_length_limit(self):
        with rewrite(0x284ab08, bytes.fromhex('4883f910')) as data:
            self.rejects(data, '0x284ab08 is not 4883f90f')

    def test_tag_compare(self):
        with rewrite(0x284ab6a, bytes.fromhex('807c240301')) as data:
            self.rejects(data, '0x284ab6a is not')

    def test_second_set_branch(self):
        with rewrite(0x284ab64, b'\x0f\x85' + rel32(0x284ab64, 6, 0x284acb3), 6, 0x284acb3) as data:
            self.rejects(data, '0x284ab64 is not 0f84')

    def test_node_ips_tag(self):
        with rewrite(0x284adeb, bytes.fromhex('41807d0003')) as data:
            self.rejects(data, '0x284adeb is not')

    def test_debug_arm(self):
        with rewrite(0x284b673, bytes.fromhex('803f00')) as data:
            self.rejects(data, '0x284b673 is not 803f01')

    def test_handle_location(self):
        with rewrite(0x284ae41, b'\x48\x8d\x05' + rel32(0x284ae41, 7, cf.WALLET_PANIC), 7, cf.WALLET_PANIC) as data:
            self.rejects(data, 'Location references are|does not pin')

    def test_stray_location_reference(self):
        lea = b'\x48\x8d\x05' + rel32(PAD, 7, cf.NODE_IPS_PANIC)
        self.rejects(patched((PAD, lea)), r"config.rs Location references are .*'0x157b559'")

    def test_location_path(self):
        self.rejects(rela_edit(cf.HANDLE, cf.PATH_VA + 1), 'config.rs Locations are')

    def test_prefix(self):
        self.rejects(rela_edit(cf.PREFIX[0], cf.PREFIX[1] + 1), 'prefix str')

    def test_template_text(self):
        self.rejects(patched((0x1ebedd + 3, b'P')), 'template 0x1ebedd is')

    def test_variant_name(self):
        self.rejects(patched((0x3f482d, b'X')), 'variant name at 0x3f482d changed')

    def test_fetch_slot(self):
        self.rejects(rela_edit(0x576e948, 0x13ca371), 'slot 0x576e948 no longer holds 0x13ca370')

    def test_parse_error_text(self):
        ptr = load()['img'].relative[cf.PARSE_ERROR['ptrs'] + 8]
        self.rejects(patched((ptr + 8, b'X')), r'AddrParseError\(Ipv4\) text changed')

    def test_operand_outside_windows(self):
        with mock.patch.dict(cf.OPERANDS, {PAD: (7, 0)}):
            self.rejects(load()['data'], 'outside every window')


if __name__ == '__main__':
    unittest.main()
