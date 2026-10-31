"""Controls for tools/local_abci_gates_static.py (node #94 local abci_state startup gates)."""
import contextlib
import io
import json
import random
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import local_abci_gates_static as la  # noqa: E402
from artifacts import check  # noqa: E402

BINARY = ROOT / la.TARGET
PACKET = ROOT / 'research/work-items/local-abci-gates-94/records.json'
CACHE = {}
PLANT = 0x2268c80  # inside the startup FDE, outside every checked window


def load():
    if not CACHE:
        identity = next(i for i in json.loads((ROOT / 'provenance/artifacts.json').read_text())['files']
                        if i['path'] == la.TARGET)
        check(BINARY, identity)
        CACHE['data'] = BINARY.read_bytes()
        CACHE['img'] = la.Image(CACHE['data'])
        CACHE['result'] = la.analyse(CACHE['data'])
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
    def test_height_gate(self):
        self.assertTrue(la.too_far_behind(0, 20000))
        self.assertFalse(la.too_far_behind(1, 20000))
        self.assertTrue(la.too_far_behind(100, 20100))
        self.assertFalse(la.too_far_behind(2 ** 64 - 10, 2 ** 64 - 2))
        self.assertTrue(la.too_far_behind(2 ** 64 - 10, 2 ** 64 - 1))

    def test_day_division_truncates(self):
        rng = random.Random(94)
        values = [0, 1, 86399, 86400, -1, -86399, -86400, -86401, 2 ** 40, -(2 ** 40)]
        values += [rng.randrange(-(2 ** 47), 2 ** 47) for _ in range(2000)]
        for x in values:
            q = abs(x) // 86400
            want = (q if x >= 0 else -q) & 0xffffffff
            self.assertEqual(la.days_86400(x), want, x)

    def test_freshness_compare(self):
        self.assertTrue(la.freshness_panics((1, 2, 3), (1, 2, 4)))
        self.assertFalse(la.freshness_panics((1, 2, 3), (1, 2, 3)))
        self.assertFalse(la.freshness_panics((2, 0, 0), (1, 86399, 999)))

    def test_nanos_split_is_floor_divmod(self):
        rng = random.Random(94)
        values = [0, 1, -1, 999_999_999, -999_999_999, 10 ** 9, -(10 ** 9), 2 ** 63 - 1, -(2 ** 63)]
        values += [rng.randrange(-(2 ** 63), 2 ** 63) for _ in range(2000)]
        for n in values:
            self.assertEqual(la.nanos_split(n), divmod(n, 10 ** 9), n)

    def test_tolerance_nanos(self):
        self.assertEqual([la.nanos_split(la.tolerance_nanos(x)) for x in (540.0, 840.0, 0.5)],
                         [(540, 0), (840, 0), (0, 500_000_000)])
        self.assertEqual(la.tolerance_nanos(float('nan')), 0)
        self.assertEqual(la.tolerance_nanos(1e300), 2 ** 63 - 1)
        self.assertEqual(la.tolerance_nanos(-1e300), -(2 ** 63))

    def test_uses_local_state(self):
        self.assertTrue(la.uses_local_state((1, 540, 0), (1, 540, 0)))
        self.assertFalse(la.uses_local_state((1, 540, 0), (1, 540, 1)))
        self.assertTrue(la.uses_local_state((2, 0, 0), (1, 86399, 999)))

    def test_startup_outcome(self):
        self.assertEqual([la.startup_outcome(w) for w in (0, 7, 2 ** 63 - 1, 2 ** 63, 2 ** 63 + 1, 2 ** 63 + 2, 2 ** 63 + 3)],
                         ['node_ips', 'node_ips', 'node_ips', 'local_state', 'unobserved', 'no_local_state', 'pending'])

    def test_validator_node_ips(self):
        signers = {b'\x02' * 20, b'\x01' * 20, b'\x03' * 20, b'\x04' * 20}
        profiles = {b'\x03' * 20: (1, b'\x0a\x00\x00\x03'), b'\x01' * 20: (0, b'\x0a\x00\x00\x01'),
                    b'\x04' * 20: (2, b'\x00\x00\x00\x00'), b'\x09' * 20: (1, b'\x0a\x00\x00\x09')}
        self.assertEqual(la.validator_node_ips(signers, profiles),
                         [(0, b'\x0a\x00\x00\x01'), (1, b'\x0a\x00\x00\x03')])
        self.assertEqual(la.validator_node_ips(set(), profiles), [])

    def test_gossip_roots(self):
        five = [(0, b'\x0a\x00\x00\x01')]
        self.assertEqual([la.gossip_roots(five, 3, None), la.gossip_roots([], 3, 3), la.gossip_roots(None, 3, 3),
                          la.gossip_roots(None, 3, 2)], ['override', 'assert', 'file', 'assert_eq'])
        self.assertEqual([la.gossip_roots(None, c, None) for c in range(4)],
                         [None, ['54.95.235.126'], ['13.231.133.202', '54.249.160.165'], None])

    def test_collect_heights(self):
        replies = [('a', (2, (1, 5))), ('b', None), ('c', (3, (9, 9))), ('d', (2, None)), ('a', (2, (1, 7)))]
        self.assertEqual(la.collect_heights(replies), {'a': (1, 7)})
        got = la.collect_heights([('a', (2, (1, 5))), ('b', None)])
        self.assertIsNone(la.select_heights(list(got.values()), other_len=2))
        self.assertEqual(la.select_heights(list(got.values()), other_len=1), (1, 5))

    def test_select_heights(self):
        self.assertIsNone(la.select_heights([]))
        self.assertIsNone(la.select_heights([(5, 9)]))
        self.assertEqual(la.select_heights([(5, 9)], other_len=1), (5, 9))
        self.assertEqual(la.select_heights([(1, 100), (2, 3), (1, 200)]), (2, 3))
        self.assertEqual(la.select_heights([(4, 10), (4, 30), (4, 20)]), (4, 30))
        rng = random.Random(94)
        for _ in range(500):
            vals = [(rng.randrange(4), rng.randrange(4)) for _ in range(rng.randrange(2, 7))]
            self.assertEqual(la.select_heights(vals), max(vals))


@unittest.skipUnless(BINARY.exists(), 'pinned node #94 binary not present')
class Results(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = load()['result']

    def test_height_gate(self):
        g = self.result['height_gate']
        self.assertEqual((g['tolerance'], g['saturating'], g['ok_branch']), (20000, True, '0x226adb1'))
        self.assertEqual({k: (v['len'], v['text']) for k, v in g['messages'].items()},
                         {'too_far_behind': (30, 'local height is too far behind'),
                          'stale_hardfork': (35, 'local height is from stale hardfork')})

    def test_tolerance_log(self):
        t = self.result['tolerance_log']
        self.assertEqual((t['default'], t['hardfork'], t['join']), (540.0, 840.0, '0x2269164'))
        self.assertEqual(t['branches_into_join'], ['0x226901b', '0x226902e'])
        self.assertEqual((t['log_placeholders'], t['tolerance_arg_index']), (5, 2))

    def test_freshness(self):
        f = self.result['freshness']
        self.assertEqual((f['added_seconds'], f['message_seconds'], f['template_placeholders']), (600, 600.0, 2))
        self.assertEqual((f['location_file'], f['location_line'], f['location_column']),
                         ('/home/ubuntu/hl/code_Mainnet/node/src/hl_node.rs', 346, 9))
        self.assertEqual(f['slots']['panic'], ['0x576e098', '0x157b810'])

    def test_stale_gate(self):
        s = self.result['stale_gate']
        self.assertEqual((s['add_slot'], s['add_helper'], s['scale'], s['clock_slot']),
                         ('0x576efb8', '0x1459ca0', 1e9, '0x576e8a0'))
        self.assertEqual(s['helper_slots'], {'add_time': '0x576e8a8', 'add_days': '0x576e8b0'})
        self.assertEqual(s['helper_panic'], '`NaiveDateTime + TimeDelta` overflowed')
        self.assertEqual((s['flow']['third_field_below_now'], s['flow']['not_below_to_fresh'],
                          s['flow']['fresh_return'], s['flow']['stale_to_retry']),
                         ('0x22693c3', '0x22691fd', '0x226ad84', '0x2268b7f'))
        self.assertEqual(s['record_refs']['0x3c30'], ['0x2268c65', '0x2269c65', '0x226a79d', '0x226a897'])
        self.assertEqual(s['record_refs']['0x3b90'], ['0x2268b81', '0x2268b88'])

    def test_outcomes(self):
        o = self.result['outcomes']
        self.assertEqual(o['file'], '{}/hyperliquid_data/abci_state.rmp')
        self.assertEqual(o['niches'], {'local_state': '0x8000000000000000', 'no_local_state': '0x8000000000000002',
                                       'pending': '0x8000000000000003'})
        self.assertEqual((o['flow']['not_file_to_none'], o['flow']['read_err_to_none'], o['flow']['height_ok_to_pass'],
                          o['flow']['reject_drop_state']), ('0x2268db2', '0x2268db2', '0x226adb1', '0x225a3b0'))
        self.assertEqual(o['templates'], {'0x2268ae0': '0x1f2309', '0x226acb9': '0x1f402c', '0x226ae90': '0x1e97e3'})

    def test_consumers(self):
        c = self.result['consumers']
        self.assertEqual(c['names'], ['fresh', 'stale', 'missing'])
        self.assertEqual(c['direct_calls'], ['0x227a250', '0x22b4919'])
        self.assertEqual((c['flow']['a_not_fresh'], c['flow']['b_fresh'], c['flow']['b_missing_to_bootstrap'],
                          c['flow']['b_stale_to_bootstrap']), ('0x227a457', '0x22b4b48', '0x22b5047', '0x22b5047'))
        self.assertEqual(c['templates'], {'0x227a3d9': '0x1fa1bc', '0x22b5119': '0x1f4129'})

    def test_chain_static(self):
        c = self.result['chain_static']
        self.assertEqual(c['statics'], {1: '0x57861d8', 2: '0x57861f8', 3: '0x5786218'})
        self.assertEqual((c['chain0_panic'], c['packed_len'], c['location']),
                         ('invalid chain', '0x1b', '/home/ubuntu/hl/code_Mainnet/l1/src/chain_ext.rs:116:29'))

    def test_validator_ips(self):
        v = self.result['validator_ips']
        self.assertEqual((v['collect'], v['value_field'], v['skipped_tag'], v['element_bytes'], v['initial_capacity']),
                         ('0x3bacce0', '+0x4c (tag byte), +0x4d (4 bytes)', 2, 5, 4))
        self.assertEqual(len(v['facts']), len(la.LOOKUP_FACTS))

    def test_gossip_override(self):
        g = self.result['gossip_override']
        self.assertEqual(g['file'], 'override_gossip_config.json')
        self.assertEqual({k: [r['ip'] for r in v] for k, v in g['default_roots'].items()},
                         {1: ['54.95.235.126'], 2: ['13.231.133.202', '54.249.160.165']})
        self.assertEqual((g['chain_assert']['kind'], g['chain_assert']['location']),
                         (0, '/home/ubuntu/hl/code_Mainnet/node/src/gossip_config.rs:89:13'))
        self.assertEqual((g['no_file_arms'][0], g['no_file_arms'][3], g['callers_of_0x227a0e0']),
                         ('0x474224f', '0x474224f', ['0x226c860', '0x22b51b4']))

    def test_root_source(self):
        r = self.result['root_source']
        self.assertEqual((r['caller_a']['loader'], r['caller_a']['path'], r['caller_b']['path'], r['future_field']),
                         ('0x4741dc0', 'root node ips', 'validator node ips', '0x80'))
        self.assertEqual(r['loader_location'], '/home/ubuntu/hl/code_Mainnet/node/src/gossip_config.rs:90:13')

    def test_node_ips(self):
        n = self.result['node_ips']
        self.assertEqual(n['flow'], {'no_root_to_validator': '0x22695db', 'clone_call': '0x254e7b0',
                                     'unlock_wake': '0x22697e8', 'root_to_tail': '0x22696c8',
                                     'exhausted_exit': '0x226a945'})
        self.assertEqual(n['slots']['0x22695f1'], ['0x5773ad0', '0x3994ea0'])
        self.assertEqual({k: (v['template'], v['placeholders']) for k, v in n['templates'].items()},
                         {'0x2269511': ('0x1fc1a0', 3), '0x22696ab': ('0x1e65d2', 2)})
        self.assertEqual(n['clone_element_bytes'], 5)

    def test_status_log_fields(self):
        st = self.result['status_log']
        self.assertEqual(st['fields'], {'[rsp+0xd8]': 'local_height', '[rsp+0xc8]': 'initial_height',
                                        '[rsp+0xd0]': 'latest_height'})
        self.assertEqual(st['template'], '0x1ef6dd')

    def test_peer_queries(self):
        q = self.result['peer_queries']
        self.assertEqual((q['request_tag'], q['ok_reply_variant'], q['request_fde']), (2, 2, ['0x226bb20', '0x226c2c8']))
        self.assertEqual(q['variant_error']['text'], 'incorrect rpc response variant')
        self.assertEqual(q['templates'], {'0x2269de3': '0x1dd96c', '0x226a143': '0x1ebdb6',
                                          '0x226a3bf': '0x1ee557', '0x226a508': '0x1e7641'})
        self.assertEqual((q['flow']['insert_call'], q['flow']['next_peer'], q['flow']['insert_to_next']),
                         ('0x28523b0', '0x2269cd8', '0x226a403'))

    def test_height_selection(self):
        h = self.result['height_selection']
        self.assertEqual(h['error'], {'text': 'unable to find at least 2 valid rpc heights', 'len': 43,
                                      'pieces': {'0x0': '0x3d7964', '0x10': '0x3d7974', '0x1b': '0x3d797f'}})
        self.assertEqual((h['iterator_next'], h['retry_template'], h['retry_template_lea']),
                         ('0x27df4f0', '0x1f2256', '0x226a7eb'))
        self.assertEqual(h['branches'], {'len_gt_1_to_loop': '0x226a56c', 'len_0_to_error': '0x226a6d2',
                                         'single_other_not_1_to_error': '0x226a6d2', 'loop_back': '0x226a680',
                                         'ok_to_result': '0x226a719', 'ok_to_slots': '0x226a912',
                                         'error_retry_back': '0x2269bcc'})

    def test_callers(self):
        c = self.result['callers']
        self.assertEqual((c['direct_calls'], c['caller_fde'], c['caller_states_when_al_set']),
                         (['0x22aef61', '0x22affe7'], '0x22ae8a0', [10, 11]))
        self.assertEqual(c['state0_arm'], '0x2271d38')
        self.assertEqual(sorted(c['future_strings'].values()), ['check_reachability_firewall_ips', 'failed to load firewall ips'])

    def test_packet_matches_regeneration(self):
        expected = json.loads(PACKET.read_text())
        got = dict(self.result, target_sha256=load()['sha256'])
        self.assertEqual(json.loads(json.dumps(got, sort_keys=True)), expected)

    def test_cli(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(la.main([]), 0)
        self.assertIn('local_height.saturating_add(20000) <= latest_height', out.getvalue())


@unittest.skipUnless(BINARY.exists(), 'pinned node #94 binary not present')
class Corruptions(unittest.TestCase):
    def refuses(self, data, pattern):
        with self.assertRaisesRegex(la.EvidenceError, pattern):
            la.analyse(data)

    def test_gate_constant(self):
        self.refuses(patched((0x226ab20, struct.pack('<i', 200))), 'gate at 0x226ab0a: bytes changed')

    def test_gate_messages(self):
        self.refuses(patched((0x3d79b2, b'L')), 'too_far_behind message at 0x3d79b2')
        self.refuses(patched((0x3d798f, b'L')), 'stale_hardfork message at 0x3d798f')

    def test_tolerance_constants(self):
        self.refuses(patched((0x20a3d8, struct.pack('<d', 600.0))), 'tolerance constants are 600.0, 840.0')
        self.refuses(patched((0x20a230, struct.pack('<d', 600.0))), 'tolerance constants are 540.0, 600.0')

    def test_extra_branch_into_join(self):
        start = PLANT
        rel = 0x2269164 - (start + 6)
        self.refuses(patched((start, b'\x0f\x84' + struct.pack('<i', rel))), 'branches into join 0x2269164')

    def test_extra_slot_reference(self):
        self.refuses(patched((PLANT, b'\x48\x8b\x84\x24\xe0\x00\x00\x00')), r'\[rsp\+0xe0\] references')

    def test_log_template(self):
        self.refuses(patched((0x1f5428 + 20, b'X')), 'log template 0x1f5428 changed')

    def test_freshness_seconds(self):
        self.refuses(patched((0x2271d52 + 0x55, struct.pack('<I', 0x4e20))), 'freshness at 0x2271d52: bytes changed')

    def test_location_file(self):
        self.refuses(patched((0x1f40cf + 1, b'X')), 'Location file is')

    def test_panic_slot_relocation(self):
        c = load()
        img = c['img']
        rela = next(s for s in img.secs if s['name'] == '.rela.dyn')
        data = bytearray(c['data'])
        for pos in range(rela['offset'], rela['offset'] + rela['size'], 24):
            where, info, _ = struct.unpack_from('<QQq', data, pos)
            if where == 0x576e098 and info & 0xffffffff == 8:
                struct.pack_into('<q', data, pos + 16, 0x157b840)
        self.refuses(bytes(data), 'panic slot does not reach the panic shim')

    def test_extra_caller(self):
        site = PLANT
        self.refuses(patched((site, b'\xe8' + struct.pack('<i', la.FRESH_FDE - (site + 5)))),
                     r"direct calls to 0x2271d00: \['0x2268c80', '0x22aef61', '0x22affe7'\]")

    def test_state0_arm_moved(self):
        self.refuses(patched((la.POLL_TABLE, struct.pack('<i', 0x2272398 - la.POLL_TABLE))), 'state-0 arm is 0x2272398')

    def test_status_label_changed(self):
        self.refuses(patched((0x1ef6dd + 14 + 29, b'X')), r'placeholder 2 label .* is not a \[name: \] field')

    def test_status_argument_swapped(self):
        self.refuses(patched((0x226aa1e + 4, b'\xc8')), 'status_log at 0x226a974: bytes changed')

    def test_extra_height_slot_reference(self):
        self.refuses(patched((PLANT, b'\x48\x8b\x84\x24\xd0\x00\x00\x00')), r'\[rsp\+0xd0\] references')

    def test_template_text(self):
        self.refuses(patched((0x1ed195, b'U')), 'freshness template 0x1ed194 changed')

    def test_selection_compare_flipped(self):
        self.refuses(patched((0x226a69e, b'\x92')), 'select_guard_loop at 0x226a53f: bytes changed')

    def test_selection_error_text(self):
        self.refuses(patched((0x3d7980, b'X')), 'error string rebuilt as')

    def test_retry_template(self):
        self.refuses(patched((0x1f2256 + 5, b'X')), 'retry template at 0x1f2256 changed')

    def test_got_heights_template(self):
        self.refuses(patched((0x1e7641 + 20, b'X')), 'template at LEA 0x226a508 changed')

    def test_variant_error_text(self):
        self.refuses(patched((0x3d79f5, b'X')), 'variant error rebuilt as')

    def test_no_heights_template(self):
        self.refuses(patched((0x1ebdb6 + 20, b'X')), 'template at LEA 0x226a143 changed')

    def test_local_height_read_in_loop(self):
        self.refuses(patched((0x2269df8, bytes.fromhex('488b83b0000000'))), r'\[rbx\+0xb0\] operands in the query loop')

    def test_stale_gate_branch_flipped(self):
        self.refuses(patched((0x22691f7 + 1, b'\x83')), 'stale_gate at 0x2269171: bytes changed')

    def test_tolerance_scale(self):
        self.refuses(patched((0x20a220, struct.pack('<d', 1e6))), 'tolerance scale is 1000000.0')

    def test_helper_overflow_text(self):
        self.refuses(patched((0x21a01f + 5, b'X')), 'helper panic text at 0x21a01f changed')

    def test_extra_record_pointer_store(self):
        self.refuses(patched((PLANT, bytes.fromhex('4c89b3903b0000'))), r'\[rbx\+0x3b90\] operands')

    def test_extra_branch_into_return(self):
        self.refuses(patched((PLANT, b'\xe9' + struct.pack('<i', 0x226ad84 - (PLANT + 5)))),
                     'branches into the return block')

    def test_value_stride(self):
        self.refuses(patched((0x3bacda7, b'\x50')), 'validator_lookup at 0x3bacce0: bytes changed')

    def test_skipped_tag(self):
        self.refuses(patched((0x3bacd0e, b'\x01')), 'validator_lookup at 0x3bacce0: bytes changed')

    def test_caller_b_root_source(self):
        self.refuses(patched((0x22b48f4, b'\x01')), 'caller_b_none at 0x22b48cb: bytes changed')

    def test_gossip_loader_slot(self):
        c = load()
        img = c['img']
        rela = next(s for s in img.secs if s['name'] == '.rela.dyn')
        data = bytearray(c['data'])
        for pos in range(rela['offset'], rela['offset'] + rela['size'], 24):
            where, info, _ = struct.unpack_from('<QQq', data, pos)
            if where == 0x5773b80 and info & 0xffffffff == 8:
                struct.pack_into('<q', data, pos + 16, 0x4741dd0)
        self.refuses(bytes(data), 'caller_a loader slot 0x5773b80 changed')

    def test_override_test_flipped(self):
        self.refuses(patched((0x4741df5, b'\x80')), 'loader_entry at 0x4741dc0: bytes changed')

    def test_default_root_changed(self):
        self.refuses(patched((0x4742804, b'\xec')), 'loader_defaults at 0x47427e4: bytes changed')

    def test_chain_assert_location(self):
        self.refuses(patched((0x4742a0b + 3, struct.pack('<i', struct.unpack('<i', load()['img'].read(0x4742a0e, 4))[0] + 0x18))),
                     'loader_chain_assert at 0x4742a03: bytes changed')

    def test_override_file_name(self):
        self.refuses(patched((0x6fb65f, b'O')), 'override file name changed')

    def test_chain_panic_text(self):
        self.refuses(patched((0x58c1ca + 8, b'X')), 'chain 0 panic text at 0x58c1ca changed')

    def test_variant_name(self):
        self.refuses(patched((0x3d7947, b'S')), 'variant names are')

    def test_extra_caller_of_startup_future(self):
        self.refuses(patched((PLANT, b'\xe8' + struct.pack('<i', la.STARTUP_FDE - (PLANT + 5)))),
                     r"direct calls to 0x22689f0: \['0x2268c80', '0x227a250', '0x22b4919'\]")

    def test_file_stem(self):
        self.refuses(patched((0x3d73f8 + 4, b'X')), 'file stem at 0x569db40')

    def test_stale_template_text(self):
        self.refuses(patched((0x1f402c + 30, b'X')), 'outcome template at 0x226acb9')

    def test_is_file_mode(self):
        self.refuses(patched((0x144a777 - 3, b'\x40')), 'is_file at 0x144a710: bytes changed')

    def test_root_template_text(self):
        self.refuses(patched((0x1fc1a0 + 20, b'X')), 'node-ip template at 0x2269511')

    def test_validator_slot_relocation(self):
        c = load()
        img = c['img']
        rela = next(s for s in img.secs if s['name'] == '.rela.dyn')
        data = bytearray(c['data'])
        for pos in range(rela['offset'], rela['offset'] + rela['size'], 24):
            where, info, _ = struct.unpack_from('<QQq', data, pos)
            if where == 0x5773ad0 and info & 0xffffffff == 8:
                struct.pack_into('<q', data, pos + 16, 0x3994eb0)
        self.refuses(bytes(data), 'slot 0x5773ad0 reaches 0x3994eb0')

    def test_add_slot_relocation(self):
        c = load()
        img = c['img']
        rela = next(s for s in img.secs if s['name'] == '.rela.dyn')
        data = bytearray(c['data'])
        for pos in range(rela['offset'], rela['offset'] + rela['size'], 24):
            where, info, _ = struct.unpack_from('<QQq', data, pos)
            if where == 0x576efb8 and info & 0xffffffff == 8:
                struct.pack_into('<q', data, pos + 16, 0x1459cb0)
        self.refuses(bytes(data), 'tolerance add slot 0x576efb8 does not reach 0x1459ca0')

    def test_request_tag(self):
        self.refuses(patched((0x2269e57 + 7, b'\x03')), 'query_call at 0x2269e1a: bytes changed')


if __name__ == '__main__':
    unittest.main()
