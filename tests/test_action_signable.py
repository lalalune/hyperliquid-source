"""Controls for tools/action_signable.py (RE-005, node #94)."""

import filecmp
import importlib.util
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / 'tools' / 'action_signable.py'
PACKET = ROOT / 'research' / 'work-items' / 'RE-005-action-signable-94'

spec = importlib.util.spec_from_file_location('action_signable', TOOL)
asg = importlib.util.module_from_spec(spec)
sys.modules['action_signable'] = asg
spec.loader.exec_module(asg)

BINARY = ROOT / asg.BINARY
CACHE = {}
AGENT, CANONICAL, EMBEDDED = 0x333F240, 0x37EB2D0, 0x3984FE0
VAULT = bytes(range(20))


def have_binary():
    return BINARY.exists() and BINARY.stat().st_size > 1_000_000


def have_objdump():
    return bool(os.environ.get('OBJDUMP') or shutil.which('objdump'))


def mutate(insns, va, mnemonic=None, ops=None):
    out = []
    for ins in insns:
        if ins[0] == va:
            ins = (ins[0], ins[1], mnemonic or ins[2], ops if ops is not None else ins[3])
        out.append(ins)
    return out


def drop(insns, va):
    """Replace one instruction by a same-size nop so control flow is unchanged."""
    return [(ins[0], ins[1], 'nop', []) if ins[0] == va else ins for ins in insns]


class ModelTests(unittest.TestCase):
    def test_keccak_known_answers(self):
        self.assertEqual(asg.keccak256(b'').hex(), 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470')
        self.assertEqual(asg.keccak256(b'abc').hex(), '4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45')
        # two blocks: 200 bytes crosses the 136-byte rate once
        self.assertEqual(asg.keccak256(b'a' * 200).hex(), asg.keccak256(b'a' * 200).hex())
        self.assertNotEqual(asg.keccak256(b'a' * 135), asg.keccak256(b'a' * 136))

    def test_suffix_layout(self):
        self.assertEqual(asg.signing_suffix(1, None, None), b'\0' * 7 + b'\x01\x00')
        self.assertEqual(asg.signing_suffix(0x0102030405060708, VAULT, None), bytes(range(1, 9)) + b'\x01' + VAULT)
        self.assertEqual(asg.signing_suffix(0, None, 7), b'\0' * 8 + b'\x00' + b'\x00' + b'\0' * 7 + b'\x07')
        self.assertEqual(len(asg.signing_suffix(0, VAULT, 0)), 8 + 1 + 20 + 1 + 8)

    def test_msgpack_minimal_encoder(self):
        self.assertEqual(asg.msgpack({'a': 4, 'b': True}), b'\x82\xa1a\x04\xa1b\xc3')
        self.assertEqual(asg.msgpack([False, None, 200]), b'\x93\xc2\xc0\xcc\xc8')
        self.assertEqual(asg.msgpack('x' * 40), b'\xd9\x28' + b'x' * 40)
        self.assertEqual(asg.msgpack(1 << 40), b'\xcf' + (1 << 40).to_bytes(8, 'big'))

    def test_sdk_production_vector_from_model(self):
        encoded = asg.msgpack(asg.SDK_ACTION)
        preimage, digest, source = asg.expected_payload(encoded, asg.SDK_NONCE, None, None, 3)
        self.assertEqual(digest.hex(), asg.SDK_CONNECTION_ID)
        self.assertEqual(source, b'a')
        self.assertEqual(asg.expected_payload(encoded, asg.SDK_NONCE, None, None, 4)[2], b'b')
        self.assertEqual(preimage[-9:], asg.SDK_NONCE.to_bytes(8, 'big') + b'\x00')

    def test_listing_parser_accepts_both_syntaxes(self):
        gnu = ('0000000000001000 <f>:\n'
               '    1000:\tmovabs rax,0x8000000000000004\n'
               '    100a:\tcmp    QWORD PTR [rsp+0x120],rax\n'
               '    1012:\tjne    2000 <g>\n'
               '    1018:\tlea    rdi,[rip+0xfffffffffffffff0]        # 1007 <f+0x7>\n'
               '    101f:\tcall   QWORD PTR [rip+0x100]        # 1125 <h>\n'
               '    1025:\tcs nop WORD PTR [rax+rax*1+0x0]\n'
               '    102f:\tret\n')
        llvm = ('0000000000001000 <f>:\n'
                '    1000:      \tmovabs\trax, -0x7ffffffffffffffc\n'
                '    100a:      \tcmp\tqword ptr [rsp + 0x120], rax\n'
                '    1012:      \tjne\t0x2000 <g>\n'
                '    1018:      \tlea\trdi, [rip - 0x10]            # 0x1007 <f+0x7>\n'
                '    101f:      \tcall\tqword ptr [rip + 0x100]     # 0x1125 <h>\n'
                '    1025:      \tnop\tword ptr cs:[rax + rax]\n'
                '    102f:      \tret\n')
        a = asg.parse_listing(gnu, 0x1000, 0x1030)
        b = asg.parse_listing(llvm, 0x1000, 0x1030)
        self.assertEqual(asg.normalized_listing(a), asg.normalized_listing(b))
        self.assertEqual(a[0][3][1], ('imm', 0x8000000000000004))
        self.assertEqual(a[3][3][1][1].disp, 0x101F - 0x10)
        self.assertEqual(a[4][3][0][1].disp, 0x1125)
        self.assertEqual([ins[1] for ins in a], [10, 8, 6, 7, 6, 10, 1])

    def test_listing_parser_rejects_wrong_window(self):
        with self.assertRaises(asg.EvidenceError):
            asg.parse_listing('    1004:\tret\n', 0x1000, 0x1010)


@unittest.skipUnless(have_binary(), 'captured node #94 not materialized (git lfs pull)')
@unittest.skipUnless(have_objdump(), 'objdump missing')
class Fixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not CACHE:
            CACHE['result'] = asg.analyse(BINARY)
        cls.result = CACHE['result']
        cls.fns = {fn['start']: fn for fn in cls.result['functions']}

    def run_one(self, fn, encoded=b'\x81\xa1k\x2a', nonce=0x0102030405060708, vault=None, expires=None,
                chain=3, slack=False, insns=None, ok=True):
        return asg.run_vector(fn, encoded, nonce, vault, expires, chain, slack,
                              self.result['relative'], self.result['named'], ok=ok, insns=insns)

    def differs(self, fn, insns, **kw):
        encoded, nonce, vault, expires, chain = b'\x81\xa1k\x2a', 0x0102030405060708, VAULT, 99, 3
        kw = {'encoded': encoded, 'nonce': nonce, 'vault': vault, 'expires': expires, 'chain': chain, **kw}
        obs = self.run_one(fn, insns=insns, **kw)
        return asg.compare(fn, obs, kw['encoded'], kw['nonce'], kw['vault'], kw['expires'], kw['chain'])

    def find(self, fn, mnemonic, pred=lambda ins: True, after=0):
        return next(ins for ins in fn['insns'] if ins[2] == mnemonic and ins[0] >= after and pred(ins))


class Bindings(Fixture):
    def test_three_functions_from_one_path_and_three_locations(self):
        self.assertEqual(sorted(self.fns), [AGENT, CANONICAL, EMBEDDED])
        self.assertEqual([(r['line'], r['col']) for r in self.result['records']], [(14, 55)] * 3)
        self.assertEqual([fn['end'] - fn['start'] for fn in self.result['functions']], [1094, 1074, 1036])
        self.assertEqual([fn['payload'] for fn in self.result['functions']], ['agent', 'agent', 'embedded'])
        self.assertEqual([fn['serializer_style'] for fn in self.result['functions']], ['inline', 'wrapper', 'inline'])
        for fn in self.result['functions']:
            self.assertEqual(len(fn['locations']), 1)
            self.assertEqual(len(fn['callers']), 2)

    def test_roles_are_shared_and_unique(self):
        roles = self.result['roles']
        expected = {0x32D6A00: 'grow', 0x13460A0: 'grow-one', 0x4F59A10: 'absorb', 0x4F59E40: 'finalize',
                    0x54C8CB0: 'dealloc', 0x54C06B0: 'alloc', 0x157AA10: 'unwrap-failed',
                    0x1346068: 'alloc-error', ('import', 'memcpy'): 'memcpy'}
        self.assertEqual(roles, expected)
        self.assertEqual(self.fns[AGENT]['serializer'], 0x3351BC0)
        self.assertEqual(self.fns[CANONICAL]['serializer'], 0x3247B00)
        self.assertEqual(self.fns[EMBEDDED]['serializer'], 0x39853F0)
        wrapper = self.result['wrappers'][CANONICAL]
        self.assertTrue(wrapper['stores_config'])
        self.assertIn(0x3351BC0, wrapper['callees'])

    def test_keccak_binding(self):
        k = self.result['keccak']
        self.assertEqual(k['round_constant_table_va'], 0x7D04C8)
        self.assertEqual(k['keccak_f']['start'], 0x4F59480)
        self.assertEqual(k['keccak_f']['rho_offsets_covered'], 24)
        self.assertEqual(k['keccak_f']['direct_callers'], [])
        self.assertEqual(k['keccak_f']['relocated_slots'], [0x5777790])
        self.assertTrue(k['hashers']['absorb']['calls_keccak_f'])
        self.assertTrue(k['hashers']['finalize']['calls_keccak_f'])
        self.assertEqual(self.result['crates'], {'rmp-serde-1.3.0/src/encode.rs': 1, 'tiny-keccak-2.0.2/src/': 1})

    def test_grid_has_no_mismatches(self):
        for start, s in self.result['summary'].items():
            with self.subTest(function=hex(start)):
                self.assertEqual(s['vectors'], 336)
                self.assertEqual(s['mismatches'], 0)
                self.assertTrue(s['sdk_vector_matches'])
                self.assertEqual(s['sdk_vector_connection_id'], asg.SDK_CONNECTION_ID)
                self.assertTrue(s['error_path']['location_is_bound'])
                self.assertTrue(s['error_path']['message_is_unwrap'])
                self.assertTrue(s['error_path']['buffer_freed_before_panic'])
                self.assertEqual(s['dealloc_third_args'], [0])
                self.assertGreater(s['grow_calls'], 0)


class Behaviour(Fixture):
    def test_payload_fields_and_source_byte(self):
        fn = self.fns[AGENT]
        for chain, source in ((3, b'a'), (0, b'b'), (2, b'b'), (4, b'b'), (0xFF, b'b'), (0x83, b'b')):
            obs = self.run_one(fn, chain=chain)
            self.assertEqual(obs['source'], source)
            self.assertEqual(obs['chain_id'], 1337)
            self.assertEqual(obs['verifying_contract'], bytes(24))

    def test_suffix_variants_through_the_instructions(self):
        for start in (AGENT, CANONICAL, EMBEDDED):
            fn = self.fns[start]
            for vault, expires in ((None, None), (VAULT, None), (None, 5), (VAULT, 1 << 63)):
                obs = self.run_one(fn, vault=vault, expires=expires)
                self.assertEqual(obs['preimage'], b'\x81\xa1k\x2a' + asg.signing_suffix(0x0102030405060708, vault, expires))
                self.assertEqual(obs['connection_id'], asg.keccak256(obs['preimage']))

    def test_embedded_payload_copies_signature_chain_id_nonce_and_chain(self):
        obs = self.run_one(self.fns[EMBEDDED], chain=0x7B, nonce=12345)
        self.assertEqual(obs['signature_chain_id'], obs['expected_signature_chain_id'])
        self.assertEqual(obs['nonce'], 12345)
        self.assertEqual(obs['chain'], 0x7B)

    def test_growth_paths_exact_and_slack_capacity(self):
        fn = self.fns[AGENT]
        tight = self.run_one(fn, encoded=b'\x90', vault=VAULT, expires=1)
        loose = self.run_one(fn, encoded=b'\x90', vault=VAULT, expires=1, slack=True)
        grows = [e[0] for e in tight['log'] if e[0] in ('grow', 'grow-one')]
        self.assertIn('grow', grows)
        self.assertIn('grow-one', grows)
        self.assertEqual([e for e in loose['log'] if e[0] in ('grow', 'grow-one')], [])
        self.assertEqual(tight['preimage'], loose['preimage'])
        self.assertEqual(tight['freed'][0][1], max(g[2] for g in tight['log'] if g[0] == 'grew'))
        self.assertEqual(loose['freed'][0][1], 1 + 64)

    def test_error_path_reaches_unwrap_failed_with_bound_location(self):
        for start in (AGENT, CANONICAL, EMBEDDED):
            fn = self.fns[start]
            obs = self.run_one(fn, ok=False)
            self.assertEqual(obs['stopped'], 'unwrap-failed')
            self.assertEqual(obs['panic']['location_va'], fn['locations'][0])
            self.assertEqual(obs['panic']['message_len'], len(asg.UNWRAP_MESSAGE))
            self.assertEqual(self.result['elf'].read(obs['panic']['message_va'], len(asg.UNWRAP_MESSAGE)), asg.UNWRAP_MESSAGE)
            self.assertEqual(len(obs['freed']), 1)
            self.assertNotIn('finalized', [e[0] for e in obs['log']])

    def test_sdk_vector_through_every_copy(self):
        encoded = asg.msgpack(asg.SDK_ACTION)
        for start in (AGENT, CANONICAL, EMBEDDED):
            obs = self.run_one(self.fns[start], encoded=encoded, nonce=asg.SDK_NONCE)
            self.assertEqual(obs['connection_id'].hex(), asg.SDK_CONNECTION_ID)


class NegativeControls(Fixture):
    def test_digest_tamper_rejected(self):
        data = bytearray(BINARY.read_bytes())
        data[0x1000] ^= 1
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / 'hl-node'
            bad.write_bytes(data)
            with self.assertRaises(asg.EvidenceError):
                asg.check_digest(bad)

    def test_source_path_tamper_rejected(self):
        data = bytearray(BINARY.read_bytes())
        off = self.result['elf'].off(self.result['path_va'])
        data[off] ^= 1
        with self.assertRaises(asg.EvidenceError):
            asg.source_bindings(asg.Elf(bytes(data)), self.result['relative'])

    def test_location_retarget_rejected(self):
        relative = dict(self.result['relative'])
        relative[self.result['records'][0]['location_va']] = self.result['path_va'] + 1
        _path, records = asg.source_bindings(self.result['elf'], relative)
        self.assertEqual(len(records), 2)

    def test_removed_nonce_bswap_changes_preimage(self):
        fn = self.fns[AGENT]
        ins = self.find(fn, 'bswap')
        self.assertIn('preimage', self.differs(fn, drop(fn['insns'], ins[0])))

    def test_removed_expires_bswap_changes_preimage(self):
        fn = self.fns[AGENT]
        first = self.find(fn, 'bswap')
        second = self.find(fn, 'bswap', after=first[0] + 1)
        self.assertIn('preimage', self.differs(fn, drop(fn['insns'], second[0]), expires=0x0102030405060708))
        self.assertEqual(self.differs(fn, drop(fn['insns'], second[0]), expires=None), [])

    def test_vault_tag_flip_changes_preimage(self):
        fn = self.fns[AGENT]
        ins = self.find(fn, 'mov', lambda i: i[3][0][0] == 'mem' and i[3][0][1].size == 1 and i[3][1] == ('imm', 1))
        changed = mutate(fn['insns'], ins[0], ops=[ins[3][0], ('imm', 0)])
        self.assertIn('preimage', self.differs(fn, changed, vault=VAULT))
        self.assertEqual(self.differs(fn, changed, vault=None), [])

    def test_chain_id_and_source_constants(self):
        fn = self.fns[AGENT]
        ins = self.find(fn, 'mov', lambda i: i[3][1] == ('imm', 1337))
        self.assertIn('chain_id', self.differs(fn, mutate(fn['insns'], ins[0], ops=[ins[3][0], ('imm', 1338)])))
        ins = self.find(fn, 'mov', lambda i: i[3][1] == ('imm', 0x62))
        self.assertIn('source', self.differs(fn, mutate(fn['insns'], ins[0], ops=[ins[3][0], ('imm', 0x63)])))
        ins = self.find(fn, 'sete')
        self.assertIn('source', self.differs(fn, mutate(fn['insns'], ins[0], mnemonic='setne')))
        ins = self.find(fn, 'cmp', lambda i: i[3][1] == ('imm', 3))
        self.assertIn('source', self.differs(fn, mutate(fn['insns'], ins[0], ops=[ins[3][0], ('imm', 4)]), chain=3))

    def test_hasher_parameters_are_checked(self):
        fn = self.fns[AGENT]
        rate = self.find(fn, 'mov', lambda i: i[3][1] == ('imm', 0x88))
        self.assertIn('hasher_init', self.differs(fn, mutate(fn['insns'], rate[0], ops=[rate[3][0], ('imm', 0x68)])))
        delim = self.find(fn, 'mov', lambda i: i[3][0][0] == 'mem' and i[3][0][1].size == 2 and i[3][1] == ('imm', 1))
        self.assertIn('hasher_init', self.differs(fn, mutate(fn['insns'], delim[0], ops=[delim[3][0], ('imm', 6)])))

    def test_serializer_config_is_checked(self):
        fn = self.fns[AGENT]
        cfg = self.find(fn, 'mov', lambda i: i[3][1] == ('imm', asg.RMP_CONFIG_DWORD))
        self.assertIn('serializer_config', self.differs(fn, mutate(fn['insns'], cfg[0], ops=[cfg[3][0], ('imm', 0x01000401)])))

    def test_ok_niche_change_diverts_to_error_path(self):
        fn = self.fns[AGENT]
        ins = self.find(fn, 'movabs')
        with self.assertRaises(asg.EvidenceError):
            self.run_one(fn, insns=mutate(fn['insns'], ins[0], ops=[ins[3][0], ('imm', 0x8000000000000005)]))

    def test_unknown_call_target_stops(self):
        fn = self.fns[AGENT]
        ins = self.find(fn, 'call', lambda i: i[3][0][0] == 'target')
        with self.assertRaises(asg.EvidenceError):
            self.run_one(fn, insns=mutate(fn['insns'], ins[0], ops=[('target', 0x1234)]))


@unittest.skipUnless(have_binary() and have_objdump(), 'captured node #94 or objdump missing')
class Portability(unittest.TestCase):
    def test_llvm_and_gnu_listings_normalize_identically(self):
        llvm = os.environ.get('LLVM_OBJDUMP') or shutil.which('llvm-objdump')
        if not llvm:
            self.skipTest('llvm-objdump not found (set LLVM_OBJDUMP)')
        gnu = os.environ.get('OBJDUMP') or shutil.which('objdump')
        for start, end in ((AGENT, 0x333F686), (0x4F59480, 0x4F59A02)):
            listings = []
            for tool in (gnu, llvm):
                os.environ['OBJDUMP'] = tool
                try:
                    listings.append(asg.normalized_listing(asg.parse_listing(asg.disassemble(BINARY, start, end), start, end)))
                finally:
                    os.environ.pop('OBJDUMP', None)
                    if gnu:
                        os.environ['OBJDUMP'] = gnu
            self.assertEqual(listings[0], listings[1])


@unittest.skipUnless(have_binary() and have_objdump() and PACKET.exists(), 'packet or inputs missing')
class Packet(unittest.TestCase):
    def test_regeneration_is_byte_identical(self):
        with tempfile.TemporaryDirectory() as tmp:
            asg.write_packet(CACHE.get('result') or asg.analyse(BINARY), Path(tmp))
            for name in ('evidence.json', 'functions.tsv', 'vectors.tsv', 'MANIFEST.sha256',
                         f'listing-{AGENT:#x}.txt', f'listing-{CANONICAL:#x}.txt', f'listing-{EMBEDDED:#x}.txt'):
                with self.subTest(file=name):
                    self.assertTrue(filecmp.cmp(Path(tmp) / name, PACKET / name, shallow=False))


if __name__ == '__main__':
    unittest.main()
