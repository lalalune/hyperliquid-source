import hashlib
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import action_wire_typed_data_115 as T  # noqa: E402

WORK = ROOT / 'research' / 'work-items' / 'action-wire-typed-data-structs-115'
DATA = T.TARGET.read_bytes()


class KeccakTests(unittest.TestCase):
    def test_known_vectors(self):
        self.assertEqual(T.keccak256(b'').hex(), 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470')
        self.assertEqual(T.keccak256(b'abc').hex(), '4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45')

    def test_multi_block_input(self):
        self.assertEqual(T.keccak256(b'a' * 200), T.keccak256(b'a' * 200))
        self.assertNotEqual(T.keccak256(b'a' * 136), T.keccak256(b'a' * 137))

    def test_transfer_event_topic(self):
        self.assertEqual(T.keccak256(b'Transfer(address,address,uint256)').hex(),
                         'ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef')


class ImageTests(unittest.TestCase):
    def test_wrong_digest_is_rejected(self):
        with self.assertRaises(T.Reject):
            T.build(DATA[:-1] + bytes([DATA[-1] ^ 1]))

    def test_nobits_sections_are_not_mapped(self):
        img = T.Image(DATA)
        self.assertTrue(all(s['type'] != 8 for s in img.secs))

    def test_read_outside_image_fails(self):
        with self.assertRaises(T.Unsupported):
            T.Image(DATA).read(0x10, 1)

    def test_patch_changes_read(self):
        img = T.Image(DATA)
        old = img.read(0x43d5840, 1)
        img.patch[0x43d5840] = old[0] ^ 0xff
        self.assertNotEqual(img.read(0x43d5840, 1), old)


class FunctionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.img = T.Image(DATA)
        cls.funcs = T.find_functions(DATA)

    def test_function_count_and_slots(self):
        self.assertEqual(len(self.funcs), 41)
        self.assertEqual(sorted(set(f[2] for f in self.funcs)), [0x6475948, 0x6488038])
        self.assertEqual(sum(1 for f in self.funcs if f[2] == 0x6475948), 1)

    def test_usd_send_spec(self):
        spec = T.spec_of(self.img, 0x43d3130)
        self.assertEqual(spec['name'], b'UsdSend')
        self.assertEqual([f[0] for f in spec['fields']], [b'hyperliquidChain', b'destination', b'amount', b'time'])
        text = T.encode_type(T.PREFIX + spec['name'], spec['fields'])
        self.assertEqual(text, b'HyperliquidTransaction:UsdSend(string hyperliquidChain,string destination,string amount,uint64 time)')

    def test_multisig_envelope_spec(self):
        spec = T.spec_of(self.img, 0x3bca050)
        self.assertEqual(spec['name'], b'SendMultiSig')
        self.assertEqual(spec['fields'][1], (b'multi_sig_action_hash', T.TAG_BASE + 7, 32))
        self.assertEqual(spec['fields'][2], (b'nonce', T.TAG_BASE + 3, 64))

    def test_alloc_failure_stops_before_constructor(self):
        outcome, events, sret, m = T.observe(self.img, 0x43d3130, 3, 'alloc-fail-0')
        self.assertEqual(outcome, 'alloc_error')
        self.assertEqual([e[0] for e in events], ['format_type_name', 'alloc', 'alloc_error'])
        self.assertIsNone(sret)

    def test_second_alloc_failure_is_not_reached(self):
        outcome, events, sret, m = T.observe(self.img, 0x43d3130, 3, 'alloc-fail-1')
        self.assertEqual(outcome, 'ok')
        self.assertEqual(sret[0], 0)

    def test_stack_garbage_does_not_change_result(self):
        a = T.observe(self.img, 0x44290c0, 1, 'ok')[:3]
        b = T.observe(self.img, 0x44290c0, 2, 'ok-shifted')[:3]
        self.assertEqual(a, b)

    def test_literal_scan_matches_run(self):
        text = [s for s in T.elf_index.sections(DATA) if s['name'] == '.text'][0]
        start, end = self.funcs[0][0], self.funcs[0][1]
        lits = T.static_literals(DATA, start, end, text)
        self.assertEqual([self.img.read(p, n) for p, n in lits], [b'multi_sig_action_hash', b'nonce'])

    def test_unknown_opcode_is_unsupported(self):
        with self.assertRaises(T.Unsupported):
            T.run_clean(self.img, 0x10)

    def test_type_word_table(self):
        self.assertEqual(T.solidity_type(T.TAG_BASE + 3, 32), 'uint32')
        self.assertEqual(T.solidity_type(T.TAG_BASE + 7, 32), 'bytes32')
        with self.assertRaises(T.Reject):
            T.solidity_type(T.TAG_BASE + 6, 0)


class ControlTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.img = T.Image(DATA)
        cls.spec = T.spec_of(cls.img, 0x43d3130)

    def test_clean_model_agrees(self):
        for variant in T.VARIANTS:
            self.assertTrue(T.agree(self.img, self.spec, 5, variant)[0], variant)

    def test_every_mutant_is_caught_on_usd_send(self):
        for mut in T.MUTANTS:
            if mut == 'bool-as-string':
                continue    # UsdSend has no bool; covered on a bool-bearing struct below
            self.assertTrue(T.caught(self.img, self.spec, mut), mut)

    def test_bool_mutant_on_bool_struct(self):
        spec = T.spec_of(self.img, 0x43d1c50)
        self.assertTrue(T.caught(self.img, spec, 'bool-as-string'))
        self.assertFalse(T.caught(self.img, spec))

    def test_byte_corruption_is_caught(self):
        sites = T.patch_sites(self.img, self.spec)
        self.assertEqual(sorted(sites), ['alloc', 'bits', 'count', 'len'])
        for kind, va in sites.items():
            old = self.img.read(va, 1)[0]
            self.img.patch[va] = old ^ 0x04
            try:
                self.assertTrue(T.caught(self.img, self.spec), kind)
            finally:
                del self.img.patch[va]
        self.assertFalse(T.caught(self.img, self.spec))

    def test_out_of_range_start_is_caught(self):
        fake = dict(self.spec)
        for addr in (0, 0x10, 0x7b97b8, 0x7fffffff):
            fake['start'] = addr
            self.assertTrue(T.caught(self.img, fake), addr)


class ArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = T.build(DATA)

    def test_all_cases_match(self):
        self.assertEqual(self.result['total'], self.result['matched'])
        self.assertGreaterEqual(self.result['total'], 10000)

    def test_all_negatives_detected(self):
        self.assertGreaterEqual(len(self.result['negatives']), 30)
        self.assertTrue(all(r[3] for r in self.result['negatives']))

    def test_committed_files_are_regenerated_exactly(self):
        for name, text in T.render(self.result, T.WORK_NAME).items():
            self.assertEqual((WORK / name).read_text(encoding='ascii'), text, name)

    def test_manifest_covers_every_file(self):
        listed = dict()
        for line in (WORK / 'MANIFEST.sha256').read_text().splitlines():
            digest, name = line.split('  ')
            listed[name] = digest
        files = sorted(p.name for p in WORK.iterdir() if p.name != 'MANIFEST.sha256')
        self.assertEqual(sorted(listed), files)
        for name, digest in listed.items():
            self.assertEqual(hashlib.sha256((WORK / name).read_bytes()).hexdigest(), digest, name)


if __name__ == '__main__':
    unittest.main()
