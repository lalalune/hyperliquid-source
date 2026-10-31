import hashlib
import json
import math
import mmap
from pathlib import Path
import random
import struct
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import state_dump_result_projection_static as result

BINARY = ROOT / 'artifacts/node/94/hl-node'
PACKET = ROOT / 'research/work-items/RE-009-state-dump-result-projection-94'


def compose(opaque, second, component, operands):
    """Only the source-derived DWORD stores and actual consumer permutation."""
    source = bytearray(b'\xcc' * 16)
    for offset, value in zip(operands['output_offsets'], (opaque, second, component)):
        struct.pack_into('<I', source, offset, value)
    p = operands['consumer']; out = bytearray(16); base = p['tag_store']
    struct.pack_into('<I', out, 0, p['tag'])
    out[p['first_store'] - base:p['first_store'] - base + 4] = source[p['first_load']:p['first_load'] + 4]
    out[p['pair_store'] - base:p['pair_store'] - base + 8] = source[p['pair_load']:p['pair_load'] + 8]
    return source, out


class ProjectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.stream = BINARY.open('rb'); cls.data = mmap.mmap(cls.stream.fileno(), 0, access=mmap.ACCESS_READ)
        result.authenticate(cls.data); cls.secs = result.sections(cls.data)
        _, cls.body = result.read_va(cls.data, cls.secs, result.START, result.END - result.START)
        _, cls.consumer = result.read_va(cls.data, cls.secs, result.USE_START, result.USE_END - result.USE_START)
        cls.record = result.inspect(cls.data); cls.p = cls.record['operands']

    @classmethod
    def tearDownClass(cls):
        cls.data.close(); cls.stream.close()

    def local_reject(self, va, replacement):
        offset, _ = result.read_va(self.data, self.secs, va, len(replacement))
        with mmap.mmap(self.stream.fileno(), 0, access=mmap.ACCESS_COPY) as changed:
            changed[offset:offset + len(replacement)] = replacement
            with self.assertRaises(ValueError): result.inspect(changed)

    def test_source_derived_proof_closes_the_entire_signed_domain(self):
        p = self.p; proof = result.prove(p); k = 64 + p['high_shift']
        self.assertEqual((p['divisor'], k, proof['delta']), (86400, 77, 12928))
        self.assertEqual(p['multiplier'] * p['divisor'], (1 << k) + proof['delta'])
        self.assertLess((1 << 63) * proof['delta'], 1 << k)
        self.assertEqual(math.gcd(p['multiplier'], 1 << k), 1)
        self.assertLess(1 << 63, 1 << k)
        self.assertEqual(proof['domain'], {'min': -(1 << 63), 'max': (1 << 63) - 1})
        self.assertIn('not divisible', proof['negative_lemma'])
        self.assertIn('signed64', proof['product_lemma'])
        self.assertEqual(proof['second_field_identity'], 's mod D (Euclidean)')

    def test_signed_endpoints_exact_multiples_and_neighbours_support_proof(self):
        d = self.p['divisor']; values = {result.MIN64, result.MAX64, -1, 0, 1}
        for q in (-106751991167300, -2148202811, -2, -1, 0, 1, 2, 2146764484, 106751991167300):
            values.update(q * d + r for r in (-1, 0, 1, d - 1) if result.MIN64 <= q * d + r <= result.MAX64)
        rng = random.Random(947)
        values.update(rng.randrange(result.MIN64, result.MAX64 + 1) for _ in range(2000))
        for s in values:
            actual = result.projection(s, self.p); floor, rem = divmod(s, d)
            trunc = (abs(s) // d) * (-1 if s < 0 else 1)
            self.assertEqual((actual['truncating_quotient'], actual['floor_quotient'], actual['second_field']), (trunc, floor, rem), s)
            self.assertTrue(result.MIN64 <= trunc * d <= result.MAX64)
        for s in (result.MIN64 - 1, result.MAX64 + 1):
            with self.assertRaises(ValueError): result.projection(s, self.p)

    def test_source_derived_index_guard_signed32_boundary(self):
        d, offset = self.p['divisor'], self.p['index_offset']
        low, high = -(1 << 31) - offset, (1 << 31) - 1 - offset
        for q in (low - 1, low, low + 1, high - 1, high, high + 1):
            for r in (0, d - 1):
                s = q * d + r; actual = result.projection(s, self.p)
                expected = -(1 << 31) <= s // d + offset < (1 << 31)
                self.assertEqual(actual['index_guard'], expected)
                if expected: self.assertEqual(actual['index_argument'], (s // d + offset) & result.MASK32)

    def test_three_writes_feed_the_actual_consumer_permutation(self):
        second = result.projection(-1, self.p)['second_field']
        source, consumer = compose(0x12345678, second, 0x89abcdef, self.p)
        self.assertEqual(struct.unpack('<III', source[:12]), (0x12345678, 86399, 0x89abcdef))
        self.assertEqual(source[12:], b'\xcc' * 4)
        self.assertEqual(struct.unpack('<IIII', consumer), (1, 86399, 0x89abcdef, 0x12345678))

    def test_actual_M_minus_one_shift_and_sign_mutations_change_field_before_rejection(self):
        controls = [(0x151cbf1, struct.pack('<Q', self.p['multiplier'] - 1), 86400),
                    (0x151cc09, b'\x0c', 2 * 86400),
                    (0x151cc05, b'\x3e', -86400)]
        for va, replacement, s in controls:
            with self.subTest(va=hex(va), s=s):
                body = bytearray(self.body); body[va - result.START:va - result.START + len(replacement)] = replacement
                changed = result.extract(body, self.consumer)
                self.assertNotEqual(result.projection(s, changed)['second_field'], s % 86400)
                with self.assertRaises(ValueError): result.validate(changed)
                self.local_reject(va, replacement)

    def test_actual_repair_mask_mutation_changes_negative_field(self):
        body = bytearray(self.body); body[0x151cc4f - result.START:0x151cc53 - result.START] = struct.pack('<I', 86399)
        changed = result.extract(body, self.consumer)
        self.assertEqual(result.projection(-1, changed)['second_field'], 86398)
        with self.assertRaises(ValueError): result.validate(changed)

    def test_actual_store_and_consumer_changes_alter_used_mapping(self):
        expected = compose(0x12345678, 1, 0x89abcdef, self.p)[1]
        body = bytearray(self.body); body[0x151cc5b - result.START] = 12
        store_change = result.extract(body, self.consumer)
        self.assertNotEqual(compose(0x12345678, 1, 0x89abcdef, store_change)[1], expected)
        with self.assertRaises(ValueError): result.validate(store_change)
        use = bytearray(self.consumer); use[0x46ced51 - result.USE_START] = 0x60
        consumer_change = result.extract(self.body, use)
        self.assertNotEqual(compose(0x12345678, 1, 0x89abcdef, consumer_change)[1], expected)
        with self.assertRaises(ValueError): result.validate(consumer_change)

    def test_all_native_bytes_guards_error_arms_and_output_stores(self):
        _, helper = result.native(self.body, result.START); _, consumer = result.native(self.consumer, result.USE_START)
        record = result.bind_native(helper, consumer)
        self.assertEqual((record['helper_instructions'], record['consumer_instructions']), (64, 7))
        self.assertEqual(len(record['calls']), 6); self.assertEqual(len(record['branches']), 3)
        self.assertEqual(record['normal_return'], '0x151cc6c')
        self.assertTrue(record['all_three_stores_dominate_local_return'])
        self.assertEqual(record['direct_destination_references'], ['0x151cc56', '0x151cc58', '0x151cc5c'])
        for va in (0x151cc36, 0x151cbb0):
            body = bytearray(self.body); body[va - result.START] ^= 1
            _, changed_rows = result.native(body, result.START)
            with self.assertRaises(ValueError): result.bind_native(changed_rows, consumer)

    def test_actual_source_transfers_and_CFI_are_required(self):
        for va in (0x151cbe4, 0x151cbe8, 0x151cbac, 0x151cc60):
            offset, raw = result.read_va(self.data, self.secs, va, 1)
            self.local_reject(va, bytes([raw[0] ^ 1]))
        for frame in self.record['frames'].values():
            off = int(frame['fde']['file_offset'], 16) + 12
            with mmap.mmap(self.stream.fileno(), 0, access=mmap.ACCESS_COPY) as changed:
                changed[off] ^= 1
                with self.assertRaises(ValueError): result.inspect(changed)

    def test_all_relocations_are_required(self):
        self.assertEqual(len(self.record['relocations']), 5)
        for row in self.record['relocations']:
            off = int(row['file_offset'], 16) + 16
            with mmap.mmap(self.stream.fileno(), 0, access=mmap.ACCESS_COPY) as changed:
                changed[off] ^= 1
                with self.assertRaises(ValueError): result.inspect(changed)

    def test_wrong_identity_rejected_and_assumptions_remain_explicit(self):
        with self.assertRaises(ValueError): result.authenticate(b'not node94')
        with mmap.mmap(self.stream.fileno(), 0, access=mmap.ACCESS_COPY) as changed:
            changed[0x151bba0] ^= 1
            with self.assertRaises(ValueError): result.authenticate(changed)
        self.assertIn('alias', ' '.join(self.record['limits']))
        self.assertIn('No clock units', ' '.join(self.record['limits']))
        self.assertFalse(self.record['captured_target_executed']); self.assertFalse(self.record['gate_changes_requested'])

    def test_real_tiny_native_binding_repeat_exports_and_packet(self):
        with tempfile.TemporaryDirectory() as tmp:
            first, second, supplied = Path(tmp) / 'first', Path(tmp) / 'second', Path(tmp) / 'supplied'
            supplied.symlink_to(BINARY)
            native_run = result.subprocess.check_output; spans = []
            def inspect_native(argv, **kwargs):
                if '-D' in argv:
                    path = Path(argv[-1]); spans.append(path.stat().st_size)
                    self.assertIn(spans[-1], (261, 46)); self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
                    if len(spans) == 1: supplied.unlink(); supplied.write_bytes(b'replaced source name')
                return native_run(argv, **kwargs)
            with mock.patch.object(result.subprocess, 'check_output', side_effect=inspect_native):
                actual = result.collect(supplied, first)
            self.assertEqual(spans, [261, 46])
            result.collect(BINARY, second)
            for p in first.iterdir(): self.assertEqual(p.read_bytes(), (second / p.name).read_bytes())
            expected = json.loads((PACKET / 'records.json').read_text())
            actual.pop('native_version'); expected.pop('native_version'); self.assertEqual(actual, expected)
            with self.assertRaises(FileExistsError): result.collect(BINARY, first)
            with self.assertRaises(ValueError): result.collect(supplied, Path(tmp) / 'rejected')
            self.assertFalse((Path(tmp) / 'rejected').exists())

    def test_packet_manifest(self):
        entries = dict(line.split('  ', 1)[::-1] for line in (PACKET / 'MANIFEST.sha256').read_text().splitlines())
        self.assertEqual(set(entries), {p.name for p in PACKET.iterdir() if p.name != 'MANIFEST.sha256'})
        for name, digest in entries.items(): self.assertEqual(hashlib.sha256((PACKET / name).read_bytes()).hexdigest(), digest)


if __name__ == '__main__': unittest.main()
