"""Static certificate controls and independently frozen binary64 boundary expectations."""
from contextlib import contextmanager
import importlib.util
import json
import mmap
from pathlib import Path
import random
import shutil
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import node115_finite_ratio_clamp as subject


class FiniteRatioClampTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.handle = subject.TARGET.open('rb')
        # One private copy-on-write mapping; only mutated pages are copied.
        cls.data = mmap.mmap(cls.handle.fileno(), 0, access=mmap.ACCESS_COPY)
        cls.record = subject.inspect_static(cls.data)
        spec = importlib.util.spec_from_file_location('finite_ratio_verifier', subject.PACKET / 'verify.py')
        cls.verifier = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.verifier)

    @classmethod
    def tearDownClass(cls):
        cls.data.close()
        cls.handle.close()

    @contextmanager
    def mutation(self, offset, value):
        before = self.data[offset:offset + len(value)]
        try:
            self.data[offset:offset + len(value)] = value
            yield
        finally:
            self.data[offset:offset + len(value)] = before

    def check_model(self, x, y, status, result, divided):
        self.assertEqual(subject.model(x, y),
                         {'status': status, 'xmm0_bits': result, 'division_reached': divided})

    def test_complete_body_fde_and_closed_cfg(self):
        r = self.record
        self.assertEqual(subject.sha(self.data), subject.SHA)
        self.assertEqual((r['window']['start'], r['window']['end'], r['window']['size']),
                         (0x14ca350, 0x14ca3e4, 148))
        self.assertEqual(len(r['instructions']), 38)
        self.assertEqual(sum(x['size'] for x in r['instructions']), 148)
        self.assertEqual(r['window']['frame']['fde'], 0xcae708)
        self.assertEqual(r['window']['frame']['cie'], 0xca6ed8)
        self.assertEqual(r['window']['padding']['size'], 12)
        self.assertEqual(r['callees'], [])
        graph = {r['va']: r['successors'] for r in r['cfg']}
        def terminal_paths(va, seen):
            self.assertNotIn(va, seen, 'a local cycle would invalidate termination')
            if not graph[va]:
                self.assertEqual(next(x for x in r['instructions'] if x['va'] == va)['mnemonic'], 'ret')
            for dest in graph[va]:
                terminal_paths(dest, seen | {va})
        terminal_paths(subject.START, set())

    def test_regeneration_byte_identical_and_readme_counts(self):
        with tempfile.TemporaryDirectory() as folder:
            _, payloads = subject.generate(out=Path(folder) / 'packet')
            self.assertEqual(set(payloads), {'records.json', 'README.md', 'verify.py', 'MANIFEST.sha256'})
            for name, content in payloads.items():
                self.assertEqual(content, (subject.PACKET / name).read_bytes(), name)
                self.assertEqual(content, (Path(folder) / 'packet' / name).read_bytes(), name)
        retained = json.loads((subject.PACKET / 'records.json').read_text())
        self.assertEqual(retained, self.record)
        # Checks all README counts, ranges and instruction rows, not a handpicked subset.
        self.assertEqual((subject.PACKET / 'README.md').read_bytes(), subject.render_readme(retained))
        changed = json.loads(json.dumps(retained))
        changed['vectors'].pop()
        self.assertNotEqual(subject.render_readme(changed), subject.render_readme(retained))

    def test_full_text_direct_and_slot_censuses(self):
        scan = self.record['direct_reference_scan']
        self.assertEqual((scan['start'], scan['end']), (0x1419300, 0x63f0a00))
        self.assertEqual(scan['matches'], [])
        refs = self.record['slot_references']
        self.assertEqual([r['site'] for r in refs], [0x44807b9, 0x4480895, 0x44af279])
        self.assertEqual(len({r['owner_fde']['start'] for r in refs}), 2)
        self.assertEqual([r['location']['line'] for r in refs], [1224, 1270, 382])
        self.assertTrue(all(r['resolved_target'] == subject.START for r in refs))
        # Independent synthetic scan checks unaligned, signed, tail and end-inclusive cases.
        raw = bytearray(23)
        target, base = 0x1200, 0x1000
        for pos, opcode in ((1, 0xe8), (8, 0xe9), (18, 0xe8)):
            raw[pos] = opcode
            struct.pack_into('<i', raw, pos + 1, target - (base + pos + 5))
        scanned = subject.scan_direct(raw, {'offset': 0, 'size': len(raw), 'address': base}, target)
        self.assertEqual([r['site'] for r in scanned['matches']], [base + 1, base + 8, base + 18])
        raw = bytearray(b'\xe9' + struct.pack('<i', -0x105))
        self.assertEqual(subject.scan_direct(raw, {'offset': 0, 'size': 5, 'address': base}, 0xf00)
                         ['matches'][0]['target'], 0xf00)

    def test_wrong_digest_rejected_before_output(self):
        with tempfile.TemporaryDirectory() as folder:
            binary, out = Path(folder) / 'bad', Path(folder) / 'out'
            for content in (b'', b'not node 115', b'\x7fELF\x02\x01'):
                binary.write_bytes(content)
                with self.assertRaisesRegex(ValueError, 'digest mismatch'):
                    subject.generate(binary, out)
                self.assertFalse(out.exists())

    def test_same_size_body_mutation_fails_public_identity(self):
        with tempfile.TemporaryDirectory() as folder:
            binary, out = Path(folder) / 'bad', Path(folder) / 'out'
            # Streaming copy avoids a second full-file bytes object.
            shutil.copyfile(subject.TARGET, binary)
            with binary.open('r+b') as f:
                f.seek(subject.START - 0x1000)
                f.write(b'\x90')
            with self.assertRaisesRegex(ValueError, 'digest mismatch'):
                subject.generate(binary, out)
            self.assertFalse(out.exists())

    def test_strict_decoder_rejects_unknown_truncated_and_body_corruption(self):
        for code in (b'\x90', b'\x48\xb9', b'\x74', b'\xff\x15\0', b'\x66\x0f\x2e\x05'):
            with self.subTest(code=code), self.assertRaises(ValueError):
                subject.decode(code, subject.START)
        original = bytes.fromhex(self.record['window']['body_bytes'])
        corrupted = bytearray(original)
        corrupted[0] = 0x90
        with self.assertRaisesRegex(ValueError, 'unsupported instruction'):
            subject.certify_body(corrupted)
        with self.assertRaises(ValueError):
            subject.certify_body(original[:-1])

    def test_real_branch_and_finite_bound_controls(self):
        original = bytes.fromhex(self.record['window']['body_bytes'])
        for offset, value, error in ((0x40, 0x1f, 'branch topology'),
                                     (0x3f, 0x77, 'instruction rule'),
                                     (0xc, 0xfe, 'finite masks'),
                                     (0x19, 0xfe, 'finite masks')):
            body = bytearray(original)
            body[offset] = value
            with self.subTest(offset=offset), self.assertRaisesRegex(ValueError, error):
                subject.certify_body(body)

    def test_real_constant_reference_control(self):
        body = bytearray.fromhex(self.record['window']['body_bytes'])
        body[0x45] ^= 1  # displacement in UCOMISD xmm0,[negative epsilon]
        with self.assertRaisesRegex(ValueError, 'constant reference'):
            subject.certify_body(body)

    def test_epsilon_data_mutation_changes_rule_before_rejection(self):
        offset = 0x459ba0
        with self.mutation(offset, (subject.EPS + 1).to_bytes(8, 'little')):
            changed = int.from_bytes(self.data[offset:offset + 8], 'little')
            # The observed equality-admission boundary is sensitive to this actual constant.
            self.assertEqual(subject.model(subject.EPS, subject.EPS)['status'], 1)
            self.assertEqual(subject.model(subject.EPS, subject.EPS, changed)['status'], 0)
            with self.assertRaisesRegex(ValueError, 'epsilon constant'):
                subject.inspect_static(self.data)

    def test_actual_fde_start_and_extent_mutations(self):
        for offset in (subject.FDE + 8, subject.FDE + 12):
            before = struct.unpack_from('<i', self.data, offset)[0]
            with self.subTest(offset=offset), self.mutation(offset, struct.pack('<i', before + 1)):
                with self.assertRaisesRegex(ValueError, 'exact FDE extent'):
                    subject.inspect_static(self.data)

    def test_wrong_relocation_callee_target(self):
        off = self.record['entry_relocation']['file_offset'] + 16
        with self.mutation(off, struct.pack('<q', subject.START + 1)):
            with self.assertRaisesRegex(ValueError, 'callee relocation target'):
                subject.inspect_static(self.data)

    def test_caller_displacement_location_and_padding_controls(self):
        for offset, error in ((0x44807b9 - 0x1000 + 2, 'slot reference census'),
                              (0x44807b2 - 0x1000 + 3, 'caller Location target'),
                              (0x44807c1 - 0x1000, 'caller result use'),
                              (subject.END - 0x1000, 'padding changed')):
            with self.subTest(offset=offset), self.mutation(offset, bytes([self.data[offset] ^ 1])):
                with self.assertRaisesRegex(ValueError, error):
                    subject.inspect_static(self.data)

    def test_signed_zero_and_exact_ratio(self):
        one, two = 0x3ff0000000000000, 0x4000000000000000
        self.check_model(one, two, 1, 0x3fe0000000000000, True)
        self.check_model(0, subject.EPS, 1, 0, True)
        self.check_model(subject.SIGN, subject.EPS, 1, subject.SIGN, True)
        self.check_model(subject.EPS, subject.EPS, 1, one, True)

    def test_strict_negative_clamp_and_divisor_boundary(self):
        s, e, one = subject.SIGN, subject.EPS, 0x3ff0000000000000
        self.check_model(s | (e - 1), one, 1, 0, True)
        self.check_model(s | e, one, 0, s | e, False)
        self.check_model(s | (e + 1), one, 0, s | (e + 1), False)
        self.check_model(s | 1, e, 1, 0, True)
        self.check_model(s | 1, 0, 0, 0, False)
        self.check_model(e, e - 1, 0, e, False)
        self.assertEqual(subject.model(e, e + 1)['status'], 1)
        for denominator in (0, s, s | one):
            self.check_model(one, denominator, 0, one, False)

    def test_nonfinite_filter_and_ordering(self):
        one = 0x3ff0000000000000
        for value in (subject.INF, subject.SIGN | subject.INF, subject.INF | 1,
                      subject.INF | (1 << 51), subject.SIGN | subject.INF | (1 << 51) | 7):
            self.check_model(value, one, 0, value, False)
            self.check_model(subject.SIGN | 1, value, 0, subject.SIGN | 1, False)

    def test_overflow_underflow_and_round_to_even(self):
        one, two = 0x3ff0000000000000, 0x4000000000000000
        self.check_model(subject.MAX_FINITE, one, 1, subject.MAX_FINITE, True)
        self.check_model(subject.MAX_FINITE, subject.EPS, 0, subject.INF, True)
        self.check_model(1, one, 1, 1, True)
        self.check_model(1, two, 1, 0, True)
        self.check_model(3, two, 1, 2, True)
        self.check_model(1, subject.MAX_FINITE, 1, 0, True)
        self.assertEqual(subject.rounded_division(0x0010000000000000, two), 0x0008000000000000)

    def test_rational_division_against_independent_binary64_arithmetic(self):
        rng = random.Random(0x14ca350)
        cases = [(1, 0x3ff0000000000000), (subject.MAX_FINITE, subject.EPS)]
        cases += [(rng.randrange(subject.MAX_FINITE + 1), rng.randrange(subject.EPS, subject.MAX_FINITE + 1))
                  for _ in range(2000)]
        for x, y in cases:
            a = struct.unpack('<d', struct.pack('<Q', x))[0]
            b = struct.unpack('<d', struct.pack('<Q', y))[0]
            expected = struct.unpack('<Q', struct.pack('<d', a / b))[0]
            self.assertEqual(subject.rounded_division(x, y), expected, (hex(x), hex(y)))

    def test_retained_boundary_vectors_and_invalid_model_inputs(self):
        self.assertEqual(len(self.record['vectors']), 28)
        self.assertEqual(self.record['vectors'], subject.vectors())
        for x, y in ((-1, 0), (1 << 64, 0), (False, 0), (0.0, 0)):
            with self.assertRaisesRegex(ValueError, 'bit patterns'):
                subject.model(x, y)

    def test_verifier_and_manifest_corruption_controls(self):
        self.assertEqual(self.verifier.verify()['target']['sha256'], subject.SHA)
        with tempfile.TemporaryDirectory() as folder:
            packet = Path(folder) / 'packet'
            shutil.copytree(subject.PACKET, packet)
            manifest = packet / 'MANIFEST.sha256'
            original = manifest.read_bytes()
            manifest.write_bytes(original + b'0' * 64 + b'  extra.txt\n')
            with self.assertRaisesRegex(ValueError, 'whitelist'):
                self.verifier.verify(packet)
            manifest.write_bytes(b'\n'.join(original.splitlines()[1:]) + b'\n')
            with self.assertRaisesRegex(ValueError, 'whitelist incomplete'):
                self.verifier.verify(packet)
            manifest.write_bytes(original)
            readme = packet / 'README.md'
            readme.write_bytes(readme.read_bytes() + b'changed')
            with self.assertRaisesRegex(ValueError, 'hash mismatch'):
                self.verifier.verify(packet)
            readme.write_bytes((subject.PACKET / 'README.md').read_bytes())
            (packet / 'extra.txt').write_text('unexpected')
            with self.assertRaisesRegex(ValueError, 'file whitelist'):
                self.verifier.verify(packet)


if __name__ == '__main__':
    unittest.main()
