"""Static target-grounded controls; never launch captured code or objdump."""
import copy
import hashlib
import importlib.util
import itertools
import json
import mmap
from pathlib import Path
import re
import shutil
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import node115_guarded_word_equality as subject


class GuardedWordEqualityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.stream = subject.TARGET.open('rb')
        cls.data = mmap.mmap(cls.stream.fileno(), 0, access=mmap.ACCESS_READ)
        cls.record = subject.analyze(cls.data)
        cls.body = bytes.fromhex(cls.record['function']['body_bytes'])
        spec = importlib.util.spec_from_file_location('guarded_word_packet_verify', subject.PACKET / 'verify.py')
        cls.verifier = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.verifier)

    @classmethod
    def tearDownClass(cls):
        cls.data.close()
        cls.stream.close()

    def test_exact_target_extent_and_complete_cfg(self):
        f = self.record['function']
        self.assertEqual((f['start'], f['end'], f['size']), (0x542f290, 0x542f31b, 139))
        self.assertEqual(f['file_offset'], 0x542e290)
        self.assertEqual(f['body_sha256'], hashlib.sha256(self.body).hexdigest())
        rows = subject.bind_body(self.body)
        self.assertEqual(sum(r['size'] for r in rows), 139)
        self.assertEqual(bytes.fromhex(''.join(r['bytes'] for r in rows)), self.body)
        self.assertEqual(f['callees'], [])
        self.assertEqual(f['indirect_transfers'], [])
        self.assertEqual(f['writes'], [])
        self.assertTrue(all(r['target'] in {x['va'] for x in rows}
                            for r in rows if 'target' in r))

    def test_target_grounded_widths_offsets_and_predicates(self):
        rows = {r['va']: r for r in self.record['function']['instructions']}
        for va in (0x542f293, 0x542f29d):
            self.assertEqual((rows[va]['width'], rows[va]['immediate']), (64, 2))
        for va in (0x542f2ad, 0x542f2b4):
            self.assertEqual((rows[va]['width'], rows[va]['immediate']), (32, 2))
        self.assertEqual((rows[0x542f2db]['width'], rows[0x542f2db]['immediate']), (32, 1))
        self.assertEqual(rows[0x542f2e0]['immediate'], 1)
        self.assertEqual(rows[0x542f2f1]['immediate'], 1)
        offsets = [rows[x]['displacement'] for x in (0x542f2c2, 0x542f2e5, 0x542f2f6, 0x542f30f)]
        self.assertEqual(offsets, [16, 8, 24, 32])
        self.assertEqual(rows[0x542f317]['op'], 'sete')
        self.assertEqual(rows[0x542f2c0]['target'], 0x542f31a)

    def test_fde_cie_and_padding(self):
        f = self.record['function']
        frame = f['frame']
        subject.bind_fde(bytes.fromhex(frame['fde_record']['bytes']), frame['fde'],
                         bytes.fromhex(frame['cie_record']['bytes']))
        self.assertEqual(frame['lsda'], None)
        self.assertEqual(frame['cie_fields']['augmentation'], 'zR')
        self.assertEqual([p['size'] for p in f['padding']], [13, 5])
        self.assertTrue(all(bytes.fromhex(p['bytes']) == b'\xcc' * p['size'] for p in f['padding']))

    def test_full_text_census_and_caller_context(self):
        census = self.record['caller_census']
        self.assertEqual(census['section']['size'], 0x63f0a00 - 0x1419300)
        self.assertEqual([(r['va'], r['opcode'], r['target']) for r in census['hits']],
                         [(0x53794cc, 'e8', 0x542f290)])
        self.assertEqual((census['owner_frame']['start'], census['owner_frame']['end']),
                         (0x5378220, 0x537aa59))
        rows = census['instructions']
        self.assertEqual([r['op'] for r in rows], ['movzx', 'cmp', 'jne', 'lea', 'lea', 'call', 'jmp'])
        self.assertEqual([rows[i]['displacement'] for i in (3, 4)], [8, 16])

    def test_rel32_scanner_boundaries_and_false_positive_policy(self):
        # Scan includes an E9 ending at the last section byte and an E8 even
        # when it could be embedded in another instruction's immediate.
        target = 0x2000
        sample = b'\x90\xe8' + struct.pack('<i', target - (0x1001 + 5))
        sample += b'\xe9' + struct.pack('<i', target - (0x1006 + 5))
        text = {'address': 0x1000, 'offset': 0, 'size': len(sample)}
        self.assertEqual([r['va'] for r in subject.scan_rel32(sample, text, target)], [0x1001, 0x1006])
        self.assertEqual(subject.scan_rel32(sample[:-1], {**text, 'size': len(sample) - 1}, target),
                         subject.scan_rel32(sample, text, target)[:1])

    def test_source_association_uses_actual_relocation(self):
        s = self.record['source_association']
        self.assertEqual((s['path'], s['line'], s['column']), ('l1/src/raw_signature_tracker.rs', 231, 9))
        self.assertEqual(s['lea_instructions'][0]['rip_target'], s['location_va'])
        self.assertEqual(struct.unpack('<QQq', bytes.fromhex(s['relocation']['bytes'])),
                         (0x64a7f08, 8, 0x44e7fd))
        self.assertEqual(bytes.fromhex(s['path_bytes']).decode(), s['path'])

    def test_frozen_instruction_derived_vectors(self):
        self.assertEqual(self.record['vectors'], subject.vectors())
        for v in self.record['vectors']:
            with self.subTest(v['name']):
                self.assertEqual(subject.model(v['left'], v['right']), v['al'])

    def test_restricted_tag_domain_matches_independent_payload_tuples(self):
        # This formulation deliberately uses an independent tuple equality
        # oracle only on the conventional tag subset established in the proof.
        pool = [0, 1, (1 << 32) - 1, 1 << 32, 1 << 63, (1 << 64) - 1]
        def payload(words):
            tag = words[0]
            return (tag,) if tag == 2 else (tag, *words[1 if tag == 1 else 2:])
        for ta, tb, left, right in itertools.product(range(3), range(3), pool, pool):
            a = [ta, left, left, left, left]
            b = [tb, right, right, right, right]
            self.assertEqual(subject.model(a, b), int(payload(a) == payload(b)))

    def test_each_payload_bit_and_ignored_word(self):
        for bit in range(64):
            for tag in (0, 1):
                a = [tag, 0, 0, 0, 0]
                for slot in range(1, 5):
                    b = a.copy()
                    b[slot] = 1 << bit
                    self.assertEqual(subject.model(a, b), int(tag == 0 and slot == 1))

    def test_high_word_tags_and_asymmetry_are_not_normalized(self):
        a, b = [(1 << 32) + 2, 1, 2, 3, 4], [0, 9, 8, 7, 6]
        self.assertEqual(subject.model(a, b), 1)
        self.assertEqual(subject.model(a, [2, *b[1:]]), 0)
        self.assertEqual(subject.model([3, 0, 0, 0, 0], [0, 0, 0, 0, 0]), 1)
        self.assertEqual(subject.model([0, 0, 0, 0, 0], [3, 0, 0, 0, 0]), 0)

    def test_model_rejects_out_of_domain_values(self):
        for bad in ([-1, 0, 0, 0, 0], [1 << 64, 0, 0, 0, 0], [True, 0, 0, 0, 0], [0]):
            with self.assertRaises(ValueError):
                subject.model(bad, [0] * 5)

    def test_wrong_digest_and_public_generation_fail_before_output(self):
        with self.assertRaisesRegex(ValueError, 'size/digest mismatch'):
            subject.analyze(b'unrelated executable')
        with tempfile.TemporaryDirectory() as folder:
            bad, output = Path(folder) / 'bad', Path(folder) / 'output'
            # Sparse file: exact length, wrong digest, no full-size copy in RAM.
            with bad.open('wb') as stream:
                stream.truncate(subject.SIZE)
            with self.assertRaisesRegex(ValueError, 'size/digest mismatch'):
                subject.generate(bad, output)
            self.assertFalse(output.exists())

    def test_actual_window_corruption_rejected_by_public_digest_gate(self):
        # ACCESS_COPY shares clean pages with the read-only mapping. Only the
        # touched page is copied; the captured file remains unchanged.
        with mmap.mmap(self.stream.fileno(), 0, access=mmap.ACCESS_COPY) as changed:
            changed[0x542e296] ^= 1
            with self.assertRaisesRegex(ValueError, 'size/digest mismatch'):
                subject.analyze(changed)
        self.assertEqual(self.data[0x542e296], 2)

    def test_every_leaf_byte_mutation_rejected_by_private_binding(self):
        # Exercise the local evidence check separately from the global digest.
        for i in range(len(self.body)):
            mutated = bytearray(self.body)
            mutated[i] ^= 1
            with self.subTest(offset=i), self.assertRaises(ValueError):
                subject.bind_body(bytes(mutated))

    def test_actual_semantic_operands_decode_before_rejection(self):
        for va, replacement, field, expected in [
            (0x542f296, 3, 'immediate', 3),
            (0x542f2c1, 0x57, 'target', 0x542f319),
            (0x542f2e8, 0x10, 'displacement', 16),
            (0x542f318, 0x95, 'op', 'setne'),
        ]:
            modified = bytearray(self.body)
            modified[va - subject.START] = replacement
            rows = subject.decode(bytes(modified), subject.START)
            hit = next(r for r in rows if r['va'] <= va < r['va'] + r['size'])
            self.assertEqual(hit[field], expected)
            with self.assertRaisesRegex(ValueError, 'body SHA-256 mismatch'):
                subject.bind_body(bytes(modified))
        # The final SETE -> SETNE counterfactual reverses the equal-last-word
        # witness; the actual retained predicate is checked above, not assumed.
        a = [0, 0, 1, 1, 7]
        self.assertEqual(subject.model(a, a), 1)
        self.assertEqual(int(a[4] != a[4]), 0)

    def test_extracted_sentinel_counterfactual_changes_first_gate(self):
        rows = subject.decode(self.body, subject.START)
        original = subject.extract_rule(rows)
        changed = bytearray(self.body)
        for va in (0x542f296, 0x542f2a0):
            changed[va - subject.START] = 3
        counterfact = subject.extract_rule(subject.decode(bytes(changed), subject.START))
        self.assertEqual(original['full_width_sentinel'], 2)
        self.assertEqual(counterfact['full_width_sentinel'], 3)
        def first_gate_rejects(rule, left, right):
            sentinel = rule['full_width_sentinel']
            return (left == sentinel) != (right == sentinel)
        self.assertFalse(first_gate_rejects(original, 3, 0))
        self.assertTrue(first_gate_rejects(counterfact, 3, 0))
        self.assertEqual(subject.model([3, 0, 0, 0, 0], [0, 0, 0, 0, 0]), 1)
        with self.assertRaisesRegex(ValueError, 'body SHA-256 mismatch'):
            subject.bind_body(bytes(changed))

    def test_shifted_fde_extent_and_wrong_cie_rejected(self):
        for off in (8, 12):
            raw = bytearray(subject.FDE_RAW)
            raw[off] ^= 1
            with self.assertRaisesRegex(ValueError, 'FDE extent mismatch'):
                subject.bind_fde(raw, subject.FDE_VA, subject.CIE_RAW)
        raw = bytearray(subject.CIE_RAW)
        raw[-1] ^= 1
        with self.assertRaisesRegex(ValueError, 'CIE bytes mismatch'):
            subject.bind_fde(subject.FDE_RAW, subject.FDE_VA, raw)

    def test_wrong_incoming_call_target_rejected(self):
        context = bytes.fromhex(''.join(r['bytes'] for r in self.record['caller_census']['instructions']))
        modified = bytearray(context)
        modified[subject.CALL_SITE - subject.CONTEXT_START + 1] ^= 1
        rows = subject.decode(bytes(modified), subject.CONTEXT_START)
        self.assertNotEqual(next(r['target'] for r in rows if r['op'] == 'call'), subject.START)
        with self.assertRaisesRegex(ValueError, 'Caller target mismatch'):
            subject.bind_caller(bytes(modified))

    def test_decoder_rejects_unknown_truncated_and_partial_instruction(self):
        for malformed in (b'\x00', b'\x48\x8b\x47', b'\xe8\x00', b'\x74', b'\x0f\x85',
                          bytes.fromhex('488d35000000'), bytes.fromhex('4883fa')):
            with self.subTest(raw=malformed.hex()), self.assertRaises(ValueError):
                subject.decode(malformed, subject.START)

    def test_byte_identical_regeneration_and_readme_counts(self):
        self.assertEqual((subject.PACKET / 'records.json').read_bytes(), subject.json_bytes(self.record))
        readme = (subject.PACKET / 'README.md').read_text()
        counts = {k: int(v) for k, v in re.findall(r'^\| ([a-z_]+) \| ([0-9]+) \|$', readme, re.M)}
        self.assertEqual(counts, self.record['counts'])
        self.assertEqual(readme, subject.render_readme(self.record))
        with tempfile.TemporaryDirectory() as folder:
            subject.generate(subject.TARGET, Path(folder) / 'packet')
            for name in ('records.json', 'README.md', 'verify.py', 'MANIFEST.sha256'):
                self.assertEqual((Path(folder) / 'packet' / name).read_bytes(),
                                 (subject.PACKET / name).read_bytes())

    def test_verifier_and_manifest_whitelist_controls(self):
        self.assertTrue(self.verifier.verify())
        with tempfile.TemporaryDirectory() as folder:
            packet = Path(folder) / 'packet'
            shutil.copytree(subject.PACKET, packet, ignore=shutil.ignore_patterns('__pycache__'))
            manifest = packet / 'MANIFEST.sha256'
            original = manifest.read_text()
            for changed in (original + original.splitlines(True)[0],
                            '\n'.join(original.splitlines()[1:]) + '\n',
                            original.replace('README.md', '../README.md')):
                manifest.write_text(changed)
                with self.assertRaisesRegex(ValueError, 'whitelist'):
                    self.verifier.verify_manifest(packet)
            manifest.write_text(original)
            (packet / 'extra.json').write_text('{}')
            with self.assertRaisesRegex(ValueError, 'payload whitelist'):
                self.verifier.verify_manifest(packet)

    def test_corrupt_record_rejected_even_with_rehashed_manifest(self):
        with tempfile.TemporaryDirectory() as folder:
            packet = Path(folder) / 'packet'
            shutil.copytree(subject.PACKET, packet, ignore=shutil.ignore_patterns('__pycache__'))
            record = copy.deepcopy(self.record)
            record['function']['callees'] = [{'start': 0}]
            (packet / 'records.json').write_bytes(subject.json_bytes(record))
            payloads = {n: (packet / n).read_bytes() for n in ('README.md', 'records.json', 'verify.py')}
            (packet / 'MANIFEST.sha256').write_bytes(subject.manifest_bytes(payloads))
            with self.assertRaisesRegex(ValueError, 'Regenerated evidence mismatch'):
                self.verifier.verify(packet)


if __name__ == '__main__':
    unittest.main()
