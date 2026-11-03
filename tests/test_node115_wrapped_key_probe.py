"""Static target-bound tests; no captured execution and no native decoder."""
from contextlib import contextmanager
import importlib.util
import itertools
import json
import mmap
from pathlib import Path
import re
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import node115_wrapped_key_probe as subject

spec = importlib.util.spec_from_file_location('wrapped_key_probe_verify', subject.PACKET / 'verify.py')
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)


class WrappedKeyProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.handle = subject.TARGET.open('rb')
        # Copy-on-write mapping dirties only the pages changed by a control.
        cls.data = mmap.mmap(cls.handle.fileno(), 0, access=mmap.ACCESS_COPY)
        cls.record = subject.records(cls.data)
        cls.sections = subject.sections(cls.data)

    @classmethod
    def tearDownClass(cls):
        cls.data.close()
        cls.handle.close()

    @contextmanager
    def changed(self, file_offset, replacement):
        old = self.data[file_offset:file_offset + len(replacement)]
        self.assertNotEqual(old, replacement, 'control must actually alter input bytes')
        self.data[file_offset:file_offset + len(replacement)] = replacement
        try:
            yield
        finally:
            self.data[file_offset:file_offset + len(old)] = old

    def va_offset(self, va, size=1):
        return subject.offset(self.sections, va, size)

    def reject_at(self, va, replacement, reason):
        with self.changed(self.va_offset(va, len(replacement)), replacement):
            with self.assertRaisesRegex(ValueError, reason):
                subject.check_image(self.data)

    def test_complete_extent_and_leaf_closure(self):
        r = self.record
        self.assertEqual(r['target']['sha256'], subject.DIGEST)
        self.assertEqual((r['function']['start'], r['function']['end']), (0x2ee0640, 0x2ee0761))
        self.assertEqual((r['function']['fde'], r['function']['cie']), (0xda2e70, 0xca6ed8))
        self.assertIsNone(r['function']['lsda'])
        self.assertEqual(r['function']['body_sha256'], subject.BODY_SHA)
        self.assertEqual(r['counts']['body_bytes'], 289)
        self.assertEqual(r['counts']['body_instructions'], 92)
        self.assertEqual(r['semantics']['callees'], [])
        self.assertEqual(r['semantics']['explicit_memory_writes'], 0)
        self.assertEqual(r['padding']['bytes'], 'cc' * 15)
        body = bytes.fromhex(''.join(row['bytes'] for row in r['instructions']))
        self.assertEqual(body, subject.read_va(self.data, self.sections, subject.START, len(body)))
        self.assertEqual(subject.decode(body, subject.START), r['instructions'])

    def test_byte_identical_generation(self):
        with tempfile.TemporaryDirectory() as directory:
            subject.generate(out=directory)
            self.assertEqual({p.name for p in Path(directory).iterdir()}, verifier.PAYLOADS)
            for name in verifier.PAYLOADS:
                self.assertEqual((Path(directory) / name).read_bytes(), (subject.PACKET / name).read_bytes(), name)
        self.assertEqual(json.loads((subject.PACKET / 'records.json').read_text()), self.record)

    def test_readme_counts_equal_json_and_actual_records(self):
        text = (subject.PACKET / 'README.md').read_text()
        rows = re.findall(r'^\| ([a-z_]+) \| ([0-9]+) \|$', text, re.MULTILINE)
        self.assertEqual(len(rows), len(self.record['counts']))
        self.assertEqual({key: int(value) for key, value in rows}, self.record['counts'])
        counts = self.record['counts']
        self.assertEqual(counts['return_sites'], sum(r['op'] == 'ret' for r in self.record['instructions']))
        self.assertEqual(counts['frozen_vectors'], len(self.record['vectors']))
        self.assertEqual(counts['caller_context_instructions'], len(self.record['caller_context']['instructions']))
        self.assertEqual(counts['direct_call_sites'], len(self.record['caller_scan']['hits']))
        self.assertEqual(counts['callees'], len(self.record['semantics']['callees']))

    def test_full_text_census_and_caller_boundary(self):
        scan = self.record['caller_scan']
        self.assertEqual((scan['start'], scan['end']), (0x1419300, 0x63f0a00))
        self.assertEqual([(r['va'], r['opcode'], r['owner_start']) for r in scan['hits']],
                         [(0x2eedcf9, '0xe8', 0x2eedb70)])
        rows = self.record['caller_context']['instructions']
        call = next(r for r in rows if r['va'] == 0x2eedcf9)
        self.assertEqual((call['op'], call['target']), ('call', subject.START))
        self.assertEqual(sum(r['size'] for r in rows), subject.CALLER_END - subject.CALLER)
        self.assertEqual(rows[0]['va'], subject.CALLER)
        self.assertEqual(rows[-1]['va'] + rows[-1]['size'], subject.CALLER_END)

    def test_rel32_scan_edges_unaligned_hits_and_signed_displacements(self):
        data = bytearray(b'\x90' * 32)
        target, base = 0x1010, 0x1000
        # Last possible starting offset must be included; one unaligned hit too.
        for pos, opcode in [(1, 0xe8), (27, 0xe9)]:
            data[pos:pos + 5] = bytes([opcode]) + struct.pack('<i', target - (base + pos + 5))
        rows = subject.rel32_scan(data, {'offset': 0, 'address': base, 'size': len(data)}, target)
        self.assertEqual([r['va'] for r in rows], [base + 1, base + 27])
        # A truncated E8 at section end must not be treated as a call.
        data[-1] = 0xe8
        rows = subject.rel32_scan(data, {'offset': 0, 'address': base, 'size': len(data)}, target)
        self.assertEqual([r['va'] for r in rows], [base + 1])

    def test_first_party_source_binding(self):
        source = self.record['source_association']
        self.assertEqual((source['path'], source['line'], source['column']), ('base/src/l1_map/entry.rs', 64, 17))
        self.assertEqual((source['relocation']['info'], source['relocation']['addend']), (8, 0x4402cd))
        self.assertEqual(source['caller_start'], subject.CALLER)

    def test_wrong_digest_and_wrong_size_rejected(self):
        with self.assertRaisesRegex(ValueError, 'size/SHA-256 mismatch'):
            subject.records(b'not the authenticated capture')
        # Same-size mutation outside the leaf is still rejected before structural work.
        with self.changed(self.va_offset(subject.START), b'\x49'):
            with self.assertRaisesRegex(ValueError, 'size/SHA-256 mismatch'):
                subject.records(self.data)

    def test_wrong_input_creates_no_output(self):
        with tempfile.TemporaryDirectory() as directory:
            binary, out = Path(directory) / 'bad', Path(directory) / 'out'
            binary.write_bytes(b'wrong target')
            with self.assertRaisesRegex(ValueError, 'size/SHA-256 mismatch'):
                subject.generate(binary, out)
            self.assertFalse(out.exists())

    def test_operative_bytes_rejected_below_digest_gate(self):
        for va, replacement in [(0x2ee066a, b'\x72'),       # JBE -> JB: exact-end becomes wrapped
                                (0x2ee06b9, b'\x43'),     # CMOVA -> CMOVAE: ties no longer advance
                                (0x2ee0729, b'\x43'),     # same corruption in the other loop
                                (0x2ee06b2, b'\x04'),     # stride shift changes
                                (0x2ee0684, b'\x85'),     # JE -> JNE at seam
                                (0x2ee06de, b'\x94')]:    # SETNE -> SETE: status inverted
            with self.subTest(va=hex(va)):
                self.reject_at(va, replacement, 'semantic anchor changed')

    def test_actual_compare_mutation_changes_duplicate_rule(self):
        va = 0x2ee06b9
        with self.changed(self.va_offset(va), b'\x43'):
            body = subject.read_va(self.data, self.sections, subject.START, subject.END - subject.START)
            rows = subject.decode(body, subject.START)
            mutated_op = next(r['op'] for r in rows if r['va'] == 0x2ee06b7)
            self.assertEqual(mutated_op, 'cmovae')
            # Extract the changed tie predicate; value-level recurrence, no CPU execution.
            def final_position(op):
                keys, cursor, span = [3, 7, 7], 0, 3
                while span > 1:
                    half = span >> 1
                    restore = keys[cursor + half] >= 7 if op == 'cmovae' else keys[cursor + half] > 7
                    if not restore:
                        cursor += half
                    span -= half
                return cursor
            self.assertEqual(final_position('cmova'), 2)
            self.assertEqual(final_position(mutated_op), 0)
            with self.assertRaisesRegex(ValueError, 'semantic anchor changed'):
                subject.check_semantics(rows)

    def test_non_anchor_body_byte_rejected(self):
        # RDX -> RCX at the final XOR: syntactically valid but outside anchor subset.
        self.reject_at(0x2ee075f, b'\xc9', 'function body digest changed')

    def test_shifted_fde_and_extent_rejected(self):
        fde = self.record['function']['fde_file_offset']
        for delta in (8, 12):
            with self.subTest(field=delta):
                old = struct.unpack_from('<i', self.data, fde + delta)[0]
                with self.changed(fde + delta, struct.pack('<i', old + 1)):
                    with self.assertRaisesRegex(ValueError, 'exact FDE binding changed'):
                        subject.check_image(self.data)

    def test_wrong_callee_target_rejected(self):
        # This leaf has no callees. Redirect its incoming direct CALL by a byte.
        displacement = self.va_offset(subject.CALL_SITE + 1, 4)
        old = struct.unpack_from('<i', self.data, displacement)[0]
        with self.changed(displacement, struct.pack('<i', old + 1)):
            with self.assertRaisesRegex(ValueError, 'direct caller census changed'):
                subject.check_image(self.data)

    def test_source_relocation_location_and_lea_rejected(self):
        source = self.record['source_association']
        with self.changed(source['relocation']['file_offset'] + 16, struct.pack('<q', 0x4402ce)):
            with self.assertRaisesRegex(ValueError, 'source relocation changed'):
                subject.check_image(self.data)
        self.reject_at(source['location_va'] + 8, b'\x19', 'source Location changed')
        self.reject_at(source['lea_va'] + 3, b'\x69', 'source LEA target changed')

    def test_padding_rejected(self):
        self.reject_at(subject.END, b'\x90', 'padding changed')

    def test_decoder_rejects_unsupported_truncated_and_malformed(self):
        for code in [b'\x62', b'\x48\x8b', b'\xe8\x00', b'\x0f\x0b',
                     b'\xf3\x90', b'\x66\xc3', b'\x48\x8d\xc0', b'\xff\xf8']:
            with self.subTest(code=code.hex()), self.assertRaises(ValueError):
                subject.decode(code, subject.START)
        # A branch into the middle of a decoded instruction fails semantic validation.
        body = bytearray(subject.read_va(self.data, self.sections, subject.START, subject.END - subject.START))
        body[0x2ee06e9 - subject.START] = 7  # short JMP originally +6
        with self.assertRaisesRegex(ValueError, 'instruction boundary'):
            subject.check_semantics(subject.decode(body, subject.START))

    def test_frozen_instruction_vectors(self):
        self.assertEqual(self.record['vectors'], subject.vector_records())
        self.assertEqual(len(self.record['vectors']), 21)
        for row in self.record['vectors']:
            with self.subTest(label=row['label']):
                args = row['physical_keys'], row['raw_head'], row['length'], row['sought']
                expected = row['rax'], row['rdx']
                self.assertEqual(subject.instruction_relation(*args), expected)
                self.assertEqual(subject.rule_model(*args), expected)

    def test_exhaustive_small_sorted_rings(self):
        # Includes duplicates spanning the physical seam and every legal small head/length.
        cases = 0
        for capacity in range(1, 7):
            for length in range(capacity + 1):
                for logical in itertools.combinations_with_replacement((0, 2, 4), length):
                    for head in range(capacity):
                        physical = [123] * capacity  # unused storage is intentionally unsorted
                        for i, key in enumerate(logical):
                            physical[(head + i) % capacity] = key
                        for extra in (0, capacity):
                            for key in range(6):
                                args = physical, head + extra, length, key
                                self.assertEqual(subject.instruction_relation(*args), subject.rule_model(*args), args)
                                cases += 1
        self.assertEqual(cases, 12096)

    def test_model_invalid_geometry_unsorted_and_empty_nonreads(self):
        for model in (subject.instruction_relation, subject.rule_model):
            self.assertEqual(model([], subject.U64, 0, subject.U64), (1, 0))
            for args in [([1], 2, 1, 1), ([1], 0, 2, 1), ([2, 1], 0, 2, 1), ([1], 0, 1, -1)]:
                with self.subTest(args=args), self.assertRaises(ValueError):
                    model(*args)

    def test_manifest_whitelist_and_hash_controls(self):
        self.assertEqual(verifier.check_manifest(), len(verifier.WHITELIST))
        with tempfile.TemporaryDirectory(dir=subject.ROOT / 'work') as directory:
            root = Path(directory)
            packet = root / 'research/work-items/test-packet'
            packet.mkdir(parents=True)
            for name in verifier.WHITELIST:
                destination = packet / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes((subject.PACKET / name).read_bytes())
            manifest = (subject.PACKET / 'MANIFEST.sha256').read_text()
            path = packet / 'MANIFEST.sha256'
            path.write_text(manifest)
            self.assertEqual(verifier.check_manifest(packet, root), len(verifier.WHITELIST))
            for bad in [manifest + manifest.splitlines()[0] + '\n',
                        '\n'.join(manifest.splitlines()[1:]) + '\n',
                        manifest + '0' * 64 + '  ../../../../outside\n']:
                path.write_text(bad)
                with self.assertRaisesRegex(ValueError, 'whitelist|duplicate'):
                    verifier.check_manifest(packet, root)
            path.write_text(manifest)
            with (packet / 'records.json').open('a') as handle:
                handle.write(' ')
            with self.assertRaisesRegex(ValueError, 'digest mismatch'):
                verifier.check_manifest(packet, root)


if __name__ == '__main__':
    unittest.main()
