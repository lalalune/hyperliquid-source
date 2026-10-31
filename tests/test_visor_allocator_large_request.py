"""Actual visor operands, interval lemma and copied-byte counterfactuals (RE-013)."""
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import visor_allocator_large_request as subject

PACKET = subject.ROOT / 'research/work-items/RE-013-visor-allocator-large-request'


class NativeLargeRequestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = subject.read_authenticated(subject.TARGET)
        cls.record = subject.inspect(cls.data)
        cls.fragments = {f['name']: bytes.fromhex(f['hex']) for f in cls.record['fragments']}

    def test_actual_selected_scope_and_unwind_identity(self):
        record = self.record
        self.assertEqual(record['target']['sha256'], subject.TARGET_SHA256)
        self.assertEqual((record['fde']['start'], record['fde']['end']), ('0x70a170', '0x70bf2b'))
        self.assertEqual(record['fde']['body_sha256'], subject.FDE_SHA256)
        self.assertFalse(record['fde']['full_body_decoded'])
        self.assertEqual((record['proof']['selected_bytes'], record['proof']['selected_instructions']), (251, 56))
        self.assertEqual(sum(f['bytes'] for f in record['fragments']), 251)

    def test_pinned_target_rejects_changed_bytes(self):
        changed = bytearray(self.data)
        changed[self.record['fragments'][0]['file_offset']] ^= 1
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            subject.inspect(changed)
        with self.assertRaisesRegex(ValueError, 'size'):
            subject.authenticate(self.data[:-1])

    def test_all_203_analytic_bins_are_contiguous_and_exact(self):
        proof = self.record['proof']
        self.assertEqual((proof['interval_count'], proof['class_range']), (203, [29, 231]))
        self.assertTrue(proof['class_join_cannot_reject'])
        intervals = proof['intervals']
        self.assertEqual((intervals[0]['lower'], intervals[-1]['upper']), (4097, 0x7000000000000000))
        self.assertEqual([r['class'] for r in intervals], list(range(29, 232)))
        for row in intervals:
            # Algebraic interval bounds are a different expectation from the
            # Rust leading_zeros implementation; these checks corroborate L3.
            k, t = row['k'], row['fractional']
            step = 1 << (k - 3)
            self.assertGreaterEqual(row['lower'], (4 + t) * step + 1)
            self.assertLessEqual(row['upper'], (5 + t) * step)
            self.assertEqual(row['class'], 4 * k + t - 23)
            for r in (row['lower'], row['upper']):
                self.assertEqual((2 * r - 1).bit_length() - 1, k)
                self.assertEqual(((r - 1) >> (k - 3)) & 3, t)
        self.assertEqual(intervals[-1]['fractional'], 2)
        self.assertTrue(all(a['upper'] + 1 == b['lower'] for a, b in zip(intervals, intervals[1:])))

    def test_zero_return_requires_actual_output_path_and_conditions(self):
        proof = self.record['proof']['conditional_zero_return']
        self.assertEqual((proof['store_width_bytes'], proof['store_value']), (4, 12))
        path = proof['actual_path_witnesses']
        self.assertLess(path.index('0x70a43c'), path.index('0x70a441'))
        self.assertLess(path.index('0x70a441'), path.index('0x70a444'))
        self.assertLess(path.index('0x70a2ce'), path.index('0x70a2d3'))
        self.assertEqual(path[-1], '0x70a2db')
        self.assertTrue(any('physical saved guard' in s for s in proof['premises']))
        self.assertTrue(proof['no_errno_or_purity_or_heap_preservation_claim'])

    def test_nonzero_gate_route_and_unknowns_remain_explicit(self):
        p = self.record['proof']
        self.assertEqual(p['request_guard']['selected_gate_value'], 0)
        self.assertIn('before size checks', p['request_guard']['nonzero_gate_route'])
        self.assertTrue(p['all_component_gates_unchanged'])
        self.assertIn('small request table', p['open'])
        self.assertIn('opaque callee effects and body', p['open'])
        self.assertIn('original runtime equivalence and whole-visor reconstruction', p['open'])

    def test_semantic_counterfactuals_do_not_use_artifact_hash_rejection(self):
        report = subject.counterfactuals(self.fragments)
        self.assertEqual(report['actual_byte_controls'], 21)
        controls = {r['name']: r for r in report['controls']}
        self.assertEqual(controls['class-bias-minus24']['changed_summary']['class_range'], [28, 230])
        self.assertFalse(controls['join-limit230']['changed_summary']['class_join_cannot_reject'])
        self.assertEqual(controls['upper-bound-endpoint']['changed_summary']['last_interval']['upper'],
                         0x7000000000000001)
        self.assertEqual(controls['large-domain-start']['changed_summary']['first_interval']['lower'], 4098)
        self.assertEqual(controls['numeric-store13']['changed_summary']['constants']['stored_word'], 13)
        for name in ('return-r13', 'skip-epilogue-witnesses', 'signed-upper-guard', 'store-through-rdx', 'sign-extended-negative-limit'):
            self.assertEqual(controls[name]['disposition'], 'rejected-unsupported-witness')
        self.assertTrue(report['whole_target_hash_not_used_to_reject_mutants'])

    def test_actual_native_rows_and_counterfactual_exports_reproduce(self):
        record_rows = self.record['proof']['instruction_bindings']
        native = []
        for name, start, _ in subject.SCOPES:
            rows, _ = subject.native_rows(self.fragments[name], name, start)
            native.extend(rows)
        self.assertEqual(sorted((r['va'], r['hex']) for r in native),
                         sorted((r['va'], r['hex']) for r in record_rows))
        controls = subject.counterfactuals(self.fragments, decode=True)
        self.assertTrue(all(r['actual_native_mutated_rows'] for r in controls['controls']))
        self.assertEqual(json.loads((PACKET / 'observed/controls.json').read_text()), controls)

    def test_fixture_is_fresh_target_derived_not_default_constants(self):
        self.assertEqual((PACKET / 'observed/class-intervals.tsv').read_text(),
                         subject.intervals_tsv(self.record['proof']['intervals']))
        record = json.loads((PACKET / 'observed/record.json').read_text())
        self.assertEqual(record['proof'], self.record['proof'])
        self.assertEqual(record['fde'], self.record['fde'])

    def test_unbound_or_missing_fragment_never_gets_a_certificate(self):
        for name, raw in self.fragments.items():
            with self.subTest(fragment=name):
                with self.assertRaisesRegex(ValueError, 'extent'):
                    subject.prove_fragments({**self.fragments, name: raw[:-1]})
        with self.assertRaisesRegex(ValueError, 'domain'):
            subject.prove_fragments({k: v for k, v in self.fragments.items() if k != 'normal-epilogue'})

    def test_certificate_lemma_rejects_wrap_and_noninert_clamps(self):
        original = self.record['proof']['constants']
        for change in ({'maximum': 1 << 63}, {'small_limit': 3}, {'shift_floor': 14},
                       {'class_floor': 14}, {'fraction_mask': 7}, {'shift_subtract': 4}):
            with self.subTest(change=change):
                with self.assertRaises(ValueError):
                    subject.class_intervals({**original, **change})


class SourceAdmissionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = subject.read_authenticated(subject.TARGET)

    def test_same_bytes_replaced_path_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix='vlarge-admit-') as directory:
            path = Path(directory) / 'visor-copy'
            replacement = Path(directory) / 'replacement'
            path.write_bytes(self.data)
            replacement.write_bytes(self.data)
            real_read = os.read
            replaced = False
            def read(fd, count):
                nonlocal replaced
                if not replaced:
                    replacement.replace(path)
                    replaced = True
                return real_read(fd, count)
            with mock.patch.object(subject.os, 'read', side_effect=read):
                with self.assertRaisesRegex(ValueError, 'path/identity'):
                    subject.read_authenticated(path)
            self.assertTrue(replaced)

    def test_private_hardlink_metadata_change_preserves_authenticated_bytes(self):
        with tempfile.TemporaryDirectory(prefix='vlarge-admit-') as directory:
            path = Path(directory) / 'visor-copy'
            path.write_bytes(self.data)
            real_read = os.read
            linked = False
            def read(fd, count):
                nonlocal linked
                if not linked:
                    os.link(path, Path(directory) / 'new-link')
                    linked = True
                return real_read(fd, count)
            with mock.patch.object(subject.os, 'read', side_effect=read):
                self.assertEqual(subject.read_authenticated(path), self.data)
            self.assertTrue(linked)


if __name__ == '__main__':
    unittest.main()
