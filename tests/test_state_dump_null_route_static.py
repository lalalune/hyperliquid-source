import hashlib
import json
import mmap
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import state_dump_null_route_static as route

BINARY = ROOT / 'artifacts/node/94/hl-node'
PACKET = ROOT / 'research/work-items/RE-009-state-dump-null-route-94'


class NullRouteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.stream = BINARY.open('rb'); cls.data = mmap.mmap(cls.stream.fileno(), 0, access=mmap.ACCESS_READ)
        route.authenticate(cls.data)
        cls.secs = route.sections(cls.data)
        _, cls.body = route.mapped(cls.data, cls.secs, route.START, route.END - route.START)
        _, cls.rows = route.disassemble(cls.body)
        cls.record = route.derive(cls.data, cls.rows, route.inspect_bytes(cls.data))

    @classmethod
    def tearDownClass(cls):
        cls.data.close(); cls.stream.close()

    def local_rejects(self, offset, replacement, derived=False):
        with mmap.mmap(self.stream.fileno(), 0, access=mmap.ACCESS_COPY) as changed:
            changed[offset:offset + len(replacement)] = replacement
            with self.assertRaises(ValueError):
                record = route.inspect_bytes(changed)
                if derived: route.derive(changed, self.rows, record)

    def test_exact_equality_predicate_and_all_single_byte_alternatives(self):
        spec = self.record['predicate']
        self.assertEqual(spec['bytes_hex'], b'/dev/null'.hex())
        self.assertTrue(route.matches_path(b'/dev/null', spec))
        cases = [b'', b'/dev/nul', b'/dev/null/', b'./dev/null', b'/dev/null\0', b'/DEV/NULL']
        for i in range(9):
            for value in range(256):
                candidate = bytearray(b'/dev/null'); candidate[i] = value
                self.assertEqual(route.matches_path(candidate, spec), bytes(candidate) == b'/dev/null')
        for case in cases: self.assertFalse(route.matches_path(case, spec), case)

    def test_actual_literal_counterfactual_changes_classifier_before_rejection(self):
        body = bytearray(self.body); body[0x46ceaf1 - route.START] = ord('!')
        spec = route.predicate(body)
        self.assertFalse(route.matches_path(b'/dev/null', spec))
        self.assertTrue(route.matches_path(b'!dev/null', spec))
        offset, _ = route.mapped(self.data, self.secs, 0x46ceaf1, 1)
        self.local_rejects(offset, b'!')

    def test_actual_je_to_jne_changes_used_call_route_before_rejection(self):
        body = bytearray(self.body); body[0x46ceb09 - route.START] = 0x85
        spec = route.predicate(body); _, rows = route.disassemble(body)
        before, _, _ = route.control_flow(self.rows, route.forced_route(b'/dev/null', self.record['predicate']))
        after, _, _ = route.control_flow(rows, route.forced_route(b'/dev/null', spec))
        calls = {int(c['va'], 16) for c in route.call_records(rows)}
        self.assertEqual(len(before & calls), 8)
        self.assertEqual(len(after & calls), 22)
        self.assertNotIn(0x46cec5e, before)
        self.assertIn(0x46cec5e, after)
        offset, _ = route.mapped(self.data, self.secs, 0x46ceb09, 1)
        self.local_rejects(offset, b'\x85')

    def test_complete_cfg_and_scoped_call_partitions(self):
        self.assertEqual(self.record['census'], {'bytes': 1478, 'instructions': 299, 'calls': 28, 'branches': 33, 'returns': 1})
        blocks = self.record['normal_cfg_blocks']
        self.assertEqual(sum(b['instructions'] for b in blocks), 299)
        self.assertEqual(sum(int(b['end'], 16) - int(b['start'], 16) for b in blocks), 1478)
        self.assertEqual([int(b['end'], 16) for b in blocks[:-1]], [int(b['start'], 16) for b in blocks[1:]])
        counts = {kind: sum(c['normal_route_class'] == kind for c in self.record['calls']) for kind in
                  ('common', 'ordinary-only', 'exception/unreachable-from-normal-entry')}
        self.assertEqual(counts, {'common': 8, 'ordinary-only': 14, 'exception/unreachable-from-normal-entry': 6})
        self.assertEqual(self.record['predicate']['equality_branch']['target'], '0x46cec83')

    def test_null_route_keeps_upstream_common_calls_and_final_output_copy(self):
        null, _, _ = route.control_flow(self.rows, route.forced_route(b'/dev/null', self.record['predicate']))
        self.assertTrue({0x46cea7c, 0x46ceac1, 0x46cec98, 0x46cecda, 0x46ced31, 0x46cee2e} <= null)
        self.assertTrue({0x46cee68, 0x46cee6c, 0x46cee80} <= null)
        self.assertFalse({0x46ceb14, 0x46ceb62, 0x46cec00, 0x46cec39, 0x46cec5e, 0x46cef7f} & null)
        self.assertIn('alias', ' '.join(self.record['limits']))
        self.assertIn('filesystem', ' '.join(self.record['limits']))
        self.assertFalse(self.record['captured_target_executed'])
        self.assertFalse(self.record['gate_changes_requested'])

    def test_actual_used_input_output_copy_corruptions_rejected(self):
        for va, byte in [(0x46cead2, b'\x18'), (0x46cead6, b'\x10'), (0x46ceabb, b'\xf0'),
                         (0x46ceacb, b'\xe8'), (0x46ceae9, b'\xd0'), (0x46cee6b, b'\x08')]:
            with self.subTest(va=hex(va)):
                offset, _ = route.mapped(self.data, self.secs, va, 1); self.local_rejects(offset, byte)

    def test_all_selected_relocation_addends_are_required(self):
        self.assertEqual(len(self.record['relocations']), 15)
        for row in self.record['relocations']:
            offset = int(row['file_offset'], 16) + 16
            with self.subTest(slot=row['slot']):
                self.local_rejects(offset, bytes([self.data[offset] ^ 1]), derived=True)

    def test_frame_location_and_lsda_corruptions_rejected(self):
        offsets = [int(self.record['fde']['file_offset'], 16) + 12,
                   int(self.record['cie']['record']['file_offset'], 16) + 14,
                   int(self.record['lsda']['file_offset'], 16) + 8,
                   int(self.record['source_locations'][0]['file_offset'], 16) + 16]
        for offset in offsets:
            with self.subTest(offset=hex(offset)):
                self.local_rejects(offset, bytes([self.data[offset] ^ 1]))
        self.assertTrue(any(not c['lsda_rows'] for c in self.record['calls']))
        self.assertEqual(len(self.record['lsda']['rows']), 11)

    def test_direct_call_retarget_and_interior_branch_rejected(self):
        for va in (0x46cea7d, 0x46ceb0a):
            body = bytearray(self.body); body[va - route.START] ^= 1
            _, rows = route.disassemble(body)
            with self.assertRaises(ValueError):
                route.call_records(rows) if va == 0x46cea7d else route.control_flow(rows)

    def test_wrong_full_identity_is_rejected(self):
        with self.assertRaises(ValueError): route.authenticate(b'not node94')
        with mmap.mmap(self.stream.fileno(), 0, access=mmap.ACCESS_COPY) as changed:
            changed[0x46cda60] ^= 1
            with self.assertRaises(ValueError): route.authenticate(changed)

    def test_small_native_slice_binding_repeat_exports_and_packet(self):
        with tempfile.TemporaryDirectory() as tmp:
            first, second, supplied = Path(tmp) / 'first', Path(tmp) / 'second', Path(tmp) / 'supplied'
            supplied.symlink_to(BINARY)
            native_run = route.subprocess.check_output; controls = []
            def checked_native(argv, **kwargs):
                if '-D' in argv:
                    selected = Path(argv[-1])
                    self.assertEqual(selected.stat().st_size, 1478)
                    self.assertEqual(selected.parent.stat().st_mode & 0o777, 0o700)
                    self.assertEqual(selected.read_bytes(), self.body)
                    if not controls:
                        supplied.unlink(); supplied.write_bytes(b'replaced input name')
                    controls.append(True)
                return native_run(argv, **kwargs)
            with mock.patch.object(route.subprocess, 'check_output', side_effect=checked_native):
                actual = route.collect(supplied, first)
            self.assertEqual(controls, [True])
            route.collect(BINARY, second)
            for name in ('records.json', 'body.objdump.txt'):
                self.assertEqual((first / name).read_bytes(), (second / name).read_bytes())
            expected = json.loads((PACKET / 'records.json').read_text())
            actual.pop('native_tool_version'); expected.pop('native_tool_version')
            self.assertEqual(actual, expected)
            with self.assertRaises(FileExistsError): route.collect(BINARY, first)

    def test_packet_manifest(self):
        entries = dict(line.split('  ', 1)[::-1] for line in (PACKET / 'MANIFEST.sha256').read_text().splitlines())
        self.assertEqual(set(entries), {p.name for p in PACKET.iterdir() if p.name != 'MANIFEST.sha256'})
        for name, digest in entries.items(): self.assertEqual(hashlib.sha256((PACKET / name).read_bytes()).hexdigest(), digest)


if __name__ == '__main__': unittest.main()
