"""Actual Node94 fields/native bytes and private corruption controls; no execution."""
import hashlib
import json
import mmap
import os
from pathlib import Path
import shutil
import struct
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import rate_result_writeback_static as writeback

BINARY = ROOT / writeback.TARGET
PACKET = ROOT / 'research/work-items/RE-001-rate-result-writeback-94'


class WritebackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.stream = BINARY.open('rb')
        cls.data = mmap.mmap(cls.stream.fileno(), 0, access=mmap.ACCESS_READ)
        if len(cls.data) != writeback.SIZE or hashlib.sha256(cls.data).hexdigest() != writeback.SHA256:
            raise ValueError('Actual Node94 identity mismatch')
        cls.image = writeback.Image(cls.data)
        cls.record = writeback.inspect_bytes(cls.data)
        cls.body = cls.image.read(writeback.START, writeback.END - writeback.START)[1]

    @classmethod
    def tearDownClass(cls):
        cls.data.close()
        cls.stream.close()

    def reject(self, offset, value):
        with mmap.mmap(self.stream.fileno(), 0, access=mmap.ACCESS_COPY) as changed:
            changed[offset:offset + len(value)] = value
            with self.assertRaises(ValueError):
                writeback.inspect_bytes(changed)

    def test_actual_extent_calls_lsda_and_last_stores(self):
        r = self.record
        self.assertEqual((r['body']['start'], r['body']['end'], r['body']['bytes']),
                         ('0x4959020', '0x495921e', 510))
        self.assertEqual(r['body']['sha256'], writeback.BODY_SHA256)
        raw_fde = self.image.read(writeback.FDE, 84)[1]
        self.assertEqual(struct.unpack_from('<I', raw_fde)[0] + 4, len(raw_fde))
        self.assertEqual(writeback.FDE + 4 - struct.unpack_from('<I', raw_fde, 4)[0], writeback.CIE)
        self.assertEqual(writeback.FDE + 8 + struct.unpack_from('<i', raw_fde, 8)[0], writeback.START)
        self.assertEqual(struct.unpack_from('<i', raw_fde, 12)[0], 510)
        self.assertEqual(len(r['calls']), 12)
        self.assertEqual(len(r['relocations']), 8)
        self.assertEqual([row['raw_uleb_values'] for row in r['lsda']['rows']], writeback.LSDA_ROWS)
        self.assertEqual(r['lsda']['first_action'], {'type_filter': -1, 'next_action': 0})
        self.assertEqual([(w['offset'], w['source_register']) for w in r['observed_tail_writes']],
                         [(0, 'r12'), (8, 'rax'), (16, 'rbp'), (24, 'rcx')])
        # Independently inspect the actual store encodings, not only JSON labels.
        self.assertEqual(self.image.read(0x495917a, 15)[1], bytes.fromhex('4d89264989460849896e1049894e18'))
        calls = {row['va']: row for row in r['calls']}
        self.assertEqual((calls['0x49591a5']['return_pc'], calls['0x49591a5']['unwind_lookup_pc'],
                          calls['0x49591a5']['lsda_row_index']), ('0x49591ab', '0x49591aa', 1))
        self.assertIsNone(calls['0x49591eb']['lsda_row_index'])
        self.assertFalse(r['captured_binary_executed'])
        self.assertFalse(r['component_gates_requested'])

    def test_encoded_zero_route_bound_and_same_destination_operands(self):
        self.assertEqual(self.image.read(0x4959105, 19)[1],
                         bytes.fromhex('410fb7ac24321b00004883fd0b0f8395000000'))
        self.assertEqual([value for value in range(1 << 16) if value < 11], list(range(11)))
        imul = self.image.read(0x4959155, 7)[1]
        self.assertEqual(imul[:3], bytes.fromhex('4869c5'))
        self.assertEqual(struct.unpack_from('<i', imul, 3)[0], 608)
        self.assertEqual(self.image.read(0x495915c, 11)[1], bytes.fromhex('4c89e74801c7ba60020000'))
        self.assertEqual(self.image.read(0x4959170, 2)[1], bytes.fromhex('31c0'))
        # Architectural address arithmetic only; no pointer validity or copy effect.
        for base, index in [(0, 0), (0x1000, 10), ((1 << 64) - 1, 1)]:
            self.assertEqual((base + index * 608) & ((1 << 64) - 1),
                             (base + index * 608) % (1 << 64))

    def test_real_caller_r9_alias_and_consumed_word_offsets(self):
        bridge = bytes.fromhex(self.record['revisited_caller_bridge']['raw'])
        self.assertEqual(bridge[:10], bytes.fromhex('488d7c2458488d742420'))
        self.assertEqual(self.image.read(0x4959067, 4)[1], bytes.fromhex('4c8d4b38'))
        self.assertEqual(0x20 + 0x38, 0x58)
        self.assertEqual(bridge[-14:], bytes.fromhex('4869442468600200004803442458'))
        self.assertEqual(0x68 - 0x58, 16)
        self.assertIn('equals its output pointer', self.record['output_alias_observation'])
        self.assertIn('no locally established index bound', self.record['selected_contract'])

    def test_actual_instruction_pointer_and_call_corruptions(self):
        for va, replacement in [(0x4959037 + 2, b'\xff'), (0x495903a + 3, b'\x28'),
                                (0x4959067 + 3, b'\x30'), (0x495908a + 4, b'\x20'),
                                (0x4959105 + 5, b'\x33'), (0x4959112 + 1, b'\x82'),
                                (0x4959155 + 3, b'\x61'), (0x495915c + 2, b'\xef'),
                                (0x4959170, b'\x30'), (0x495917a + 2, b'\x27'),
                                (0x4959181 + 3, b'\x18'), (0x4956e63 + 4, b'\x50')]:
            with self.subTest(va=hex(va)):
                self.reject(self.image.read(va, 1)[0], replacement)
        for row in self.record['calls']:
            va = int(row['va'], 16)
            offset, raw = self.image.read(va, 6)
            displacement = 1 if raw[0] == 0xe8 else 2
            with self.subTest(call=row['va']):
                self.reject(offset + displacement, bytes([raw[displacement] ^ 1]))

    def test_actual_relocation_cfi_and_lsda_corruptions(self):
        for row in self.record['relocations']:
            offset = int(row['file_offset'], 16) + 16
            with self.subTest(relocation=row['slot']):
                self.reject(offset, bytes([self.data[offset] ^ 1]))
        controls = [(int(self.record['fde']['file_offset'], 16) + 12, b'\xff'),
                    (int(self.record['cie']['raw_record']['file_offset'], 16) + 19, b'\x28')]
        for delta in (1, 5, 39):
            off = int(self.record['lsda']['file_offset'], 16) + delta
            controls.append((off, bytes([self.data[off] ^ 1])))
        for offset, value in controls:
            with self.subTest(offset=hex(offset)):
                self.reject(offset, value)

    def test_native_rows_reject_bad_bytes_and_interior_branch(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'normal'
            normal = writeback.collect(BINARY, output)
            text = (output / 'helper.objdump.txt').read_text()
            rows, graph = writeback.native_rows(text, self.body)
            self.assertEqual((len(rows), len(graph['calls']), len(graph['branches'])), (119, 12, 8))
            self.assertTrue(all(graph['tail_store_dominance'].values()))
            self.assertTrue(graph['index_bound_branch_dominates_last_imported_call'])
            self.assertFalse(graph['index_ge_11_route_reaches_local_return'])
            self.assertEqual(graph['fallthrough_outside_extent'], ['0x4959218'])
            self.assertEqual(normal['native']['rows'], 119)
            changed = bytearray(self.body)
            changed[0] ^= 1
            with self.assertRaisesRegex(ValueError, 'row bytes'):
                writeback.native_rows(text, changed)
            changed = bytearray(self.body)
            changed[0x495903f - writeback.START + 1] += 1
            with writeback.private_slice(changed) as path:
                # Real native decoding of one corrupted owned raw slice, not execution.
                mutated = writeback.subprocess.check_output(normal['native']['argv'], cwd=path.parent,
                                                            encoding='utf-8', env=dict(os.environ, LC_ALL='C'))
            with self.assertRaisesRegex(ValueError, 'branch target'):
                writeback.native_rows(mutated, changed)

    def test_native_reader_stays_on_slice_when_private_source_path_changes(self):
        with tempfile.TemporaryDirectory() as temporary:
            supplied = Path(temporary) / 'input.elf'
            with supplied.open('xb') as target, BINARY.open('rb') as source:
                shutil.copyfileobj(source, target, length=1024 * 1024)
            output = Path(temporary) / 'output'
            native = writeback.subprocess.check_output
            visited = []
            def replace_path(argv, **kwargs):
                if '-D' in argv and not visited:
                    path = Path(kwargs['cwd']) / argv[-1]
                    self.assertEqual(path.stat().st_size, 510)
                    self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                    self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
                    self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), writeback.BODY_SHA256)
                    supplied.unlink()
                    supplied.write_bytes(b'private replacement')
                    visited.append(path)
                return native(argv, **kwargs)
            with mock.patch.object(writeback.subprocess, 'check_output', side_effect=replace_path):
                with self.assertRaisesRegex(ValueError, 'Source changed'):
                    writeback.collect(supplied, output)
            self.assertEqual(len(visited), 1)
            self.assertFalse(visited[0].exists())
            self.assertFalse(output.exists())
            self.assertEqual(hashlib.sha256(BINARY.read_bytes()).hexdigest(), writeback.SHA256)

    def test_actual_collector_repeat_and_existing_output_preservation(self):
        with tempfile.TemporaryDirectory() as temporary:
            first, second = Path(temporary) / 'first', Path(temporary) / 'second'
            actual = writeback.collect(BINARY, first)
            writeback.collect(BINARY, second)
            committed = json.loads((PACKET / 'observed/records.json').read_text())
            # Host tool versions can differ; no instruction/data operand is masked.
            actual['native'].pop('tool')
            committed['native'].pop('tool')
            self.assertEqual(actual, committed)
            self.assertEqual({p.name: p.read_bytes() for p in first.iterdir()},
                             {p.name: p.read_bytes() for p in second.iterdir()})
            before = {p.name: p.read_bytes() for p in first.iterdir()}
            with self.assertRaisesRegex(ValueError, 'new directory'):
                writeback.collect(BINARY, first)
            self.assertEqual({p.name: p.read_bytes() for p in first.iterdir()}, before)

    def test_wrong_identity_and_owned_slice_mutation_do_not_publish(self):
        with tempfile.TemporaryDirectory() as temporary:
            fake = Path(temporary) / 'not-node94'
            fake.write_bytes(b'private wrong input')
            output = Path(temporary) / 'output'
            with self.assertRaisesRegex(ValueError, 'identity mismatch'):
                writeback.collect(fake, output)
            self.assertFalse(output.exists())
        seen = []
        with self.assertRaisesRegex(ValueError, 'Owned slice changed'):
            with writeback.private_slice(self.body) as path:
                seen.append(path)
                path.write_bytes(bytes([self.body[0] ^ 1]) + self.body[1:])
        self.assertFalse(seen[0].exists())


if __name__ == '__main__':
    unittest.main()
