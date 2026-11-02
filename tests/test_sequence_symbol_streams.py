# SPDX-License-Identifier: MIT
"""Static controls for the packed-symbol leaf; no native target execution."""
import copy
import hashlib
import json
import mmap
from pathlib import Path
import re
import struct
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import sequence_symbol_streams as subject


class SequenceSymbolStreamsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.handle = subject.BINARY.open('rb')
        cls.data = mmap.mmap(cls.handle.fileno(), 0, access=mmap.ACCESS_READ)
        if hashlib.sha256(cls.data).hexdigest() != subject.SHA256:
            raise ValueError('test target digest mismatch')
        cls.image = subject.Image(cls.data)
        cls.body = cls.image.read(subject.START, subject.END - subject.START)
        cls.records = json.loads((subject.PACKET / 'records.json').read_text())

    @classmethod
    def tearDownClass(cls):
        cls.data.close()
        cls.handle.close()

    def offset(self, va):
        s = next(s for s in self.image.sections if s['type'] != 8
                 and s['flags'] & 2 and s['address'] <= va < s['address'] + s['size'])
        return s['offset'] + va - s['address']

    def rejected_patch(self, va, replacement, regex=None):
        # Copy-on-write mapping shares file pages and only copies touched pages.
        with mmap.mmap(self.handle.fileno(), 0, access=mmap.ACCESS_COPY) as changed:
            off = self.offset(va)
            changed[off:off + len(replacement)] = replacement
            with self.assertRaisesRegex(ValueError, regex or '.'):
                subject.analyze(changed)

    def temporary_packet(self, folder):
        folder = Path(folder)
        for name in subject.PACKET_NAMES:
            (folder / name).write_bytes((subject.PACKET / name).read_bytes())
        return folder

    def test_packet_reproduces_without_process_tools(self):
        with mock.patch('subprocess.Popen', side_effect=AssertionError('external tool')):
            subject.check_packet(subject.PACKET, self.data)

    def test_cli_out_is_byte_identical(self):
        with tempfile.TemporaryDirectory() as folder:
            self.assertEqual(subject.main(['--out', folder]), 0)
            for name in subject.PACKET_NAMES:
                self.assertEqual((Path(folder) / name).read_bytes(),
                                 (subject.PACKET / name).read_bytes(), name)

    def test_decoder_tiles_entire_body_and_closes_cfg(self):
        ins = subject.validate_body(self.body)
        self.assertEqual(b''.join(i.raw for i in ins), self.body)
        dead = subject.check_cfg(ins)
        self.assertEqual([(i.address, i.op, len(i.raw)) for i in dead],
                         [(0x555f2e1, 'nop', 7)])
        self.assertEqual([i.address for i in ins if i.op == 'ret'], [0x555f2e0])
        self.assertFalse(any(i.op == 'call' for i in ins))

    def test_decoded_rule_operands_and_widths(self):
        ins = {i.address: i for i in subject.decode(self.body, subject.START)}
        expected = {
            0x555f269: ('sar', ('rcx', '0x3')),
            0x555f26d: ('mov', ('ebx', 'ecx')),
            0x555f273: ('bsr', ('edi', '32-bit [rsi+rdx*8]')),
            0x555f277: ('movzx', ('ecx', '16-bit [rsi+rdx*8+0x4]')),
            0x555f284: ('movzx', ('edi', '16-bit [rsi+rdx*8+0x6]')),
            0x555f289: ('cmp', ('ecx', '0x3f')),
            0x555f2a2: ('cmp', ('edi', '0x7f')),
            0x555f2aa: ('lea', ('ecx', '[rdi+0x24]')),
            0x555f2eb: ('add', ('ecx', '0x13')),
            0x555f2c5: ('mov', ('8-bit [r8+rdx*1]', '0x23')),
            0x555f2d5: ('mov', ('8-bit [r9+rax*1]', '0x34')),
            0x555f2db: ('xor', ('eax', 'eax')),
        }
        for va, want in expected.items():
            with self.subTest(va=hex(va)):
                self.assertEqual((ins[va].op, ins[va].args), want)

    def test_every_body_byte_mutation_is_rejected(self):
        for offset in range(len(self.body)):
            changed = bytearray(self.body)
            changed[offset] ^= 1
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                subject.validate_body(bytes(changed))

    def test_unsupported_and_truncated_decodes_fail_closed(self):
        for raw in ('ff', 'ff10', 'f2', 'f390', '48', '0fb7', '488b84',
                    'e80102', 'c7c001000000', '83d001', '0f1f80000000'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                subject.decode(bytes.fromhex(raw), subject.START)

    def test_leaf_rejects_injected_callee(self):
        raw = b'\xe8' + struct.pack('<i', 0x100) + b'\xc3'
        ins = subject.decode(raw, subject.START)
        with self.assertRaisesRegex(ValueError, 'callee'):
            subject.check_cfg(ins, subject.START, subject.START + len(raw))

    def test_branch_into_instruction_is_rejected(self):
        changed = bytearray(self.body)
        changed[0x555f271 - subject.START + 1] += 1
        with self.assertRaisesRegex(ValueError, 'branch'):
            subject.check_cfg(subject.decode(changed, subject.START))

    def test_target_digest_wrong_and_no_output_written(self):
        with tempfile.TemporaryDirectory() as folder:
            fake = Path(folder) / 'wrong-node'
            with fake.open('wb') as handle:
                handle.truncate(subject.SIZE)  # Sparse file; no full binary copies.
            output = Path(folder) / 'packet'
            with self.assertRaisesRegex(ValueError, 'digest'):
                with subject.target(fake):
                    self.fail('wrong digest admitted')
            self.assertEqual(subject.main(['--binary', str(fake), '--out', str(output)]), 1)
            self.assertFalse(output.exists())

    def test_target_size_wrong(self):
        with tempfile.TemporaryDirectory() as folder:
            fake = Path(folder) / 'short-node'
            fake.write_bytes(b'\x7fELF')
            with self.assertRaisesRegex(ValueError, 'size'):
                with subject.target(fake):
                    self.fail('wrong size admitted')

    def test_shifted_fde_start_is_rejected(self):
        va = int(self.records['function']['fde_va'], 16) + 8
        old = struct.unpack('<i', self.image.read(va, 4))[0]
        self.rejected_patch(va, struct.pack('<i', old + 1), 'FDE')

    def test_shortened_fde_extent_is_rejected(self):
        va = int(self.records['function']['fde_va'], 16) + 12
        self.rejected_patch(va, struct.pack('<I', len(self.body) - 1), 'FDE')

    def test_shifted_cie_link_is_rejected(self):
        va = int(self.records['function']['fde_va'], 16) + 4
        old = struct.unpack('<I', self.image.read(va, 4))[0]
        self.rejected_patch(va, struct.pack('<I', old + 1), 'CIE')

    def test_substituted_valid_fde_record_is_rejected(self):
        frame = copy.deepcopy(self.records['function'])
        frame['fde_section_offset'] = self.records['next_frame']['fde_section_offset']
        with self.assertRaisesRegex(ValueError, 'association'):
            subject.check_frame(frame)

    def test_padding_corruption_is_rejected(self):
        self.rejected_patch(subject.END, b'\x90', 'padding')

    def test_table_data_corruption_is_rejected(self):
        for va, _ in subject.TABLES:
            with self.subTest(table=hex(va)):
                self.rejected_patch(va, b'\xff', 'table')

    def test_wrong_table_reference_is_rejected(self):
        va = 0x555f28e + 3
        old = struct.unpack('<i', self.image.read(va, 4))[0]
        self.rejected_patch(va, struct.pack('<i', old + 1), 'body|table')

    def test_wrong_incoming_call_target_is_rejected(self):
        for site in subject.CALL_SITES:
            va = site + 1
            old = struct.unpack('<i', self.image.read(va, 4))[0]
            with self.subTest(site=hex(site)):
                self.rejected_patch(va, struct.pack('<i', old + 1), 'census')

    def test_full_text_scan_matches_json(self):
        self.assertEqual(subject.scan_rel32(self.image, subject.START), self.records['incoming'])
        self.assertEqual(len(self.records['callees']), 0)
        self.assertEqual([r['opcode'] for r in self.records['incoming']], ['0xe8', '0xe8'])

    def test_table_and_fallback_models_cover_all_u16_values(self):
        a = self.image.read(*subject.TABLES[0])
        b = self.image.read(*subject.TABLES[1])
        for value in range(1 << 16):
            self.assertEqual(subject.symbol_a(value),
                             a[value] if value < len(a) else value.bit_length() - 1 + 19)
            self.assertEqual(subject.symbol_b(value),
                             b[value] if value < len(b) else value.bit_length() - 1 + 36)

    def test_threshold_neighbors_have_reviewed_codes(self):
        for value, code in ((15, 15), (16, 16), (23, 19), (24, 20),
                            (31, 21), (32, 22), (47, 23), (48, 24),
                            (63, 24), (64, 25), (65535, 34)):
            self.assertEqual(subject.symbol_a(value), code)
        for value, code in ((31, 31), (32, 32), (39, 35), (40, 36),
                            (63, 39), (64, 40), (95, 41), (96, 42),
                            (127, 42), (128, 43), (65535, 51)):
            self.assertEqual(subject.symbol_b(value), code)

    def test_bsr_power_edges(self):
        for power in range(32):
            value = 1 << power
            self.assertEqual(subject.model([(value, 0, 0)])['c'], bytes([power]).hex())
            if power:
                self.assertEqual(subject.model([(value - 1, 0, 0)])['c'],
                                 bytes([power - 1]).hex())
        self.assertEqual(subject.model([(0xffffffff, 0, 0)])['c'], '1f')

    def test_zero_bsr_is_outside_model_domain(self):
        with self.assertRaisesRegex(ValueError, 'BSR'):
            subject.model([(0, 0, 0)])

    def test_span_narrowing_wrap_and_unaligned_edges(self):
        for begin, end, expected in ((0x1000, 0x1000, 0), (0x1000, 0x1007, 0),
                                     (0x1000, 0x100f, 1), (8, 0, 0xffffffff),
                                     ((1 << 64) - 8, 0, 1),
                                     (0, (1 << 32) * 8, 0),
                                     (0, ((1 << 32) + 2) * 8, 2)):
            self.assertEqual(subject.count_from_span(begin, end), expected)

    def test_overrides_do_not_depend_on_record_count(self):
        self.assertEqual(subject.model([], 1, 1, 3),
                         {'return': 0, 'a': 'a523a5', 'b': 'a5a5a5', 'c': 'a5a5a5'})
        self.assertEqual(subject.model([], 2, 1, 3)['b'], 'a534a5')
        out = subject.model([(0xffffffff, 65535, 65535)], 2)
        self.assertEqual(out, {'return': 0, 'a': '22', 'b': '34', 'c': '1f'})
        self.assertEqual(subject.model([(1, 1, 1)], 1, 2, 3)['a'], '01a523')
        self.assertEqual(subject.model([], 0xffffffff, 0xffffffff, 1)['a'], 'a5')
        with self.assertRaisesRegex(ValueError, 'allocation'):
            subject.model([], 1, 0)

    def test_recorded_vectors_and_return(self):
        for v in self.records['vectors']:
            with self.subTest(name=v['name']):
                self.assertEqual(subject.model(v['records'], v['tag'], v['position'], v['capacity']),
                                 v['result'])
                self.assertEqual(v['result']['return'], self.records['rule']['return'])
        self.assertEqual(self.records['vectors'][2]['result'],
                         {'return': 0, 'a': '181922', 'b': '2a2b33', 'c': '02031f'})

    def test_readme_counts_equal_json_and_rederived_counts(self):
        readme = (subject.PACKET / 'README.md').read_text()
        self.assertEqual(readme, subject.render_readme(self.records))
        actual = {name: int(value) for name, value in
                  re.findall(r'^\| ([^|]+) \| ([0-9]+) \|$', readme, re.MULTILINE)}
        self.assertEqual(actual, subject.metrics(self.records))
        ins = subject.decode(self.body, subject.START)
        self.assertEqual(actual['Decoded instructions'], len(ins))
        self.assertEqual(actual['Reachable instructions'], len(ins) - len(subject.check_cfg(ins)))
        self.assertEqual(actual['Function bytes'], len(self.body))
        self.assertEqual(actual['Focused tests passed'],
                         unittest.defaultTestLoader.loadTestsFromTestCase(type(self)).countTestCases())
        self.assertEqual(actual['E8 call candidates'], len(self.records['incoming']))
        self.assertEqual(actual['Direct or indirect callees'], len(self.records['callees']))
        self.assertEqual(actual['Lookup tables'], len(self.records['tables']))
        self.assertEqual(actual['Full .text bytes scanned'], self.image.by_name['.text']['size'])

    def test_novelty_snapshot_is_empty_and_address_in_band(self):
        self.assertTrue(0x5000000 <= subject.START < 0x5660000)
        checks = self.records['novelty']['checks']
        self.assertEqual({c['pattern'] for c in checks}, {f'{subject.START:x}', str(subject.START)})
        self.assertEqual({c['scope'] for c in checks}, {'research', 'PR titles'})
        for check in checks:
            self.assertEqual((check['exit_code'], check['stdout'], check['stderr']), (1, '', ''))

    def test_manifest_detects_changed_evidence(self):
        with tempfile.TemporaryDirectory() as folder:
            p = self.temporary_packet(folder)
            with (p / 'disassembly.txt').open('ab') as handle:
                handle.write(b'changed\n')
            with self.assertRaisesRegex(ValueError, 'manifest digest'):
                subject.check_packet(p, self.data)

    def test_rehashed_false_semantic_record_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            p = self.temporary_packet(folder)
            rec = copy.deepcopy(self.records)
            rec['incoming'] = []
            (p / 'records.json').write_text(json.dumps(rec) + '\n')
            (p / 'MANIFEST.sha256').write_text(''.join(
                f'{subject.digest((p / name).read_bytes())}  {name}\n'
                for name in sorted(subject.PAYLOAD_NAMES)))
            with self.assertRaisesRegex(ValueError, 'regeneration mismatch'):
                subject.check_packet(p, self.data)

    def test_manifest_whitelist_duplicates_and_traversal(self):
        for alteration in ('duplicate', 'traversal', 'extra', 'symlink'):
            with self.subTest(alteration=alteration), tempfile.TemporaryDirectory() as folder:
                p = self.temporary_packet(folder)
                manifest = p / 'MANIFEST.sha256'
                if alteration == 'duplicate':
                    manifest.write_text(manifest.read_text() + manifest.read_text().splitlines()[0] + '\n')
                elif alteration == 'traversal':
                    manifest.write_text('0' * 64 + '  ../records.json\n')
                elif alteration == 'extra':
                    (p / 'surprise.txt').write_text('not evidence')
                else:
                    (p / 'frames.txt').unlink()
                    (p / 'frames.txt').symlink_to(subject.PACKET / 'frames.txt')
                with self.assertRaises(ValueError):
                    subject.verify_manifest(p)


if __name__ == '__main__':
    unittest.main()
