"""Static controls for the complete node #115 ring-range leaf; MIT."""
from contextlib import contextmanager
import mmap
from pathlib import Path
import re
import struct
import tempfile
import unittest
from unittest import mock

from tools import node115_ring_ranges as b


class RingRangesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.handle = b.TARGET.open('rb')
        # One private copy-on-write map; changes touch only the selected pages.
        cls.data = mmap.mmap(cls.handle.fileno(), 0, access=mmap.ACCESS_COPY)
        b.authenticate(cls.data)
        cls.record = b.inspect(cls.data)
        cls.body = bytes.fromhex(cls.record['function']['body_hex'])
        namespace = {'__file__': str(b.PACKET / 'verify.py'), '__name__': 'packet_verifier'}
        exec(compile((b.PACKET / 'verify.py').read_bytes(), 'verify.py', 'exec'), namespace)
        cls.verifier = namespace

    @classmethod
    def tearDownClass(cls):
        cls.data.close()
        cls.handle.close()

    @contextmanager
    def changed(self, offset, raw):
        saved = self.data[offset:offset + len(raw)]
        try:
            self.data[offset:offset + len(raw)] = raw
            yield
        finally:
            self.data[offset:offset + len(raw)] = saved

    def test_authenticated_regeneration_is_byte_identical(self):
        self.assertEqual((b.PACKET / 'records.json').read_bytes(), b.records_bytes(self.record))
        self.assertEqual((b.PACKET / 'README.md').read_text(), b.render_readme(self.record))
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp) / 'packet'
            b.generate(b.TARGET, out)
            for name in ('README.md', 'records.json'):
                self.assertEqual((out / name).read_bytes(), (b.PACKET / name).read_bytes())

    def test_digest_gate_rejects_same_size_mutation_before_inspection_and_output(self):
        @contextmanager
        def injected(_):
            yield self.data
        with tempfile.TemporaryDirectory() as temp, self.changed(0x100, bytes([self.data[0x100] ^ 1])):
            out = Path(temp) / 'must-not-exist'
            with mock.patch.object(b, 'mapped', injected), mock.patch.object(b, 'inspect') as inspect:
                with self.assertRaisesRegex(ValueError, 'SHA-256'):
                    b.generate('injected-copy-on-write-target', out)
                inspect.assert_not_called()
            self.assertFalse(out.exists())

    def test_wrong_size_rejected_before_output(self):
        with tempfile.TemporaryDirectory() as temp:
            wrong = Path(temp) / 'wrong'
            wrong.write_bytes(b'not the target')
            out = Path(temp) / 'output'
            with self.assertRaisesRegex(ValueError, 'SHA-256'):
                b.generate(wrong, out)
            self.assertFalse(out.exists())

    def test_every_body_byte_mutation_rejected_below_digest_gate(self):
        for index in range(len(self.body)):
            bad = bytearray(self.body)
            bad[index] ^= 1
            with self.subTest(index=index), self.assertRaises(ValueError):
                b.certify_body(bad)

    def test_actual_shifted_fde_rejected_below_digest_gate(self):
        off = b.FDE['fde'] + 8
        value = struct.unpack_from('<i', self.data, off)[0]
        with self.changed(off, struct.pack('<i', value + 1)):
            with self.assertRaisesRegex(ValueError, 'FDE'):
                b.inspect(self.data)

    def test_actual_extended_fde_rejected_below_digest_gate(self):
        off = b.FDE['fde'] + 12
        with self.changed(off, struct.pack('<I', b.END - b.START + 1)):
            with self.assertRaisesRegex(ValueError, 'FDE'):
                b.inspect(self.data)

    def test_actual_cie_mutation_rejected(self):
        # Change CFA offset, keeping the CIE parseable.
        off = b.FDE['cie'] + 18
        with self.changed(off, bytes([self.data[off] ^ 1])):
            with self.assertRaisesRegex(ValueError, 'CIE'):
                b.inspect(self.data)

    def test_wrong_actual_incoming_callee_target_rejected(self):
        off = b.CALLERS[0][0] - 0x1000 + 1
        with self.changed(off, bytes([self.data[off] ^ 1])):
            with self.assertRaisesRegex(ValueError, 'caller census/target'):
                b.inspect(self.data)

    def test_actual_source_relocation_rejected(self):
        off = b.LOCATIONS[0][2] + 16
        with self.changed(off, struct.pack('<q', b.LOCATIONS[0][3] + 1)):
            with self.assertRaisesRegex(ValueError, 'relocation'):
                b.inspect(self.data)

    def test_actual_source_location_rejected(self):
        off = b.LOCATIONS[0][1] - 0x2000 + 16
        with self.changed(off, struct.pack('<I', b.LOCATIONS[0][5] + 1)):
            with self.assertRaisesRegex(ValueError, 'Location words'):
                b.inspect(self.data)

    def test_padding_mutation_rejected(self):
        with self.changed(b.END - 0x1000, b'\x90'):
            with self.assertRaisesRegex(ValueError, 'padding'):
                b.inspect(self.data)

    def test_stride_mutation_changes_decoded_operand_and_is_rejected(self):
        bad = bytearray(self.body)
        off = 0x24cdb14 - b.START
        bad[off:off + 4] = struct.pack('<i', 400)
        decoded = b.decode(bad, b.START)
        self.assertEqual([r['immediate'] for r in decoded if r['mnemonic'] == 'imul'], [400, 408, 408])
        with self.assertRaisesRegex(ValueError, 'instruction contract'):
            b.certify_body(bad)

    def test_branch_retarget_changes_decode_and_is_rejected(self):
        bad = bytearray(self.body)
        bad[0x24cdafc - b.START] += 1
        row = next(r for r in b.decode(bad, b.START) if r['mnemonic'] == 'ja')
        self.assertEqual(row['target'], 0x24cdb0e)
        with self.assertRaisesRegex(ValueError, 'instruction contract'):
            b.certify_body(bad)

    def test_input_offset_mutation_rejected(self):
        bad = bytearray(self.body)
        bad[6] = 0x10  # L load becomes H load, still a valid instruction.
        self.assertEqual(b.decode(bad, b.START)[1]['operands'], ['r8', '[rsi+0x10]'])
        with self.assertRaisesRegex(ValueError, 'instruction contract'):
            b.certify_body(bad)

    def test_strict_decoder_rejects_unsupported_and_truncated_forms(self):
        for code in (b'\x90', b'\x48\x8b', b'\xe8\x00', b'\xff\xd0',
                     b'\x48\x0f\x42\xfa', b'\x48\x8b\x04\x00', b'\x48\x8d\xc0'):
            with self.subTest(code=code.hex()), self.assertRaises(ValueError):
                b.decode(code, b.START)
        for row in self.record['function']['instructions']:
            code = bytes.fromhex(row['bytes'])
            self.assertEqual(b.decode(code, row['address']), [row])
            if len(code) > 1:
                with self.assertRaises(ValueError):
                    b.decode(code[:-1], row['address'])

    def test_full_byte_coverage_branch_closure_and_no_callees(self):
        rows = self.record['function']['instructions']
        self.assertEqual(b''.join(bytes.fromhex(r['bytes']) for r in rows), self.body)
        cursor = b.START
        for row in rows:
            self.assertEqual(row['address'], cursor)
            cursor += row['size']
        self.assertEqual(cursor, b.END)
        self.assertEqual(rows[-1]['mnemonic'], 'ret')
        self.assertFalse(any(r['mnemonic'] == 'call' for r in rows))
        self.assertTrue(all(r['target'] in {q['address'] for q in rows} for r in rows if 'target' in r))
        self.assertEqual(self.record['function']['callees'], [])

    def test_full_text_census_includes_every_saved_site(self):
        scan = self.record['caller_scan']
        self.assertEqual((scan['start'], scan['end']), (b.TEXT_START, b.TEXT_END))
        self.assertEqual([r['address'] for r in scan['candidates']], [r[0] for r in b.CALLERS])
        for row in scan['callers']:
            self.assertIn(row['instruction'], row['instructions'])
            self.assertEqual(row['instruction']['target'], b.START)

    def test_scan_includes_last_possible_offset_and_tail_jumps(self):
        # A sparse fake mapping exercises the real full-range scanner without
        # allocating another target-sized image or executing native instructions.
        class SparseData:
            def __init__(self):
                self.sites = {b.TEXT_START - 0x1000: b'\xe8', b.TEXT_END - 0x1000 - 5: b'\xe9'}
            def find(self, byte, start, end):
                return next((p for p in sorted(self.sites) if start <= p < end and self.sites[p] == byte), -1)
            def __getitem__(self, key):
                pos = key.start
                va = pos + 0x1000
                return self.sites[pos] + struct.pack('<i', b.START - va - 5)
        class SparseImage:
            def __init__(self):
                self.data = SparseData()
            def section(self, _):
                return {'address': b.TEXT_START, 'offset': b.TEXT_START - 0x1000,
                        'size': b.TEXT_END - b.TEXT_START, 'flags': 6}
        # unpack_from requires a buffer; provide only the requested rel32 in
        # this scanner boundary test, retaining the native implementation above.
        original = struct.unpack_from
        def unpack(fmt, data, offset):
            if isinstance(data, SparseData):
                va = offset - 1 + 0x1000
                return (b.START - va - 5,)
            return original(fmt, data, offset)
        with mock.patch.object(b.struct, 'unpack_from', unpack):
            rows = b.scan_calls(SparseImage(), b.START)
        self.assertEqual([(r['address'], r['mnemonic']) for r in rows],
                         [(b.TEXT_START, 'call'), (b.TEXT_END - 5, 'jmp')])

    def test_frozen_vectors_and_raw_word_edges(self):
        for label, args, expected in b.VECTORS:
            with self.subTest(case=label):
                self.assertEqual(b.project(*args), expected)
        self.assertNotEqual(b.project(8, 4096, 16, 1), b.project(8, 4096, 0, 1))
        for args in ((-1, 0, 0, 0), (0, 1 << 64, 0, 0), (True, 0, 0, 0)):
            with self.assertRaises(ValueError):
                b.project(*args)

    def test_valid_rings_against_independent_enumerated_index_oracle(self):
        for capacity in range(1, 25):
            for head in range(2 * capacity):
                for length in range(capacity + 1):
                    # Enumerate logical items and split when physical indices
                    # descend; this does not repeat the machine's L>tail rule.
                    indices = [(head + i) % capacity for i in range(length)]
                    if not indices:
                        expected = (4096,) * 4
                    else:
                        runs = [[indices[0]]]
                        for index in indices[1:]:
                            if index != runs[-1][-1] + 1:
                                runs.append([])
                            runs[-1].append(index)
                        first = runs[0]
                        second_end = runs[1][-1] + 1 if len(runs) > 1 else 0
                        expected = (4096 + 408 * first[0], 4096 + 408 * (first[-1] + 1),
                                    4096, 4096 + 408 * second_end)
                    self.assertEqual(b.project(capacity, 4096, head, length), expected)

    def test_readme_counts_equal_json_and_actual_records(self):
        r = self.record
        c = r['counts']
        table = {name: int(value) for name, value in re.findall(
            r'^\| ([a-z_]+) \| ([0-9]+) \|$', (b.PACKET / 'README.md').read_text(), re.M)}
        self.assertEqual(table, c)
        self.assertEqual(c, {
            'function_bytes': r['function']['end'] - r['function']['start'],
            'instructions': len(r['function']['instructions']), 'callees': len(r['function']['callees']),
            'direct_call_sites': sum(q['mnemonic'] == 'call' for q in r['caller_scan']['candidates']),
            'caller_fdes': len({q['owner']['start'] for q in r['caller_scan']['callers']}),
            'direct_tail_jump_sites': sum(q['mnemonic'] == 'jmp' for q in r['caller_scan']['candidates']),
            'source_locations': len(r['source_association']), 'vectors': len(r['vectors']),
            'padding_before': len(bytes.fromhex(r['function']['padding'][0]['bytes'])),
            'padding_after': len(bytes.fromhex(r['function']['padding'][1]['bytes'])),
        })

    def test_manifest_exact_whitelist_and_packet_verifier(self):
        self.assertEqual(self.verifier['verify'](), self.record['counts'])
        text = (b.PACKET / 'MANIFEST.sha256').read_text()
        row = text.splitlines()[0]
        for bad in (text + row + '\n', '\n'.join(text.splitlines()[1:]) + '\n',
                    text + '0' * 64 + '  ../../escape\n', text + '0' * 64 + '  extra.json\n'):
            with self.assertRaises(ValueError):
                self.verifier['manifest_entries'](bad)

    def test_verifier_rejects_artifact_drift_and_unlisted_file(self):
        with tempfile.TemporaryDirectory() as temp:
            packet = Path(temp)
            for path in b.PACKET.iterdir():
                (packet / path.name).write_bytes(path.read_bytes())
            (packet / 'records.json').write_text('{}\n')
            with self.assertRaisesRegex(ValueError, 'hash mismatch'):
                self.verifier['verify'](packet=packet)
            (packet / 'records.json').write_bytes((b.PACKET / 'records.json').read_bytes())
            (packet / 'unlisted').write_text('unexpected')
            with self.assertRaisesRegex(ValueError, 'file whitelist'):
                self.verifier['verify'](packet=packet)


if __name__ == '__main__':
    unittest.main()
