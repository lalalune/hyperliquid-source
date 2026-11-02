"""Static controls for the selected legacy transaction evidence exporter."""
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'tools'))
import re21_legacy_signature94 as subject


class OverlayView:
    def __init__(self, original, changes):
        self.original = original
        self.changes = changes
        self.data = original.data
        self.sections = original.sections

    def offset(self, *args, **kwargs):
        return self.original.offset(*args, **kwargs)

    def read(self, va, size, executable=False):
        raw = bytearray(self.original.read(va, size, executable))
        for address, mask in self.changes.items():
            if va <= address < va + size:
                raw[address - va] ^= mask
        return bytes(raw)


def decode_rlp_one(buf, pos=0):
    """Independent, recursive canonical RLP reader for synthetic test cases."""
    if pos >= len(buf):
        raise ValueError('missing prefix')
    p = buf[pos]
    if p < 128:
        return bytes((p,)), pos + 1
    if p < 184:
        n = p - 128
        end = pos + 1 + n
        if end > len(buf) or (n == 1 and buf[pos + 1] < 128):
            raise ValueError('bad short string')
        return bytes(buf[pos + 1:end]), end
    if p < 192:
        nlen = p - 183
        h = pos + 1 + nlen
        if h > len(buf) or buf[pos + 1] == 0:
            raise ValueError('bad length')
        n = int.from_bytes(buf[pos + 1:h], 'big')
        if n < 56 or h + n > len(buf):
            raise ValueError('bad long string')
        return bytes(buf[h:h + n]), h + n
    if p < 248:
        begin, end = pos + 1, pos + 1 + p - 192
    else:
        nlen = p - 247
        begin = pos + 1 + nlen
        if begin > len(buf) or buf[pos + 1] == 0:
            raise ValueError('bad list length')
        n = int.from_bytes(buf[pos + 1:begin], 'big')
        if n < 56:
            raise ValueError('noncanonical list length')
        end = begin + n
    if end > len(buf):
        raise ValueError('truncated list')
    result = []
    while begin < end:
        item, begin = decode_rlp_one(buf, begin)
        if begin > end:
            raise ValueError('child outside list')
        result.append(item)
    return result, end


class LegacyEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = subject.ARTIFACT.read_bytes()
        cls.view = subject.View(cls.data)
        cls.fdes = subject.selected_fdes(cls.data, cls.view)
        cls.const = subject.constants(cls.view)

    def test_exact_artifact_identity(self):
        self.assertEqual(subject.authenticate(self.data), subject.TARGET_SHA256)
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), subject.TARGET_SHA256)
        with self.assertRaises(ValueError):
            subject.authenticate(b'corrupt input')
        damaged = bytearray(self.data)
        damaged[-1] ^= 1
        with self.assertRaises(ValueError):
            subject.authenticate(damaged)

    def test_digest_checked_before_parsing_and_writing(self):
        with tempfile.TemporaryDirectory() as base:
            base = Path(base)
            bad = base / 'wrong-node'
            bad.write_bytes(b'not the pinned artifact')
            out = base / 'out'
            with mock.patch.object(subject, 'ARTIFACT', bad):
                with self.assertRaises(ValueError):
                    subject.main(['--out', str(out)])
            self.assertFalse(out.exists())

    def test_selected_fde_join_and_file_backing(self):
        self.assertEqual(len(self.fdes), 12)
        self.assertTrue(all(x['size'] > 0 for x in self.fdes))
        for f in self.fdes:
            start, end = int(f['start_va'], 16), int(f['end_va'], 16)
            self.assertEqual(end - start, f['size'])
            self.assertEqual(hashlib.sha256(self.view.read(start, f['size'], True)).hexdigest(), f['sha256'])
        with mock.patch.object(subject, 'unwind_index', return_value=([], [])):
            with mock.patch.object(subject, 'eh_frame_records', return_value=({}, [])):
                with self.assertRaises(ValueError):
                    subject.selected_fdes(self.data, self.view)

    def test_corrupt_unwind_index_and_fde_range(self):
        chosen = next(f for f in self.fdes if f['start_va'] == '0x1352710')
        hdr = next(s for s in self.view.sections if s['name'] == '.eh_frame_hdr')
        damaged = bytearray(self.data)
        index_fde_delta = hdr['offset'] + 12 + chosen['index'] * 8 + 4
        damaged[index_fde_delta] ^= 4
        with self.assertRaises(ValueError):
            subject.selected_fdes(damaged, subject.View(damaged))
        damaged[index_fde_delta] ^= 4
        fde_off = self.view.offset(int(chosen['fde_va'], 16), 16)
        struct.pack_into('<i', damaged, fde_off + 12, 0)
        with self.assertRaises(ValueError):
            subject.selected_fdes(damaged, subject.View(damaged))

    def test_all_fixed_windows_detect_single_byte_corruption(self):
        self.assertEqual(len(subject.check_windows(self.view)), len(subject.WINDOWS))
        for name, va, _ in subject.WINDOWS:
            with self.subTest(window=name):
                with self.assertRaises(ValueError):
                    subject.check_windows(OverlayView(self.view, {va: 1}))

    def test_selected_branch_opcodes_and_destinations(self):
        for name, va, prefix, target in subject.BRANCHES:
            with self.subTest(name=name):
                edge = subject.relative_edge(self.view, name, va, prefix, target)
                self.assertEqual(int(edge['target_va'], 16), target)
                with self.assertRaises(ValueError):
                    subject.relative_edge(OverlayView(self.view, {va: 1}), name, va, prefix, target)
                with self.assertRaises(ValueError):
                    subject.relative_edge(OverlayView(self.view, {va + len(bytes.fromhex(prefix)): 1}), name, va, prefix, target)
                with self.assertRaises(ValueError):
                    subject.relative_edge(self.view, name, va, prefix, target + 1)

    def test_instruction_shapes_and_misaligned_branch_rejection(self):
        for raw in (b'', b'\x48', b'\x0f', b'\x0f\xff', b'\xe8\x01\x00', b'\xf0\xc3'):
            with self.subTest(raw=raw.hex()):
                with self.assertRaises(ValueError):
                    subject.decode_instruction(raw)
        insns, transfers, starts = subject.walk_selected(self.view, self.fdes)
        self.assertEqual(sum(len(x['raw']) for x in insns), sum(f['size'] for f in self.fdes))
        self.assertIn(0x135273c, starts)
        self.assertTrue(any(x['site_va'] == '0x135273c' for x in transfers))
        # 0x135273c's two-byte branch is changed to target byte 0x135273f,
        # inside the immediately following instruction at 0x135273e.
        with self.assertRaisesRegex(ValueError, 'inside an instruction'):
            subject.walk_selected(OverlayView(self.view, {0x135273d: 0x0c}), self.fdes)

    def test_rip_calls_and_displacements(self):
        for name, va, slot in subject.RIP_CALLS:
            with self.subTest(name=name):
                self.assertEqual(int(subject.rip_edge(self.view, name, va, slot)['target_va'], 16), slot)
                with self.assertRaises(ValueError):
                    subject.rip_edge(OverlayView(self.view, {va + 2: 1}), name, va, slot)
                with self.assertRaises(ValueError):
                    subject.rip_edge(OverlayView(self.view, {va: 1}), name, va, slot)

    def test_missing_duplicate_or_corrupt_relocation(self):
        rows = subject.selected_relocations(self.data, self.view)
        self.assertEqual(len(rows), len(subject.RELOCATION_SPECS))
        damaged = bytearray(self.data)
        for row in rows:
            offset = int(row['entry_file_offset'], 16)
            damaged[offset + 8] ^= 1
            try:
                with self.subTest(slot=row['slot_va']):
                    with self.assertRaises(ValueError):
                        subject.selected_relocations(damaged, self.view)
            finally:
                damaged[offset + 8] ^= 1
        offset = int(rows[0]['entry_file_offset'], 16)
        damaged[offset + 16] ^= 1
        with self.assertRaises(ValueError):
            subject.selected_relocations(damaged, self.view)
        damaged[offset + 16] ^= 1
        second = int(rows[1]['entry_file_offset'], 16)
        original = bytes(damaged[second:second + 24])
        damaged[second:second + 24] = damaged[offset:offset + 24]
        with self.assertRaises(ValueError):
            subject.selected_relocations(damaged, self.view)
        damaged[second:second + 24] = original
        section = next(s for s in self.view.sections if s['name'] == '.rela.dyn')
        bad_sections = [dict(s) for s in self.view.sections]
        next(s for s in bad_sections if s['name'] == '.rela.dyn')['size'] = section['size'] - 1
        with self.assertRaises(ValueError):
            subject.selected_relocations(self.data, subject.View(self.data, bad_sections))

    def test_copy_dynamic_symbol_binding_and_corruption(self):
        relocs = subject.selected_relocations(self.data, self.view)
        symbol = subject.memcpy_symbol(self.data, self.view, relocs)
        self.assertEqual(symbol['name'], 'memcpy')
        damaged = bytearray(self.data)
        damaged[int(symbol['name_file_offset'], 16)] ^= 1
        with self.assertRaises(ValueError):
            subject.memcpy_symbol(damaged, self.view, relocs)
        damaged = bytearray(self.data)
        offset = int(symbol['symbol_file_offset'], 16)
        struct.pack_into('<I', damaged, offset, 0xffffffff)
        with self.assertRaises(ValueError):
            subject.memcpy_symbol(damaged, self.view, relocs)

    def test_file_mapping_rejects_nobits_crossing_and_ambiguity(self):
        sect = {'name': '.text', 'type': 1, 'flags': 6, 'address': 0x1000, 'offset': 0, 'size': 4}
        bss = {'name': '.bss', 'type': 8, 'flags': 3, 'address': 0x2000, 'offset': 0, 'size': 4}
        view = subject.View(b'1234', [sect, bss])
        self.assertEqual(view.read(0x1000, 4, True), b'1234')
        for start, length in ((0xfff, 1), (0x1003, 2), (0x2000, 1), (0x1000, 0), (-1, 1)):
            with self.subTest(start=start, length=length):
                with self.assertRaises(ValueError):
                    view.read(start, length)
        with self.assertRaises(ValueError):
            subject.View(b'1234', [sect, dict(sect)]).read(0x1000, 1)
        with self.assertRaises(ValueError):
            subject.View(b'1234', [dict(sect, flags=2)]).read(0x1000, 1, True)

    def test_lsda_bounds_and_corruption(self):
        headers, rows = subject.lsda_rows(self.view, self.fdes)
        self.assertEqual((len(headers), len(rows)), (2, 9))
        self.assertEqual(sum(bool(row['landing_va']) for row in rows), 4)
        damaged = bytearray(self.data)
        offset = self.view.offset(int(headers[0]['lsda_va'], 16))
        damaged[offset] ^= 1
        with self.assertRaises(ValueError):
            subject.lsda_rows(subject.View(damaged), self.fdes)
        fake_fdes = [dict(self.fdes[3], lsda_va=hex(0x2000))]
        with self.assertRaises(ValueError):
            subject.lsda_rows(self.view, fake_fdes)

    def test_recipient_lanes_derive_all_twenty_bytes(self):
        lanes = subject.recipient_lanes(self.view, self.const)
        self.assertEqual(len(lanes), 21)
        self.assertEqual([int(x['output_offset'], 16) for x in lanes], list(range(0x70, 0x85)))
        for byte in range(20):
            for bit in range(8):
                with self.subTest(byte=byte, bit=bit):
                    source = bytearray(144)
                    source[0x70] = 1
                    source[0x71 + byte] = 1 << bit
                    stage = bytearray(144)
                    for lane in lanes:
                        stage[int(lane['stage_offset'], 16)] = source[int(lane['field_result_offset'], 16)]
                    self.assertEqual(stage[0x70:0x85], source[0x70:0x85])
        with self.assertRaises(ValueError):
            subject.recipient_lanes(OverlayView(self.view, {0x13528b9: 1}), self.const)

    def test_v_classification_and_protected_upper_bound(self):
        c = self.const
        max_u64 = (1 << 64) - 1
        probes = list(range(8192)) + [(1 << 64) - 1, 1 << 64,
                  (2 * max_u64 + 35), (2 * max_u64 + 36), (2 * max_u64 + 37), (1 << 128) - 1]
        for v in probes:
            actual = subject.classify_v(v, c)
            if v in (27, 28):
                expected = ('unprotected', v - 27, None)
            elif 35 <= v <= 2 * max_u64 + 36:
                chain, parity = divmod(v - 35, 2)
                expected = ('protected', parity, chain)
            else:
                expected = ('invalid', None, None)
            self.assertEqual((actual['kind'], actual['parity'], actual['chain_id']), expected)
        for bad in (-1, 1 << 128, '27'):
            with self.assertRaises(ValueError):
                subject.classify_v(bad, c)

    def test_v_roundtrip_at_chain_boundaries(self):
        c = self.const
        for chain in (0, 1, 46, 47, 127, 128, 255, 256, (1 << 63) - 1, 1 << 63, (1 << 64) - 1):
            for parity in (0, 1):
                fields = subject.tx_fields(0, 0, 0, None, 0, b'', c)
                _, _, v = subject.signing_and_signed(fields, chain, parity, 0, 0, c)
                self.assertEqual(subject.classify_v(v, c), {'kind': 'protected', 'parity': parity, 'chain_id': chain})
        for parity in (0, 1):
            _, _, v = subject.signing_and_signed([], None, parity, 0, 0, c)
            self.assertEqual(subject.classify_v(v, c)['parity'], parity)
        for args in ((-1, 0), (1 << 64, 0), (0, 2)):
            with self.assertRaises(ValueError):
                subject.signing_and_signed([], args[0], args[1], 0, 0, c)

    def test_header_error_precedence_and_consumed_bytes(self):
        c = self.const
        expected = {
            b'': ('error', 2, 0), b'\x01': ('error', 6, 0),
            b'\x80': ('error', 6, 1), b'\x81': ('error', 2, 1),
            b'\x81\x00': ('error', 3, 1), b'\x81\x80': ('error', 6, 1),
            b'\xc0': ('list', 0, 1), b'\xc1': ('error', 2, 1),
            b'\xc1\x80': ('list', 1, 1), b'\xf8': ('error', 2, 1),
            b'\xf8\x00': ('error', 1, 2),
            b'\xf8\x37' + bytes(55): ('error', 4, 2),
            b'\xf8\x38' + bytes(55): ('error', 2, 2),
            b'\xf8\x38' + bytes(56): ('list', 56, 2),
            b'\xb8\x38' + bytes(56): ('error', 6, 2),
        }
        for inp, (kind, value, consumed) in expected.items():
            with self.subTest(inp=inp[:3].hex(), length=len(inp)):
                actual = subject.outer_header(inp, c)
                self.assertEqual(actual['result'], kind)
                self.assertEqual(actual['consumed'], consumed)
                self.assertEqual(actual['length' if kind == 'list' else 'detail'], value)

    def test_body_length_check_order(self):
        f = subject.body_length_decision
        self.assertEqual(f(8, 5, 3), {'result': 'equal'})
        self.assertEqual(f(8, 4, 3), {'result': 'length_mismatch', 'declared': 4, 'consumed': 5})
        self.assertEqual(f(8, 6, 3), {'result': 'length_mismatch', 'declared': 6, 'consumed': 5})
        self.assertEqual(f(8, 0, 9), {'result': 'subtract_underflow'})
        self.assertEqual(f((1 << 64) - 1, 1, (1 << 64) - 1), {'result': 'add_overflow'})
        for bad in (-1, 1 << 64, '0'):
            with self.assertRaises(ValueError):
                f(0, bad, 0)

    def test_integer_reader_error_order_and_width(self):
        c = self.const
        cases = [
            (b'', 8, 'error', 2, 0), (b'\x00', 8, 'error', 1, 1),
            (b'\x80', 8, 'value', 0, 1), (b'\x81\x00', 8, 'error', 3, 1),
            (b'\x81\x80', 8, 'value', 128, 2),
            (b'\x88' + b'\xff' * 8, 8, 'value', (1 << 64) - 1, 9),
            (b'\x89' + b'\x00' * 9, 8, 'error', 0, 10),
            (b'\xa1' + b'\x00' * 33, 32, 'error', 1, 34),
            (b'\xa1' + b'\x01' * 33, 32, 'error', 0, 34),
            (b'\xc0', 32, 'error', 7, 1), (b'\xc1', 32, 'error', 2, 1),
            (b'\xb8\x37' + bytes(55), 32, 'error', 4, 2),
        ]
        for inp, width, kind, value, consumed in cases:
            with self.subTest(width=width, inp=inp[:3].hex()):
                result = subject.decode_bounded_uint(inp, width, c)
                self.assertEqual((result['result'], result['consumed']), (kind, consumed))
                self.assertEqual(result['value' if kind == 'value' else 'detail'], value)
        with self.assertRaises(ValueError):
            subject.decode_bounded_uint(b'\x80', 16, c)
        self.assertEqual(subject.decode_bounded_uint(b'\x91' + bytes(17), 16, c, field=True),
                         {'result': 'error', 'detail': 0, 'consumed': 18})
        self.assertEqual(subject.decode_bounded_uint(b'\xa1' + bytes(33), 32, c, field=True),
                         {'result': 'error', 'detail': 1, 'consumed': 34})
        self.assertEqual(subject.decode_bounded_uint(b'\xa1' + b'\x01' * 33, 32, c, field=True),
                         {'result': 'error', 'detail': 0, 'consumed': 34})

    def test_scalar_overwidth_result_store_is_zero_at_offset_eight(self):
        raw = self.view.read(0x13535b5, 16, True)
        self.assertEqual(raw[0], 0xb8)
        self.assertEqual(struct.unpack_from('<I', raw, 1)[0], 1)
        self.assertEqual(raw[5], 0xb9)
        self.assertEqual(struct.unpack_from('<I', raw, 6)[0], 8)
        self.assertEqual(raw[10:12], b'\x31\xd2')
        self.assertEqual(raw[12:16], b'\x48\x89\x14\x0f')
        self.assertEqual(subject.decode_bounded_uint(b'\xa1' + b'\x01' * 33, 32, self.const),
                         {'result': 'error', 'detail': 0, 'consumed': 34})

    def test_payload_reader_and_213_byte_boundary(self):
        c = self.const
        for size in (0, 1, 2, 55, 56, 212, 213, 214, 255, 256):
            raw = bytes([0x80]) * size
            encoded = subject.encode_bytes(raw, c)
            observed = subject.decode_payload(encoded, c)
            self.assertEqual(observed, {'result': 'value', 'hex': raw.hex(),
                                        'length': size, 'consumed': len(encoded)})
            self.assertEqual(decode_rlp_one(encoded), (raw, len(encoded)))
        self.assertEqual(subject.decode_payload(b'\x00', c),
                         {'result': 'value', 'hex': '00', 'length': 1, 'consumed': 1})
        self.assertEqual(subject.decode_payload(b'\x81\x00', c),
                         {'result': 'error', 'detail': 3, 'consumed': 1})
        self.assertEqual(subject.decode_payload(b'\xb8\xd5' + bytes(212), c),
                         {'result': 'error', 'detail': 2, 'consumed': 2})
        self.assertEqual(subject.decode_payload(b'\xc0', c),
                         {'result': 'error', 'detail': 7, 'consumed': 1})

    def test_integer_encoding_against_independent_reader(self):
        c = self.const
        values = list(range(512)) + [255, 256, (1 << 64) - 1, (1 << 128) - 1, (1 << 256) - 1]
        for v in values:
            encoded = subject.encode_uint(v, c)
            raw, consumed = decode_rlp_one(encoded)
            self.assertEqual(consumed, len(encoded))
            self.assertEqual(int.from_bytes(raw, 'big'), v)
            self.assertEqual(raw, b'' if v == 0 else v.to_bytes((v.bit_length() + 7) // 8, 'big'))
            self.assertEqual(subject.decode_bounded_uint(encoded, 32, c),
                             {'result': 'value', 'value': v, 'consumed': len(encoded)})
        for v in (-1, 1 << 256):
            with self.assertRaises(ValueError):
                subject.encode_uint(v, c)

    def test_string_and_list_length_boundaries(self):
        c = self.const
        for n in (0, 1, 2, 54, 55, 56, 57, 127, 128, 213, 255, 256):
            raw = bytes([0x80]) * n
            encoded = subject.encode_bytes(raw, c)
            parsed, pos = decode_rlp_one(encoded)
            self.assertEqual((parsed, pos), (raw, len(encoded)))
            wrapped = subject.encode_list([encoded], c)
            parsed_list, pos = decode_rlp_one(wrapped)
            self.assertEqual((parsed_list, pos), ([raw], len(wrapped)))
        self.assertEqual(subject.encode_bytes(b'\x7f', c), b'\x7f')
        self.assertEqual(subject.encode_bytes(b'\x80', c), b'\x81\x80')
        for bad in (b'\x81\x01', b'\xf8\x01\x80'):
            with self.assertRaises(ValueError):
                decode_rlp_one(bad)

    def test_synthetic_transactions_independent_split(self):
        c = self.const
        for row in subject.synthetic_examples(self.view, c):
            signing = bytes.fromhex(row['signing_hex'])
            signed = bytes.fromhex(row['signed_hex'])
            a, apos = decode_rlp_one(signing)
            b, bpos = decode_rlp_one(signed)
            self.assertEqual((apos, bpos), (len(signing), len(signed)))
            self.assertEqual(a[:6], b[:6])
            self.assertEqual([int.from_bytes(b[i], 'big') for i in (0, 1, 2, 4)],
                             [9, 20_000_000_000, 21_000, 0])
            self.assertEqual(b[3], bytes(19) + b'\x09')
            self.assertEqual(b[5], bytes(213))
            self.assertEqual(int.from_bytes(b[6], 'big'), row['v'])
            self.assertEqual(b[7:], [b'\x01', b'\x01'])
            if row['chain_id'] is None:
                self.assertEqual(len(a), 6)
            else:
                self.assertEqual(len(a), 9)
                self.assertEqual((int.from_bytes(a[6], 'big'), a[7], a[8]), (row['chain_id'], b'', b''))
        with self.assertRaises(ValueError):
            subject.tx_fields(1, 2, 3, bytes(19), 4, b'', c)

    def test_generated_evidence_matches_extractor(self):
        folder = ROOT / 'research' / 'work-items' / 'RE-021-legacy-signature-94'
        files = subject.collect(self.data)
        actual = {p.name for p in folder.iterdir() if p.suffix in ('.json', '.tsv')}
        self.assertEqual(actual, set(files))
        for name, expected in files.items():
            with self.subTest(name=name):
                self.assertEqual((folder / name).read_bytes(), expected)


if __name__ == '__main__':
    unittest.main()
