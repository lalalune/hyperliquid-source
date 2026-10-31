import contextlib
import hashlib
import io
from pathlib import Path
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import qty_newtype_sign_guards as qsg

PACKET = ROOT / 'research' / 'work-items' / 'RE-004-qty-newtype-sign-guards-94'
GENERATED = ['call-sites.tsv', 'evidence.json', 'guard-bytes.txt']


def synthetic(jcc=b'\x78\x0a', spill=b'\x48\x89\x44\x24\x08', pad=0):
    """mov [rsp+8],rax; test rax,rax; js err; mov [rdi+8],rax; ret ... err: lea rdi,[rsp+8]; call."""
    ok = b'\x48\x89\x47\x08' + b'\xc3' + b'\xcc' * (5 + pad)
    body = spill + b'\x48\x85\xc0' + jcc + ok
    err = b'\x48\x8d\x7c\x24\x08'
    fn = body + err + b'\xe8\x00\x00\x00\x00'
    return fn, len(body) + len(err)


class DecoderTests(unittest.TestCase):
    def test_digest_mismatch_is_rejected(self):
        with self.assertRaises(qsg.EvidenceError):
            qsg.check_digest(b'not the node binary')
        self.assertEqual(qsg.check_digest(b'', hashlib.sha256(b'').hexdigest()), hashlib.sha256(b'').hexdigest())

    def test_test_reg_reg_only(self):
        self.assertEqual(qsg.decode_test(b'\x48\x85\xc0', 0), 'rax')
        self.assertEqual(qsg.decode_test(b'\x4d\x85\xf6', 0), 'r14')
        self.assertIsNone(qsg.decode_test(b'\x48\x85\xc8', 0))  # test rax,rcx
        self.assertIsNone(qsg.decode_test(b'\x48\x84\xc0', 0))  # 8-bit test
        self.assertIsNone(qsg.decode_test(b'\x85\xc0', 0))      # 32-bit test

    def test_narrow_test_widths(self):
        self.assertEqual(qsg.decode_narrow_test(b'\x84\xc0', 2), (8, 0, 0))
        self.assertEqual(qsg.decode_narrow_test(b'\x66\x85\xc0', 3), (16, 0, 0))
        self.assertEqual(qsg.decode_narrow_test(b'\x90\x85\xc0', 3), (32, 0, 1))
        self.assertIsNone(qsg.decode_narrow_test(b'\x48\x85\xc0', 3))  # 64-bit is not narrow
        self.assertIsNone(qsg.decode_narrow_test(b'\x90\x85\xc8', 3))  # test eax,ecx
        self.assertIsNone(qsg.decode_narrow_test(b'\x90\x84\x00', 3))  # memory operand

    def test_only_sign_branches_count(self):
        self.assertEqual(qsg.decode_sign_jcc(b'\x78\x05', 0), ('js', 2, 5))
        self.assertEqual(qsg.decode_sign_jcc(b'\x0f\x89' + struct.pack('<i', -300), 0), ('jns', 6, -300))
        for other in (b'\x7c\x05', b'\x7e\x05', b'\x0f\x8c\x00\x00\x00\x00', b'\x74\x05'):
            self.assertIsNone(qsg.decode_sign_jcc(other, 0))

    def test_models_and_message_predicates(self):
        for jcc in ('js', 'jns'):
            self.assertTrue(qsg.admitted((1 << 63) - 1, jcc))
            self.assertFalse(qsg.admitted(1 << 63, jcc))
        self.assertTrue(qsg.message_predicate(0, 'i64'))
        self.assertFalse(qsg.message_predicate((1 << 64) - 1, 'i64'))   # -1
        self.assertTrue(qsg.message_predicate((1 << 63) - 1, 'u64'))
        self.assertFalse(qsg.message_predicate(1 << 63, 'u64'))         # i64::MAX + 1
        with self.assertRaises(qsg.EvidenceError):
            qsg.message_predicate(0, 'u128')
        self.assertFalse(qsg.narrow_admitted(0x80, 8))
        self.assertTrue(qsg.narrow_admitted(0x7fff, 16))
        self.assertEqual(qsg.narrow_mismatch(8, 'i64'), (0, 256))
        self.assertEqual(qsg.narrow_mismatch(16, 'i64'), (0, 65536))
        self.assertEqual(qsg.narrow_mismatch(32, 'i64')[0], 0)

    def test_synthetic_guard_and_corruptions(self):
        fn, call = synthetic()
        guards = qsg.guards_for_call(0x1000, fn, 0x1000 + call)
        self.assertEqual(len(guards), 1)
        self.assertTrue(guards[0]['spilled_value_is_tested_value'] and guards[0]['spill_slot_passed_to_error'])
        fn2, call2 = synthetic(jcc=b'\x7c\x0a')                        # jl: not a sign guard
        self.assertEqual(qsg.guards_for_call(0x1000, fn2, 0x1000 + call2), [])
        fn3, call3 = synthetic(spill=b'\x48\x89\x4c\x24\x08')          # spill of rcx, not rax
        self.assertFalse(qsg.guards_for_call(0x1000, fn3, 0x1000 + call3)[0]['spilled_value_is_tested_value'])
        self.assertEqual(qsg.guards_for_call(0x1000, fn, 0x1000 + call + qsg.MAX_ERROR_BLOCK + 1), [])


class BinaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = (ROOT / qsg.BINARY).read_bytes()
        cls.result, cls.callers = qsg.analyse(cls.data)

    def test_summary(self):
        self.assertEqual(self.result['summary'], {
            'all_sites_one_tied_guard': True, 'call_sites': 34, 'call_sites_with_exactly_one_sign_guard': 34,
            'caller_functions': 34, 'constructors': 16, 'guard_value_is_formatted_value': 34,
            'jns_guards': 23, 'js_guards': 11, 'lea_refs': 16, 'mismatch_vs_message_predicate': 0,
            'narrow_guards': 21, 'narrow_mismatch_vs_message_predicate': 0, 'ok_path_stores_unchanged': 11,
            'unexplained_error_entries': 0})
        per = {t['newtype']: (t['visited'], t['summary']['call_sites'], t['summary']['narrow_guards'])
               for t in self.result['types']}
        self.assertEqual(per, {'NtlPriv': ('i64', 13, 12), 'BigNtlPriv': ('i64', 3, 3), 'SzPriv': ('i64', 6, 6),
                               'SziPriv': ('u64', 3, 0), 'NtliPriv': ('u64', 9, 0)})

    def test_corrupted_binary_is_rejected(self):
        bad = bytearray(self.data)
        bad[0x2e65cdf] ^= 0x04  # js -> jl in an NtlPriv caller
        with self.assertRaises(qsg.EvidenceError):
            qsg.analyse(bytes(bad))

    def test_flipped_guards_in_real_caller(self):
        start = 0x2e65a90
        r, fn = self.callers[start]
        self.assertEqual(len(qsg.guards_for_call(start, fn, 0x2e65d1a)), 1)
        flipped = bytearray(fn)
        self.assertEqual(flipped[0x2e65cdf - start], 0x78)
        flipped[0x2e65cdf - start] = 0x7c                              # js -> jl
        self.assertEqual(qsg.guards_for_call(start, bytes(flipped), 0x2e65d1a), [])
        good = qsg.narrow_entries(start, fn, 0x2e65d0d, 0x2e65ce1, 0x2e65cdc)
        self.assertEqual(sorted(e['width'] for e in good if e['width']), [8, 16, 32])
        narrow = bytearray(fn)
        self.assertEqual(bytes(narrow[0x2e65b3f - start:0x2e65b41 - start]), b'\x0f\x89')
        narrow[0x2e65b40 - start] = 0x8d                              # i32 jns -> jge
        bad = qsg.narrow_entries(start, bytes(narrow), 0x2e65d0d, 0x2e65ce1, 0x2e65cdc)
        self.assertEqual(sorted(e['width'] for e in bad if e['width']), [8, 16])

    def test_out_of_range_addresses_and_unknown_piece(self):
        img = qsg.Image(self.data)
        with self.assertRaises(qsg.EvidenceError):
            img.off(0x10, 4)
        fdes = qsg.Fdes(img)
        self.assertEqual(fdes.range_of(0x2e65d1a)['end'], 0x2e65d88)
        with self.assertRaises(qsg.EvidenceError):
            fdes.range_of(0x2e65d88 + 1)  # padding after the caller FDE
        with self.assertRaises(qsg.EvidenceError):
            qsg.find_piece(img, 'SzPriv', 'u64')  # no such diagnostic in node #94

    def test_packet_files_regenerate_byte_for_byte(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(qsg.main(['--out', tmp]), 0)
            for name in GENERATED:
                self.assertEqual((Path(tmp) / name).read_bytes(), (PACKET / name).read_bytes(), name)
        manifest = {}
        for line in (PACKET / 'MANIFEST.sha256').read_text().splitlines():
            digest, name = line.split('  ', 1)
            manifest[name] = digest
        self.assertEqual(set(manifest), {p.name for p in PACKET.iterdir() if p.name != 'MANIFEST.sha256'})
        for name, digest in manifest.items():
            self.assertEqual(hashlib.sha256((PACKET / name).read_bytes()).hexdigest(), digest, name)


class MainErrorHandlingTest(unittest.TestCase):
    def test_missing_binary_is_one_line_error(self):
        err = io.StringIO()
        with tempfile.TemporaryDirectory() as d, contextlib.redirect_stderr(err):
            rc = qsg.main(['--out', d, '--binary', '/nonexistent.bin'])
        self.assertEqual(rc, 1)
        self.assertTrue(err.getvalue().startswith('error: '))
        self.assertEqual(len(err.getvalue().strip().splitlines()), 1)
        self.assertNotIn('Traceback', err.getvalue())


if __name__ == '__main__':
    unittest.main()
