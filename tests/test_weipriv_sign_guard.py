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
import weipriv_sign_guard as wsg

PACKET = ROOT / 'research' / 'work-items' / 'RE-004-weipriv-sign-guard-94'
GENERATED = ['call-sites.tsv', 'caller-bytes.txt', 'evidence.json']


def synthetic(jcc=b'\x78\x0a', spill=b'\x48\x89\x44\x24\x08', pad=0):
    """mov [rsp+8],rax; test rax,rax; js err; mov [rdi+8],rax; ret ... err: lea rdi,[rsp+8]; call."""
    ok = b'\x48\x89\x47\x08' + b'\xc3' + b'\xcc' * (5 + pad)
    body = spill + b'\x48\x85\xc0' + jcc + ok
    err = b'\x48\x8d\x7c\x24\x08'
    fn = body + err + b'\xe8\x00\x00\x00\x00'
    return fn, len(body) + len(err)


class DecoderTests(unittest.TestCase):
    def test_digest_mismatch_is_rejected(self):
        with self.assertRaises(wsg.EvidenceError):
            wsg.check_digest(b'not the node binary')
        self.assertEqual(wsg.check_digest(b'', hashlib.sha256(b'').hexdigest()), hashlib.sha256(b'').hexdigest())

    def test_test_reg_reg_only(self):
        self.assertEqual(wsg.decode_test(b'\x48\x85\xc0', 0), 'rax')
        self.assertEqual(wsg.decode_test(b'\x4d\x85\xf6', 0), 'r14')
        self.assertIsNone(wsg.decode_test(b'\x48\x85\xc8', 0))  # test rax,rcx
        self.assertIsNone(wsg.decode_test(b'\x48\x84\xc0', 0))  # 8-bit test
        self.assertIsNone(wsg.decode_test(b'\x48\x85\x00', 0))  # memory operand
        self.assertIsNone(wsg.decode_test(b'\x85\xc0', 0))      # 32-bit test

    def test_only_sign_branches_count(self):
        self.assertEqual(wsg.decode_sign_jcc(b'\x78\x05', 0), ('js', 2, 5))
        self.assertEqual(wsg.decode_sign_jcc(b'\x79\xfe', 0), ('jns', 2, -2))
        self.assertEqual(wsg.decode_sign_jcc(b'\x0f\x89' + struct.pack('<i', -300), 0), ('jns', 6, -300))
        for other in (b'\x7c\x05', b'\x7e\x05', b'\x0f\x8c\x00\x00\x00\x00', b'\x74\x05'):
            self.assertIsNone(wsg.decode_sign_jcc(other, 0))

    def test_guard_model_boundaries(self):
        for jcc in ('js', 'jns'):
            self.assertTrue(wsg.admitted(0, jcc))
            self.assertTrue(wsg.admitted((1 << 63) - 1, jcc))
            self.assertFalse(wsg.admitted(1 << 63, jcc))       # i64::MIN
            self.assertFalse(wsg.admitted((1 << 64) - 1, jcc))  # -1

    def test_synthetic_guard_and_corruptions(self):
        fn, call = synthetic()
        guards = wsg.guards_for_call(0x1000, fn, 0x1000 + call)
        self.assertEqual(len(guards), 1)
        g = guards[0]
        self.assertEqual((g['register'], g['jcc']), ('rax', 'js'))
        self.assertTrue(g['spilled_value_is_tested_value'] and g['spill_slot_passed_to_error'])
        self.assertTrue(g['ok_stores_tested_value_unchanged'])
        # jl instead of js: not a sign-bit guard.
        fn2, call2 = synthetic(jcc=b'\x7c\x0a')
        self.assertEqual(wsg.guards_for_call(0x1000, fn2, 0x1000 + call2), [])
        # Spill of a different register: guard found but not tied to the message.
        fn3, call3 = synthetic(spill=b'\x48\x89\x4c\x24\x08')
        self.assertFalse(wsg.guards_for_call(0x1000, fn3, 0x1000 + call3)[0]['spilled_value_is_tested_value'])
        # Error block farther than the limit from the call is not matched.
        fn4, call4 = synthetic(jcc=b'\x78\x0a')
        self.assertEqual(wsg.guards_for_call(0x1000, fn4, 0x1000 + call4 + wsg.MAX_ERROR_BLOCK + 1), [])


class BinaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = (ROOT / wsg.BINARY).read_bytes()
        cls.result, cls.callers = wsg.analyse(cls.data)

    def test_summary(self):
        self.assertEqual(self.result['summary'], {
            'lea_refs': 5, 'constructors': 5, 'call_sites': 6,
            'call_sites_with_exactly_one_sign_guard': 6,
            'guard_value_is_formatted_value': True, 'ok_path_stores_unchanged': 4})

    def test_corrupted_binary_is_rejected(self):
        bad = bytearray(self.data)
        bad[0x16ca29e] ^= 0x04  # js -> jl in the first caller
        with self.assertRaises(wsg.EvidenceError):
            wsg.analyse(bytes(bad))

    def test_flipped_guard_in_real_caller_is_not_matched(self):
        start = 0x16ca240
        r, fn = self.callers[start]
        fn = bytearray(fn)
        self.assertEqual(fn[0x16ca29e - start], 0x78)
        self.assertEqual(len(wsg.guards_for_call(start, bytes(fn), 0x16ca30a)), 1)
        fn[0x16ca29e - start] = 0x7c
        self.assertEqual(wsg.guards_for_call(start, bytes(fn), 0x16ca30a), [])

    def test_out_of_range_addresses(self):
        img = wsg.Image(self.data)
        with self.assertRaises(wsg.EvidenceError):
            img.off(0x10, 4)  # before .interp; not inside any allocated section
        fdes = wsg.Fdes(img)
        with self.assertRaises(wsg.EvidenceError):
            fdes.range_of(0x16ca355)  # int3 padding after the caller FDE ends at 0x16ca353
        self.assertEqual(fdes.range_of(0x16ca30a)['end'], 0x16ca353)

    def test_packet_files_regenerate_byte_for_byte(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(wsg.main(['--out', tmp]), 0)
            for name in GENERATED:
                self.assertEqual((Path(tmp) / name).read_bytes(), (PACKET / name).read_bytes(), name)
        manifest = {}
        for line in (PACKET / 'MANIFEST.sha256').read_text().splitlines():
            digest, name = line.split('  ', 1)
            manifest[name] = digest
        self.assertEqual(set(manifest), {p.name for p in PACKET.iterdir() if p.name != 'MANIFEST.sha256'})
        for name, digest in manifest.items():
            self.assertEqual(hashlib.sha256((PACKET / name).read_bytes()).hexdigest(), digest, name)


class MainErrorHandlingTests(unittest.TestCase):
    def test_missing_binary_is_one_line_error(self):
        err = io.StringIO()
        with tempfile.TemporaryDirectory() as d:
            with contextlib.redirect_stderr(err):
                rc = wsg.main(['--binary', '/nonexistent.bin', '--out', str(Path(d) / 'out.json')])
        self.assertEqual(rc, 1)
        self.assertTrue(err.getvalue().startswith('error: '))
        self.assertEqual(len(err.getvalue().strip().splitlines()), 1)
        self.assertNotIn('Traceback', err.getvalue())


if __name__ == '__main__':
    unittest.main()
