import hashlib
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


_EHF_HDR_VA = 0x1000
_EHF_FRAME_VA = 0x2000

# CIE understood by Fdes.cie_r_encoding: id=0, version=1, aug "zR",
# code_align=1, data_align=-1 (0x7f), retreg=0x10, aug_len=1, R enc=0x1b
# (DW_EH_PE_pcrel | DW_EH_PE_sdata4).
_EHF_CIE = (struct.pack('<I', 20) + struct.pack('<I', 0) + bytes([1]) + b'zR\0'
            + bytes([1, 0x7f, 0x10, 1, 0x1b]) + b'\0\0\0')


def _ehf_fde(va, cie_va, start, length):
    return (struct.pack('<I', 16) + struct.pack('<I', va + 4 - cie_va)
            + struct.pack('<i', start - (va + 8)) + struct.pack('<i', length))


def synthetic_ehf_elf(entries):
    """Minimal ELF whose .eh_frame_hdr search table holds the (start, length)
    FDE entries in the given order."""
    ehf = bytearray(_EHF_CIE)
    fde_vas = []
    for i, (start, length) in enumerate(entries):
        va = _EHF_FRAME_VA + 20 + 16 * i
        ehf += _ehf_fde(va, _EHF_FRAME_VA, start, length)
        fde_vas.append(va)
    ehf += b'\0' * (192 - len(ehf))  # cie_r_encoding reads a fixed 64-byte window
    hdr = bytearray()
    hdr += bytes([1, 0x1b, 0x03, 0x3b])
    hdr += struct.pack('<i', _EHF_FRAME_VA - (_EHF_HDR_VA + 4))  # eh_frame_ptr
    hdr += struct.pack('<I', len(entries))                       # fde_count
    for (start, _length), fva in zip(entries, fde_vas):
        hdr += struct.pack('<ii', start - _EHF_HDR_VA, fva - _EHF_HDR_VA)
    shstr = b'\0.eh_frame_hdr\0.eh_frame\0.shstrtab\0'
    off_hdr, off_ehf, off_shstr, shoff = 0x100, 0x200, 0x400, 0x500
    data = bytearray(shoff + 4 * 64)
    data[off_hdr:off_hdr + len(hdr)] = hdr
    data[off_ehf:off_ehf + len(ehf)] = ehf
    data[off_shstr:off_shstr + len(shstr)] = shstr
    data[0:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<Q', data, 0x28, shoff)
    struct.pack_into('<HHH', data, 0x3a, 64, 4, 3)
    secs = [(0, 0, 0, 0, 0, 0),
            (1, 1, 0, _EHF_HDR_VA, off_hdr, len(hdr)),
            (15, 1, 0, _EHF_FRAME_VA, off_ehf, len(ehf)),
            (25, 3, 0, 0, off_shstr, len(shstr))]
    for i, s in enumerate(secs):
        struct.pack_into('<IIQQQQIIQQ', data, shoff + i * 64,
                         s[0], s[1], s[2], s[3], s[4], s[5], 0, 0, 1, 0)
    return bytes(data)


class FdesTableOrderTests(unittest.TestCase):
    def test_sorted_unique_table_is_accepted(self):
        fdes = wsg.Fdes(wsg.Image(synthetic_ehf_elf([(0x5000, 0x10), (0x6000, 0x20)])))
        self.assertEqual(fdes.range_of(0x5000), {'start': 0x5000, 'end': 0x5010,
                                                 'fde': fdes.fde[0], 'hdr_index': 0})
        self.assertEqual(fdes.range_of(0x600f)['end'], 0x6020)

    def test_duplicate_starts_are_rejected(self):
        # Same start, contradictory lengths: range_of would flip its verdict
        # on the entry order alone.
        for entries in ([(0x5000, 0x10), (0x5000, 0x40)],
                        [(0x5000, 0x40), (0x5000, 0x10)]):
            with self.assertRaises(wsg.EvidenceError):
                wsg.Fdes(wsg.Image(synthetic_ehf_elf(entries)))

    def test_unsorted_table_is_rejected(self):
        # The wide 0x5000 FDE is listed before the 0x4000 FDE; bisect over the
        # unchecked table would reject VAs the 0x5000 FDE covers.
        with self.assertRaises(wsg.EvidenceError):
            wsg.Fdes(wsg.Image(synthetic_ehf_elf([(0x5000, 0x100), (0x4000, 0x10)])))


if __name__ == '__main__':
    unittest.main()
