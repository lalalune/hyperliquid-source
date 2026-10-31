import contextlib
import filecmp
import io
import struct
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

import spot_token_decimals as tool  # noqa: E402

PACKET = ROOT / 'research' / 'work-items' / 'RE-004-spot-token-decimals-94'
GENERATED = ['evidence.json', 'admission.tsv', 'guard-bytes.txt']
RANGE_GUARD_A = bytes.fromhex('4538ec0f97c04180fd0b0f93c108c10f84fe000000' '66bddf00')
RANGE_GUARD_B = bytes.fromhex('4138ef0f97c04080fd0b0f93c108c10f84ca000000' '66b8df00')


def count(pred):
    return sum(1 for a in range(256) for b in range(256) if pred(a, b))


class SpotTokenDecimalsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = (ROOT / tool.BINARY).read_bytes()
        cls.result, cls.funcs, cls.grid = tool.analyse(cls.data)

    def test_rejects_wrong_digest(self):
        with self.assertRaises(tool.EvidenceError):
            tool.check_digest(self.data[:4096])
        corrupted = bytearray(self.data)
        corrupted[0x5997f9] ^= 0x01          # one byte of "szDecimals too large"
        with self.assertRaises(tool.EvidenceError):
            tool.analyse(bytes(corrupted))

    def test_summary(self):
        s = self.result['summary']
        self.assertEqual((s['deploy_lea_refs'], s['wei_min_lea_refs']), (1, 1))
        self.assertEqual((s['deploy_sites_decoded'], s['deploy_sites_fully_verified']), (1, 1))
        self.assertEqual((s['deploy_sz_max'], s['deploy_wei_offset']), (5, 5))
        self.assertEqual(s['deploy_admitted_pairs'], 1491)
        self.assertFalse(s['deploy_add_can_wrap'])
        self.assertEqual(s['deploy_gated'], 1)
        self.assertEqual((s['range_lea_refs'], s['range_functions']), (5, 5))
        self.assertEqual(s['range_sites_with_exactly_one_guard'], 5)
        self.assertEqual(s['range_sites_fully_verified'], 5)
        self.assertEqual(s['range_byte_forms'], 2)
        self.assertEqual(s['range_admitted_pairs'], [66])
        self.assertEqual(s['range_load_disps'], [[0x18, 0x19]])
        self.assertEqual(s['joint_admitted_pairs'], 21)
        self.assertEqual(s['error_tags'], [0xdf])

    def test_every_guard_matches_message_predicate(self):
        for g in self.result['deploy_sites']:
            self.assertEqual(g['mismatch_vs_message_predicate'], 0)
            self.assertEqual(g['wei_min_for_sz'], {str(a): a + 5 for a in range(6)})
        for s in self.result['range_sites']:
            g = s['guards'][0]
            self.assertEqual(g['mismatch_vs_message_predicate'], 0, s['lea_va'])
            self.assertEqual((g['n'], g['tag'], s['length']['value']), (11, 0xdf, len(tool.RANGE)))

    def test_model_negative_controls(self):
        # Range: an off-by-one bound, or swapped operands, changes the admitted set.
        spec = lambda a, b: a <= b <= 10  # noqa: E731
        self.assertEqual(count(lambda a, b: tool.range_admitted(a, b, 11) != spec(a, b)), 0)
        self.assertNotEqual(count(lambda a, b: tool.range_admitted(a, b, 10) != spec(a, b)), 0)
        self.assertNotEqual(count(lambda a, b: tool.range_admitted(b, a, 11) != spec(a, b)), 0)
        self.assertTrue(tool.range_admitted(10, 10, 11))
        self.assertFalse(tool.range_admitted(0, 11, 11))
        self.assertFalse(tool.range_admitted(3, 2, 11))
        # Deploy: sz 5 / wei 10 admitted; sz 6, or wei one below sz+5, rejected.
        self.assertTrue(tool.deploy_admitted(5, 10, 5, 5))
        self.assertTrue(tool.deploy_admitted(0, 255, 5, 5))
        self.assertFalse(tool.deploy_admitted(6, 255, 5, 5))
        self.assertFalse(tool.deploy_admitted(2, 6, 5, 5))
        self.assertNotEqual(count(lambda a, b: tool.deploy_admitted(a, b, 5, 4)), 1491)
        # With a wider sz bound the u8 add would wrap: sz 251 + 5 = 0 admits wei 0.
        self.assertTrue(tool.deploy_admitted(251, 0, 255, 5))

    def test_range_decoder_and_corruptions(self):
        for raw, regs in ((RANGE_GUARD_A, ('r12b', 'r13b')), (RANGE_GUARD_B, ('r15b', 'bpl'))):
            got = tool.decode_range(raw + b'\x48\x8d\x05\0\0\0\0', 0x1000, len(raw))
            self.assertEqual(len(got), 1)
            self.assertEqual(((got[0]['a_reg'], got[0]['b_reg']), got[0]['n'], got[0]['tag']), (regs, 11, 0xdf))
        pad = b'\x48\x8d\x05\0\0\0\0'
        # setb instead of seta, compare of a different register with 0xb, je -> jne.
        for i, v in ((4, 0x92), (8, 0xfc), (16, 0x85)):
            bad = bytearray(RANGE_GUARD_A)
            bad[i] = v
            self.assertEqual(tool.decode_range(bytes(bad) + pad, 0, len(bad)), [], (i, v))

    def test_deploy_decoder_rejects_corruption(self):
        fn_start = int(self.result['deploy_sites'][0]['fn_start'], 16)
        lea = int(self.result['deploy_sites'][0]['lea_va'], 16)
        r, fn = self.funcs[fn_start]
        self.assertEqual(len(tool.decode_deploy(fn, fn_start, lea - fn_start)), 1)
        bad = bytearray(fn)
        bad[lea - fn_start - 7] = 0x77      # jbe -> ja
        self.assertEqual(tool.decode_deploy(bytes(bad), fn_start, lea - fn_start), [])
        self.assertEqual(tool.decode_deploy(fn, fn_start, lea - fn_start + 1), [])

    def test_out_of_range_and_message_parsing(self):
        img = tool.Image(self.data)
        with self.assertRaises(tool.EvidenceError):
            img.read(0x10, 4)
        fdes = tool.Fdes(img)
        with self.assertRaises(tool.EvidenceError):
            fdes.range_of(0x1000)
        with self.assertRaises(tool.EvidenceError):
            tool.parse_range_message(b'must have szDecimals <= weiDecimals')
        with self.assertRaises(tool.EvidenceError):
            tool.parse_deploy_messages(tool.SZ_TOO_LARGE, b'weiDecimals must be large')
        self.assertEqual(tool.parse_range_message(tool.RANGE), 10)
        self.assertEqual(tool.parse_deploy_messages(tool.SZ_TOO_LARGE, tool.WEI_MIN), 5)

    def test_generated_files_match_packet(self):
        with tempfile.TemporaryDirectory() as tmp:
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(tool.main(['--out', tmp]), 0)
            for name in GENERATED:
                self.assertTrue(filecmp.cmp(Path(tmp) / name, PACKET / name, shallow=False), name)


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
        fdes = tool.Fdes(tool.Image(synthetic_ehf_elf([(0x5000, 0x10), (0x6000, 0x20)])))
        self.assertEqual(fdes.range_of(0x5000), {'start': 0x5000, 'end': 0x5010,
                                                 'fde': fdes.fde[0], 'hdr_index': 0})
        self.assertEqual(fdes.range_of(0x600f)['end'], 0x6020)

    def test_duplicate_starts_are_rejected(self):
        # Same start, contradictory lengths: range_of would flip its verdict
        # on the entry order alone.
        for entries in ([(0x5000, 0x10), (0x5000, 0x40)],
                        [(0x5000, 0x40), (0x5000, 0x10)]):
            with self.assertRaises(tool.EvidenceError):
                tool.Fdes(tool.Image(synthetic_ehf_elf(entries)))

    def test_unsorted_table_is_rejected(self):
        # The wide 0x5000 FDE is listed before the 0x4000 FDE; bisect over the
        # unchecked table would reject VAs the 0x5000 FDE covers.
        with self.assertRaises(tool.EvidenceError):
            tool.Fdes(tool.Image(synthetic_ehf_elf([(0x5000, 0x100), (0x4000, 0x10)])))


if __name__ == '__main__':
    unittest.main()
