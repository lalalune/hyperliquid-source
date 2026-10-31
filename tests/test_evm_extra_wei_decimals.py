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

import evm_extra_wei_decimals as tool  # noqa: E402

PACKET = ROOT / 'research' / 'work-items' / 'RE-004-evm-extra-wei-decimals-94'
GENERATED = ['evidence.json', 'guards.tsv', 'guard-bytes.txt']
EXPECTED = list(range(-2, 19))


class EvmExtraWeiDecimalsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = (ROOT / tool.BINARY).read_bytes()
        cls.result, cls.funcs, cls.table = tool.analyse(cls.data)

    def test_rejects_wrong_digest(self):
        bad = bytearray(self.data[:4096])
        with self.assertRaises(tool.EvidenceError):
            tool.check_digest(bytes(bad))
        corrupted = bytearray(self.data)
        corrupted[0x599967] ^= 0x01
        with self.assertRaises(tool.EvidenceError):
            tool.analyse(bytes(corrupted))

    def test_summary(self):
        s = self.result['summary']
        self.assertEqual(s['lea_refs'], 6)
        self.assertEqual(s['functions'], 6)
        self.assertEqual(s['sites_with_exactly_one_guard'], 6)
        self.assertEqual(s['sites_fully_verified'], 6)
        self.assertEqual(s['sites_gated_by_already_set'], 6)
        self.assertEqual(s['sites_ok_path_stores_input_byte'], 3)
        self.assertEqual(s['guard_forms'], 2)
        self.assertEqual((s['admitted_i8_min'], s['admitted_i8_max'], s['admitted_count']), (-2, 18, 21))
        self.assertEqual(s['error_tags'], [0xdf])

    def test_every_guard_admits_exactly_message_range(self):
        for site in self.result['sites']:
            g = site['guards'][0]
            self.assertEqual(tool.admitted_signed(g['k'], g['c'], g['jcc']), EXPECTED, site['lea_va'])
            self.assertEqual(site['payload']['length'], len(tool.MESSAGE))

    def test_model_negative_controls(self):
        # Off-by-one compare constants or a shifted bias change the admitted set.
        self.assertNotEqual(tool.admitted_signed(0xed, 0xeb, 'ja'), EXPECTED)
        self.assertNotEqual(tool.admitted_signed(0xed, 0xea, 'jae'), EXPECTED)
        self.assertNotEqual(tool.admitted_signed(0xec, 0xea, 'ja'), EXPECTED)
        self.assertEqual(len(tool.admitted_signed(0xed, 0xea, 'ja')), 21)
        self.assertFalse(tool.admitted(0x13, 0xed, 0xea, 'ja'))   # 19
        self.assertFalse(tool.admitted(0xfd, 0xed, 0xeb, 'jae'))  # -3
        self.assertTrue(tool.admitted(0xfe, 0xed, 0xeb, 'jae'))   # -2
        self.assertTrue(tool.admitted(0x12, 0xed, 0xea, 'ja'))    # 18

    def test_decoder_both_forms_and_prefix_dedup(self):
        a = bytes.fromhex('418d40ed3cea7723')
        got = tool.decode_guard(a, 0x1000, len(a))
        self.assertEqual(len(got), 1)
        self.assertEqual((got[0]['input_reg'], got[0]['k'], got[0]['c'], got[0]['jcc']), ('r8', 0xed, 0xea, 'ja'))
        b = bytes.fromhex('4180c1ed4180f9eb732e')
        got = tool.decode_guard(b, 0x1000, len(b))
        self.assertEqual(len(got), 1)
        self.assertEqual((got[0]['input_reg'], got[0]['c'], got[0]['jcc']), ('r9', 0xeb, 'jae'))

    def test_decoder_rejects_corrupted_guard(self):
        # jbe instead of ja, and a compare on a different register.
        self.assertEqual(tool.decode_guard(bytes.fromhex('418d40ed3cea7623'), 0, 8), [])
        self.assertEqual(tool.decode_guard(bytes.fromhex('4180c1ed4180faeb732e'), 0, 10), [])

    def test_out_of_range_addresses(self):
        img = tool.Image(self.data)
        with self.assertRaises(tool.EvidenceError):
            img.read(0x10, 4)
        fdes = tool.Fdes(img)
        with self.assertRaises(tool.EvidenceError):
            fdes.range_of(0x1000)
        with self.assertRaises(tool.EvidenceError):
            tool.message_bounds(b'EVM extra wei decimals must be small')

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
