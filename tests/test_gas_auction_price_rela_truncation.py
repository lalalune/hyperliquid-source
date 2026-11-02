"""Synthetic-ELF tests for the gas_auction_price .rela.dyn entry-size guard.

Builds a minimal ELF64 whose .rela.dyn is followed in the file by a filler
section. A declared size that is not a multiple of the 24-byte RELA entry
makes relocations() read the partial final entry's info/addend out of the
filler section's bytes and relative() attests it as a RELATIVE binding; it
must instead fail closed as EvidenceError ('.rela.dyn truncated'), the
guard evm_amount_scale already applies to the same table. Whole-entry
sizes keep their exact prior behavior.
"""
import struct
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import gas_auction_price as gas  # noqa: E402

GENUINE = struct.pack('<QQq', 0x1000, 8, 0x1111)
SECOND = struct.pack('<QQq', 0x1800, 8, 0x2222)
# Filler bytes spell info=8 (RELATIVE) and addend=0x4141 for a partial
# entry whose 8-byte slot prefix sits at the end of .rela.dyn.
FILLER = struct.pack('<Qq', 8, 0x4141) + b'\0' * 8


def build(rela):
    cie_body = b'\x01zR\x00' + b'\x01' + b'\x78' + b'\x10' + b'\x01' + b'\x1b'
    cie = struct.pack('<II', 4 + len(cie_body), 0) + cie_body
    eh_frame = cie + b'\x00\x00\x00\x00'
    names = [b'', b'.text', b'.eh_frame', b'.rela.dyn', b'.rodata',
             b'.shstrtab']
    shstr = b''
    name_off = []
    for n in names:
        name_off.append(len(shstr))
        shstr += n + b'\0'
    contents = [(1, 1, 0x6, 0x5000, b'\x90' * 16),
                (2, 1, 0, 0x6000, eh_frame),
                (3, 4, 0, 0x7000, rela),
                (4, 1, 0, 0x8000, FILLER),
                (5, 3, 0, 0, shstr)]
    blob = bytearray(b'\0' * 64)
    offsets = []
    for (_, _, _, _, data) in contents:
        offsets.append(len(blob))
        blob += data
    shoff = len(blob)
    blob += b'\0' * 64
    for (ni, typ, flags, addr, data), off in zip(contents, offsets):
        blob += struct.pack('<IIQQQQIIQQ', name_off[ni], typ, flags, addr,
                            off, len(data), 0, 0, 1, 0)
    blob[0:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<Q', blob, 40, shoff)
    struct.pack_into('<HHH', blob, 58, 64, 6, 5)
    return bytes(blob)


class GasRelaTruncationTests(unittest.TestCase):
    def test_partial_entry_fails_closed(self):
        # 32-byte .rela.dyn: one genuine entry plus an 8-byte slot prefix.
        # On base, relative() attests {0x1000: 0x1111, 0x2000: 0x4141},
        # the second binding fabricated from the filler section's bytes.
        blob = build(GENUINE + struct.pack('<Q', 0x2000))
        with self.assertRaisesRegex(gas.EvidenceError, '.rela.dyn truncated'):
            gas.Image(blob).relative()

    def test_whole_entry_sizes_unchanged(self):
        self.assertEqual(gas.Image(build(GENUINE)).relative(),
                         {0x1000: 0x1111})
        self.assertEqual(gas.Image(build(GENUINE + SECOND)).relative(),
                         {0x1000: 0x1111, 0x1800: 0x2222})
        self.assertEqual(gas.Image(build(b'')).relative(), {})


if __name__ == '__main__':
    unittest.main()
