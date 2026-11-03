"""Synthetic-ELF tests for node115_latency_pair_rust missing .rodata.

Memory.allowed read the image's .rodata entry by raw dict indexing, so
an image that simply lacks .rodata escaped a read check as a bare
KeyError instead of the module's ValueError ('outside qualified pair
projection memory'). The builder mirrors the gas_auction_price
synthetic-ELF layout. The subject module imports capstone at module
level, so the class is skipped where capstone is unavailable.
"""
import importlib.util
import struct
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))


def build(drop=()):
    cie_body = b'\x01zR\x00' + b'\x01' + b'\x78' + b'\x10' + b'\x01' + b'\x1b'
    cie = struct.pack('<II', 4 + len(cie_body), 0) + cie_body
    eh_frame = cie + b'\x00\x00\x00\x00'
    allsecs = [(b'.text', 1, 0x6, 0x5000, b'\x90' * 16),
               (b'.eh_frame', 1, 0, 0x6000, eh_frame),
               (b'.rela.dyn', 4, 0, 0x7000,
                struct.pack('<QQq', 0x1000, 8, 0x1111)),
               (b'.rodata', 1, 0, 0x8000, b'\x00' * 16)]
    secs = [s for s in allsecs if s[0] not in drop]
    names = [b''] + [s[0] for s in secs] + [b'.shstrtab']
    shstr = b''
    name_off = {}
    for n in names:
        name_off[n] = len(shstr)
        shstr += n + b'\0'
    blob = bytearray(b'\0' * 64)
    offs = []
    for (_, _, _, _, data) in secs:
        offs.append(len(blob))
        blob += data
    shstr_off = len(blob)
    blob += shstr
    shoff = len(blob)
    blob += b'\0' * 64
    for (nm, typ, flags, addr, data), off in zip(secs, offs):
        blob += struct.pack('<IIQQQQIIQQ', name_off[nm], typ, flags, addr,
                            off, len(data), 0, 0, 1, 0)
    blob += struct.pack('<IIQQQQIIQQ', name_off[b'.shstrtab'], 3, 0, 0,
                        shstr_off, len(shstr), 0, 0, 1, 0)
    blob[0:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<Q', blob, 40, shoff)
    struct.pack_into('<HHH', blob, 58, 64, len(secs) + 2, len(secs) + 1)
    return bytes(blob)


@unittest.skipUnless(importlib.util.find_spec('capstone'),
                     'capstone required to import the subject module')
class LatencyPairMissingSectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import gas_auction_price as gas
        import node115_latency_pair_rust as lp
        cls.gas = gas
        cls.lp = lp

    def test_rodata_read_allowed_on_valid_image(self):
        mem = self.lp.Memory(self.gas.Image(build()))
        self.assertIsNone(mem.allowed(0x8000, 1))

    def test_missing_rodata_fails_closed(self):
        mem = self.lp.Memory(self.gas.Image(build((b'.rodata',))))
        with self.assertRaisesRegex(ValueError,
                                    'outside qualified pair projection'):
            mem.allowed(0x8000, 1)


if __name__ == '__main__':
    unittest.main()
