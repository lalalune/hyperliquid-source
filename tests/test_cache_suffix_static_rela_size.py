"""Synthetic-ELF tests for the cache_suffix_static .rela.dyn entry-size guard.

Builds a minimal ELF64 that passes elf_index.sections(), the unwind/FDE
checks and the crafted 350-byte selector body in analyze(), varying only
the .rela.dyn section size. A size that is not a multiple of the 24-byte
RELA entry must fail closed as ValueError ('truncated .rela.dyn'), the
contract every other malformed case in analyze() raises; on the base it
escapes as a bare struct.error, which is not a ValueError subclass.

A second truncation shape reaches the same unpack: elf_index.sections()
exempts SHT_NOBITS (type 8) rows from its outside-file check, so a header
typed 8 whose declared range runs past the end of the file hands
iter_unpack a short buffer even when the declared size is a whole
multiple of 24. The guard therefore also bounds-checks the declared
range at the read site, like evm_amount_scale's unpack guards.
"""
import struct
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import cache_suffix_static as subject  # noqa: E402


def selector_body():
    body = bytearray(350)
    body[0x1d:0x21] = b'\x48\x83\x7e\x08'
    body[0x21] = 10                                   # length
    body[0x27:0x29] = b'\x48\xb9'
    body[0x29:0x31] = b'abci_sta'                     # prefix
    body[0x38:0x3b] = b'\x48\x81\xf2'
    struct.pack_into('<I', body, 0x3b, 0x6574)        # tail_xor
    struct.pack_into('<i', body, 0x47, 0x9382b9 - (0x5942a24 + 7))
    struct.pack_into('<i', body, 0x4e, 0x459f60 - (0x5942a2b + 7))
    body[0x52:0x56] = bytes.fromhex('480f44ca')
    body[0x56:0x59] = bytes.fromhex('0f95c0')
    body[0x59:0x5d] = bytes.fromhex('4883c003')       # also sets body[0x5c]=3
    struct.pack_into('<I', body, 0x9b, 4)
    return bytes(body)


def build_elf(rela_size):
    names = [b'', b'.text', b'.eh_frame_hdr', b'.eh_frame',
             b'.rela.dyn', b'.shstrtab']
    shstr = b''
    name_off = []
    for n in names:
        name_off.append(len(shstr))
        shstr += n + b'\0'
    text_addr = 0x59429e0
    hdr_addr, frame_addr = 0x100000, 0x100100
    cie_body = b'\x01zR\x00' + b'\x01' + b'\x78' + b'\x10' + b'\x01' + b'\x1b'
    cie = struct.pack('<II', 4 + len(cie_body), 0) + cie_body
    eh_frame = cie + b'\x00\x00\x00\x00'
    eh_hdr = (bytes([1, 0x1b, 0x03, 0x3b])
              + struct.pack('<i', frame_addr - (hdr_addr + 4))
              + struct.pack('<I', 0))
    contents = [(1, 1, 0x6, text_addr, selector_body()),
                (2, 1, 0, hdr_addr, eh_hdr),
                (3, 1, 0, frame_addr, eh_frame),
                (4, 4, 0, 0, b'\0' * rela_size),
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


def patch_rela_header(blob, rela_type=None, offset=None, size=None):
    """Rewrite fields of the .rela.dyn section header (index 4)."""
    blob = bytearray(blob)
    shoff = struct.unpack_from('<Q', blob, 40)[0]
    hdr = shoff + 4 * 64
    if rela_type is not None:
        struct.pack_into('<I', blob, hdr + 4, rela_type)
    if offset is not None:
        struct.pack_into('<Q', blob, hdr + 24, offset)
    if size is not None:
        struct.pack_into('<Q', blob, hdr + 32, size)
    return bytes(blob)


class CacheSuffixRelaSizeTests(unittest.TestCase):
    def test_truncated_rela_dyn_fails_closed(self):
        with self.assertRaisesRegex(ValueError, 'truncated .rela.dyn'):
            subject.analyze(build_elf(25))

    def test_rela_dyn_with_trailing_partial_entry_fails_closed(self):
        with self.assertRaisesRegex(ValueError, 'truncated .rela.dyn'):
            subject.analyze(build_elf(26))

    def test_nobits_rela_dyn_past_eof_fails_closed(self):
        # SHT_NOBITS exempts .rela.dyn from sections()' outside-file
        # check, so a declared 48-byte range with only 25/30 bytes left
        # in the file reaches iter_unpack as a short buffer; it must
        # fail closed with the same ValueError, not a bare struct.error.
        blob = build_elf(48)
        for left in (25, 30):
            patched = patch_rela_header(
                blob, rela_type=8, offset=len(blob) - left)
            with self.assertRaisesRegex(ValueError, 'truncated .rela.dyn'):
                subject.analyze(patched)

    def test_nobits_rela_dyn_fully_present_reaches_bindings_check(self):
        # Negative control: a type-8 header whose declared range is
        # fully inside the file still parses and fails at the bindings
        # check, proving the bounds guard is not a blanket type refusal.
        patched = patch_rela_header(build_elf(48), rela_type=8)
        with self.assertRaisesRegex(
                ValueError, 'cache formatting/global relocation changed'):
            subject.analyze(patched)

    def test_whole_entry_sizes_still_reach_bindings_check(self):
        # Negative controls: sizes 0/24/48 parse and fail at the very next
        # check with the module's pre-existing ValueError, proving the
        # guard does not change well-formed entry handling.
        for size in (0, 24, 48):
            with self.assertRaisesRegex(
                    ValueError, 'cache formatting/global relocation changed'):
                subject.analyze(build_elf(size))


if __name__ == '__main__':
    unittest.main()
