"""Missing required sections in foundation_hour.analyze().

analyze() looked its required sections up with bare dict indexing, so a
binary without .eh_frame, .rela.dyn or .text escaped its ValueError
contract (every other malformed input goes through require()) as a bare
KeyError. The fixtures are synthetic ELFs built only from the module's
own retained constants: the .text case additionally carries the exact
relocation, location, message and caller bytes the earlier checks demand,
so the missing-.text lookup is the first failure reached.
"""
import hashlib
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import foundation_hour as hour

EH = 0xce1518  # implied by both retained FDE constants' PC deltas
CALLER_CIE = bytes.fromhex(
    '1c00000000000000017a504c5200017810079b29ca7b041b1b0c070890010000')


def elf(sections):
    names = b'\x00'
    offs = {}
    for name, _, _, _ in sections:
        offs[name] = len(names)
        names += name.encode() + b'\x00'
    offs['.shstrtab'] = len(names)
    names += b'.shstrtab\x00'
    shoff = 64
    nsec = len(sections) + 2
    data_off = shoff + nsec * 64
    blobs = []
    cur = data_off
    for _, _, _, blob in sections:
        blobs.append((cur, blob))
        cur += len(blob)
    names_off = cur
    total = names_off + len(names)
    data = bytearray(total)
    data[0:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<Q', data, 40, shoff)
    struct.pack_into('<HHH', data, 58, 64, nsec, len(sections) + 1)

    def shdr(i, name_off, typ, addr, off, size):
        struct.pack_into('<IIQQQQIIQQ', data, shoff + i * 64,
                         name_off, typ, 0, addr, off, size, 0, 0, 0, 0)

    shdr(0, 0, 0, 0, 0, 0)
    for i, (name, typ, addr, blob) in enumerate(sections, start=1):
        shdr(i, offs[name], typ, addr, blobs[i - 1][0], len(blob))
    shdr(nsec - 1, offs['.shstrtab'], 3, 0, names_off, len(names))
    for off, blob in blobs:
        data[off:off + len(blob)] = blob
    data[names_off:names_off + len(names)] = names
    return bytes(data)


def eh_frame():
    eh = bytearray(0x2e86f4 + len(hour.CALLER_FDE))
    eh[0:len(hour.CIE)] = hour.CIE
    eh[0x2dc714:0x2dc714 + len(CALLER_CIE)] = CALLER_CIE
    eh[0xad08:0xad08 + len(hour.FDE)] = hour.FDE
    eh[0x2e86f4:0x2e86f4 + len(hour.CALLER_FDE)] = hour.CALLER_FDE
    return bytes(eh)


def full_sections(code_name='.text'):
    secs = [(code_name, 1, hour.START, hour.BODY),
            ('.eh_frame', 1, EH, eh_frame())]
    rels = [(0x576efc0, hour.START), (0x576e048, 0x157aa10),
            (0x576e108, 0x157b7f0), (0x566aac8, 0x1de94e),
            (0x5666dd8, 0x1f0469)]
    secs.append(('.rela.dyn', 1, 0x500000,
                 b''.join(struct.pack('<QQq', s, 8, t) for s, t in rels)))
    secs.append(('relptr1', 1, 0x576efc0, b'\x00' * 8))
    secs.append(('relptr2', 1, 0x576e048, b'\x00' * 8))
    secs.append(('relptr3', 1, 0x576e108, b'\x00' * 8))
    path1 = b'/home/ubuntu/hl/code_Mainnet/base/src/time.rs'
    path2 = b'/home/ubuntu/hl/code_Mainnet/base/src/hour.rs'
    secs.append(('loc1', 1, 0x566aac8,
                 b'\x00' * 8 + struct.pack('<QII', len(path1), 62, 44)))
    secs.append(('loc2', 1, 0x5666dd8,
                 b'\x00' * 8 + struct.pack('<QII', len(path2), 12, 13)))
    secs.append(('str1', 1, 0x1de94e, path1))
    secs.append(('str2', 1, 0x1f0469, path2))
    secs.append(('msg1', 1, 0x219daa,
                 b'called `Result::unwrap()` on an `Err` value'))
    secs.append(('msg2', 1, 0x216f29, b'assertion failed: hour <= 24'))
    secs.append(('caller', 1, 0x140380f,
                 bytes.fromhex('488d7c2410ff15a6b73604')))
    return secs


class MissingSectionTests(unittest.TestCase):
    def test_missing_eh_frame(self):
        with self.assertRaisesRegex(ValueError, 'Missing section .eh_frame'):
            hour.analyze(elf([('.text', 1, hour.START, hour.BODY)]))

    def test_missing_rela_dyn(self):
        secs = [('.text', 1, hour.START, hour.BODY),
                ('.eh_frame', 1, EH, eh_frame())]
        with self.assertRaisesRegex(ValueError, 'Missing section .rela.dyn'):
            hour.analyze(elf(secs))

    def test_missing_text(self):
        # Every earlier check passes; the .text lookup is the first failure.
        with self.assertRaisesRegex(ValueError, 'Missing section .text'):
            hour.analyze(elf(full_sections(code_name='.code')))

    def test_present_sections_reach_relocation_check(self):
        # Empty .rela.dyn passes the section guards, then the relocation
        # check itself rejects the input -- proving the guards let valid
        # sections through.
        secs = [('.text', 1, hour.START, hour.BODY),
                ('.eh_frame', 1, EH, eh_frame()),
                ('.rela.dyn', 1, 0x500000, b'')]
        with self.assertRaisesRegex(ValueError, 'Relative relocation changed'):
            hour.analyze(elf(secs))


if __name__ == '__main__':
    unittest.main()
