"""Missing .eh_frame section in foundation_millis.analyze().

analyze() read its required .eh_frame address with a bare dict lookup,
so a binary without that section escaped its ValueError contract (every
other malformed input goes through require()) as a bare KeyError. The
fixtures are minimal synthetic ELFs; records carry only the target
identity, so the section lookup is the first failure reached.
"""
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import foundation_millis as millis


def elf(with_eh_frame):
    sections = [('.dummy', 1, 0x1000, b'\x00' * 8)]
    if with_eh_frame:
        sections.append(('.eh_frame', 1, 0x2000, b'\x00' * 16))
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
    data = bytearray(names_off + len(names))
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


RECORDS = {'target_sha256': millis.SHA256, 'windows': []}


class MissingEhFrameTests(unittest.TestCase):
    def test_missing_eh_frame(self):
        with self.assertRaisesRegex(ValueError, 'Missing section .eh_frame'):
            millis.analyze(elf(False), RECORDS)

    def test_present_eh_frame_reaches_window_checks(self):
        # The section guard passes; the empty window set then fails the
        # required-address check -- proving the guard lets valid
        # sections through.
        with self.assertRaisesRegex(ValueError, 'Required address'):
            millis.analyze(elf(True), RECORDS)


if __name__ == '__main__':
    unittest.main()
