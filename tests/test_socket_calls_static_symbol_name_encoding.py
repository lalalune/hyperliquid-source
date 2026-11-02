"""Synthetic-ELF tests for the socket_calls_static symbol name decode.

Builds a minimal ELF64-LE image with one GLOB_DAT relocation whose dynamic
symbol name lives in .dynstr, mirroring tools/socket_calls_static.py::Image.
A non-UTF-8 name must fail closed as the module's EvidenceError, the same
contract every other malformed case in Image.__init__ raises via require().
"""
import struct
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import socket_calls_static as sc  # noqa: E402

SLOT = 0x5770000


def build(sym_name):
    names = [b'', b'.text', b'.rela.dyn', b'.dynsym', b'.dynstr',
             b'.eh_frame_hdr', b'.eh_frame', b'.shstrtab']
    shstr = b''
    offs = []
    for n in names:
        offs.append(len(shstr))
        shstr += n + b'\0'
    dynstr = b'\0' + sym_name + b'\0'
    rela = struct.pack('<QQq', SLOT, 6, 0)                # GLOB_DAT, sym 0
    dynsym = struct.pack('<IBBHQQ', 1, 0x12, 0, 0, 0, 0)  # st_name=1
    eh_hdr = bytes([1, 0x1b, 0x03, 0x3b]) + b'\0' * 8     # count 0
    nsec = len(names)
    shoff = 64
    cur = shoff + nsec * 64
    blobs = {}
    for key, blob in (('.text', b'\x90' * 16), ('.rela.dyn', rela),
                      ('.dynsym', dynsym), ('.dynstr', dynstr),
                      ('.eh_frame_hdr', eh_hdr), ('.eh_frame', b'\0' * 4),
                      ('.shstrtab', shstr)):
        blobs[key] = (cur, blob)
        cur += len(blob)
    data = bytearray(cur)
    data[:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<Q', data, 40, shoff)
    struct.pack_into('<HHH', data, 58, 64, nsec, nsec - 1)
    for i, n in enumerate(names):
        if i == 0:
            continue
        off, blob = blobs[n.decode()]
        data[off:off + len(blob)] = blob
        struct.pack_into('<IIQQQQIIQQ', data, shoff + i * 64,
                         offs[i], 1, 0, 0x1000 * (i + 1), off, len(blob),
                         0, 0, 1, 0)
    return bytes(data)


class SocketCallsSymbolNameEncodingTests(unittest.TestCase):
    def test_non_utf8_symbol_name_fails_closed(self):
        # On base the bare .decode() escapes as UnicodeDecodeError, which
        # is not an EvidenceError; with the fix it fails closed.
        with self.assertRaisesRegex(sc.EvidenceError,
                                    'dynamic symbol name is not valid UTF-8'):
            sc.Image(build(b'\xffsocket'))

    def test_latin1_symbol_name_fails_closed(self):
        with self.assertRaisesRegex(sc.EvidenceError,
                                    'dynamic symbol name is not valid UTF-8'):
            sc.Image(build(b'sock\xe9t'))

    def test_valid_symbol_name_unchanged(self):
        img = sc.Image(build(b'socket'))
        self.assertEqual(img.named, {'socket': [SLOT]})


if __name__ == '__main__':
    unittest.main()
