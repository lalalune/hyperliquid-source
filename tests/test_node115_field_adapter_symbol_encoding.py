"""RE-014 control: a non-UTF-8 .strtab symbol name must fail closed.

Image.symbol() bounds-checks the name through need() like every other
defect in the module, but decoded it raw, so a crafted member ELF let a
UnicodeDecodeError escape derive() instead of the module's EvidenceError.
EvidenceError and UnicodeDecodeError are both ValueError subclasses, so
the exact-type check is what separates the defect from the fix.
Static synthetic bytes only; no captured execution.
"""
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import node115_field_adapter_drift as drift

PARENT = drift.PARENT_SECTION.encode()
ADAPTER = drift.ADAPTER_SECTION.encode()
MEMBER = drift.MEMBER.encode()


def elf(kind, sections):
    """Minimal ELF64-LE image; sections are (name, type, flags, blob, link, entsize)."""
    shstr = b"\0"
    name_offsets = []
    for name, *_ in sections:
        name_offsets.append(len(shstr))
        shstr += name + b"\0"
    shstr_name_offset = len(shstr)
    shstr += b".shstrtab\0"
    body = bytearray(64)
    body[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<HH", body, 16, kind, 62)
    offsets = []
    for name, typ, flags, blob, link, entsize in sections:
        offsets.append(len(body))
        body += blob
    shstr_off = len(body)
    body += shstr
    shoff = len(body)
    struct.pack_into("<Q", body, 40, shoff)
    struct.pack_into("<HHH", body, 58, 64, len(sections) + 2, len(sections) + 1)
    body += struct.pack("<IIQQQQIIQQ", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    for (name, typ, flags, blob, link, entsize), noff, off in zip(sections, name_offsets, offsets):
        body += struct.pack("<IIQQQQIIQQ", noff, typ, flags, 0, off, len(blob), link, 0, 1, entsize)
    body += struct.pack("<IIQQQQIIQQ", shstr_name_offset, 3, 0, 0, shstr_off, len(shstr), 0, 0, 1, 0)
    return bytes(body)


def member_elf(strtab, symbols):
    """kind=1 member ELF: parent/adapter .text extents, .symtab linked to .strtab."""
    symtab = b"".join(struct.pack("<IBBHQQ", *s) for s in symbols)
    return elf(1, [
        (PARENT, 1, 6, bytes(390), 0, 0),
        (ADAPTER, 1, 6, bytes(622), 0, 0),
        (b".symtab", 2, 0, symtab, 4, 24),
        (b".strtab", 3, 0, strtab, 0, 0),
    ])


def ar_member(name_field, body):
    header = name_field.ljust(16, b" ")
    header += b"0".ljust(12, b" ") + b"0".ljust(6, b" ") + b"0".ljust(6, b" ")
    header += b"100644".ljust(8, b" ") + str(len(body)).encode().ljust(10, b" ") + b"`\n"
    return header + body + (b"\n" if len(body) % 2 else b"")


def archive(member):
    return b"!<arch>\n" + ar_member(b"//", MEMBER + b"/\n") + ar_member(b"/0", member)


BAD_MEMBER = member_elf(b"\0\xff\xfe\0", [(1, 0x12, 0, 1, 0, 390)])
PARENT_NAME = PARENT[len(b".text."):]
ADAPTER_NAME = ADAPTER[len(b".text."):]
GOOD_STRTAB = b"\0" + PARENT_NAME + b"\0" + ADAPTER_NAME + b"\0"
GOOD_MEMBER = member_elf(GOOD_STRTAB, [
    (1, 0x12, 0, 1, 0, 390),
    (1 + len(PARENT_NAME) + 1, 0x12, 0, 2, 0, 622),
])
TARGET = elf(3, [])


class SymbolNameEncodingTests(unittest.TestCase):
    def test_non_utf8_symbol_name_rejected_via_derive(self):
        with self.assertRaises(drift.EvidenceError) as ctx:
            drift.derive(TARGET, archive(BAD_MEMBER))
        self.assertIs(type(ctx.exception), drift.EvidenceError)
        self.assertEqual(str(ctx.exception), "invalid symbol name encoding")

    def test_non_utf8_symbol_name_rejected_at_symbol(self):
        image = drift.Image(BAD_MEMBER, 1)
        with self.assertRaises(drift.EvidenceError) as ctx:
            image.symbol(3, 0)
        self.assertIs(type(ctx.exception), drift.EvidenceError)
        self.assertEqual(str(ctx.exception), "invalid symbol name encoding")

    def test_valid_symbol_names_accepted(self):
        image = drift.Image(GOOD_MEMBER, 1)
        self.assertEqual(image.symbol(3, 0)["name"], PARENT_NAME.decode())
        self.assertEqual(image.symbol(3, 1)["name"], ADAPTER_NAME.decode())
        # derive() scans every .symtab entry before any frame work, so with
        # valid names it refuses only at the deliberately minimal target's
        # missing .eh_frame_hdr, not at the symbol scan.
        with self.assertRaisesRegex(drift.EvidenceError, "expected one section: .eh_frame_hdr"):
            drift.derive(TARGET, archive(GOOD_MEMBER))


if __name__ == "__main__":
    unittest.main()
