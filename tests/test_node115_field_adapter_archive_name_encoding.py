"""RE-014 control: a non-ASCII GNU ar long name must fail closed.

archive_member() bounds-checks a `/NNN` long name through need() like
every other defect in the module, and converts the fixed header's
name/size decode, but decoded the // string-table entry raw, so a
crafted archive let a UnicodeDecodeError escape archive_member() (and
derive(), whose first step it is) instead of the module's
EvidenceError. EvidenceError and UnicodeDecodeError are both ValueError
subclasses, so the exact-type check is what separates the defect from
the fix. Static synthetic bytes only; no captured execution.
"""
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import node115_field_adapter_drift as drift

MEMBER = drift.MEMBER.encode()
PAYLOAD = b"payload-bytes"


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


def ar_member(name_field, body):
    header = name_field.ljust(16, b" ")
    header += b"0".ljust(12, b" ") + b"0".ljust(6, b" ") + b"0".ljust(6, b" ")
    header += b"100644".ljust(8, b" ") + str(len(body)).encode().ljust(10, b" ") + b"`\n"
    return header + body + (b"\n" if len(body) % 2 else b"")


def archive(names_entry, member_body):
    """Archive whose only real member is referenced as /0 into the // table."""
    return b"!<arch>\n" + ar_member(b"//", names_entry) + ar_member(b"/0", member_body)


BAD = archive(b"core-\xff.o/\n", PAYLOAD)
GOOD_MEMBER = archive(MEMBER + b"/\n", PAYLOAD)
OTHER_NAME = archive(b"other.o/\n", PAYLOAD)
TARGET = elf(3, [])


class ArchiveNameEncodingTests(unittest.TestCase):
    def test_non_ascii_long_name_rejected_at_archive_member(self):
        with self.assertRaises(drift.EvidenceError) as ctx:
            drift.archive_member(BAD)
        self.assertIs(type(ctx.exception), drift.EvidenceError)
        self.assertEqual(str(ctx.exception), "invalid ar long name encoding")

    def test_non_ascii_long_name_rejected_via_derive(self):
        # archive_member() is derive()'s first step, so the conversion
        # must already hold at the below-identity seam.
        with self.assertRaises(drift.EvidenceError) as ctx:
            drift.derive(TARGET, BAD)
        self.assertIs(type(ctx.exception), drift.EvidenceError)
        self.assertEqual(str(ctx.exception), "invalid ar long name encoding")

    def test_valid_long_names_accepted(self):
        body, offset = drift.archive_member(GOOD_MEMBER)
        self.assertEqual(body, PAYLOAD)
        self.assertEqual(GOOD_MEMBER[offset:offset + len(PAYLOAD)], PAYLOAD)
        # A well-formed long name that is not the target member still
        # fails closed at the member check, not at the decode.
        with self.assertRaises(drift.EvidenceError) as ctx:
            drift.archive_member(OTHER_NAME)
        self.assertIs(type(ctx.exception), drift.EvidenceError)
        self.assertEqual(str(ctx.exception), "expected one exact core object member")


if __name__ == "__main__":
    unittest.main()
