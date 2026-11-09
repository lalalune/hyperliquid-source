"""Fail-closed controls: node115_tuple_threshold on a missing .text
section and a missing/truncated .rela.dyn table.

direct_scan() looked .text up with bare next(); source_association()
looked .rela.dyn up with bare next() and walked it with a range-step
loop, so a truncated table was silently accepted. The mutants rename
a section in .shstrtab or shrink .rela.dyn by one byte; no
instruction bytes change. The module's refusal idiom is demand()
-> ValueError. collect() itself digest-gates on the pinned binary,
so these are helper-level controls; the helpers are called directly.
"""
import hashlib
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import node115_tuple_threshold as subject
from elf_index import sections
from fde_extents import eh_frame_records


def renamed(data, name):
    shoff = struct.unpack_from("<Q", data, 40)[0]
    entsize, count, strndx = struct.unpack_from("<HHH", data, 58)
    rows = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * entsize)
            for i in range(count)]
    strtab = rows[strndx]
    table = data[strtab[4]:strtab[4] + strtab[5]]
    target = None
    for row in rows:
        end = table.find(b"\0", row[0])
        if table[row[0]:end].decode() == name:
            target = row
            break
    assert target is not None, name
    shstr = next(s for s in sections(data) if s["name"] == ".shstrtab")
    mutant = bytearray(data)
    mutant[shstr["offset"] + target[0]] = ord("X")
    return bytes(mutant)


def resized(data, name, new_size):
    shoff = struct.unpack_from("<Q", data, 40)[0]
    entsize, count, strndx = struct.unpack_from("<HHH", data, 58)
    rows = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * entsize)
            for i in range(count)]
    strtab = rows[strndx]
    table = data[strtab[4]:strtab[4] + strtab[5]]
    target = None
    for row in rows:
        end = table.find(b"\0", row[0])
        if table[row[0]:end].decode() == name:
            target = row
            break
    assert target is not None, name
    mutant = bytearray(data)
    struct.pack_into("<Q", mutant, shoff + rows.index(target) * entsize + 32,
                     new_size)
    return bytes(mutant)


class TupleThresholdRequiredSections(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = subject.TARGET.read_bytes()
        if hashlib.sha256(cls.data).hexdigest() != subject.SHA:
            raise unittest.SkipTest("node 115 artifact is not materialised")
        _cies, cls.fdes = eh_frame_records(cls.data, sections(cls.data))

    def test_direct_scan_missing_text_refuses(self):
        mutant = renamed(self.data, ".text")
        with self.assertRaisesRegex(ValueError, "missing.text section"):
            subject.direct_scan(mutant, sections(mutant), {subject.START})

    def test_source_association_missing_rela_dyn_refuses(self):
        mutant = renamed(self.data, ".rela.dyn")
        with self.assertRaisesRegex(ValueError, "missing.rela.dyn section"):
            subject.source_association(mutant, sections(mutant), self.fdes)

    def test_source_association_truncated_rela_dyn_refuses(self):
        secs = sections(self.data)
        rela = next(s for s in secs if s["name"] == ".rela.dyn")
        mutant = resized(self.data, ".rela.dyn", rela["size"] - 1)
        with self.assertRaisesRegex(ValueError, "truncated.rela.dyn section"):
            subject.source_association(mutant, sections(mutant), self.fdes)

    def test_unmutated_controls(self):
        secs = sections(self.data)
        hits = subject.direct_scan(self.data, secs, {subject.START})
        self.assertTrue(hits)
        assoc = subject.source_association(self.data, secs, self.fdes)
        self.assertIn("relocation", assoc)
        self.assertIsInstance(subject.collect(self.data), dict)


if __name__ == "__main__":
    unittest.main()
