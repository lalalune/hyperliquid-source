"""Fail-closed controls: node115_cli_output_config on missing sections and
non-ASCII decoded names.

Image.symbol() looked .dynsym/.dynstr up with bare next() and decoded with a
bare .decode('ascii'); lsda() looked .gcc_except_table up with bare next();
observe() decoded each query name with a bare .decode('ascii'). The mutants
rename a section in .shstrtab by flipping the first byte of its name string,
or flip one byte inside a decoded name; no instruction bytes change.
collect() itself digest-gates (Image defaults to authenticate=True), so
these controls use the module's own authenticate=False corruption path,
which its existing test file also uses for mutated inputs. The collect()
FDE lookup is not claimed: eh_frame_records refuses a truncated .eh_frame
first, so that site is unreachable.
"""
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import node115_cli_output_config as output
from elf_index import sections


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


class CliOutputConfigRequiredSections(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = (ROOT / output.ARTIFACT).read_bytes()
        cls.image = output.Image(cls.data)
        cls.observation = output.observe(cls.image)
        cls.lsda_va = next(f for f in cls.image.fdes
                           if f["start"] == output.PRIMARY)["lsda"]

    def test_symbol_missing_dynsym_refuses(self):
        image = output.Image(renamed(self.data, ".dynsym"), authenticate=False)
        with self.assertRaisesRegex(ValueError, "missing.dynsym section"):
            image.symbol(1)

    def test_symbol_missing_dynstr_refuses(self):
        image = output.Image(renamed(self.data, ".dynstr"), authenticate=False)
        with self.assertRaisesRegex(ValueError, "missing.dynstr section"):
            image.symbol(1)

    def test_symbol_non_ascii_name_refuses(self):
        secs = sections(self.data)
        sym = next(s for s in secs if s["name"] == ".dynsym")
        strs = next(s for s in secs if s["name"] == ".dynstr")
        name_off = struct.unpack_from("<I", self.data, sym["offset"] + 24)[0]
        mutant = bytearray(self.data)
        mutant[strs["offset"] + name_off] = 0xFF
        image = output.Image(bytes(mutant), authenticate=False)
        with self.assertRaisesRegex(ValueError, "not valid ASCII"):
            image.symbol(1)

    def test_lsda_missing_gcc_except_table_refuses(self):
        image = output.Image(renamed(self.data, ".gcc_except_table"),
                             authenticate=False)
        with self.assertRaisesRegex(ValueError, "missing.gcc_except_table section"):
            output.lsda(image, output.PRIMARY, self.lsda_va)

    def test_observe_non_ascii_query_name_refuses(self):
        query = self.observation["queries_in_execution_order"][0]
        va = int(query["literal_va"], 16)
        pos = self.image.offset(va, query["length"])
        mutant = bytearray(self.data)
        mutant[pos + 1] = 0xFF
        image = output.Image(bytes(mutant), authenticate=False)
        with self.assertRaisesRegex(ValueError, "query name is not valid ASCII"):
            output.observe(image)

    def test_unmutated_image_controls(self):
        image = output.Image(self.data, authenticate=False)
        self.assertEqual(image.symbol(1), "__libc_start_main")
        lsda = output.lsda(image, output.PRIMARY, self.lsda_va)
        self.assertTrue(lsda["header_and_call_sites"].startswith("ffff0111"))
        self.assertEqual(
            len(output.observe(image)["queries_in_execution_order"]), 14)


if __name__ == "__main__":
    unittest.main()
