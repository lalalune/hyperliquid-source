"""Tests for tools/read_precompile_gas.py. Expected numbers here are literals, not calls to the tool's rule list."""
import copy
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import read_precompile_gas as tool  # noqa: E402

FOLDER = ROOT / "research" / "work-items" / "RE-004-read-precompile-gas-94"
TOP = 2 ** 64 - 1
IN_SCOPE = (0x800, 0x801, 0x804, 0x805, 0x809, 0x80B, 0x80C, 0x80D, 0x810, 0x811, 0x812, 0x813)
FIXED = {0x800: 160, 0x801: 96, 0x805: 128, 0x809: 32, 0x810: 32, 0x813: 160}


class Shared:
    image = None
    entries = None
    full = None


def shared_get():
    if Shared.image is None:
        Shared.image = tool.load_image()
        _, Shared.entries = tool.family(Shared.image)
        for entry in Shared.entries:
            tool.gate_shape(Shared.image, entry)
            tool.final_shape(Shared.image, entry)
    return Shared.image, Shared.entries


def shared_result():
    if Shared.full is None:
        Shared.full = tool.analyse(shared_get()[0])
    return Shared.full


def patched(image, va, value):
    other = copy.copy(image)
    blob = bytearray(image.blob)
    blob[image.offset(va)] = value
    other.blob = bytes(blob)
    return other


class Base(unittest.TestCase):
    def setUp(self):
        self.image, self.entries = shared_get()
        self.by_number = {entry["number"]: entry for entry in self.entries}


class Identity(unittest.TestCase):
    def test_wrong_digest_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(expected="0" * 64)

    def test_changed_byte_refused(self):
        blob = bytearray(tool.BINARY.read_bytes())
        blob[-1] ^= 1
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "copy"
            path.write_bytes(blob)
            with self.assertRaises(tool.EvidenceError):
                tool.load_image(path)

    def test_source_starts_no_program(self):
        text = (ROOT / "tools" / "read_precompile_gas.py").read_text()
        for word in ("subprocess", "popen", "os.system"):
            self.assertNotIn(word, text)


class Family(Base):
    def test_twenty_values(self):
        numbers, entries = tool.family(self.image)
        self.assertEqual(numbers, list(range(0x800, 0x814)))
        self.assertEqual(tuple(entry["number"] for entry in entries), IN_SCOPE)

    def test_function_bounds_come_from_fdes(self):
        entry = self.by_number[0x812]
        self.assertEqual((entry["start"], entry["end"]), (0x324BDF0, 0x324C52D))

    def test_scope_excludes_named_numbers(self):
        for number in tool.OUT_OF_SCOPE:
            self.assertNotIn(number, self.by_number)

    def test_moved_constant_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.family(patched(self.image, 0x582610 + 19, 0x14))

    def test_section_for_nobits_refused(self):
        bss = self.image.named[".bss"]
        with self.assertRaises(tool.EvidenceError):
            self.image.offset(bss["address"] + 8)


class Finals(Base):
    def test_fixed_sizes(self):
        for number, size in FIXED.items():
            entry = self.by_number[number]
            self.assertEqual((entry["form"], entry["output"], entry["final_value"]), ("fixed", size, 1000 + 33 * size))

    def test_runtime_form(self):
        for number in (0x804, 0x80B, 0x80C, 0x80D, 0x811, 0x812):
            self.assertEqual(self.by_number[number]["form"], "runtime")

    def test_docs_differ(self):
        self.assertEqual((tool.cost(32, 32), tool.doc_cost(32, 32)), (3112, 6160))

    def test_constant_edit_refused(self):
        entry = dict(self.by_number[0x805])
        with self.assertRaises(tool.EvidenceError):
            tool.final_shape(patched(self.image, entry["final"] + 3, 0x69), entry)

    def test_multiply_edit_refused(self):
        entry = dict(self.by_number[0x812])
        other = patched(self.image, entry["final"] + 1, 0x22)
        with self.assertRaises(tool.EvidenceError):
            tool.final_shape(other, entry)

    def test_path_walk_sees_a_write(self):
        entry = self.by_number[0x805]
        start = tool.decode(tool.Machine(self.image).read_code, entry["decoder_site"]).next
        with self.assertRaises(tool.EvidenceError):
            tool.clean_path(self.image, entry, start, entry["fold"], (tool.RAX,))

    def test_path_walk_needs_a_path(self):
        entry = self.by_number[0x805]
        with self.assertRaises(tool.EvidenceError):
            tool.clean_path(self.image, entry, entry["final"], entry["fold"], ())

    def test_slot_stores_reads_both_forms(self):
        short = bytes.fromhex("4c89642470")
        wide = bytes.fromhex("4c89a42488000000")
        self.assertEqual(tool.slot_stores(short + wide), {0x70: [12], 0x88: [12]})


class Gates(Base):
    def run_case(self, number, **fields):
        harness = tool.Harness(self.image)
        return harness.run(self.by_number[number], tool.Case("probe", **fields))[1]

    def test_every_function_cap_edge(self):
        for number in IN_SCOPE:
            self.assertEqual(self.run_case(number, n=2000, gas=TOP)[0], "reached")
            self.assertEqual(self.run_case(number, n=2001, gas=TOP)[0], "returned")

    def test_every_function_gas_edge(self):
        for number in IN_SCOPE:
            self.assertEqual(self.run_case(number, n=32, gas=2056)[0], "reached")
            self.assertEqual(self.run_case(number, n=32, gas=2055)[0], "returned")

    def test_every_function_set_hit(self):
        for number in IN_SCOPE:
            self.assertEqual(self.run_case(number, keys=(0, 1), set_shape="deep")[0], "returned")
            self.assertEqual(self.run_case(number, keys=(1, 2), set_shape="deep")[0], "reached")

    def test_cap_edit_is_caught(self):
        entry = self.by_number[0x801]
        harness = tool.Harness(patched(self.image, entry["cap"] + 3, 0xD1))
        case = tool.Case("edge", n=2001, gas=TOP)
        before, got = harness.run(entry, case)
        self.assertFalse(tool.same(got, tool.spec_run(entry, case, before)))

    def test_rule_list_rejects_other_decoder(self):
        got = ("reached", b"", 0x1234, "rdi,rsi")
        self.assertFalse(tool.same(got, ("reached", b"", 0x37E6060, None)))

    def test_unknown_argument_form_rejected(self):
        self.assertFalse(tool.same(("reached", b"", 1, "other"), ("reached", b"", 1, None)))

    def test_step_limit_control(self):
        harness = tool.Harness(self.image)
        harness.machine.step_limit = 5
        with self.assertRaises(tool.Halt):
            harness.run(self.by_number[0x812], tool.Case("short"))


class Evidence(unittest.TestCase):
    def test_mutations(self):
        rows = shared_result()["mutations"]
        self.assertGreater(len(rows), 300)
        self.assertEqual([row for row in rows if row[3] == "survived"], [])

    def test_every_function_sees_both_outcomes(self):
        for _, counts, forms in shared_result()["outcomes"]:
            self.assertGreater(counts["returned"], 20)
            self.assertGreater(counts["reached"], 20)
            self.assertEqual(len(forms), 1)

    def test_folder_equals_generated_set(self):
        files = tool.render(shared_result())
        names = sorted(path.name for path in FOLDER.iterdir())
        self.assertEqual(names, sorted(list(files) + ["MANIFEST.sha256", "README.md"]))
        for name, text in files.items():
            self.assertEqual((FOLDER / name).read_text(), text, name)


if __name__ == "__main__":
    unittest.main()
