import hashlib
import pathlib
import struct
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import bole_reserve_reply115 as tool  # noqa: E402

WORK = ROOT / "research" / "work-items" / "RE-004-bole-reserve-reply-115"
E14 = tool.E14
# Files that do not depend on the number of pseudo-random vectors; the regeneration test rebuilds these with a short vector run.
STABLE = ("function-rows.tsv", "table-entries.tsv", "slots.tsv", "call-sites.tsv", "constants.tsv", "reciprocals.tsv", "reply-samples.tsv", "outcomes.tsv",
          "model-variants.tsv", "structural-controls.tsv", "rust-vectors.tsv")


class ReserveReplyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = tool.load_image()
        cls.harnesses = {False: tool.Harness(cls.image), True: tool.Harness(cls.image, stub_callees=True)}
        cls.cases = tool.named_cases()
        cls.by_name = {case.name: (case, stubbed) for case, stubbed in cls.cases}
        cls.rows = tool.decode_range(cls.image, tool.ENTRY, tool.BODY_END)

    def run_plain(self, case, stubbed=False):
        layout, before, after, events, divides, panicked = self.harnesses[stubbed].run(case)
        return struct.unpack_from("<5Q", after, tool.OUT - tool.HEAP_BASE), after, events, divides, panicked

    def reply(self, case, stubbed=False):
        words, after, events, divides, panicked = self.run_plain(case, stubbed)
        self.assertEqual(words[0], tool.VTABLE)
        data = after[tool.ALLOCS - tool.HEAP_BASE:tool.ALLOCS - tool.HEAP_BASE + tool.REPLY_SIZE]
        self.assertTrue(all(not any(data[index * 32:index * 32 + 24]) for index in range(8)))
        return [int.from_bytes(data[index * 32 + 24:index * 32 + 32], "big") for index in range(8)]

    # ----- identity of the input and the function -----

    def test_digest_is_checked_first(self):
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "hl-node"
            path.write_bytes(b"\x7fELF" + bytes(100))
            with self.assertRaises(tool.EvidenceError):
                tool.load_image(path)
        self.assertEqual(hashlib.sha256(self.image.blob).hexdigest(), "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")

    def test_function_extent_and_decode(self):
        self.assertEqual(self.image.exact_fde(tool.ENTRY), (0x38E64B0, 0x38E6D3F))
        self.assertEqual(len(self.rows), 393)
        self.assertEqual(self.rows[-1].next, tool.BODY_END)
        self.assertEqual(self.rows[-1].op, "ud2")
        with self.assertRaises(tool.EvidenceError):
            self.image.exact_fde(tool.ENTRY + 1)

    def test_table_entry_is_address_0812(self):
        rows = tool.table_rows(self.image)
        self.assertEqual(rows[1], ("0x646e758", "00" * 18 + "0812", "0x38e64b0"))
        self.assertEqual([row[1][-4:] for row in rows], ["0811", "0812", "0814"])

    def test_only_the_table_slot_refers_to_the_body(self):
        base, text = self.image.text_bytes()
        hits = []
        for opcode in (b"\xe8", b"\xe9"):
            at = text.find(opcode)
            while 0 <= at <= len(text) - 5:
                if base + at + 5 + struct.unpack_from("<i", text, at + 1)[0] == tool.ENTRY:
                    hits.append(base + at)
                at = text.find(opcode, at + 1)
        self.assertEqual(hits, [])
        self.assertEqual([slot for slot, addend in self.image.relative().items() if addend == tool.ENTRY], [tool.TABLE_SLOT])

    def test_slots_resolve_through_relative_relocations(self):
        self.assertEqual(dict(tool.slot_rows(self.image))["0x64e8d50"], "0x36a09f0")
        sites = tool.site_rows(self.rows)
        self.assertEqual([site for site in sites if site[2] == "0x36a0b30"], [("0x38e6830", "direct", "0x36a0b30")])
        self.assertEqual([site for site in sites if site[2] == "0x36a08b0"], [("0x38e6845", "direct", "0x36a08b0")])
        self.assertEqual([site[0] for site in sites if site[2] == "0x64e8d50"], ["0x38e686a"])
        self.assertEqual([site[0] for site in sites if site[2] == "0x64dfaf8"], ["0x38e67f4", "0x38e6823"])

    # ----- the bytes against the rule list -----

    def test_every_named_case_agrees_with_the_rule_list(self):
        for case, stubbed in self.cases:
            self.assertIsNone(tool.compare(self.harnesses[stubbed], case), case.name)
        self.assertGreaterEqual(len(self.cases), 470)

    def test_vectors_agree_with_the_rule_list(self):
        count = stubbed_count = 0
        for case, stubbed in tool.vector_cases(700):
            self.assertIsNone(tool.compare(self.harnesses[stubbed], case), case.name)
            count += 1
            stubbed_count += stubbed
        self.assertEqual(count, 700)
        self.assertGreater(stubbed_count, 150)

    def test_every_wrong_reading_is_refused(self):
        sample = self.cases + list(tool.vector_cases(400, seed=0x77))
        for name in tool.VARIANTS:
            self.assertIsNotNone(tool.first_failure(self.harnesses, sample, frozenset((name,))), name)
        self.assertEqual(len(tool.VARIANTS), len(set(tool.VARIANTS)))

    def test_structural_controls(self):
        rows = tool.structural_controls(self.image, self.harnesses, self.cases)
        self.assertEqual(len(rows), 11)
        self.assertTrue(all(outcome == "detected" for _, outcome in rows), rows)

    def test_selected_byte_edits_are_noticed(self):
        kill = [pair for pair in self.cases if not pair[1]]
        edits = {(va, kind): patch for va, kind, patch in tool.rate.edits_for(self.image, self.rows, {row.va for row in self.rows})}
        # the length limit, the per-byte charge shift, the count test, the tag test, the guard test and the big-endian swap of word 1
        for key in ((0x38E64C4, "immediate"), (0x38E64D3, "immediate"), (0x38E653F, "condition"), (0x38E69EC, "immediate"), (0x38E6A32, "condition")):
            harnesses = {False: tool.Harness(self.image, edits[key]), True: tool.Harness(self.image, edits[key], stub_callees=True)}
            self.assertIsNotNone(tool.first_failure(harnesses, kill), hex(key[0]))
        self.assertEqual(len(tool.EQUIVALENT), 8)
        self.assertTrue(all(key in edits for key in tool.EQUIVALENT))

    # ----- properties of the bytes, stated without the rule list -----

    def test_gas_boundaries(self):
        whole = 1000 + 33 * 32 + 33 * 256
        words, _, events, _, _ = self.run_plain(tool.Case("exact", gas=whole))
        self.assertEqual((words[0], words[4]), (tool.VTABLE, whole))
        words, _, events, _, _ = self.run_plain(tool.Case("short", gas=whole - 1))
        self.assertEqual((words[0], words[1]), (0, 0x8000000000000001))
        self.assertEqual(events[-1], ("bytes_drop", 256))
        words, _, events, _, _ = self.run_plain(tool.Case("before parse", gas=1000 + 33 * 32 - 1))
        self.assertEqual((words[0], words[1], events), (0, 0x8000000000000001, []))
        words, _, events, _, _ = self.run_plain(tool.Case("too long", input_len=2001, gas=tool.TOP))
        self.assertEqual((words[0], words[1], events), (0, 0x8000000000000001, []))
        words, _, events, _, _ = self.run_plain(tool.Case("longest", input_len=2000, gas=tool.TOP))
        self.assertEqual(words[4], 1000 + 33 * 2000 + 33 * 256)

    def test_refused_parse_gives_the_text(self):
        words, after, events, _, _ = self.run_plain(tool.Case("bad", parse=("err", 4)))
        self.assertEqual(words[:4], (0, 13, tool.ALLOCS, 13))
        self.assertEqual(after[tool.ALLOCS - tool.HEAP_BASE:tool.ALLOCS - tool.HEAP_BASE + 13], b"Invalid input")
        self.assertEqual([event[0] for event in events], ["parse", "drop_parse", "alloc"])

    def test_refusal_codes(self):
        _, _, events, _, _ = self.run_plain(tool.Case("count", parse=("ok", 9), count=9, keys=[9]))
        self.assertEqual(events[1:], [("fmt_a", 0xFA, 9, 0), ("drop_code",)])
        _, _, events, _, _ = self.run_plain(tool.Case("missing", parse=("ok", 9), keys=[7, 11]))
        self.assertEqual(events[1:], [("fmt_a", 0xF1, 0, 0), ("drop_code",)])
        _, _, events, _, _ = self.run_plain(tool.Case("no supply shares, debt", rec=tool.rate.record(a=tool.TOP, ia=tool.TOP, b=1)))
        self.assertEqual(events[1:], [("fmt_b", 0xF1, 0x0C)])

    def test_reply_words_of_a_worked_record(self):
        rec = tool.rate.record(a=50, b=100, mn=0, kr=5 * 10 ** 12, mx=E14, k=8 * 10 ** 13, ltv=8 * 10 ** 13, px=3, bal=4)
        self.assertEqual(self.reply(tool.Case("worked", rec=rec, reserve=10 ** 13)), [312, 140, 4, 5000, 3, 8000, 100, 50])
        self.assertEqual(self.reply(tool.Case("no reserve", rec=rec, reserve=0))[1], 156)
        self.assertEqual(self.reply(tool.Case("all reserve", rec=rec, reserve=E14))[1], 0)
        self.assertEqual(self.reply(tool.Case("reserve above one", rec=rec, reserve=3 * E14))[1], 0)
        absent = dict(rec, ltv=None)
        self.assertEqual(self.reply(tool.Case("absent", rec=absent))[5], 0)

    def test_borrowed_total_is_floored_in_the_reply_and_ceiled_in_the_ratio(self):
        # 3 * (1e14 + 1) / 1e14 = 3.00000000000003: word 7 says 3, while the utilization divides the ceiled 4 by the supplied 8
        rec = tool.rate.record(a=3, ia=E14 + 1, b=8)
        words = self.reply(tool.Case("ceil", rec=rec))
        self.assertEqual(words[7], 3)
        self.assertEqual(words[3], 5000)  # ceil(3.00000000000003) / 8 = 0.5, not 3 / 8

    def test_supply_rate_reads_the_low_half_of_the_rate_as_signed(self):
        def supply(rate_word, used, reserve=0):
            case = tool.Case("s", callee=dict(rate=rate_word, util_word=(0, 1), util_f64=(0, tool.to_bits(used))), reserve=reserve)
            return self.reply(case, True)[1]
        self.assertEqual(supply(4096, 1.0), 4096)
        self.assertEqual(supply((1 << 32) + 5, 1.0), 5)
        self.assertEqual(supply(1 << 31, 1.0), 0)
        self.assertEqual(supply((1 << 32) - 1, -1.0), 1)
        self.assertEqual(supply(4096, float("nan")), 0)
        self.assertEqual(supply(4096, float("inf")), 0)
        self.assertEqual(supply(1, 1.7976931348623157e308), tool.TOP)
        self.assertEqual(supply(4096, 0.9999), 4095)
        # the largest rate word the real callee can return is below 2^31, so the conversion loses nothing on real input
        self.assertLess(tool.TOP // tool.E10, 1 << 31)

    def test_ring_search_flags(self):
        ring = [5, 9, 14, 20, 33, 41]

        def events(lookups):
            return self.run_plain(tool.Case("ring", parse=("ok", 14), keys=ring, store=("ring", 8, 5), lookups=lookups))[2]
        self.assertEqual(events([(2, 2), (0, 2)])[-2][:3], ("fmt_a", 0xF1, 0))  # first answer: any non-zero word refuses
        self.assertEqual(events([(0, 2), (2, 2)])[-1][0], "bytes")  # second answer: only bit 0 refuses
        self.assertEqual(events([(0, 2), (3, 2)])[-1], ("fmt_b", 0xF1, 0x0C))
        self.assertEqual(events([(0, 2), (0, 6)])[-1], ("fmt_b", 0xF1, 0x0C))

    def test_every_body_row_but_the_trap_is_reached(self):
        for case, stubbed in self.cases:
            self.harnesses[stubbed].run(case)
        seen = set(self.harnesses[False].machine.seen) | set(self.harnesses[True].machine.seen)
        missing = [row.va for row in self.rows if row.va not in seen and row.op not in ("int3", "nop")]
        self.assertEqual(missing, [0x38E6C6E])

    # ----- committed evidence -----

    def test_manifest_matches_committed_files(self):
        listed = {}
        for line in (WORK / "MANIFEST.sha256").read_text().splitlines():
            digest, name = line.split("  ")
            listed[name] = digest
        self.assertEqual(sorted(listed), sorted(p.name for p in WORK.iterdir() if p.is_file() and p.name != "MANIFEST.sha256"))
        for name, digest in listed.items():
            self.assertEqual(hashlib.sha256((WORK / name).read_bytes()).hexdigest(), digest, name)

    def test_committed_evidence_is_regenerated(self):
        files = tool.render(tool.analyse(self.image, vectors=1500, mutate=False))
        for name in STABLE:
            self.assertEqual(files[name], (WORK / name).read_text(encoding="ascii"), name)
        short = files["vector-outcomes.tsv"].splitlines()
        self.assertEqual(short, (WORK / "vector-outcomes.tsv").read_text(encoding="ascii").splitlines()[:len(short)])
        self.assertEqual(len(short), 151)


if __name__ == "__main__":
    unittest.main()
