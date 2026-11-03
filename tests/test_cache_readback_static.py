import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))

import cache_readback_static as readback  # noqa: E402


TARGET = ROOT / "artifacts" / "node" / "115" / "hl-node"
PACKET = (
    ROOT
    / "research"
    / "work-items"
    / "RE-002-node115-cache-readback"
)
SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"


def mutate(data, virtual_address, replacement):
    changed = bytearray(data)
    changed[virtual_address - 0x1000] = replacement
    return bytes(changed)


def retained_records():
    return json.loads((PACKET / "records.json").read_text(encoding="utf-8"))


def consumer(records, prefix):
    for row in records["consumers"]:
        if row["range"].startswith(prefix):
            return row
    raise AssertionError(f"no consumer {prefix}")


class AuthenticatedCacheReadbackTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.capture = TARGET.read_bytes()
        if len(cls.capture) != 105896032 or \
                hashlib.sha256(cls.capture).hexdigest() != SHA:
            raise AssertionError("target is not the pinned node115 capture")
        cls.report, _frames, _exports = readback.analyse(cls.capture)

    def test_packet_regeneration_matches_retained_outputs(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary:
            output = Path(temporary) / "retained"
            readback.generate(TARGET, output)
            for name in ("records.json", "frames.txt",
                         "consumers.objdump.txt"):
                self.assertEqual(
                    (output / name).read_bytes(),
                    (PACKET / name).read_bytes(),
                    f"regenerated {name} differs from the retained packet")

    def test_census_counts(self):
        census = self.report["census"]
        self.assertEqual(census["fde_count"], 135313)
        self.assertEqual(census["candidate_sites"], 246)
        self.assertEqual(census["validated_sites"], 246)
        self.assertEqual(census["rejected_candidates"], [])
        self.assertEqual(census["rip_sites_by_kind"],
                         {"slot_ptr": 123, "slot_refresh": 123})
        self.assertEqual(census["movabs_hits"], [])
        self.assertEqual(census["direct_calls_to_refresh_helper"], [])
        self.assertEqual(census["direct_calls_to_selector"], [])
        self.assertEqual(self.report["summary"]["owner_fdes"], 104)
        self.assertEqual(self.report["summary"]["consumers"], 102)

    def test_slots_are_unique(self):
        slots = self.report["slots"]
        self.assertEqual(slots["slots_with_cache_addend"], ["0x64dfa60"])
        self.assertEqual(slots["slots_pointing_at_C1_C2"], [])

    def test_no_c1_c2_readers(self):
        summary = self.report["summary"]
        self.assertEqual(summary["word_readers"]["C1"], [])
        self.assertEqual(summary["word_readers"]["C2"], [])
        self.assertEqual(len(summary["word_readers"]["C0"]), 103)
        for row in self.report["consumers"]:
            self.assertEqual(row["words_read"], ["C0"])

    def test_tested_bits_and_drivers(self):
        summary = self.report["summary"]
        self.assertEqual(
            sorted(int(b) for b in summary["bits_tested"]["C0"]),
            [9, 10, 11, 14, 15, 19, 25])
        self.assertEqual(summary["bits_tested"]["C1"], {})
        self.assertEqual(summary["bits_tested"]["C2"], {})
        self.assertEqual(
            sorted(self.report["drivers"]),
            ["C010", "C011", "C014", "C015", "C019", "C025", "C09"])
        self.assertEqual(self.report["drivers"]["C09"],
                         "cpuid leaf 1 ecx bit 9")
        self.assertTrue(self.report["drivers"]["C025"].startswith(
            "the constant 1, selected by cpuid leaf 7"))

    def test_selector_matches_merged_theorem(self):
        selector = self.report["selector"]
        self.assertEqual(selector["bits_tested"]["C0"], [10, 15, 19, 25])
        self.assertEqual(selector["bits_tested"]["A"], [10, 15, 19, 25])
        self.assertEqual(len(selector["refresh_call_sites"]), 4)
        self.assertEqual(len(selector["loads"]), 4)

    def test_publisher_stores_exactly_the_triple(self):
        publisher = self.report["publisher"]
        writes = [e for e in publisher["events"]
                  if e["kind"] == "cache_write"]
        self.assertEqual(
            [(e["site"], e["offset"]) for e in writes],
            [("0x5cae3a8", 0), ("0x5cae3b6", 8), ("0x5cae3c4", 16)])
        self.assertEqual(publisher["slot_load_sites"], ["0x5cae3a1"])
        self.assertEqual(publisher["loads"], [])

    def test_every_consumer_zero_checks_and_mirrors_a(self):
        for row in self.report["consumers"]:
            self.assertTrue(
                any(e["kind"] == "zero_check" for e in row["events"]),
                row["range"])
            self.assertEqual(row["bits_tested"].get("A", []),
                             row["bits_tested"].get("C0", []),
                             row["range"])

    def test_no_consumer_forwards_a_word(self):
        for row in self.report["consumers"]:
            for event in row["events"]:
                self.assertNotIn(
                    event["kind"],
                    ("call_forward", "ptr_forward", "store_forward",
                     "return_forward"),
                    f"{row['range']} {event}")
        live_in = [e for row in self.report["consumers"]
                   for e in row["events"] if e["kind"] == "call_live_in"]
        self.assertEqual(len(live_in), 6)
        self.assertTrue(all(e["reg"] == "rcx" for e in live_in))
        self.assertEqual(
            {e["site"] for e in live_in},
            {"0x2e56d42", "0x2e56e72", "0x2e5714a"})

    def test_neighbourhood_references_are_not_the_triple(self):
        neighbours = self.report["census"]["neighbour_references"]
        self.assertEqual(len(neighbours), 42)
        self.assertEqual(
            {n["target"] for n in neighbours},
            {"0x6500078", "0x6500080", "0x6500083", "0x6500084",
             "0x6500087", "0x6500088", "0x6500089", "0x650008a",
             "0x650008b", "0x65000b0"})

    # ------------------------------------------------ counterfactuals

    def test_mutated_consumer_body_breaks_its_pinned_hash(self):
        secs = readback.sections(self.capture)
        retained = consumer(retained_records(), "0x298a490")
        changed = mutate(self.capture, 0x298a490, 0x54)
        self.assertNotEqual(
            readback.body_sha256(changed, secs, 0x298A490, 0x298A626),
            retained["sha256"])

    def test_mutated_test_immediate_changes_the_tested_bit(self):
        # test eax,0x200 at 0x298a4f6: imm32 byte 0x02 -> 0x04 (bit 10)
        changed = mutate(self.capture, 0x298A4F8, 0x04)
        report, _f, _e = readback.analyse(changed)
        row = consumer(report, "0x298a490")
        self.assertEqual(row["bits_tested"].get("C0"), [10])
        retained = consumer(retained_records(), "0x298a490")
        self.assertEqual(retained["bits_tested"].get("C0"), [9])

    def test_mutated_slot_disp32_leaves_the_census(self):
        # slot load at 0x143a68e: disp32 low byte 0xcb -> 0xca
        changed = mutate(self.capture, 0x143A691, 0xCA)
        report, _f, _e = readback.analyse(changed)
        self.assertEqual(report["census"]["candidate_sites"], 245)
        row = consumer(report, "0x143a660")
        self.assertEqual(row["words_read"], [])

    def test_mutated_relocation_addend_is_rejected(self):
        secs = readback.sections(self.capture)
        rela = next(s for s in secs if s["name"] == ".rela.dyn")
        index = None
        for i, (off, _info, add) in enumerate(
                readback.relocations(self.capture, secs)):
            if off == readback.SLOT_PTR and add == readback.CACHE_BASE:
                index = i
                break
        self.assertIsNotNone(index)
        addend_pos = rela["offset"] + index * 24 + 16
        changed = bytearray(self.capture)
        changed[addend_pos] ^= 0x01
        with self.assertRaises(ValueError):
            readback.analyse(bytes(changed))

    def test_wrong_inputs_are_rejected_at_the_digest_gate(self):
        with self.assertRaises(ValueError):
            readback.authenticate(bytes(105896032))
        with self.assertRaises(ValueError):
            readback.authenticate(self.capture[:1000])
        with self.assertRaises(ValueError):
            readback.authenticate(mutate(self.capture, 0x298A490, 0x54))


if __name__ == "__main__":
    unittest.main()
