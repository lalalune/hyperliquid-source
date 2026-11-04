import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))

import bit9_arms_static as arms  # noqa: E402


TARGET = ROOT / "artifacts" / "node" / "115" / "hl-node"
PACKET = (
    ROOT
    / "research"
    / "work-items"
    / "RE-002-node115-bit9-arms"
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


def target(records, prefix):
    for row in records["targets"]:
        if row["range"].startswith(prefix):
            return row
    raise AssertionError(f"no target {prefix}")


class AuthenticatedBit9ArmsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.capture = TARGET.read_bytes()
        if len(cls.capture) != 105896032 or \
                hashlib.sha256(cls.capture).hexdigest() != SHA:
            raise AssertionError("target is not the pinned node115 capture")
        cls.report, _f, _c, _t = arms.analyse(cls.capture)

    def test_packet_regeneration_matches_retained_outputs(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary:
            output = Path(temporary) / "retained"
            arms.generate(TARGET, output)
            for name in ("records.json", "frames.txt",
                         "consumers.objdump.txt", "targets.objdump.txt"):
                self.assertEqual(
                    (output / name).read_bytes(),
                    (PACKET / name).read_bytes(),
                    f"regenerated {name} differs from the retained packet")

    def test_census_counts_agree_with_readback_packet(self):
        census = self.report["census"]
        self.assertEqual(census["fde_count"], 135313)
        self.assertEqual(census["candidate_sites"], 246)
        self.assertEqual(census["validated_sites"], 246)
        self.assertEqual(census["rejected_candidates"], [])
        self.assertEqual(census["rip_sites_by_kind"],
                         {"slot_ptr": 123, "slot_refresh": 123})
        self.assertEqual(census["movabs_hits"], [])
        self.assertEqual(self.report["summary"]["owner_fdes"], 104)
        self.assertEqual(self.report["summary"]["consumers"], 102)
        self.assertEqual(self.report["slots"]["slots_with_cache_addend"],
                         ["0x64dfa60"])
        self.assertEqual(self.report["slots"]["slots_pointing_at_C1_C2"],
                         [])
        self.assertEqual(self.report["drivers"],
                         {"C09": "cpuid leaf 1 ecx bit 9"})

    def test_bit9_family_counts(self):
        summary = self.report["summary"]
        self.assertEqual(summary["bit9_bodies"], 92)
        self.assertEqual(summary["bit9_test_events"], 208)
        self.assertEqual(summary["bit9_test_sites"], 189)
        self.assertEqual(summary["sequences"], 104)
        per_body = {}
        for row in self.report["consumers"]:
            per_body[len(row["sequences"])] = \
                per_body.get(len(row["sequences"]), 0) + 1
            for seq in row["sequences"]:
                self.assertEqual(
                    sorted(t["word"] for t in seq["tests"]), ["A", "C0"])
        self.assertEqual(per_body, {1: 82, 2: 8, 3: 2})

    def test_arm_shapes(self):
        summary = self.report["summary"]
        self.assertEqual(summary["shapes"], {
            "call/inbody": 97, "call/empty": 6, "tailjmp/inbody": 1})
        for row in self.report["consumers"]:
            for seq in row["sequences"]:
                set_arm = seq["set_arm"]
                self.assertEqual(set_arm["block_count"], 1)
                self.assertEqual(len(set_arm["transfers"]), 1)
                self.assertIn(set_arm["transfers"][0]["kind"],
                              ("call", "tailjmp"))
                # no clear arm anywhere transfers out of the body
                self.assertEqual(seq["clear_arm"]["transfers"], [])

    def test_grouping(self):
        summary = self.report["summary"]
        self.assertEqual(summary["sequence_pair_groups"], 17)
        self.assertEqual(summary["body_pair_groups"], 17)
        self.assertEqual(summary["distinct_exact_pairs"], 101)
        self.assertEqual(summary["distinct_clear_regions"], 98)
        top = self.report["groups"]["by_sequence"][:3]
        self.assertEqual(
            [(g["set_arm"], g["clear_arm"], g["sequences"]) for g in top],
            [("call:0x2a31790", "inbody", 29),
             ("call:0x47358a0", "inbody", 26),
             ("call:0x4ef75a0", "inbody", 20)])
        guarded = [g for g in self.report["groups"]["by_sequence"]
                   if g["clear_arm"] == "empty"]
        self.assertEqual(
            sorted((g["set_arm"], g["sequences"]) for g in guarded),
            [("call:0x2a31790", 2), ("call:0x47358a0", 2),
             ("call:0x4ef75a0", 2)])
        # no body's sequences split across pair groups
        for group in self.report["groups"]["by_body"]:
            self.assertEqual(len(group["pairs"]), 1)

    def test_targets(self):
        targets = self.report["targets"]
        self.assertEqual(len(targets), 14)
        self.assertEqual(
            sum(t["selected_by_sequences"] for t in targets), 104)
        families = {}
        for row in targets:
            families.setdefault(row["stream_family"], []).append(row)
        self.assertEqual(
            {k: len(v) for k, v in families.items()},
            {"F1": 11, "F2": 1, "F3": 1, "F4": 1})
        f1 = families["F1"]
        self.assertTrue(all(t["bytes"] == 319 for t in f1))
        self.assertTrue(all(t["insns"] == 76 for t in f1))
        self.assertEqual(len({t["normalised_sha256"] for t in f1}), 1)
        self.assertEqual(len({t["sha256"] for t in f1}), 11)
        big = target(self.report, "0x2a31790")
        self.assertEqual(big["selected_by_sequences"], 31)
        self.assertEqual(len(big["selected_by_bodies"]), 27)
        self.assertEqual(big["entry"][0],
                         "movabs rax,0x7ffffffffffffff0")
        self.assertEqual(big["entry"][1], "and rax,rsi")
        tail = target(self.report, "0x5bba120")
        self.assertEqual(tail["bytes"], 1758)
        self.assertEqual(tail["selected_by_sequences"], 1)
        f4 = target(self.report, "0x5bddee0")
        self.assertEqual(f4["bytes"], 303)
        self.assertEqual(f4["entry"][1], "and eax,0x30")
        # every target is an FDE start selected by a recorded transfer
        starts = {t["range"].split("..")[0] for t in targets}
        for row in self.report["consumers"]:
            for seq in row["sequences"]:
                for arm in (seq["set_arm"], seq["clear_arm"]):
                    for transfer in arm["transfers"]:
                        self.assertIn(transfer["target"], starts)

    # ------------------------------------------------ counterfactuals

    def test_mutated_consumer_body_breaks_its_pinned_hash(self):
        secs = arms.sections(self.capture)
        retained = consumer(retained_records(), "0x298a490")
        changed = mutate(self.capture, 0x298a490, 0x54)
        self.assertNotEqual(
            arms.body_sha256(changed, secs, 0x298A490, 0x298A626),
            retained["sha256"])

    def test_mutated_test_immediate_removes_body_from_family(self):
        # test eax,0x200 at 0x298a4f6: imm32 byte 0x02 -> 0x04 (bit 10)
        changed = mutate(self.capture, 0x298A4F8, 0x04)
        report, _f, _c, _t = arms.analyse(changed)
        self.assertEqual(report["summary"]["bit9_bodies"], 91)
        self.assertFalse(any(
            row["range"].startswith("0x298a490")
            for row in report["consumers"]))

    def test_mutated_set_arm_call_changes_the_recorded_target(self):
        # call 0x1435a90 at 0x143a714 in body 0x143a660: disp32 low
        # byte +1 moves the recorded target by one byte
        changed = mutate(self.capture, 0x143A715, 0x78)
        report, _f, _c, _t = arms.analyse(changed)
        row = consumer(report, "0x143a660")
        transfer = row["sequences"][0]["set_arm"]["transfers"][0]
        self.assertEqual(transfer["target"], "0x1435a91")
        retained = consumer(retained_records(), "0x143a660")
        self.assertEqual(
            retained["sequences"][0]["set_arm"]["transfers"][0]["target"],
            "0x1435a90")

    def test_mutated_target_body_breaks_its_pinned_hash(self):
        secs = arms.sections(self.capture)
        retained = target(retained_records(), "0x2a31790")
        changed = mutate(self.capture, 0x2A3179A, 0x21)
        self.assertNotEqual(
            arms.body_sha256(changed, secs, 0x2A31790, 0x2A318CF),
            retained["sha256"])

    def test_mutated_slot_disp32_leaves_the_census(self):
        # slot load at 0x143a68e: disp32 low byte 0xcb -> 0xca
        changed = mutate(self.capture, 0x143A691, 0xCA)
        report, _f, _c, _t = arms.analyse(changed)
        self.assertEqual(report["census"]["candidate_sites"], 245)
        self.assertEqual(report["summary"]["bit9_bodies"], 91)

    def test_wrong_inputs_are_rejected_at_the_digest_gate(self):
        with self.assertRaises(ValueError):
            arms.authenticate(bytes(105896032))
        with self.assertRaises(ValueError):
            arms.authenticate(self.capture[:1000])
        with self.assertRaises(ValueError):
            arms.authenticate(mutate(self.capture, 0x298A490, 0x54))


if __name__ == "__main__":
    unittest.main()
