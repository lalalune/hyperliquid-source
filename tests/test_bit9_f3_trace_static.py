import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))

import bit9_f3_trace_static as f3  # noqa: E402


TARGET = ROOT / "artifacts" / "node" / "115" / "hl-node"
PACKET = (
    ROOT
    / "research"
    / "work-items"
    / "RE-002-node115-bit9-f3-trace"
)
SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"


def mutate(data, virtual_address, replacement):
    changed = bytearray(data)
    offset = f3.va_to_offset(f3.sections(data), virtual_address)
    changed[offset] = replacement
    return bytes(changed)


def retained_records():
    return json.loads((PACKET / "records.json").read_text(encoding="utf-8"))


class AuthenticatedBit9F3TraceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.capture = TARGET.read_bytes()
        if len(cls.capture) != 105896032 or \
                hashlib.sha256(cls.capture).hexdigest() != SHA:
            raise AssertionError("target is not the pinned node115 capture")
        cls.report, _f, _t, _r = f3.analyse(cls.capture)

    def test_packet_regeneration_matches_retained_outputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            out = Path(temporary) / "packet"
            f3.generate(TARGET, out)
            for name in ("records.json", "frames.txt",
                         "targets.objdump.txt",
                         "clear_regions.objdump.txt"):
                self.assertEqual(
                    (out / name).read_bytes(),
                    (PACKET / name).read_bytes(),
                    f"regenerated {name} differs from the retained packet")

    def test_f3_stream_identity(self):
        stream = self.report["f3_stream"]
        self.assertEqual(stream["placements"], ["0x5bd6e90..0x5bd6fcf"])
        self.assertEqual(stream["distinct_normalised_streams"], 1)
        self.assertEqual(
            stream["normalised_sha256"],
            "f9ceb9a855a558f7d973b18522faff60207eb9cdd8c380213b0b8fda3db2fa77")
        self.assertEqual(stream["selected_by_sequences"], 2)
        verified = self.report["targets_verified"]
        self.assertEqual(len(verified), 14)
        self.assertEqual(
            sum(1 for t in verified if t["stream_family"] == "F3"), 1)
        self.assertEqual(self.report["consumers_verified"], 92)

    def test_trace_names_full_length_lowercase_hex_encoding(self):
        trace = self.report["trace"]
        self.assertEqual(trace["body"], "0x5bd6e90..0x5bd6fcf")
        self.assertEqual(trace["bytes"], 319)
        self.assertEqual(trace["insns"], 78)
        self.assertEqual(trace["calls"], 0)
        self.assertEqual(
            trace["length_semantics"]["vector_bytes"],
            "length & 0x7ffffffffffffff0")
        self.assertEqual(
            trace["length_semantics"]["converted_bytes"],
            "(length & ~0xf) + (length & 0xf) = length")
        self.assertEqual(
            trace["length_semantics"]["exact_for"],
            "every length (no truncation)")
        consts = {c["address"]: c for c in trace["constants"]}
        self.assertEqual(consts["0x455d40"]["ascii"], "0123456789abcdef")
        self.assertEqual(
            consts["0x4503b0"]["bytes"], "0f" * 16)
        loop = trace["main_loop"]
        self.assertEqual(loop["head"], "0x5bd6ec0")
        self.assertEqual(loop["back_edge"], "0x5bd6f09")
        self.assertEqual(loop["insns"], 17)
        self.assertEqual(loop["pshufb"], 2)
        self.assertEqual(loop["vector_stores_to_output"], 2)
        self.assertEqual(loop["counter_register"], "r8")
        tail = trace["scalar_tail"]
        self.assertEqual(tail["pairs_loop"]["head"], "0x5bd6f50")
        self.assertEqual(tail["pairs_loop"]["back_edge"], "0x5bd6f9d")
        self.assertEqual(
            tail["pairs_loop"]["store_displacements"], [-3, -2, -1, 0])
        self.assertEqual(
            tail["remainder_one_shortcut"]["lands_on"],
            tail["final_byte"]["output_advance_site"])
        self.assertEqual(tail["table_lookups"], 6)
        self.assertEqual(
            self.report["operation"]["name"],
            "lowercase hexadecimal encoding "
            "(full-length form, F1's operation)")

    def test_every_f3_clear_region_is_the_scalar_form(self):
        summary = self.report["summary"]
        self.assertEqual(summary["f3_sequences"], 2)
        self.assertEqual(summary["f3_bodies"], 2)
        self.assertEqual(
            summary["clear_verdicts"], {"scalar-hex-table": 2})
        self.assertEqual(summary["clear_forms"], {"loop": 2})
        self.assertEqual(summary["nibble_orders"], {"hi-first": 2})
        self.assertEqual(
            summary["unrolled_length_agreement"],
            {"agree": 0, "disagree": 0})
        self.assertEqual(
            [row["set_length_const"] for row in self.report["sequences"]],
            [32, None])
        for row in self.report["sequences"]:
            self.assertEqual(
                row["clear"]["verdict"], "scalar-hex-table")
            self.assertEqual(row["clear"]["nibble_order"], "hi-first")
            self.assertTrue(
                row["clear"]["table_ref"].startswith("lea"))

    def test_direct_callers_are_exactly_the_set_arm_sites(self):
        callers = self.report["direct_callers"]
        self.assertEqual(
            callers["validated_direct_calls"],
            ["0x5bd45b4", "0x5bd4c3f"])
        self.assertEqual(callers["validated_direct_jumps"], [])

    def test_consumers_downstream_use(self):
        downstream = {
            row["consumer"]: row
            for row in self.report["consumers_downstream"]}
        self.assertEqual(
            sorted(downstream),
            ["0x5bd4500..0x5bd45d5", "0x5bd4bb0..0x5bd4d24"])
        self.assertIn("0x7830", downstream["0x5bd4500..0x5bd45d5"]
                      ["framing"])
        self.assertIn("66-byte", downstream["0x5bd4500..0x5bd45d5"]
                      ["downstream"])
        self.assertIn("2 * length", downstream["0x5bd4bb0..0x5bd4d24"]
                      ["downstream"])

    def test_authenticate_rejects_wrong_capture(self):
        with self.assertRaises(ValueError):
            f3.authenticate(self.capture[:-1])
        changed = mutate(self.capture, 0x5BD6E90, 0x90)
        with self.assertRaises(ValueError):
            f3.authenticate(changed)

    def test_traced_target_byte_mutation_fails_closed(self):
        changed = mutate(self.capture, 0x5BD6E90 + 40, 0x90)
        with self.assertRaises(ValueError):
            f3.analyse(changed)

    def test_other_target_byte_mutation_fails_closed(self):
        changed = mutate(self.capture, 0x5BDDEE0 + 40, 0x90)
        with self.assertRaises(ValueError):
            f3.analyse(changed)

    def test_hex_table_byte_mutation_fails_closed(self):
        changed = mutate(self.capture, 0x455D40, ord("g"))
        with self.assertRaises(ValueError):
            f3.analyse(changed)

    def test_clear_region_byte_mutation_fails_closed(self):
        # Inside the clear region of the first consumer's sequence
        # (its scalar loop block at 0x5bd4550).
        changed = mutate(self.capture, 0x5BD4550 + 8, 0x90)
        with self.assertRaises(ValueError):
            f3.analyse(changed)


if __name__ == "__main__":
    unittest.main()
