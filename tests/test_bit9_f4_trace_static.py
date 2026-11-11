import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))

import bit9_f4_trace_static as f4  # noqa: E402


TARGET = ROOT / "artifacts" / "node" / "115" / "hl-node"
PACKET = (
    ROOT
    / "research"
    / "work-items"
    / "RE-002-node115-bit9-f4-trace"
)
SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"


def mutate(data, virtual_address, replacement):
    changed = bytearray(data)
    offset = f4.va_to_offset(f4.sections(data), virtual_address)
    changed[offset] = replacement
    return bytes(changed)


def retained_records():
    return json.loads((PACKET / "records.json").read_text(encoding="utf-8"))


class AuthenticatedBit9F4TraceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.capture = TARGET.read_bytes()
        if len(cls.capture) != 105896032 or \
                hashlib.sha256(cls.capture).hexdigest() != SHA:
            raise AssertionError("target is not the pinned node115 capture")
        cls.report, _f, _t, _r = f4.analyse(cls.capture)

    def test_packet_regeneration_matches_retained_outputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            out = Path(temporary) / "packet"
            f4.generate(TARGET, out)
            for name in ("records.json", "frames.txt",
                         "targets.objdump.txt",
                         "clear_regions.objdump.txt"):
                self.assertEqual(
                    (out / name).read_bytes(),
                    (PACKET / name).read_bytes(),
                    f"regenerated {name} differs from the retained packet")

    def test_f4_stream_identity(self):
        stream = self.report["f4_stream"]
        self.assertEqual(stream["placements"], ["0x5bddee0..0x5bde00f"])
        self.assertEqual(stream["distinct_normalised_streams"], 1)
        self.assertEqual(
            stream["normalised_sha256"],
            "d54230ce448978ed933e1f2326524c56294de3c5ef4ba77b116a18a18303c00a")
        self.assertEqual(stream["selected_by_sequences"], 3)
        verified = self.report["targets_verified"]
        self.assertEqual(len(verified), 14)
        self.assertEqual(
            sum(1 for t in verified if t["stream_family"] == "F4"), 1)
        self.assertEqual(self.report["consumers_verified"], 92)

    def test_trace_names_bounded_lowercase_hex_encoding(self):
        trace = self.report["trace"]
        self.assertEqual(trace["body"], "0x5bddee0..0x5bde00f")
        self.assertEqual(trace["insns"], 78)
        self.assertEqual(trace["calls"], 0)
        self.assertEqual(
            trace["length_semantics"]["vector_bytes"], "length & 0x30")
        self.assertEqual(
            trace["length_semantics"]["remainder_bytes"], "length & 0xf")
        consts = {c["address"]: c for c in trace["constants"]}
        self.assertEqual(consts["0x455d40"]["ascii"], "0123456789abcdef")
        self.assertEqual(
            consts["0x4503b0"]["bytes"], "0f" * 16)
        loop = trace["main_loop"]
        self.assertEqual(loop["head"], "0x5bddf10")
        self.assertEqual(loop["pshufb"], 2)
        self.assertEqual(loop["vector_stores_to_output"], 2)
        tail = trace["scalar_tail"]
        self.assertEqual(tail["pairs_loop"]["head"], "0x5bddf90")
        self.assertEqual(tail["table_lookups"], 6)
        self.assertEqual(
            self.report["operation"]["name"],
            "lowercase hexadecimal encoding (bounded variant)")

    def test_every_f4_clear_region_is_the_scalar_form(self):
        summary = self.report["summary"]
        self.assertEqual(summary["f4_sequences"], 3)
        self.assertEqual(summary["f4_bodies"], 1)
        self.assertEqual(
            summary["clear_verdicts"], {"scalar-hex-table": 3})
        self.assertEqual(
            summary["clear_forms"], {"loop": 1, "unrolled": 2})
        self.assertEqual(summary["nibble_orders"], {"hi-first": 3})
        self.assertEqual(
            summary["unrolled_length_agreement"],
            {"agree": 2, "disagree": 0})
        self.assertEqual(
            [row["set_length_const"] for row in self.report["sequences"]],
            [32, 2, 2])
        for row in self.report["sequences"]:
            self.assertEqual(
                row["clear"]["verdict"], "scalar-hex-table")
            self.assertEqual(
                row["clear"]["table_ref"], "lea-in-region")
            self.assertEqual(row["clear"]["nibble_order"], "hi-first")

    def test_authenticate_rejects_wrong_capture(self):
        with self.assertRaises(ValueError):
            f4.authenticate(self.capture[:-1])
        changed = mutate(self.capture, 0x5BDDEE0, 0x90)
        with self.assertRaises(ValueError):
            f4.authenticate(changed)

    def test_traced_target_byte_mutation_fails_closed(self):
        changed = mutate(self.capture, 0x5BDDEE0 + 40, 0x90)
        with self.assertRaises(ValueError):
            f4.analyse(changed)

    def test_other_target_byte_mutation_fails_closed(self):
        changed = mutate(self.capture, 0x5BD6E90 + 40, 0x90)
        with self.assertRaises(ValueError):
            f4.analyse(changed)

    def test_hex_table_byte_mutation_fails_closed(self):
        changed = mutate(self.capture, 0x455D40, ord("g"))
        with self.assertRaises(ValueError):
            f4.analyse(changed)

    def test_clear_region_byte_mutation_fails_closed(self):
        # Inside the clear region of the consumer's sequence 1
        # (its unrolled block at 0x5bddd90).
        changed = mutate(self.capture, 0x5BDDD90 + 8, 0x90)
        with self.assertRaises(ValueError):
            f4.analyse(changed)


if __name__ == "__main__":
    unittest.main()
