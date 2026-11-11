import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))

import bit9_f1_trace_static as f1  # noqa: E402


TARGET = ROOT / "artifacts" / "node" / "115" / "hl-node"
PACKET = (
    ROOT
    / "research"
    / "work-items"
    / "RE-002-node115-bit9-f1-trace"
)
SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"


def mutate(data, virtual_address, replacement):
    changed = bytearray(data)
    offset = f1.va_to_offset(f1.sections(data), virtual_address)
    changed[offset] = replacement
    return bytes(changed)


def retained_records():
    return json.loads((PACKET / "records.json").read_text(encoding="utf-8"))


class AuthenticatedBit9F1TraceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.capture = TARGET.read_bytes()
        if len(cls.capture) != 105896032 or \
                hashlib.sha256(cls.capture).hexdigest() != SHA:
            raise AssertionError("target is not the pinned node115 capture")
        cls.report, _f, _t, _r = f1.analyse(cls.capture)

    def test_packet_regeneration_matches_retained_outputs(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary:
            out = Path(temporary) / "packet"
            f1.generate(TARGET, out)
            for name in ("records.json", "frames.txt",
                         "targets.objdump.txt",
                         "clear_regions.objdump.txt"):
                self.assertEqual(
                    (out / name).read_bytes(),
                    (PACKET / name).read_bytes(),
                    f"regenerated {name} differs from the retained packet")

    def test_f1_stream_identity(self):
        stream = self.report["f1_stream"]
        self.assertEqual(len(stream["placements"]), 11)
        self.assertEqual(stream["distinct_normalised_streams"], 1)
        self.assertEqual(
            stream["normalised_sha256"],
            "f9ad70135228ba7de46bd90151643d12f82c941861fcecea624035cfee28f112")
        verified = self.report["targets_verified"]
        self.assertEqual(len(verified), 14)
        self.assertEqual(
            sum(1 for t in verified if t["stream_family"] == "F1"), 11)

    def test_trace_names_lowercase_hex_encoding(self):
        trace = self.report["trace"]
        self.assertEqual(trace["body"], "0x2a31790..0x2a318cf")
        self.assertEqual(trace["insns"], 76)
        self.assertEqual(trace["calls"], 0)
        consts = {c["address"]: c for c in trace["constants"]}
        self.assertEqual(consts["0x455d40"]["ascii"], "0123456789abcdef")
        self.assertEqual(
            consts["0x4503b0"]["bytes"], "0f" * 16)
        loop = trace["main_loop"]
        self.assertEqual(loop["head"], "0x2a317c0")
        self.assertEqual(loop["pshufb"], 2)
        self.assertEqual(loop["vector_stores_to_output"], 2)
        self.assertEqual(
            self.report["operation"]["name"],
            "lowercase hexadecimal encoding")

    def test_every_f1_clear_region_is_the_scalar_form(self):
        summary = self.report["summary"]
        self.assertEqual(summary["f1_sequences"], 98)
        self.assertEqual(summary["f1_bodies"], 88)
        self.assertEqual(
            summary["clear_verdicts"],
            {"scalar-hex-table": 92, "empty": 6})
        self.assertEqual(
            summary["clear_forms"],
            {"loop": 66, "unrolled": 26, "none": 6})
        self.assertEqual(
            summary["nibble_orders"], {"hi-first": 92, "none": 6})
        self.assertEqual(
            summary["unrolled_length_agreement"],
            {"agree": 26, "disagree": 0})
        for row in self.report["sequences"]:
            if row["clear_kind"] == "empty":
                self.assertEqual(row["clear"]["verdict"], "empty")
            else:
                self.assertEqual(
                    row["clear"]["verdict"], "scalar-hex-table")
                self.assertEqual(
                    row["clear"]["table_ref"], "lea-in-region")
                self.assertEqual(row["clear"]["nibble_order"], "hi-first")

    def test_authenticate_rejects_wrong_capture(self):
        with self.assertRaises(ValueError):
            f1.authenticate(self.capture[:-1])
        changed = mutate(self.capture, 0x2A31790, 0x90)
        with self.assertRaises(ValueError):
            f1.authenticate(changed)

    def test_traced_target_byte_mutation_fails_closed(self):
        changed = mutate(self.capture, 0x2A31790 + 40, 0x90)
        with self.assertRaises(ValueError):
            f1.analyse(changed)

    def test_other_f1_target_byte_mutation_fails_closed(self):
        changed = mutate(self.capture, 0x47358A0 + 40, 0x90)
        with self.assertRaises(ValueError):
            f1.analyse(changed)

    def test_hex_table_byte_mutation_fails_closed(self):
        changed = mutate(self.capture, 0x455D40, ord("g"))
        with self.assertRaises(ValueError):
            f1.analyse(changed)

    def test_clear_region_byte_mutation_fails_closed(self):
        # Inside the clear region of consumer 0x298c640..0x298c76b
        # (its scalar loop block at 0x298c6b0).
        changed = mutate(self.capture, 0x298C6B0 + 8, 0x90)
        with self.assertRaises(ValueError):
            f1.analyse(changed)


if __name__ == "__main__":
    unittest.main()
