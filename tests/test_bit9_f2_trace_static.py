import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))

import bit9_f2_trace_static as f2  # noqa: E402


TARGET = ROOT / "artifacts" / "node" / "115" / "hl-node"
PACKET = (
    ROOT
    / "research"
    / "work-items"
    / "RE-002-node115-bit9-f2-trace"
)
SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"


def mutate(data, virtual_address, replacement):
    changed = bytearray(data)
    offset = f2.va_to_offset(f2.sections(data), virtual_address)
    changed[offset] = replacement
    return bytes(changed)


def retained_records():
    return json.loads((PACKET / "records.json").read_text(encoding="utf-8"))


class AuthenticatedBit9F2TraceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.capture = TARGET.read_bytes()
        if len(cls.capture) != 105896032 or \
                hashlib.sha256(cls.capture).hexdigest() != SHA:
            raise AssertionError("target is not the pinned node115 capture")
        cls.report, _f, _t, _r, _d = f2.analyse(cls.capture)

    def test_packet_regeneration_matches_retained_outputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            out = Path(temporary) / "packet"
            f2.generate(TARGET, out)
            for name in ("records.json", "frames.txt",
                         "targets.objdump.txt",
                         "clear_regions.objdump.txt",
                         "dispatcher.objdump.txt"):
                self.assertEqual(
                    (out / name).read_bytes(),
                    (PACKET / name).read_bytes(),
                    f"regenerated {name} differs from the retained packet")

    def test_f2_stream_identity(self):
        stream = self.report["f2_stream"]
        self.assertEqual(stream["placements"], ["0x5bba120..0x5bba7fe"])
        self.assertEqual(stream["distinct_normalised_streams"], 1)
        self.assertEqual(
            stream["normalised_sha256"],
            "c1ea182b6e4281bbbcc48be58904200776445b0b614e24b7233f0edba8c3bd36")
        self.assertEqual(stream["selected_by_sequences"], 1)
        verified = self.report["targets_verified"]
        self.assertEqual(len(verified), 14)
        self.assertEqual(
            sum(1 for t in verified if t["stream_family"] == "F2"), 1)
        self.assertEqual(self.report["consumers_verified"], 92)

    def test_trace_names_the_chacha_block_function(self):
        trace = self.report["trace"]
        self.assertEqual(trace["body"], "0x5bba120..0x5bba7fe")
        self.assertEqual(trace["bytes"], 1758)
        self.assertEqual(trace["insns"], 340)
        self.assertEqual(trace["calls"], 0)
        self.assertEqual(
            trace["branches"],
            [{"site": "0x5bba1e2", "kind": "je", "target": "0x5bba6bc"},
             {"site": "0x5bba693", "kind": "jne", "target": "0x5bba230"},
             {"site": "0x5bba6ba", "kind": "jmp", "target": "0x5bba6fd"}])
        consts = {c["address"]: c for c in trace["constants"]}
        self.assertEqual(
            sorted(consts),
            ["0x4519c0", "0x452ec0", "0x4531c0", "0x456c50"])
        self.assertEqual(consts["0x4519c0"]["ascii"], "expand 32-byte k")
        self.assertEqual(
            consts["0x456c50"]["bytes"],
            "caf0e0c2dcc84066645ac4f2e8ca40d6")
        self.assertEqual(
            consts["0x4531c0"]["bytes"],
            "03000102070405060b08090a0f0c0d0e")
        loop = trace["round_loop"]
        self.assertEqual(loop["head"], "0x5bba230")
        self.assertEqual(loop["back_edge"], "0x5bba693")
        self.assertEqual(loop["insns"], 217)
        self.assertEqual(loop["rotations"]["pshufb"], 16)
        self.assertEqual(loop["rotations"]["paddd"], 32)
        self.assertEqual(loop["rotations"]["pxor"], 32)
        self.assertEqual(
            trace["input"]["counter_load"], "0x5bba12d")
        epi = trace["epilogue"]
        self.assertEqual(epi["output_bytes"], 256)
        self.assertEqual(len(epi["output_stores"]), 16)
        self.assertEqual(epi["counter_writeback_site"], "0x5bba72f")
        self.assertEqual(
            self.report["operation"]["name"],
            "ChaCha block function (SSSE3 form): four "
            "blocks in parallel with feed-forward, the "
            "state's 64-bit counter advanced by 4")

    def test_dispatcher_and_tail_jump(self):
        disp = self.report["dispatcher"]
        self.assertEqual(disp["body"], "0x5bba800..0x5bbb030")
        self.assertEqual(disp["feature_slot"], "0x64dfa60")
        self.assertEqual(disp["refresh_slot"], "0x64dfa68")
        self.assertEqual(len(disp["refresh_call_sites"]), 4)
        self.assertEqual(
            disp["bit_tests"]["0x200_bit9"],
            ["0x5bba863", "0x5bbb013"])
        self.assertEqual(
            disp["exits"],
            [{"site": "0x5bbaf92", "target": "0x5bbb630"},
             {"site": "0x5bbafc5", "target": "0x5bbb030"},
             {"site": "0x5bbaff8", "target": "0x5bb9a60"},
             {"site": "0x5bbb02b", "target": "0x5bba120"}])
        self.assertEqual(disp["set_arm"]["tail_jump_site"], "0x5bbb02b")
        self.assertEqual(disp["set_arm"]["target"], "0x5bba120")
        self.assertEqual(disp["clear_fallthrough"], "0x5bba86e")

    def test_clear_region_is_the_sse2_form(self):
        summary = self.report["summary"]
        self.assertEqual(summary["f2_sequences"], 1)
        self.assertEqual(summary["f2_bodies"], 1)
        self.assertEqual(
            summary["clear_verdicts"], {"same-operation-sse2-form": 1})
        row = self.report["sequences"][0]
        self.assertEqual(row["set_kind"], "tailjmp")
        clear = row["clear"]
        self.assertEqual(clear["verdict"], "same-operation-sse2-form")
        self.assertEqual(clear["bytes"], 1753)
        self.assertEqual(
            clear["region_sha256"],
            "ab8a5c9f0fe3fc7e313f849d087cbad2b3dd3b84aa1d8d0fb5dd155925b17c76")
        counts = clear["counts"]
        self.assertEqual(counts["pshufb"], 0)
        self.assertEqual(counts["rot8_shift_pairs"], 8)
        self.assertEqual(counts["counter_variant_leas"], 3)
        self.assertEqual(counts["output_stores"], 16)
        self.assertEqual(counts["counter_writebacks"], 1)

    def test_direct_transfers_are_exactly_the_tail_jump(self):
        transfers = self.report["direct_transfers"]
        self.assertEqual(transfers["validated_direct_calls"], [])
        self.assertEqual(
            transfers["validated_direct_jumps"], ["0x5bbb02b"])
        self.assertEqual(
            transfers["dispatcher_validated_direct_calls"], [])
        self.assertEqual(
            transfers["dispatcher_validated_direct_jumps"], [])

    def test_authenticate_rejects_wrong_capture(self):
        with self.assertRaises(ValueError):
            f2.authenticate(self.capture[:-1])
        changed = mutate(self.capture, 0x5BBA120, 0x90)
        with self.assertRaises(ValueError):
            f2.authenticate(changed)

    def test_traced_target_byte_mutation_fails_closed(self):
        changed = mutate(self.capture, 0x5BBA120 + 40, 0x90)
        with self.assertRaises(ValueError):
            f2.analyse(changed)

    def test_other_target_byte_mutation_fails_closed(self):
        changed = mutate(self.capture, 0x5BDDEE0 + 40, 0x90)
        with self.assertRaises(ValueError):
            f2.analyse(changed)

    def test_sigma_byte_mutation_fails_closed(self):
        changed = mutate(self.capture, 0x4519C0, ord("x"))
        with self.assertRaises(ValueError):
            f2.analyse(changed)

    def test_clear_region_byte_mutation_fails_closed(self):
        # Inside the clear region of the dispatcher's sequence
        # (its round-loop block at 0x5bba970).
        changed = mutate(self.capture, 0x5BBA970 + 8, 0x90)
        with self.assertRaises(ValueError):
            f2.analyse(changed)


if __name__ == "__main__":
    unittest.main()
