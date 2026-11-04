import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))

import dispatcher_400_exit_static as disp400  # noqa: E402


TARGET = ROOT / "artifacts" / "node" / "115" / "hl-node"
PACKET = (
    ROOT
    / "research"
    / "work-items"
    / "RE-002-node115-dispatcher-400-exit"
)
SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"


def mutate(data, virtual_address, replacement):
    changed = bytearray(data)
    offset = disp400.va_to_offset(disp400.sections(data), virtual_address)
    changed[offset] = replacement
    return bytes(changed)


def retained_records():
    return json.loads((PACKET / "records.json").read_text(encoding="utf-8"))


class AuthenticatedDispatcher400ExitTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.capture = TARGET.read_bytes()
        if len(cls.capture) != 105896032 or \
                hashlib.sha256(cls.capture).hexdigest() != SHA:
            raise AssertionError("target is not the pinned node115 capture")
        cls.report, _f, _t, _d = disp400.analyse(cls.capture)

    def test_packet_regeneration_matches_retained_outputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            out = Path(temporary) / "packet"
            disp400.generate(TARGET, out)
            for name in ("records.json", "frames.txt",
                         "targets.objdump.txt",
                         "dispatcher.objdump.txt"):
                self.assertEqual(
                    (out / name).read_bytes(),
                    (PACKET / name).read_bytes(),
                    f"regenerated {name} differs from the retained packet")

    def test_body_identity(self):
        trace = self.report["trace"]
        self.assertEqual(trace["body"], "0x5bb9a60..0x5bba11a")
        self.assertEqual(trace["bytes"], 1722)
        self.assertEqual(trace["insns"], 324)
        self.assertEqual(
            trace["sha256"],
            "24663d382ee225bf024a091df6fcf0293aaa29a6059c320ef321561f4c4e46f0")
        self.assertEqual(trace["calls"], 0)
        retained = retained_records()
        self.assertEqual(retained["trace"]["sha256"], trace["sha256"])

    def test_trace_names_the_chacha_block_function(self):
        trace = self.report["trace"]
        self.assertEqual(
            trace["branches"],
            [{"site": "0x5bb9ada", "kind": "je", "target": "0x5bb9fe5"},
             {"site": "0x5bb9fa0", "kind": "jne", "target": "0x5bb9b40"},
             {"site": "0x5bb9fe3", "kind": "jmp", "target": "0x5bba03b"}])
        consts = {c["address"]: c for c in trace["constants"]}
        self.assertEqual(
            sorted(consts),
            ["0x4519c0", "0x452ec0", "0x4531c0", "0x456c50"])
        self.assertEqual(consts["0x4519c0"]["ascii"], "expand 32-byte k")
        self.assertEqual(
            consts["0x456c50"]["bytes"],
            "caf0e0c2dcc84066645ac4f2e8ca40d6")
        self.assertEqual(
            trace["input"]["counter_load"], "0x5bb9a73")
        self.assertEqual(
            trace["input"]["record_row_loads"],
            [{"site": "0x5bb9a64", "disp": 0},
             {"site": "0x5bb9a68", "disp": 16},
             {"site": "0x5bb9a6e", "disp": 32}])
        loop = trace["round_loop"]
        self.assertEqual(loop["head"], "0x5bb9b40")
        self.assertEqual(loop["back_edge"], "0x5bb9fa0")
        self.assertEqual(loop["insns"], 214)
        self.assertEqual(loop["rotations"]["pshufb"], 16)
        self.assertEqual(loop["rotations"]["paddd"], 32)
        self.assertEqual(loop["rotations"]["pxor"], 32)
        self.assertEqual(
            trace["pre_merge_sigma_adds"],
            ["0x5bb9faf", "0x5bb9fb4", "0x5bb9fb9", "0x5bb9fc4"])
        epi = trace["epilogue"]
        self.assertEqual(epi["output_bytes"], 256)
        self.assertEqual(len(epi["output_stores"]), 16)
        self.assertEqual(epi["counter_writeback_site"], "0x5bba059")
        self.assertEqual(epi["feed_forward_adds"], 12)
        self.assertEqual(
            self.report["operation"]["name"],
            "ChaCha block function (SSE4.1 / legacy-encoded "
            "form): four blocks in parallel with feed-forward, "
            "the state's 64-bit counter advanced by 4")

    def test_fourth_form_same_contract_as_the_three_traced_forms(self):
        trace = self.report["trace"]
        enc = trace["encoding"]
        self.assertEqual(enc["vex_prefixed_insns"], 0)
        self.assertEqual(enc["ymm_insns"], 0)
        self.assertEqual(enc["vector_width_bits"], 128)
        self.assertIsNone(enc["vzeroupper_site"])
        self.assertEqual(enc["pinsrd_insns"], 8)
        stack = trace["stack"]
        self.assertEqual(stack["frame_bytes"], 0x28)
        self.assertEqual(stack["accesses"], 45)
        self.assertEqual(stack["in_loop_accesses"], 22)
        self.assertEqual(
            stack["working_slots_in_loop"],
            ["-0x80", "-0x70", "-0x60", "-0x50"])
        f2 = self.report["comparison_f2"]
        self.assertEqual(f2["body"], "0x5bba120..0x5bba7fe")
        self.assertEqual(f2["bytes"], 1758)
        self.assertEqual(f2["insns"], 340)
        self.assertEqual(f2["pinsrd_insns"], 0)
        self.assertEqual(f2["movd_insns"], 8)
        avx = self.report["comparison_avx"]
        self.assertEqual(avx["body"], "0x5bbb030..0x5bbb62a")
        self.assertEqual(avx["bytes"], 1530)
        self.assertEqual(avx["insns"], 301)
        self.assertEqual(avx["pinsrd_insns"], 8)
        sign = self.report["comparison_sign"]
        self.assertEqual(sign["body"], "0x5bbb630..0x5bbb994")
        self.assertEqual(sign["bytes"], 868)
        self.assertEqual(sign["insns"], 173)
        self.assertEqual(sign["ymm_operands"], 110)
        # This body's loop census equals the F2/AVX census
        # exactly, and doubles the AVX2 form's census.
        mine = trace["round_loop"]["rotations"]
        self.assertEqual(mine, f2["round_loop"]["rotations"])
        self.assertEqual(mine, avx["round_loop"]["rotations"])
        doubled_sign = {
            k: (v * 2 if isinstance(v, int)
                else {kk: vv * 2 for kk, vv in v.items()})
            for k, v in sign["round_loop"]["rotations"].items()}
        self.assertEqual(mine, doubled_sign)
        self.assertEqual(f2["round_loop"]["insns"], 217)
        self.assertEqual(avx["round_loop"]["insns"], 189)
        self.assertEqual(sign["round_loop"]["insns"], 84)
        # The epilogue contract points coincide with all three.
        for form in (f2, avx, sign):
            self.assertEqual(trace["epilogue"]["output_stores"],
                             form["epilogue"]["output_stores"])
            self.assertEqual(trace["epilogue"]["output_bytes"],
                             form["epilogue"]["output_bytes"])
        self.assertEqual(
            self.report["comparison"]["verdict"],
            "same-operation-sse41-form")
        self.assertTrue(self.report["summary"]["fourth_form"])
        self.assertFalse(self.report["summary"]["reduced_form"])

    def test_dispatcher_selection(self):
        disp = self.report["dispatcher"]
        self.assertEqual(disp["body"], "0x5bba800..0x5bbb030")
        self.assertEqual(disp["feature_slot"], "0x64dfa60")
        self.assertEqual(
            disp["bit_tests"]["0x400"],
            ["0x5bba84c", "0x5bbafe0"])
        self.assertEqual(
            disp["bit_tests"]["0x4000"],
            ["0x5bba835", "0x5bbafad"])
        self.assertEqual(
            disp["exits"],
            [{"site": "0x5bbaf92", "target": "0x5bbb630"},
             {"site": "0x5bbafc5", "target": "0x5bbb030"},
             {"site": "0x5bbaff8", "target": "0x5bb9a60"},
             {"site": "0x5bbb02b", "target": "0x5bba120"}])
        self.assertEqual(disp["exit_400"]["jump_site"], "0x5bbaff8")
        self.assertEqual(disp["exit_400"]["target"], "0x5bb9a60")
        self.assertEqual(disp["exit_400"]["block"], "0x5bbafeb")

    def test_direct_transfers_are_exactly_the_exit_jump(self):
        transfers = self.report["direct_transfers"]
        self.assertEqual(transfers["validated_direct_calls"], [])
        self.assertEqual(
            transfers["validated_direct_jumps"], ["0x5bbaff8"])

    def test_authenticate_rejects_wrong_capture(self):
        with self.assertRaises(ValueError):
            disp400.authenticate(self.capture[:-1])
        changed = mutate(self.capture, 0x5BB9A60, 0x90)
        with self.assertRaises(ValueError):
            disp400.authenticate(changed)

    def test_traced_body_byte_mutation_fails_closed(self):
        changed = mutate(self.capture, 0x5BB9A60 + 40, 0x90)
        with self.assertRaises(ValueError):
            disp400.analyse(changed)

    def test_sigma_byte_mutation_fails_closed(self):
        changed = mutate(self.capture, 0x4519C0, ord("x"))
        with self.assertRaises(ValueError):
            disp400.analyse(changed)

    def test_f2_body_byte_mutation_fails_closed(self):
        changed = mutate(self.capture, 0x5BBA120 + 40, 0x90)
        with self.assertRaises(ValueError):
            disp400.analyse(changed)

    def test_dispatcher_exit_byte_mutation_fails_closed(self):
        # The low byte of the 0x400 exit jump's rel32 at
        # 0x5bbaff8: retargeting it breaks the exit pins.
        changed = mutate(self.capture, 0x5BBAFF8 + 1, 0x00)
        with self.assertRaises(ValueError):
            disp400.analyse(changed)


if __name__ == "__main__":
    unittest.main()
