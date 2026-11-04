import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))

import dispatcher_4000_exit_static as vexit  # noqa: E402


TARGET = ROOT / "artifacts" / "node" / "115" / "hl-node"
PACKET = (
    ROOT
    / "research"
    / "work-items"
    / "RE-002-node115-dispatcher-4000-exit"
)
SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"


def mutate(data, virtual_address, replacement):
    changed = bytearray(data)
    offset = vexit.va_to_offset(vexit.sections(data), virtual_address)
    changed[offset] = replacement
    return bytes(changed)


def retained_records():
    return json.loads((PACKET / "records.json").read_text(encoding="utf-8"))


class AuthenticatedDispatcher4000ExitTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.capture = TARGET.read_bytes()
        if len(cls.capture) != 105896032 or \
                hashlib.sha256(cls.capture).hexdigest() != SHA:
            raise AssertionError("target is not the pinned node115 capture")
        cls.report, _f, _t, _d = vexit.analyse(cls.capture)

    def test_packet_regeneration_matches_retained_outputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            out = Path(temporary) / "packet"
            vexit.generate(TARGET, out)
            for name in ("records.json", "frames.txt",
                         "targets.objdump.txt",
                         "dispatcher.objdump.txt"):
                self.assertEqual(
                    (out / name).read_bytes(),
                    (PACKET / name).read_bytes(),
                    f"regenerated {name} differs from the retained packet")

    def test_body_identity(self):
        trace = self.report["trace"]
        self.assertEqual(trace["body"], "0x5bbb030..0x5bbb62a")
        self.assertEqual(trace["bytes"], 1530)
        self.assertEqual(trace["insns"], 301)
        self.assertEqual(
            trace["sha256"],
            "c04bc82ee291c06eb8e65fe73d86dd880a11f4ff06aec15c62956a579b916892")
        self.assertEqual(trace["calls"], 0)
        retained = retained_records()
        self.assertEqual(retained["trace"]["sha256"], trace["sha256"])

    def test_trace_names_the_chacha_block_function(self):
        trace = self.report["trace"]
        self.assertEqual(
            trace["branches"],
            [{"site": "0x5bbb084", "kind": "je", "target": "0x5bbb503"},
             {"site": "0x5bbb4ad", "kind": "jne", "target": "0x5bbb100"},
             {"site": "0x5bbb501", "kind": "jmp", "target": "0x5bbb55b"}])
        consts = {c["address"]: c for c in trace["constants"]}
        self.assertEqual(
            sorted(consts),
            ["0x4519c0", "0x452ec0", "0x4531c0", "0x456c50"])
        self.assertEqual(consts["0x4519c0"]["ascii"], "expand 32-byte k")
        self.assertEqual(
            consts["0x456c50"]["bytes"],
            "caf0e0c2dcc84066645ac4f2e8ca40d6")
        self.assertEqual(
            trace["input"]["counter_load"], "0x5bbb03d")
        loop = trace["round_loop"]
        self.assertEqual(loop["head"], "0x5bbb100")
        self.assertEqual(loop["back_edge"], "0x5bbb4ad")
        self.assertEqual(loop["insns"], 189)
        self.assertEqual(loop["rotations"]["pshufb"], 16)
        self.assertEqual(loop["rotations"]["paddd"], 32)
        self.assertEqual(loop["rotations"]["pxor"], 32)
        epi = trace["epilogue"]
        self.assertEqual(epi["output_bytes"], 256)
        self.assertEqual(len(epi["output_stores"]), 16)
        self.assertEqual(epi["counter_writeback_site"], "0x5bbb572")
        self.assertEqual(epi["feed_forward_adds"], 12)
        self.assertEqual(
            self.report["operation"]["name"],
            "ChaCha block function (AVX / VEX-encoded form): "
            "four blocks in parallel with feed-forward, the "
            "state's 64-bit counter advanced by 4")

    def test_not_wider_vector_same_contract_as_f2(self):
        trace = self.report["trace"]
        enc = trace["encoding"]
        self.assertEqual(enc["ymm_operands"], 0)
        self.assertEqual(enc["vector_width_bits"], 128)
        self.assertEqual(enc["vzeroupper_site"], "0x5bbb622")
        self.assertGreater(enc["vex_prefixed_insns"], 250)
        f2 = self.report["comparison_f2"]
        self.assertEqual(f2["body"], "0x5bba120..0x5bba7fe")
        self.assertEqual(f2["bytes"], 1758)
        self.assertEqual(f2["insns"], 340)
        self.assertEqual(f2["vex_prefixed_insns"], 0)
        # The round-loop rotation census is identical.
        self.assertEqual(trace["round_loop"]["rotations"],
                         f2["round_loop"]["rotations"])
        self.assertEqual(f2["round_loop"]["insns"], 217)
        # The epilogue contract points coincide.
        self.assertEqual(trace["epilogue"]["output_stores"],
                         f2["epilogue"]["output_stores"])
        self.assertEqual(trace["epilogue"]["output_bytes"],
                         f2["epilogue"]["output_bytes"])
        self.assertEqual(trace["epilogue"]["feed_forward_adds"],
                         f2["epilogue"]["feed_forward_adds"])
        self.assertEqual(
            self.report["comparison"]["verdict"],
            "same-operation-avx-form")
        self.assertFalse(self.report["summary"]["wider_vector"])

    def test_dispatcher_selection(self):
        disp = self.report["dispatcher"]
        self.assertEqual(disp["body"], "0x5bba800..0x5bbb030")
        self.assertEqual(disp["feature_slot"], "0x64dfa60")
        self.assertEqual(
            disp["bit_tests"]["0x4000"],
            ["0x5bba835", "0x5bbafad"])
        self.assertEqual(
            disp["exits"],
            [{"site": "0x5bbaf92", "target": "0x5bbb630"},
             {"site": "0x5bbafc5", "target": "0x5bbb030"},
             {"site": "0x5bbaff8", "target": "0x5bb9a60"},
             {"site": "0x5bbb02b", "target": "0x5bba120"}])
        self.assertEqual(disp["exit_4000"]["jump_site"], "0x5bbafc5")
        self.assertEqual(disp["exit_4000"]["target"], "0x5bbb030")
        self.assertEqual(disp["exit_4000"]["block"], "0x5bbafb8")

    def test_direct_transfers_are_exactly_the_exit_jump(self):
        transfers = self.report["direct_transfers"]
        self.assertEqual(transfers["validated_direct_calls"], [])
        self.assertEqual(
            transfers["validated_direct_jumps"], ["0x5bbafc5"])

    def test_authenticate_rejects_wrong_capture(self):
        with self.assertRaises(ValueError):
            vexit.authenticate(self.capture[:-1])
        changed = mutate(self.capture, 0x5BBB030, 0x90)
        with self.assertRaises(ValueError):
            vexit.authenticate(changed)

    def test_traced_body_byte_mutation_fails_closed(self):
        changed = mutate(self.capture, 0x5BBB030 + 40, 0x90)
        with self.assertRaises(ValueError):
            vexit.analyse(changed)

    def test_sigma_byte_mutation_fails_closed(self):
        changed = mutate(self.capture, 0x4519C0, ord("x"))
        with self.assertRaises(ValueError):
            vexit.analyse(changed)

    def test_f2_body_byte_mutation_fails_closed(self):
        changed = mutate(self.capture, 0x5BBA120 + 40, 0x90)
        with self.assertRaises(ValueError):
            vexit.analyse(changed)

    def test_dispatcher_exit_byte_mutation_fails_closed(self):
        # The low byte of the 0x4000 exit jump's rel32 at
        # 0x5bbafc5: retargeting it breaks the exit pins.
        changed = mutate(self.capture, 0x5BBAFC5 + 1, 0x00)
        with self.assertRaises(ValueError):
            vexit.analyse(changed)


if __name__ == "__main__":
    unittest.main()
