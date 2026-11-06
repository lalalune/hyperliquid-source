import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))

import dispatcher_sign_exit_static as signexit  # noqa: E402


TARGET = ROOT / "artifacts" / "node" / "115" / "hl-node"
PACKET = (
    ROOT
    / "research"
    / "work-items"
    / "RE-002-node115-dispatcher-sign-exit"
)
SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"


def mutate(data, virtual_address, replacement):
    changed = bytearray(data)
    offset = signexit.va_to_offset(signexit.sections(data), virtual_address)
    changed[offset] = replacement
    return bytes(changed)


def retained_records():
    return json.loads((PACKET / "records.json").read_text(encoding="utf-8"))


class AuthenticatedDispatcherSignExitTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.capture = TARGET.read_bytes()
        if len(cls.capture) != 105896032 or \
                hashlib.sha256(cls.capture).hexdigest() != SHA:
            raise AssertionError("target is not the pinned node115 capture")
        cls.report, _f, _t, _d = signexit.analyse(cls.capture)

    def test_packet_regeneration_matches_retained_outputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            out = Path(temporary) / "packet"
            signexit.generate(TARGET, out)
            for name in ("records.json", "frames.txt",
                         "targets.objdump.txt",
                         "dispatcher.objdump.txt"):
                self.assertEqual(
                    (out / name).read_bytes(),
                    (PACKET / name).read_bytes(),
                    f"regenerated {name} differs from the retained packet")

    def test_body_identity(self):
        trace = self.report["trace"]
        self.assertEqual(trace["body"], "0x5bbb630..0x5bbb994")
        self.assertEqual(trace["bytes"], 868)
        self.assertEqual(trace["insns"], 173)
        self.assertEqual(
            trace["sha256"],
            "963fe9acf58718076c5a6fa97b4cfc297cd0b8d73719ac18d50b7242bf72a944")
        self.assertEqual(trace["calls"], 0)
        retained = retained_records()
        self.assertEqual(retained["trace"]["sha256"], trace["sha256"])

    def test_trace_names_the_chacha_block_function(self):
        trace = self.report["trace"]
        self.assertEqual(
            trace["branches"],
            [{"site": "0x5bbb698", "kind": "je", "target": "0x5bbb87d"},
             {"site": "0x5bbb85f", "kind": "jne", "target": "0x5bbb6d0"},
             {"site": "0x5bbb87b", "kind": "jmp", "target": "0x5bbb892"}])
        consts = {c["address"]: c for c in trace["constants"]}
        self.assertEqual(
            sorted(consts),
            ["0x4519c0", "0x457ca0", "0x458120", "0x458660"])
        self.assertEqual(consts["0x4519c0"]["ascii"], "expand 32-byte k")
        self.assertEqual(
            consts["0x458660"]["bytes"],
            "657870616e642033322d62797465206b" * 2)
        self.assertEqual(
            trace["input"]["counter_load"], "0x5bbb635")
        self.assertEqual(
            trace["input"]["insert_sites"],
            ["0x5bbb67e", "0x5bbb684", "0x5bbb68a", "0x5bbb690"])
        loop = trace["round_loop"]
        self.assertEqual(loop["head"], "0x5bbb6d0")
        self.assertEqual(loop["back_edge"], "0x5bbb85f")
        self.assertEqual(loop["insns"], 84)
        self.assertEqual(loop["rotations"]["pshufb"], 8)
        self.assertEqual(loop["rotations"]["paddd"], 16)
        self.assertEqual(loop["rotations"]["pxor"], 16)
        epi = trace["epilogue"]
        self.assertEqual(epi["output_bytes"], 256)
        self.assertEqual(len(epi["output_stores"]), 16)
        self.assertEqual(epi["counter_writeback_site"], "0x5bbb8a9")
        self.assertEqual(epi["feed_forward_adds"], 16)
        self.assertEqual(
            self.report["operation"]["name"],
            "ChaCha block function (AVX2 / 256-bit ymm form): "
            "four blocks in parallel with feed-forward, the "
            "state's 64-bit counter advanced by 4")

    def test_widest_form_same_contract_as_f2_and_avx(self):
        trace = self.report["trace"]
        enc = trace["encoding"]
        self.assertEqual(enc["ymm_insns"], 110)
        self.assertEqual(enc["vector_width_bits"], 256)
        self.assertEqual(enc["vzeroupper_site"], "0x5bbb990")
        self.assertEqual(enc["vex_prefixed_insns"], 156)
        f2 = self.report["comparison_f2"]
        self.assertEqual(f2["body"], "0x5bba120..0x5bba7fe")
        self.assertEqual(f2["bytes"], 1758)
        self.assertEqual(f2["insns"], 340)
        self.assertEqual(f2["ymm_operands"], 0)
        avx = self.report["comparison_avx"]
        self.assertEqual(avx["body"], "0x5bbb030..0x5bbb62a")
        self.assertEqual(avx["bytes"], 1530)
        self.assertEqual(avx["insns"], 301)
        self.assertEqual(avx["ymm_operands"], 0)
        # The sign loop census doubled equals both narrower
        # forms' censuses exactly.
        sign = trace["round_loop"]["rotations"]
        doubled = {
            k: (v * 2 if isinstance(v, int)
                else {kk: vv * 2 for kk, vv in v.items()})
            for k, v in sign.items()}
        self.assertEqual(doubled, f2["round_loop"]["rotations"])
        self.assertEqual(doubled, avx["round_loop"]["rotations"])
        self.assertEqual(f2["round_loop"]["insns"], 217)
        self.assertEqual(avx["round_loop"]["insns"], 189)
        # The epilogue contract points coincide.
        self.assertEqual(trace["epilogue"]["output_stores"],
                         f2["epilogue"]["output_stores"])
        self.assertEqual(trace["epilogue"]["output_stores"],
                         avx["epilogue"]["output_stores"])
        self.assertEqual(trace["epilogue"]["output_bytes"],
                         avx["epilogue"]["output_bytes"])
        self.assertEqual(
            self.report["comparison"]["verdict"],
            "same-operation-avx2-form")
        self.assertTrue(self.report["summary"]["wider_vector"])
        self.assertFalse(self.report["summary"]["reduced_form"])

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
        self.assertEqual(disp["exit_sign"]["jump_site"], "0x5bbaf92")
        self.assertEqual(disp["exit_sign"]["target"], "0x5bbb630")
        self.assertEqual(disp["exit_sign"]["block"], "0x5bbaf85")

    def test_direct_transfers_are_exactly_the_exit_jump(self):
        transfers = self.report["direct_transfers"]
        self.assertEqual(transfers["validated_direct_calls"], [])
        self.assertEqual(
            transfers["validated_direct_jumps"], ["0x5bbaf92"])

    def test_authenticate_rejects_wrong_capture(self):
        with self.assertRaises(ValueError):
            signexit.authenticate(self.capture[:-1])
        changed = mutate(self.capture, 0x5BBB630, 0x90)
        with self.assertRaises(ValueError):
            signexit.authenticate(changed)

    def test_traced_body_byte_mutation_fails_closed(self):
        changed = mutate(self.capture, 0x5BBB630 + 40, 0x90)
        with self.assertRaises(ValueError):
            signexit.analyse(changed)

    def test_sigma_byte_mutation_fails_closed(self):
        changed = mutate(self.capture, 0x4519C0, ord("x"))
        with self.assertRaises(ValueError):
            signexit.analyse(changed)

    def test_f2_body_byte_mutation_fails_closed(self):
        changed = mutate(self.capture, 0x5BBA120 + 40, 0x90)
        with self.assertRaises(ValueError):
            signexit.analyse(changed)

    def test_dispatcher_exit_byte_mutation_fails_closed(self):
        # The low byte of the sign exit jump's rel32 at
        # 0x5bbaf92: retargeting it breaks the exit pins.
        changed = mutate(self.capture, 0x5BBAF92 + 1, 0x00)
        with self.assertRaises(ValueError):
            signexit.analyse(changed)


if __name__ == "__main__":
    unittest.main()
