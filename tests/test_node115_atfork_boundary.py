"""Target-backed replay and independent mutations of native instruction fields."""
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research/work-items/RE-001-node115-atfork-boundary"
spec = importlib.util.spec_from_file_location("atfork_boundary", PACKET / "replay.py")
replay = importlib.util.module_from_spec(spec)
spec.loader.exec_module(replay)

class AtforkBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.actual = replay.collect()
        cls.windows = [bytes.fromhex(w["hex"]) for w in cls.actual["windows"]]

    def test_real_target_replay(self):
        self.assertEqual(self.actual, json.loads((PACKET / "records.json").read_text()))
        self.assertFalse(self.actual["target_executed"])
        self.assertEqual(self.actual["diagnostic_text"], "<jemalloc>: Error in pthread_atfork()\n")

    def test_callback_fde_entries(self):
        self.assertEqual([int(self.actual["semantics"][r],16) for r in ["rdi","rsi","rdx"]],
                         [int(f["start"],16) for f in self.actual["fdes"][1:4]])
        self.assertTrue(int(self.actual["fdes"][0]["start"],16) <= 0x634f351 <
                        int(self.actual["fdes"][0]["end_exclusive"],16))

    def test_bounded_denominator(self):
        self.assertEqual(sum(len(w) for w in self.windows), 109)
        self.assertEqual(self.actual["denominator"], {"selected_callers":1,
            "callback_arguments":3,"exact_fdes":5,"bounded_code_bytes":109})

    def decode(self, windows):
        return replay.decode_boundary(windows[0], windows[2], windows[3], windows[1])

    def test_unmodified_decoder(self):
        self.assertEqual(self.decode(self.windows), self.actual["semantics"])

    def test_truncated_windows_rejected(self):
        for i in range(4):
            with self.subTest(window=i):
                w=self.windows.copy(); w[i]=w[i][:-1]
                with self.assertRaises(ValueError): self.decode(w)

# These mutate actual target bytes after digest-authenticated extraction, so the
# semantic checks are exercised rather than merely the top-level digest guard.
def corruption_test(window, index):
    def test(self):
        w=self.windows.copy(); b=bytearray(w[window]); b[index]^=1; w[window]=bytes(b)
        with self.assertRaises(ValueError): self.decode(w)
    return test

for name, window, index in [
    ("rdx_opcode",0,2),("rdx_coordinate",0,3),("rsi_coordinate",0,10),
    ("rdi_coordinate",0,17),("call_opcode",0,21),("call_target",0,22),
    ("return_test",0,26),("branch_predicate",0,29),("nonzero_target",0,30),
    ("zero_target",0,35),("stub_opcode",2,0),("dso_slot",2,7),
    ("plt_target",2,12),("plt_opcode",3,0),("got_slot",3,2),
    ("diagnostic_address",1,3),("diagnostic_helper",1,8)]:
    setattr(AtforkBoundaryTests,"test_reject_"+name,corruption_test(window,index))

if __name__ == "__main__": unittest.main()
