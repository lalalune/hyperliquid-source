import hashlib
import importlib.util
import os
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "timeout_round_transition", ROOT / "tools/timeout_round_transition.py")
TR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TR)
BIN = ROOT / "artifacts/node/94/hl-node"
PACKET = ROOT / "research/work-items/RE-008-timeout-round-transition-94"
DATA = BIN.read_bytes() if BIN.exists() else None


@unittest.skipIf(DATA is None, "pinned node #94 binary not present")
class TimeoutRoundTransitionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = TR.build(DATA)
        cls.rendered = TR.render(cls.result)
        cls.elf = TR.Elf(DATA)

    def mutate(self, va, replacement):
        changed = bytearray(DATA)
        off = self.elf.off(va)
        changed[off:off + len(replacement)] = replacement
        changed = bytes(changed)
        return TR.build(changed, expected_sha256=hashlib.sha256(changed).hexdigest())

    def test_pinned_binary_and_fde_bounds(self):
        self.assertEqual(self.result["binary_sha256"], TR.EXPECTED_SHA256)
        by_name = {x["name"]: x for x in self.result["functions"]}
        self.assertEqual((by_name["state_dispatch"]["start"],
                          by_name["state_dispatch"]["end"]),
                         (0x44adfa0, 0x44b303a))
        self.assertEqual((by_name["round_transition"]["start"],
                          by_name["round_transition"]["end"]),
                         (0x44b6670, 0x44b7e10))
        self.assertEqual((by_name["verify_timeout_certificate"]["start"],
                          by_name["verify_timeout_certificate"]["end"]),
                         (0x47594f0, 0x4759963))

    def test_bounded_cfg_records_are_complete_and_pinned(self):
        blocks = self.result["bounded_cfg_blocks"]
        self.assertEqual(len(blocks), 39)
        for block in blocks:
            raw = bytes.fromhex(block["bytes"])
            self.assertEqual(len(raw), block["end"] - block["start"])
            self.assertEqual(hashlib.sha256(raw).hexdigest(), block["sha256"])
            self.assertTrue(block["edges"])
        entry = next(b for b in blocks if b["name"] == "round_entry_guard")
        self.assertEqual(entry["edges"], [
            {"kind": "taken", "to": 0x44b66e6},
            {"kind": "fallthrough", "to": 0x44b66a7},
        ])

    def test_state_dispatch_reaches_both_verifiers_and_round_helper(self):
        calls = {x["name"]: x for x in self.result["calls"]}
        self.assertEqual(calls["direct_tc_verify"]["target"], 0x47594f0)
        self.assertEqual(calls["timeout_verify"]["target"], 0x454aa10)
        self.assertEqual(calls["direct_tc_round_transition"]["target"], 0x44b6670)
        self.assertEqual(calls["quorum_round_transition"]["target"], 0x44b6670)

    def test_relocation_backed_calls(self):
        calls = {x["name"]: x for x in self.result["calls"]}
        self.assertEqual(calls["validator_snapshot_by_round"], {
            "name": "validator_snapshot_by_round", "site": 0x44b15ea,
            "kind": "slot", "slot": 0x57769e8, "target": 0x4b31d40,
        })
        self.assertEqual(calls["tc_quorum_predicate"]["slot"], 0x5776ae8)
        self.assertEqual(calls["tc_quorum_predicate"]["target"], 0x4ad90d0)
        self.assertEqual(calls["round_queue_push"]["target"], 0x4758390)

    def test_round_update_is_saturating_add_one(self):
        transition = self.result["proven_transition"]
        self.assertEqual(transition["write_site"], 0x44b66b8)
        self.assertEqual(transition["stale_branch_site"], 0x44b66a5)
        sites = {x["name"]: x for x in self.result["state_offset_sites"]}
        self.assertEqual(sites["round_saturating_store"]["bytes"],
                         "4c89f048ffc049c7c5ffffffff4c0f45e84c89af18090000")

    def test_duplicate_and_round_mismatch_precede_verification(self):
        table = {x["case"]: x for x in self.result["branch_table"]}
        wrong = table["individual timeout wrong round"]
        duplicate = table["individual timeout duplicate"]
        self.assertFalse(wrong["caller_state_write_before_outcome"])
        self.assertFalse(duplicate["caller_state_write_before_outcome"])
        self.assertLess(wrong["sites"][-1], 0x44b1560)
        self.assertLess(duplicate["sites"][-1], 0x44b1560)

    def test_absent_validator_has_zero_observed_weight_not_explicit_reject(self):
        case = next(x for x in self.result["branch_table"]
                    if x["case"] == "validator key absent from stake tree")
        self.assertIn("no stake is added", case["outcome"])
        self.assertIn("no separate membership rejection", case["outcome"])
        sites = {x["name"]: x for x in self.result["state_offset_sites"]}
        self.assertIn("14", sites["stake_key_memcmp"]["bytes"])

    def test_exact_two_thirds_is_not_quorum(self):
        case = next(x for x in self.result["branch_table"]
                    if x["case"] == "individual timeout insufficient or exact two-thirds stake")
        self.assertEqual(case["predicate"], "2*total >= 3*signed_weight")
        self.assertIn("round and timeout-map clearing path not taken", case["outcome"])

    def test_wrong_binary_hash_rejected(self):
        with self.assertRaises(TR.EvidenceError):
            TR.build(DATA[:-1] + bytes([DATA[-1] ^ 1]))

    def test_round_store_corruption_rejected(self):
        with self.assertRaises(TR.EvidenceError):
            self.mutate(0x44b66b8, b"\x90" * 7)

    def test_duplicate_branch_corruption_rejected(self):
        with self.assertRaises(TR.EvidenceError):
            self.mutate(0x44b038b, bytes.fromhex("0f85b7110000"))

    def test_quorum_branch_corruption_rejected(self):
        with self.assertRaises(TR.EvidenceError):
            self.mutate(0x44b255f, bytes.fromhex("0f82b7f2ffff"))

    def test_tc_verifier_call_corruption_rejected(self):
        with self.assertRaises(TR.EvidenceError):
            self.mutate(0x44af543, b"\x90" * 5)

    def test_stake_key_width_corruption_rejected(self):
        with self.assertRaises(TR.EvidenceError):
            self.mutate(0x4b33be9, bytes.fromhex("ba15000000"))

    def test_packet_matches_tool(self):
        packet = PACKET / "timeout-round-transition.json"
        if not packet.exists():
            self.skipTest("packet not generated yet")
        self.assertEqual(packet.read_bytes(), self.rendered)

    def test_hashseed_invariance(self):
        hashes = set()
        for seed in ("0", "7", "99"):
            env = dict(os.environ, PYTHONHASHSEED=seed)
            proc = subprocess.run(
                [sys.executable, "-I", "-B", str(ROOT / "tools/timeout_round_transition.py")],
                cwd=ROOT, env=env, capture_output=True, check=True)
            hashes.add(hashlib.sha256(proc.stdout).hexdigest())
        self.assertEqual(len(hashes), 1)


if __name__ == "__main__":
    unittest.main()
