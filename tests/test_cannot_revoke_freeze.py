"""RE-040: cannot-revoke-token-freeze gate: exact pins, negatives, mutation/tamper."""
import hashlib
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research" / "work-items" / "RE-040-cannot-revoke-freeze-94"
sys.path.insert(0, str(ROOT / "tools"))
import cannot_revoke_freeze as tool  # noqa: E402

DATA = bytearray(tool.TARGET.read_bytes()) if tool.TARGET.exists() else None


def _mutate(va, offset, mask):
    segs = tool.segments(bytes(DATA))
    mutated = bytearray(DATA)
    for base, off, filesz in segs:
        if base <= va < base + filesz:
            mutated[off + (va - base) + offset] ^= mask
            return bytes(mutated)
    raise AssertionError("va not mapped: " + hex(va))


@unittest.skipIf(DATA is None, "node #94 binary not present")
class CannotRevokeFreezeStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.r = tool.analyse(bytes(DATA))

    def test_static_output_pin_and_expectations(self):
        r = self.r
        self.assertEqual(tool.expectation_errors(r), [])
        text = tool.render(r)
        pin = (PACKET / "cannot_revoke_freeze.json").read_text()
        self.assertEqual(text, pin)
        self.assertEqual(r["carve"]["len"], 270)
        self.assertEqual(r["carve"]["sha256"], tool.CARVED_SHA256)
        self.assertEqual(r["direct_calls"], 1)
        self.assertEqual(r["direct_call_sites"], ["0x23e804f"])
        self.assertEqual(r["direct_e9_calls"], 0)
        self.assertEqual(r["got_relative_to_entry"], [])
        self.assertEqual(r["abi"]["err_tag"], "0xdf")
        self.assertEqual(r["abi"]["err_tag_kind"], "movw_store")
        self.assertFalse(r["abi"]["ok_186_claimed"])
        self.assertEqual(r["extent"]["int3_pad_len"], 2)
        self.assertTrue(r["extent"]["next_fn_is_push_rbp"])
        self.assertEqual(r["extent"]["next_fn_va"], hex(tool.NEXT_FN))
        s = r["error_strings"][0]
        self.assertTrue(s["match"])
        self.assertEqual(s["occurrence_count"], 1)
        self.assertTrue(s["lea_in_carve"]["targets_string"])
        self.assertEqual(s["len"], 64)
        self.assertEqual(
            s["not_claimed_leas_same_string"], [hex(v) for v in tool.NOT_CLAIMED_LEAS]
        )

    def test_committed_json_pins(self):
        disk = json.loads((PACKET / "cannot_revoke_freeze.json").read_text())
        self.assertEqual(disk["component"], "RE-040")
        self.assertEqual(disk["claim"], "cannot_revoke_token_freeze_err_only")
        self.assertIsNone(disk["adjacent_prior_work"]["sibling"])
        self.assertEqual(disk["adjacent_prior_work"]["inventory_only"][0]["pr"], 650)
        claimed = {r["name"] for r in disk["rules"] if r["claimed"]}
        self.assertEqual(claimed, {"cannot_revoke_token_freeze_err"})
        for arm in disk["unclaimed_ok_tags"]:
            self.assertFalse(arm["claimed"])
            self.assertEqual(arm["kind"], "movw_store")

    def test_error_string_bytes_verbatim(self):
        segs = tool.segments(bytes(DATA))
        name, va, expected = tool.ERROR_STRING
        raw = tool.read_va(bytes(DATA), segs, va, len(expected))
        self.assertEqual(
            raw, b"cannot revoke token freeze privilege when there are frozen users"
        )
        self.assertEqual(len(raw), tool.STR_LEN_IMM)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), tool.STRING_SHA256)

    def test_negative_controls_per_rule(self):
        r = self.r
        for key, val in r["negatives"].items():
            self.assertTrue(val, key)
        rule = r["rules"][0]
        self.assertTrue(rule["match"])
        self.assertTrue(rule["fallthrough_to_err"])
        self.assertEqual(rule["cmp_priv_bytes"], "837c081001")
        self.assertEqual(rule["jne_priv_target"], "0x2750793")
        self.assertEqual(rule["cmp_frozen_bytes"], "49837c242800")
        self.assertEqual(rule["je_frozen_target"], "0x275071d")

    def _assert_fails(self, data, words):
        errs = tool.expectation_errors(tool.analyse(data, check_sha=False))
        self.assertTrue(any(any(w in e for w in words) for e in errs), errs)

    def test_mutation_tamper_jne_priv(self):
        # Flip the jne rel32 low byte: privilege guard must stop pinning.
        self._assert_fails(_mutate(tool.JNE_PRIV_VA, 2, 0x01), ("rule", "key", "negative"))

    def test_mutation_tamper_je_frozen(self):
        self._assert_fails(_mutate(tool.JE_FROZEN_VA, 1, 0x01), ("rule", "key", "negative"))

    def test_mutation_tamper_cmp_priv_imm(self):
        # cmp dword [..+0x10], 1 -> 0: privilege compare changes.
        self._assert_fails(_mutate(tool.CMP_PRIV_VA, 4, 0x01), ("rule", "key", "negative"))

    def test_mutation_tamper_err_tag(self):
        self._assert_fails(_mutate(tool.ERR_DF_VA, 3, 0x01), ("rule", "key", "negative"))

    def test_mutation_tamper_carve(self):
        self._assert_fails(_mutate(tool.FN, 0, 0x01), ("carve", "key"))


if __name__ == "__main__":
    unittest.main()
