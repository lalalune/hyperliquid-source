"""RE-039: genesis-already-happened host gate: exact pins, negatives, mutation/tamper."""
import hashlib
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research" / "work-items" / "RE-039-genesis-already-happened-94"
sys.path.insert(0, str(ROOT / "tools"))
import genesis_already_happened as tool  # noqa: E402

DATA = bytearray(tool.TARGET.read_bytes()) if tool.TARGET.exists() else None


@unittest.skipIf(DATA is None, "node #94 binary not present")
class GenesisAlreadyHappenedStaticTests(unittest.TestCase):
    def test_static_output_pin_and_expectations(self):
        r = tool.analyse(bytes(DATA))
        self.assertEqual(tool.expectation_errors(r), [])
        text = tool.render(r)
        digest = hashlib.sha256(text.encode()).hexdigest()
        pin = (PACKET / "genesis_already_happened.json").read_text()
        self.assertEqual(text, pin)
        self.assertEqual(digest, hashlib.sha256(pin.encode()).hexdigest())
        self.assertEqual(r["carve"]["len"], 166)
        self.assertEqual(r["carve"]["sha256"], tool.CARVED_SHA256)
        self.assertEqual(r["direct_calls"], 0)
        self.assertEqual(r["direct_call_sites"], [])
        self.assertEqual(r["got_slot"], hex(tool.GOT_SLOT))
        self.assertTrue(r["got_addend_match"])
        self.assertEqual(r["ff15_inbound_via_got"], 6)
        self.assertEqual(r["ff15_sites"], [hex(v) for v in tool.FF15_SITES])
        self.assertEqual(r["abi"]["err_tag"], hex(tool.ERR_TAG))
        self.assertEqual(r["abi"]["err_tag_kind"], "movw_store")
        self.assertIn("movw STORE", r["abi"]["err_note"])
        self.assertFalse(r["abi"]["ok_ea_claimed"])
        self.assertFalse(r["abi"]["ok_186_claimed"])
        self.assertTrue(r["extent"]["int3_padding_at_fde_end"])
        self.assertEqual(r["extent"]["int3_pad_len"], 10)
        self.assertTrue(r["extent"]["next_fn_is_push_rbp"])
        for s in r["error_strings"]:
            self.assertTrue(s["match"], s["name"])
            self.assertEqual(s["occurrence_count"], 1)
            self.assertTrue(s["lea_in_carve"]["targets_string"], s["name"])
            self.assertEqual(s["len"], 24)
            self.assertEqual(
                s["not_claimed_leas_same_string"],
                [hex(v) for v in tool.NOT_CLAIMED_LEAS],
            )

    def test_committed_json_pins(self):
        disk = json.loads((PACKET / "genesis_already_happened.json").read_text())
        self.assertEqual(disk["carve"]["sha256"], tool.CARVED_SHA256)
        self.assertEqual(disk["got_slot"], hex(tool.GOT_SLOT))
        self.assertEqual(disk["claim"], "genesis_already_happened_membership_err_only")
        self.assertEqual(disk["component"], "RE-039")
        self.assertEqual(disk["adjacent_prior_work"]["sibling"]["pr"], 449)
        self.assertEqual(disk["adjacent_prior_work"]["inventory_only"], [])
        texts = {s["name"]: s["text"] for s in disk["error_strings"]}
        self.assertEqual(texts["genesis_already_happened"], "genesis already happened")
        claimed = {r["name"] for r in disk["rules"] if r["claimed"]}
        self.assertEqual(claimed, {"genesis_already_happened_membership_err"})
        self.assertEqual(len(disk["unclaimed_ok_tags"]), 2)
        for arm in disk["unclaimed_ok_tags"]:
            self.assertFalse(arm["claimed"])
            self.assertEqual(arm["kind"], "movw_store")

    def test_error_string_bytes_verbatim(self):
        segs = tool.segments(bytes(DATA))
        name, va, expected = tool.ERROR_STRING
        raw = tool.read_va(bytes(DATA), segs, va, len(expected))
        self.assertEqual(raw, expected, name)
        self.assertEqual(len(raw), len(expected), name)
        self.assertEqual(len(expected), tool.STR_LEN_IMM, name)
        self.assertEqual(raw, b"genesis already happened")
        self.assertEqual(
            hashlib.sha256(raw).hexdigest(),
            "a4ee7b2f1581b7d1ac103e234b5275fdf9be1ef251c53d8bfaf7bf0b95e71036",
        )

    def test_negative_controls_per_rule(self):
        r = tool.analyse(bytes(DATA))
        self.assertTrue(r["negatives"]["cmp_key_bytes_match"])
        self.assertTrue(r["negatives"]["je_found_bytes_match"])
        self.assertTrue(r["negatives"]["je_found_targets_err"])
        self.assertTrue(r["negatives"]["test_rdx_bytes_match"])
        self.assertTrue(r["negatives"]["je_rdx0_bytes_match"])
        self.assertTrue(r["negatives"]["je_rdx0_targets_err"])
        self.assertTrue(r["negatives"]["err_e9_movw_store"])
        self.assertTrue(r["negatives"]["string_exact"])
        self.assertTrue(r["negatives"]["string_len_imm_0x18"])
        self.assertTrue(r["negatives"]["lea_targets_string"])
        self.assertTrue(r["negatives"]["occurrence_count_is_1"])
        self.assertTrue(r["negatives"]["ff15_inbound_is_6"])
        self.assertTrue(r["negatives"]["got_rela_present"])
        self.assertTrue(r["negatives"]["no_direct_e8_e9"])
        self.assertTrue(r["negatives"]["ok_ea_store_observed"])
        self.assertTrue(r["negatives"]["ok_186_store_observed"])
        self.assertTrue(r["negatives"]["not_claimed_lea_list_matches"])
        self.assertTrue(r["rules"][0]["match"])
        self.assertEqual(r["rules"][0]["cmp_key_bytes"], "483b54f910")
        self.assertEqual(r["rules"][0]["je_found_bytes"], "741b")
        self.assertEqual(r["rules"][0]["je_found_target"], hex(tool.JE_FOUND_TARGET))
        self.assertIn("membership", r["rules"][0]["description"])
        self.assertIn("found-equal", r["rules"][0]["proof"]["found_equal_takes_err"])

    def test_mutation_tamper_je_found_gate(self):
        # One tamper negative on the claimed membership->Err gate.
        segs = tool.segments(bytes(DATA))
        mutated = bytearray(DATA)
        for base, off, filesz in segs:
            if base <= tool.JE_FOUND_VA < base + filesz:
                file_off = off + (tool.JE_FOUND_VA - base)
                # Flip the relative displacement of je.
                mutated[file_off + 1] ^= 0x01
                break
        else:
            self.fail("je_found not mapped")
        r = tool.analyse(bytes(mutated), check_sha=False)
        errs = tool.expectation_errors(r)
        self.assertTrue(
            any(
                "rule" in e or "key" in e or "negative" in e or "je" in e
                for e in errs
            ),
            errs,
        )

    def test_mutation_tamper_cmp_key(self):
        segs = tool.segments(bytes(DATA))
        mutated = bytearray(DATA)
        for base, off, filesz in segs:
            if base <= tool.CMP_KEY_VA < base + filesz:
                file_off = off + (tool.CMP_KEY_VA - base)
                mutated[file_off] ^= 0x01
                break
        else:
            self.fail("cmp_key not mapped")
        r = tool.analyse(bytes(mutated), check_sha=False)
        errs = tool.expectation_errors(r)
        self.assertTrue(
            any(
                "rule" in e or "key" in e or "negative" in e or "cmp" in e
                for e in errs
            ),
            errs,
        )

    def test_mutation_tamper_carve(self):
        segs = tool.segments(bytes(DATA))
        mutated = bytearray(DATA)
        for base, off, filesz in segs:
            if base <= tool.FN < base + filesz:
                file_off = off + (tool.FN - base)
                mutated[file_off] ^= 0x01
                break
        else:
            self.fail("fn not mapped")
        r = tool.analyse(bytes(mutated), check_sha=False)
        errs = tool.expectation_errors(r)
        self.assertTrue(
            any("carve" in e or "key" in e for e in errs),
            errs,
        )


if __name__ == "__main__":
    unittest.main()
