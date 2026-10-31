import hashlib
import json
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import bridge_state_json as tool  # noqa: E402

FOLDER = ROOT / "research" / "work-items" / "bridge-state-json-94"


def one(harness, state, **keys):
    return harness.serialize(tool.Case("x", state, **keys))


class Image(unittest.TestCase):
    def test_wrong_digest_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(expected="0" * 64)

    def test_digest_is_the_target(self):
        self.assertEqual(hashlib.sha256(tool.BINARY.read_bytes()).hexdigest(), tool.SHA256)
        self.assertEqual(tool.SHA256, "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f")

    def test_function_outside_any_body_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.load_image().exact_fde(tool.ROOT_JSON + 1)


class Json(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = tool.load_image()
        cls.harness = tool.Harness(cls.image)

    def test_full_output_parses_and_keeps_field_order(self):
        data = json.loads(one(self.harness, tool.full_state())[1])
        self.assertEqual(list(data), [row[0] for row in tool.FIELDS])

    def test_full_state_matches_the_rule_list(self):
        for level in (0, 2):
            case = tool.Case("full", tool.full_state(), level=level)
            self.assertEqual(self.harness.serialize(case), tool.spec_run(case))

    def test_field_wrapper_writes_the_key(self):
        text = one(self.harness, tool.State(), field=1, level=1)[1]
        self.assertTrue(text.startswith('\n  "bridge2": {\n'))
        self.assertTrue(one(self.harness, tool.State(), field=2, level=1)[1].startswith(',\n  "bridge2": {'))

    def test_noop_policy_is_null_but_deposit_policy_is_an_object(self):
        data = json.loads(one(self.harness, tool.State())[1])
        self.assertIsNone(data["withdrawal_signatures"]["hsc"])
        self.assertEqual(data["eth_id_to_deposit_votes"]["hsc"], {"q": 0.5, "i": 0.25})

    def test_nan_and_infinity_become_null(self):
        for word in (0x7FF8000000000000, 0x7FF0000000000000, 0xFFF0000000000000):
            data = json.loads(one(self.harness, tool.State(q=word))[1])
            self.assertIsNone(data["eth_id_to_deposit_votes"]["hsc"]["q"])

    def test_float_text_uses_no_plus_sign(self):
        self.assertEqual(tool.float_text(0x4341C37937E08000), "1e16")
        self.assertEqual(tool.float_text(0x3EE4F8B588E368F1), "0.00001")
        self.assertEqual(tool.float_text(0x3EB0C6F7A0B5ED8D), "1e-6")

    def test_name_escapes(self):
        state = tool.State(names=('a"b', "c\\d", "e\x01f", "g\x7fh", "i☃j"))
        self.assertEqual(json.loads(one(self.harness, state)[1])["validator_set_finalized_votes"]["name"], "i☃j")
        self.assertIn('"name": "e\\u0001f"', one(self.harness, state)[1])

    def test_no_voter_row_panics_with_the_type_name(self):
        state = tool.State(sig=[tool.sign_row(inner=[((1, tool.USER), [], "novoter")])])
        self.assertEqual(one(self.harness, state), ("panic", tool.NO_VOTER_TEXT))

    def test_edited_key_writer_is_seen(self):
        at = 0x29741FC
        row = tool.row_at(self.image, at)
        data = bytes(self.image.blob[self.image.offset(at):self.image.offset(at) + row.size])
        harness = tool.Harness(self.image, {at + row.imm_at: data[row.imm_at] ^ 1})
        case = tool.Case("x", tool.State())
        self.assertNotEqual(harness.serialize(case), tool.spec_run(case))

    def test_wrong_rule_is_caught(self):
        case = tool.Case("x", tool.State())
        good = tool.spec_run
        tool.spec_run = lambda item: ("text", "other")
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.check_all(self.harness, [case])
        finally:
            tool.spec_run = good
        self.assertTrue(tool.check_all(self.harness, [case]))


class FileRoute(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = tool.load_image()
        cls.harness = tool.Harness(cls.image)

    def run_path(self, path, **keys):
        return self.harness.run_file(tool.FileCase("x", path, **keys))

    def test_extension_picks_msgpack_in_any_case(self):
        for path in ("x.rmp", "x.RMP", "x.rMp", "a/b.c.rmp"):
            self.assertIn("msgpack options 0004000100", self.run_path(path)[1], path)

    def test_other_paths_take_pretty_json(self):
        for path in ("x.json", "x", ".rmp", "x.rmpp", "x.rm", "a.rmp/b", "a.rmp/.."):
            self.assertIn("json indent 2020 level 0", self.run_path(path)[1], path)

    def test_exact_null_path_skips_everything(self):
        self.assertEqual(self.run_path("/dev/null"), ("file", "", 0))
        self.assertIn("json", self.run_path("/dev/nulL")[1])

    def test_failed_parent_step_skips_the_write(self):
        got = self.run_path("x.rmp", parent=0xE3)
        self.assertNotIn("write", got[1])
        self.assertEqual(got[2], 0xE3)

    def test_both_routes_match_every_rule(self):
        for case in tool.file_cases():
            self.assertEqual(self.harness.run_file(case), tool.spec_file(case), case.name)

    def test_negative_control_flipped_extension_test(self):
        at = 0x28EB237
        row = tool.row_at(self.image, at)
        data = bytes(self.image.blob[self.image.offset(at):self.image.offset(at) + row.size])
        index = row.size - 5 if row.size >= 6 else 0
        harness = tool.Harness(self.image, {at + index: data[index] ^ 1})
        case = tool.FileCase("x", "x.rmp")
        self.assertNotEqual(harness.run_file(case), tool.spec_file(case))

    def test_chain_refuses_a_wrong_target(self):
        good = tool.CHAIN
        tool.CHAIN = ((0x28EB278, 0x2206FF0, "wrong"),)
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.chain_rows(self.image)
        finally:
            tool.CHAIN = good
        self.assertEqual(len(tool.chain_rows(self.image)), len(good))


class Stored(unittest.TestCase):
    def test_manifest_matches_files(self):
        for line in (FOLDER / "MANIFEST.sha256").read_text().splitlines():
            digest, name = line.split("  ")
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest, name)

    def test_regenerated_light_files_match(self):
        image = tool.load_image()
        for name, rows in (("fields.tsv", tool.field_table(image)), ("texts.tsv", tool.text_rows(image)), ("key-rows.tsv", tool.key_rows(image)), ("call-chain.tsv", tool.chain_rows(image))):
            stored = (FOLDER / name).read_text().splitlines()[1:]
            self.assertEqual(stored, ["\t".join(str(cell) for cell in row) for row in rows], name)

    def test_sample_is_the_real_output(self):
        harness = tool.Harness(tool.load_image())
        self.assertEqual((FOLDER / "sample-full.json").read_text(), harness.serialize(tool.Case("sample", tool.full_state()))[1] + "\n")


if __name__ == "__main__":
    unittest.main()
