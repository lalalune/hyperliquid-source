"""Controls for tools/wire_asset_codec.py (RE-004, node #94)."""

import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools" / "wire_asset_codec.py"
PACKET = ROOT / "research" / "work-items" / "RE-004-wire-asset-codec-94"

spec = importlib.util.spec_from_file_location("wire_asset_codec", TOOL)
wac = importlib.util.module_from_spec(spec)
sys.modules["wire_asset_codec"] = wac
spec.loader.exec_module(wac)

DATA = {}


def target():
    if not DATA:
        DATA["bytes"] = wac.TARGET.read_bytes()
        DATA["image"] = wac.Image(DATA["bytes"])
    return DATA["bytes"], DATA["image"]


def patched(va, old, new):
    """Copy of the target with the bytes at text address va replaced."""
    data, image = target()
    off = va - image.text_va + image.text_off
    copy = bytearray(data)
    if bytes(copy[off:off + len(old)]) != old:
        raise AssertionError(f"control does not start from the expected bytes at {va:#x}")
    copy[off:off + len(new)] = new
    return copy


def imm(value):
    return value.to_bytes(4, "little", signed=value < 0)


class Target(unittest.TestCase):
    def test_hash_check_rejects_a_changed_target(self):
        data, _ = target()
        wac.check_target(data)
        with self.assertRaises(wac.ToolError):
            wac.check_target(bytes(data[:-1]) + bytes([data[-1] ^ 1]))

    def test_addresses_outside_the_image_are_refused(self):
        _, image = target()
        with self.assertRaises(wac.ToolError):
            image.fde_of(0x10)
        with self.assertRaises(wac.ToolError):
            image.file_offset(0xffff_0000_0000)
        with self.assertRaises(wac.ToolError):
            image.fetch(0x10)

    def test_the_tool_calls_no_external_program(self):
        source = TOOL.read_text()
        for word in ("subprocess", "os.system", "popen"):
            self.assertNotIn(word, source)


class Refinement(unittest.TestCase):
    def test_an_equality_compare_isolates_one_id(self):
        _, image = target()
        world = wac.World(wac.PARTIAL_LENS, 100000, table_id=5, side=1, q=12)
        rows = wac.merge(wac.refine(lambda lo, hi: wac.decode_id(image, world, lo, hi), 0, wac.U32))
        hits = [row for row in rows if row[2][0] == "ok" and row[2][1] == 1]
        self.assertEqual([(row[0], row[1]) for row in hits], [(100000121, 100000121)])

    def test_rows_cover_the_domain_with_no_gap(self):
        _, image = target()
        tables = wac.encoder_tables(image)
        for rows in tables.values():
            self.assertEqual(rows[0][0], 0)
            self.assertEqual(rows[-1][1], wac.U64)
            for left, right in zip(rows, rows[1:]):
                self.assertEqual(left[1] + 1, right[0])

    def test_a_split_outside_the_interval_is_refused(self):
        def bad(lo, hi):
            raise wac.Split(hi + 1)
        with self.assertRaises(wac.ToolError):
            wac.refine(bad, 0, 10)

    def test_a_wrong_rule_is_refused(self):
        with self.assertRaises(wac.ToolError):
            wac.check_rows("control", [[0, 9, ("value", (1, 0)), 1]], lambda x: ("value", (1, 1)))
        with self.assertRaises(wac.ToolError):
            wac.check_rows("control", [[0, 9, ("value", (1, 0)), 1]],
                           lambda x: ("value", (1, 0 if x == 0 else 1)))


class Mutations(unittest.TestCase):
    def refused(self, va, old, new, parts):
        with self.assertRaises(wac.ToolError):
            wac.analyse(patched(va, old, new), parts)

    def test_unchanged_target_passes_the_same_parts(self):
        data, _ = target()
        result = wac.analyse(data, ("decoder-small", "encoder", "inline", "helper", "tail"))
        self.assertIn("encoder perp", result["tables"])

    def test_decoder_spot_limit(self):
        self.refused(0x3c0cd5a, imm(110000), imm(110001), ("decoder-small", ))

    def test_decoder_perp_offset(self):
        self.refused(0x3c0cd6f, imm(-100000), imm(-99999), ("decoder-small", ))

    def test_decoder_spot_base(self):
        self.refused(0x3c0cd63, imm(-10000), imm(-10001), ("decoder-small", ))

    def test_decoder_returning_the_temporary_tag(self):
        self.refused(0x3c0ce4f, bytes.fromhex("66c7036000"), bytes.fromhex("66c7034101"), ("decoder-small", ))

    def test_decoder_round_trip_branch(self):
        self.refused(0x3c0cd34, bytes.fromhex("0f85"), bytes.fromhex("0f84"), ("decoder-small", ))

    def test_decoder_outcome_scale(self):
        self.refused(0x3c0ccf5, bytes.fromhex("b80a000000"), bytes.fromhex("b80b000000"), ("decoder-small", ))

    def test_encoder_cap(self):
        self.refused(0x3c0cfb8, imm(99999999), imm(100000000), ("encoder", ))

    def test_encoder_spot_base(self):
        self.refused(0x3c0cf8f, imm(10000), imm(10001), ("encoder", ))

    def test_encoder_outcome_base(self):
        self.refused(0x3c0cf88, imm(100000000), imm(100000001), ("encoder", ))

    def test_encoder_spot_limit(self):
        self.refused(0x3c0d009, imm(110000), imm(109999), ("encoder", ))

    def test_inline_loop_cap(self):
        self.refused(0x3bfd2a3, imm(99999999), imm(100000000), ("inline", ))

    def test_inline_array_cap(self):
        self.refused(0x3bfda6b, imm(100000000), imm(99999999), ("inline", ))

    def test_inline_array_low_edge(self):
        self.refused(0x3bfda1d, imm(10000), imm(10001), ("inline", ))

    def test_helper_side_check(self):
        self.refused(0x3c0ca0e, b"\x01", b"\x02", ("helper", ))

    def test_helper_side_offset(self):
        self.refused(0x3c0ca16, imm(0x28), imm(0x30), ("helper", ))

    def test_helper_reciprocal(self):
        self.refused(0x3c0c9e9, bytes.fromhex("cd"), bytes.fromhex("cb"), ("helper", ))

    def test_helper_base(self):
        self.refused(0x3c0c9a4, imm(100000000), imm(100000001), ("helper", ))

    def test_tail_list_length(self):
        self.refused(0x3c0cbae, b"\x01", b"\x02", ("tail", ))

    def test_shadowed_guards_are_not_observable(self):
        """Limit: both >>5 guards are shadowed by later compares, so a one-step change survives."""
        for va, old, new in ((0x3bfd28e, 0x7fff3ca, 0x7fff3c9), (0x3bfda75, 0x7fff3cb, 0x7fff3cc)):
            wac.analyse(patched(va, imm(old), imm(new)), ("inline", ))

    def test_literal_outside_the_family_is_refused(self):
        self.refused(0x26df356, imm(0x2b), imm(110000), ("census", ))


class Facts(unittest.TestCase):
    def test_sentinel_never_decodes_through_the_helper(self):
        _, image = target()
        self.assertEqual(wac.run_helper(image, wac.SENTINEL, 7, 0, 1), ("none", ))
        self.assertEqual((wac.SENTINEL - wac.OUTCOME_BASE) % 10, 5)

    def test_helper_splits_an_outcome_id(self):
        _, image = target()
        self.assertEqual(wac.run_helper(image, 100000121, 7, 0, 1), ("probe", 12, 0x28))
        self.assertEqual(wac.run_helper(image, 100000120, 7, 0, 1), ("probe", 12, 0))
        self.assertEqual(wac.run_helper(image, 100000122, 7, 0, 1), ("none", ))

    def test_token_index_past_the_spot_window_has_no_id(self):
        _, image = target()
        rows = wac.encoder_tables(image)["encoder token side=2"]
        self.assertEqual(wac.find_row(rows, 200000)[2], ("value", (0, wac.SENTINEL)))

    def test_last_outcome_id_fits_below_the_sentinel(self):
        self.assertEqual(wac.OUTCOME_BASE + 10 * wac.MAX_Q + 1, 4294967291)
        self.assertLess(wac.OUTCOME_BASE + 10 * (wac.MAX_Q + 1) - wac.U32, 10)


class Packet(unittest.TestCase):
    def test_generated_files_match_the_packet_and_manifest(self):
        data, _ = target()
        files = wac.generate(data)
        with tempfile.TemporaryDirectory() as folder:
            for name, text in files.items():
                (Path(folder) / name).write_text(text)
                self.assertEqual((PACKET / name).read_bytes(), (Path(folder) / name).read_bytes(), name)
        listed = {}
        for line in (PACKET / "MANIFEST.sha256").read_text().splitlines():
            digest, name = line.split("  ", 1)
            listed[name] = digest
        self.assertEqual(set(listed), {path.name for path in PACKET.iterdir()} - {"MANIFEST.sha256"})
        for name, digest in listed.items():
            self.assertEqual(hashlib.sha256((PACKET / name).read_bytes()).hexdigest(), digest, name)
        evidence = json.loads(files["evidence.json"])
        self.assertEqual(evidence["callers"], {"direct encoder": 31, "slot decoder": 64})
        self.assertEqual(evidence["sentinel_remainder_mod_10"], 5)
        self.assertEqual(evidence["round_trip"]["ids_proved_ok_and_returning"], 99999999 + 1)
        self.assertEqual(evidence["reciprocal"]["excess"], 2)


if __name__ == "__main__":
    unittest.main()
