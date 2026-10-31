"""Tests for tools/bridge_eth_event_wire.py: rule list against real bytes, and negative controls."""
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import bridge_eth_event_wire as tool  # noqa: E402


FOLDER = ROOT / "research" / "work-items" / "bridge-eth-event-wire-94"
HEXT = "a (both 0x-prefixed or not) hex string or byte array containing %d bytes"


def value(name, **items):
    return tool.changed(tool.GOOD_ID, **items) if name == "id" else tool.changed(tool.GOOD_ACT, **items)


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = tool.load_image()
        cls.harness = tool.Harness(cls.image)

    def decode(self, entry, item):
        return tool.run_case(self.harness, tool.De("t", entry, item))

    def encode(self, entry, action=None, named=1, capacity=0x1000):
        return bytes.fromhex(tool.run_case(self.harness, tool.Ser("t", entry, action or tool.Action(), named, capacity))[1])


class Rules(Base):
    def test_named_cases_match(self):
        self.assertGreater(len(tool.check_all(self.harness, tool.named_cases())), 2500)

    def test_generated_cases_match(self):
        self.assertEqual(len(tool.check_all(self.harness, tool.vector_cases(100))), 100)

    def test_event_id_fields_in_order(self):
        data = self.encode(tool.ID_MP_A)
        self.assertEqual(data[:3], b"\x85\xa1b")
        self.assertEqual([data.index(key) for key in (b"\xa1b", b"\xa1t", b"\xa1e", b"\xa1i", b"\xa1h")], sorted(data.index(key) for key in (b"\xa1b", b"\xa1t", b"\xa1e", b"\xa1i", b"\xa1h")))

    def test_compact_form_has_no_keys(self):
        data = self.encode(tool.ID_MP_A, named=0)
        self.assertEqual(data[0], 0x95)
        self.assertNotIn(b"\xa1b", data)

    def test_six_events_by_name(self):
        for index, name in enumerate(tool.EVENTS):
            self.assertEqual(self.encode(tool.EVENT_JSON, tool.Action(event=index)), ('"%s"' % name).encode())

    def test_flat_and_nested_tags(self):
        self.assertEqual(self.encode(tool.FLAT_MP_A)[:6], b"\x84\xa4type")
        self.assertIn(tool.FLAT_TAG.encode(), self.encode(tool.FLAT_MP_B))
        self.assertEqual(self.encode(tool.NEST_MP_A)[:6], b"\x82\xa4type")
        self.assertIn(b"\xa6action\x83", self.encode(tool.NEST_MP_B))

    def test_event_id_ignores_a_key_the_action_refuses(self):
        self.assertEqual(self.decode(tool.DE_ID_J, value("id", z=1))[0], "ok")
        self.assertEqual(self.decode(tool.DE_ACT_J, value("act", z=1)), ("error", "unknown field `z`, expected one of `user`, `usd`, `ethId`"))

    def test_hex_prefix_is_lower_case_only(self):
        self.assertEqual(self.decode(tool.DE_ID_J, value("id", h=tool.HASH))[0], "ok")
        self.assertEqual(self.decode(tool.DE_ID_J, value("id", h="0X" + tool.HASH)), ("error", "invalid length 66, expected " + HEXT % 32))

    def test_user_takes_a_newtype_and_hash_does_not(self):
        newtype = tool.Con(tool.NEWTYPE, tool.wrap("0x" + tool.USER))
        self.assertEqual(self.decode(tool.DE_ACT_R, value("act", user=newtype))[0], "ok")
        self.assertEqual(self.decode(tool.DE_ID_J, value("id", h=tool.Con(tool.NEWTYPE, tool.wrap(tool.HASH)))), ("error", "invalid type: newtype struct, expected " + HEXT % 32))

    def test_unit_text_splits_the_two_error_types(self):
        unit = tool.Con(tool.UNIT)
        self.assertEqual(self.decode(tool.DE_ACT_J, unit), ("error", "invalid type: null, expected struct VoteEthDepositAction"))
        self.assertEqual(self.decode(tool.DE_ACT_R, unit), ("error", "invalid type: unit value, expected struct VoteEthDepositAction"))

    def test_nested_seq_of_one(self):
        self.assertEqual(self.decode(tool.DE_NEST_J, [tool.GOOD_ACT])[0], "ok")
        self.assertEqual(self.decode(tool.DE_NEST_R, []), ("error", "invalid length 0, expected struct L1ValidatorVoteBridgeDepositAction with 1 element"))

    def test_non_ascii_hex_byte_is_named_as_a_latin_character(self):
        self.assertEqual(self.decode(tool.DE_ID_J, value("id", h="0xé" + tool.HASH[2:])), ("error", "invalid hex character: Ã, at 2"))


class Negative(Base):
    def test_wrong_hash_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(expected="0" * 64)

    def test_address_outside_every_function_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            self.image.exact_fde(tool.ID_MP_A + 1)

    def patched(self, va, flip, case):
        offset = self.image.offset(va)
        harness = tool.Harness(self.image, {va: self.image.blob[offset] ^ flip})
        try:
            return tool.run_case(harness, case) != tool.spec_run(case)
        except (tool.Halt, tool.EvidenceError, tool.Panicked):
            return True

    def test_changed_head_is_caught(self):
        self.assertTrue(self.patched(0x374C22A, 1, tool.Ser("t", tool.ID_MP_A, tool.Action())))

    def test_changed_nested_head_is_caught(self):
        self.assertTrue(self.patched(0x3282D7C, 1, tool.Ser("t", tool.NEST_MP_A, tool.Action())))

    def test_changed_event_offset_is_caught(self):
        self.assertTrue(self.patched(0x374C2EC, 8, tool.Ser("t", tool.ID_MP_A, tool.Action(event=1))))

    def test_changed_map_tag_is_caught(self):
        self.assertTrue(self.patched(0x3A77C7C, 1, tool.De("t", tool.DE_ID_J, tool.GOOD_ID)))

    def test_changed_sequence_tag_is_caught(self):
        self.assertTrue(self.patched(0x3B67AEC, 1, tool.De("t", tool.DE_ACT_J, ["0x" + tool.USER, 5, tool.GOOD_ID])))

    def test_a_call_outside_the_real_set_stops_the_run(self):
        harness = tool.Harness(self.image)
        harness.machine.real = harness.machine.real - {tool.DE_ID_J}
        with self.assertRaises(tool.Halt):
            tool.run_case(harness, tool.De("t", tool.DE_ACT_J, tool.GOOD_ACT))

    def test_rule_list_rejects_a_wrong_rule(self):
        case = tool.De("t", tool.DE_ID_J, tool.changed(tool.GOOD_ID, z=1))
        names = tool.field_index

        def strict(key, listed, deny, flavor):
            return names(key, listed, True, flavor)

        tool.field_index = strict
        try:
            self.assertNotEqual(tool.run_case(self.harness, case), tool.spec_run(case))
        finally:
            tool.field_index = names

    def test_rule_list_rejects_a_wrong_field_order(self):
        case = tool.Ser("t", tool.ID_MP_B, tool.Action())
        shape = tool.id_shape
        tool.id_shape = lambda action: list(reversed(shape(action)))
        try:
            self.assertNotEqual(tool.run_case(self.harness, case), tool.spec_run(case))
        finally:
            tool.id_shape = shape

    def test_moved_key_row_fails(self):
        rows = tool.KEY_ROWS
        tool.KEY_ROWS = ((0x374C227, "wrong operation", "mov"),)
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.key_rows(self.image)
        finally:
            tool.KEY_ROWS = rows

    def test_moved_event_text_fails(self):
        rows = tool.EVENT_TEXT
        tool.EVENT_TEXT = ((0x597EC1, 7),) + rows[1:]
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.event_rows(self.image)
        finally:
            tool.EVENT_TEXT = rows

    def test_moved_event_arm_fails(self):
        rows = tool.EVENT_ARMS
        tool.EVENT_ARMS = (rows[1],) + rows[1:]
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.event_rows(self.image)
        finally:
            tool.EVENT_ARMS = rows

    def test_moved_field_text_fails(self):
        rows = tool.FIELD_TEXT
        tool.FIELD_TEXT = ((0x597FC8, "t"),)
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.text_rows(self.image)
        finally:
            tool.FIELD_TEXT = rows

    def test_a_copy_with_the_wrong_primary_fails(self):
        rows = tool.SERIALIZER_COPIES
        tool.SERIALIZER_COPIES = ((0x1E940F0, tool.NEST_MP_B),)
        decoders = tool.DECODER_COPIES
        tool.DECODER_COPIES = ()
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.copy_rows(self.image, self.harness, [])
        finally:
            tool.SERIALIZER_COPIES = rows
            tool.DECODER_COPIES = decoders
            tool.FORMS.pop(0x1E940F0, None)


class Output(Base):
    def test_files_match_the_tool_without_mutation_rows(self):
        files = tool.render(tool.analyse(self.image, mutate=False, vectors=200))
        for name, text in files.items():
            if name == "evidence.json":
                continue
            self.assertEqual((FOLDER / name).read_text(encoding="ascii"), text, name)

    def test_manifest_lists_every_file(self):
        listed = {line.split("  ", 1)[1] for line in (FOLDER / "MANIFEST.sha256").read_text(encoding="ascii").splitlines()}
        present = {path.name for path in FOLDER.iterdir() if path.name != "MANIFEST.sha256"}
        self.assertEqual(listed, present)


if __name__ == "__main__":
    unittest.main()
