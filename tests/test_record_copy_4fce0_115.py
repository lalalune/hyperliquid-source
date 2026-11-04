"""Tests for the node #115 record copy model (0x5d4fce0, RE-001)."""
import unittest

from tools.record_copy_4fce0_115 import (
    NullRecordError, clone_string, copy_record)


def new_tracker():
    return {"strings": {}, "freed": set()}


def alloc(tracker, text):
    alloc_id = f"alloc{len(tracker['strings'])}"
    tracker["strings"][alloc_id] = text
    return alloc_id


class RecordCopyTest(unittest.TestCase):
    def test_fresh_dest_full_copy(self):
        tracker = new_tracker()
        src_id = alloc(tracker, "hello")
        src = {"field32": 0xDEADBEEF, "field16": 0x1234,
               "pad": "AB", "text": src_id}
        dest = {"field32": 0, "field16": 0, "pad": "ZZ", "text": None}
        out = copy_record(dest, src, tracker)
        self.assertEqual(dest["field32"], 0xDEADBEEF)
        self.assertEqual(dest["field16"], 0x1234)
        self.assertEqual(dest["pad"], "ZZ")  # +0x06..+0x07 untouched
        self.assertIsNotNone(dest["text"])
        self.assertNotEqual(dest["text"], src_id)  # fresh clone
        self.assertEqual(tracker["strings"][dest["text"]], "hello")
        self.assertEqual(out, {"dropped_old": None, "freed": []})

    def test_null_source_string(self):
        tracker = new_tracker()
        src = {"field32": 7, "field16": 3, "pad": "Q", "text": None}
        dest = {"field32": 0, "field16": 0, "pad": "Q", "text": None}
        out = copy_record(dest, src, tracker)
        self.assertEqual(dest["text"], None)
        self.assertEqual(tracker["strings"], {})
        self.assertEqual(out["freed"], [])

    def test_empty_string_clones(self):
        tracker = new_tracker()
        src_id = alloc(tracker, "")
        src = {"field32": 1, "field16": 2, "pad": "P", "text": src_id}
        dest = {"field32": 0, "field16": 0, "pad": "P", "text": None}
        copy_record(dest, src, tracker)
        self.assertEqual(tracker["strings"][dest["text"]], "")

    def test_prefilled_dest_old_string_dropped_not_freed(self):
        # The observed leak: the old destination string is dropped
        # by the prologue zero with no delete, and the post-clone
        # delete check is dead, so it stays allocated.
        tracker = new_tracker()
        old_id = alloc(tracker, "old")
        src_id = alloc(tracker, "new")
        src = {"field32": 9, "field16": 9, "pad": "P", "text": src_id}
        dest = {"field32": 0, "field16": 0, "pad": "P", "text": old_id}
        out = copy_record(dest, src, tracker)
        self.assertEqual(out["dropped_old"], old_id)
        self.assertEqual(out["freed"], [])
        self.assertNotIn(old_id, tracker["freed"])
        self.assertIn(old_id, tracker["strings"])
        self.assertEqual(tracker["strings"][dest["text"]], "new")

    def test_prefilled_dest_null_source_drops_old(self):
        tracker = new_tracker()
        old_id = alloc(tracker, "old")
        src = {"field32": 0, "field16": 0, "pad": "P", "text": None}
        dest = {"field32": 0, "field16": 0, "pad": "P", "text": old_id}
        out = copy_record(dest, src, tracker)
        self.assertEqual(dest["text"], None)
        self.assertEqual(out["dropped_old"], old_id)
        self.assertEqual(out["freed"], [])

    def test_clone_helper_direct(self):
        tracker = new_tracker()
        new_id = clone_string("abc", tracker)
        self.assertEqual(tracker["strings"][new_id], "abc")

    def test_null_guards(self):
        tracker = new_tracker()
        src = {"field32": 0, "field16": 0, "pad": "P", "text": None}
        with self.assertRaises(NullRecordError):
            copy_record(None, src, tracker)
        with self.assertRaises(NullRecordError):
            copy_record(src, None, tracker)


if __name__ == "__main__":
    unittest.main()
