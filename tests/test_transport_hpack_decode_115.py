import json
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import transport_hpack_decode_115 as tool  # noqa: E402

WORK = ROOT / "research" / "work-items" / "transport-hpack-decode-115"


class HpackDecodeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = tool.load_image(tool.BINARY, tool.SHA256)
        cls.table = tool.read_table(cls.image)
        cls.rig = tool.HdrRig(cls.image)

    def test_digest_guard_rejects_other_binary(self):
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(tool.BINARY, "0" * 64)

    def test_integer_examples_from_the_hpack_spec(self):
        self.assertEqual(tool.model_int(bytes([0x0A]), 0, 5), ("ok", 10, 1))
        self.assertEqual(tool.model_int(bytes([0x1F, 0x9A, 0x0A]), 0, 5), ("ok", 1337, 3))
        self.assertEqual(tool.model_int(bytes([0x2A]), 0, 8), ("ok", 42, 1))
        for data, pos, prefix in ((bytes([0x0A]), 0, 5), (bytes([0x1F, 0x9A, 0x0A]), 0, 5), (bytes([0x2A]), 0, 8)):
            self.assertEqual(self.rig.run_int(data, pos, prefix), tool.model_int(data, pos, prefix))

    def test_integer_failure_boundaries_match_code(self):
        cases = (
            (b"", 0, 7, ("err", 1, 0)),
            (bytes([0x7F]), 0, 7, ("err", 1, 1)),
            (bytes([0x7F, 0x80, 0x80, 0x80]), 0, 7, ("err", 1, 4)),
            (bytes([0x7F, 0x80, 0x80, 0x80, 0x80]), 0, 7, ("err", 0xB, 5)),
            (bytes([0x7F, 0x80, 0x80, 0x80, 0x01]), 0, 7, ("ok", 127 + (1 << 21), 5)),
            (bytes([0xFF, 0x01]), 0, 8, ("ok", 0, 2)),
        )
        for data, pos, prefix, expected in cases:
            self.assertEqual(tool.model_int(data, pos, prefix), expected)
            self.assertEqual(self.rig.run_int(data, pos, prefix), expected)

    def test_huffman_spec_vectors_and_dirty_buffer(self):
        for hexed, plain in tool.RFC_VECTORS:
            self.assertEqual(self.rig.run_huffman(bytes.fromhex(hexed)), ("ok", plain, 0))
            self.assertEqual(tool.model_huffman(self.table, bytes.fromhex(hexed)), ("ok", plain, 0))
        self.assertEqual(self.rig.run_huffman(bytes.fromhex("a8eb10649cbf"), b"XY"), ("ok", b"XYno-cache", 0))
        self.assertEqual(self.rig.run_huffman(b""), ("ok", b"", 0))

    def test_huffman_error_keeps_partial_output(self):
        bad = bytes.fromhex("a8ebffffffff")
        got = self.rig.run_huffman(bad)
        self.assertEqual(got, tool.model_huffman(self.table, bad))
        self.assertEqual(got[0], "err")
        self.assertEqual(got[1], tool.ERR_HUFFMAN)
        self.assertGreater(got[2], 0)
        # bad padding on the last byte: the text is complete but the string is still rejected
        self.assertEqual(self.rig.run_huffman(bytes([0x1F])), ("ok", b"a", 0))
        self.assertEqual(self.rig.run_huffman(bytes([0x18])), ("err", tool.ERR_HUFFMAN, 1))

    def test_string_forms(self):
        plain = bytes([0x0A]) + b"custom-key"
        self.assertEqual(self.rig.run_string(plain, 0), ("ok", "plain", b"", 1, 10, 11, 0))
        huff = bytes([0x86]) + bytes.fromhex("a8eb10649cbf")
        self.assertEqual(self.rig.run_string(huff, 0), ("ok", "huffman", b"no-cache", 1, 6, 7, 0))
        self.assertEqual(self.rig.run_string(b"", 0), ("err", 0, 0, 0))
        self.assertEqual(self.rig.run_string(bytes([0x05, 1, 2]), 0), ("err", tool.ERR_STRING_UNDERFLOW, 1, 0))
        self.assertEqual(self.rig.run_string(huff[:-1], 0), ("err", tool.ERR_STRING_UNDERFLOW, 1, 0))

    def test_generated_cases_agree(self):
        for data, pos, prefix in list(tool.int_cases(300)):
            self.assertEqual(self.rig.run_int(data, pos, prefix), tool.model_int(data, pos, prefix))
        for src, initial in list(tool.huffman_cases(300)):
            self.assertEqual(self.rig.run_huffman(src, initial), tool.model_huffman(self.table, src, initial))
        for data, pos in list(tool.string_cases(300)):
            self.assertEqual(self.rig.run_string(data, pos), tool.model_string(self.table, data, pos))

    def test_table_is_a_consistent_automaton(self):
        for state in range(256):
            for nibble in range(16):
                nxt, _, flags = tool.entry(self.table, state, nibble)
                self.assertLess(nxt, 256)
                self.assertIn(flags, (0, 1, 2, 3, 4, 5))
        self.assertEqual(tool.entry(self.table, 250, 15), (0, self.table[(250 * 16 + 15) * 16 + 8], 4))

    # ---- negative controls ----
    def test_wrong_models_are_caught(self):
        for kind, mut in tool.MODEL_MUTANTS:
            rig = {"idx": tool.NameRig, "name": tool.NameRig, "drop": tool.DropRig}.get(kind, tool.HdrRig)(self.image)
            expect, run = tool.checker(kind, self.table, rig, mut)
            cases = tool.sample_cases(kind)
            self.assertIsNotNone(tool.first_diff(cases, expect, run), mut)

    def test_patched_code_is_caught(self):
        rows = [r for r in tool.enumerate_mutants(self.image) if r[1] == "decode_int"]
        self.assertGreaterEqual(len(rows), 10)
        caught = 0
        for style, func, va, at, new, old in rows:
            rig = tool.HdrRig(self.image, patches={at: new})
            expect, run = tool.checker("int", self.table, rig)
            caught += tool.first_diff(tool.sample_cases("int")[:300], expect, run) is not None
        self.assertGreaterEqual(caught, len(rows) - 2)

    def test_corrupt_table_byte_is_caught_and_state_overflow_panics(self):
        at, new = tool.table_mutants(self.table)[0][:2]
        rig = tool.HdrRig(self.image, byte_overrides={at: new})
        expect, run = tool.checker("huffman", self.table, rig)
        self.assertIsNotNone(tool.first_diff(tool.sample_cases("huffman"), expect, run))
        broken = bytearray(self.table)
        broken[0:8] = (256).to_bytes(8, "little")
        with self.assertRaises(tool.Panic):
            tool.model_huffman(bytes(broken), bytes([0x00, 0x00]))

    def test_out_of_range_inputs(self):
        self.assertEqual(self.rig.run_int(b"\x7f", 5, 7), ("err", 1, 5))
        self.assertEqual(self.rig.run_string(b"\x03abc", 9), ("err", 0, 9, 0))

    # ---- Table::get, Header::clone, decode_literal ----
    def test_static_table_rows_match_rfc_7541(self):
        empty = tool.Ring(1, 0, 0, [("status", 200)])
        for index in range(1, 62):
            header, clones = self.rig.run_get(index, empty)
            self.assertEqual(header, tool.static_header(index), index)
            self.assertEqual(clones, ())
        self.assertEqual(self.rig.run_get(0, empty), (("err", 5), ()))
        self.assertEqual(self.rig.run_get(62, empty), (("err", 5), ()))
        self.assertEqual(tool.static_header(16), ("field", ("std", 2), b"gzip, deflate"))
        self.assertEqual(tool.static_header(14), ("status", 500))

    def test_static_field_ids_follow_name_order(self):
        names = [row[0] for row in tool.STATIC_ROWS[14:]]
        ordered = sorted(names)
        ids = [tool.STD_ID[n] for n in ordered]
        self.assertEqual(ids, sorted(ids))
        self.assertEqual(len(set(ids)), len(ids))

    def test_dynamic_ring_wrap_and_clone_order(self):
        slots = [("authority", b"a.b"), ("field", ("custom", b"x-k"), b"v"), ("method", 1), ("status", 404)]
        ring = tool.Ring(4, 2, 4, slots)
        expected = [slots[2], slots[3], slots[0], slots[1]]
        for k, entry in enumerate(expected):
            header, clones = self.rig.run_get(62 + k, ring)
            self.assertEqual(header, entry)
            self.assertEqual(clones, tuple(tool.clone_events(entry)))
        self.assertEqual(self.rig.run_get(66, ring), (("err", 5), ()))
        self.assertEqual(tool.clone_events(slots[1]), [b"x-k", b"v"])

    def test_literal_paths(self):
        ring = tool.Ring(2, 0, 1, [("path", b"/p"), ("status", 200)])
        # indexed name, static: :scheme https (index 7) with prefix 6 then a plain value "ab"
        got = self.rig.run_literal(bytes([0x47, 0x02]) + b"ab", 0, 1, ring)
        self.assertEqual(got, tool.model_literal(self.table, bytes([0x47, 0x02]) + b"ab", 0, 1, ring))
        self.assertEqual(got[0], ("built", 0xB1))
        self.assertEqual(got[3][-2], ("by-index", 3, ("scheme", b"https"), (b"ab", 0)))
        # literal name and value (index 0)
        data = bytes([0x40, 0x01]) + b"k" + bytes([0x01]) + b"v"
        got = self.rig.run_literal(data, 0, 1, ring)
        self.assertEqual(got, tool.model_literal(self.table, data, 0, 1, ring))
        self.assertEqual(got[0], ("built", 0xB2))
        self.assertEqual(got[3], (("by-name", (b"k", 0), (b"v", 0)),))
        self.assertEqual((got[1], got[2]), (0, len(data)))  # plain strings are split off the input, cursor back to 0
        # index beyond the table: Table::get error 5, no string is read
        got = self.rig.run_literal(bytes([0x7F, 0x30, 0x01]) + b"a", 0, 1, ring)
        self.assertEqual(got[0], ("err", 5))
        self.assertEqual(got[3], ())

    def test_literal_failure_cleanup(self):
        ring = tool.Ring(1, 0, 1, [("authority", b"h")])
        data = bytes([0x7E, 0x05, 0x01])  # index 62 (prefix 6: 0x3f + 0x... ), then a truncated string
        got = self.rig.run_literal(data, 0, 1, ring)
        self.assertEqual(got, tool.model_literal(self.table, data, 0, 1, ring))
        self.assertEqual(got[0][0], "err")

    def test_wrong_get_and_literal_models_are_caught(self):
        for kind, mut in tool.MODEL_MUTANTS:
            if kind not in ("get", "literal"):
                continue
            expect, run = tool.checker(kind, self.table, self.rig, mut)
            self.assertIsNotNone(tool.first_diff(tool.sample_cases(kind), expect, run), mut)

    def test_patched_static_row_and_ring_code_is_caught(self):
        rows = [r for r in tool.enumerate_mutants(self.image) if r[1] == "table_get"]
        self.assertGreaterEqual(len(rows), 40)
        caught = 0
        for style, func, va, at, new, old in rows[:12]:
            rig = tool.HdrRig(self.image, patches={at: new})
            expect, run = tool.checker("get", self.table, rig)
            caught += tool.first_diff(tool.sample_cases("get")[:200], expect, run) is not None
        self.assertGreaterEqual(caught, 8)

    def test_literal_vec_backed_input_and_overflow(self):
        ring = tool.Ring(1, 0, 0, [("status", 200)])
        data = bytes([0x47, 0x02]) + b"ab"
        tag = (5 << 5) | 1
        got = self.rig.run_literal(data, 0, 1, ring, tag)
        self.assertEqual(got, tool.model_literal(self.table, data, 0, 1, ring, tag))
        self.assertEqual(got[3][-2][3], (b"ab", ((5 + 2) << 5) | 1))
        huge = (((1 << 59) - 2) << 5) | 1
        self.assertEqual(self.rig.run_literal(data, 0, 1, ring, huge), ("panic",))
        self.assertEqual(tool.model_literal(self.table, data, 0, 1, ring, huge), ("panic",))

    def test_out_of_range_literal_input(self):
        ring = tool.Ring(1, 0, 0, [("status", 200)])
        got = self.rig.run_literal(b"", 0, 0, ring)
        self.assertEqual(got, tool.model_literal(self.table, b"", 0, 0, ring))
        self.assertEqual(got[0], ("err", 1))
        got = self.rig.run_literal(b"\x00", 4, 2, ring)
        self.assertEqual(got[0], ("err", 1))

    def test_generated_get_and_literal_cases_agree(self):
        for index, ring in list(tool.get_cases(150)):
            self.assertEqual(self.rig.run_get(index, ring), tool.get_expect(index, ring))
        for data, pos, arg, ring, tag in list(tool.literal_cases(150)):
            self.assertEqual(self.rig.run_literal(data, pos, arg, ring, tag),
                             tool.model_literal(self.table, data, pos, arg, ring, tag))

    def test_index_builder_selectors_and_failures(self):
        brig = tool.NameRig(self.image)
        cases = (
            (1, None, (1, b"example.com", 5), (("authority", b"example.com", tool.VT_AT, 5)), ()),
            (1, None, (1, b"\xff", 5), ("err", 7), (("bytes-drop",),)),
            (2, None, (1, b"GET", 5), ("method", 1), (("bytes-drop",),)),
            (2, None, (1, b"a b", 5), ("err", 7), (("bytes-drop",),)),
            (6, None, (1, b"404", 5), ("status", 404), (("bytes-drop",),)),
            (6, None, (1, b"099", 5), ("err", 8), (("bytes-drop",),)),
            (6, None, (1, b"2000", 5), ("err", 8), (("bytes-drop",),)),
        )
        for sel, entry, value, header, events in cases:
            self.assertEqual(tool.model_idx(sel, entry, value, False), (header, events))
            self.assertEqual(brig.run_idx(sel, entry, value), (header, events))

    def test_index_builder_field_value_rules(self):
        brig = tool.NameRig(self.image)
        entry = ("field", ("custom", b"x-a"), b"")
        for data in (b"ok value", b"tab\tok", b"bad\x01", b"del\x7f", b""):
            got = brig.run_idx(0, entry, (1, data, 9), odd=False)
            self.assertEqual(got, tool.model_idx(0, entry, (1, data, 9), False))
        self.assertEqual(brig.run_idx(0, entry, (1, b"bad\x01", 9))[0], ("err", 7))
        self.assertEqual(brig.run_idx(0, entry, (1, b"bad\x01", 9))[1], (("clone", b"x-a"), ("bytes-drop",), ("bytes-drop",)))
        self.assertEqual(brig.run_idx(0, entry, (1, b"v", 9), oom=True), ("panic",))

    def test_name_builder_pseudo_table(self):
        nrig = tool.NameRig(self.image)
        for name, kind in tool.PSEUDO.items():
            data = {"method": b"POST", "status": b"200"}.get(kind, b"/x" if kind == "path" else b"v")
            got = nrig.run_name(name, (1, data, 3))
            self.assertEqual(got, tool.model_name_build(name, (1, data, 3), False))
            self.assertNotEqual(got[0][0], "err")
        for name in (b":", b":x", b":Path", b":paths", b":method2", b":authorit"):
            got = nrig.run_name(name, (1, b"v", 3))
            self.assertEqual(got[0], ("err", 9))
        self.assertEqual(nrig.run_name(b"", (1, b"v", 3))[0], ("err", 0))

    def test_name_builder_field_and_failure_cleanup(self):
        nrig = tool.NameRig(self.image)
        got = nrig.run_name(b"X-Custom", (1, b"v", 3))
        self.assertEqual(got[0][:3], ("field", ("custom", b"x-custom"), b"v"))
        got = nrig.run_name(b"x-custom", (1, b"v\x00", 3))
        self.assertEqual(got[0], ("err", 7))
        self.assertEqual([e[0] for e in got[1]], ["bytes-drop", "value-drop", "name-drop"])
        got = nrig.run_name(b"bad name", (1, b"v", 3))
        self.assertEqual([e[0] for e in got[1]], ["value-drop", "name-drop"])
        self.assertEqual(nrig.run_name(b"host", (1, b"v", 3), oom=True), ("panic",))

    def test_status_edges_agree(self):
        nrig = tool.NameRig(self.image)
        for data in tool.STATUS_EDGES:
            self.assertEqual(nrig.run_name(b":status", (1, data, 3)),
                             tool.model_name_build(b":status", (1, data, 3), False))
        self.assertEqual(tool.status_of(b"100"), 100)
        self.assertEqual(tool.status_of(b"099"), 0)
        self.assertEqual(tool.status_of(b"20:"), 0)

    def test_header_drop_order_and_methods(self):
        drig = tool.DropRig(self.image)
        field = ("field", ("custom", b"nm"), b"val")
        self.assertEqual(drig.run_drop(field), (("bytes-drop", 0x11, 2), ("bytes-drop", 0x22, 3)))
        self.assertEqual(drig.run_drop(("field", ("std", 3), b"v")), (("bytes-drop", 0x22, 1),))
        self.assertEqual(drig.run_drop(("method", 10, b"GRAB")), (("free", 4, b"GRAB", 0),))
        self.assertEqual(drig.run_drop(("method", 3)), ())
        self.assertEqual(drig.run_drop(("status", 200)), ())
        self.assertEqual(drig.run_drop(("raw", 9)), ())
        self.assertEqual(drig.run_drop(("only-method", ("method", 10, b"x"))), (("free", 1, b"x", 0),))
        self.assertEqual(drig.run_drop(("only-method", ("method", 11, b"x"))), ())
        self.assertEqual(drig.run_drop(("only-method", ("method", 10, b""))), ())

    def test_new_wrong_models_and_patches_are_caught(self):
        brig = tool.NameRig(self.image)
        value = (1, b"\xff", 5)
        self.assertNotEqual(brig.run_idx(1, None, value), tool.model_idx(1, None, value, False, "latin1_ok"))
        self.assertNotEqual(brig.run_name(b":status", (1, b"100", 5)),
                            tool.model_name_build(b":status", (1, b"200", 5), False))
        low, high = tool.RANGES["status_parse"]
        patched = tool.NameRig(self.image, patches={0x179B37C: 0xF8})
        self.assertNotEqual(patched.run_name(b":status", (1, b"100", 5)),
                            tool.model_name_build(b":status", (1, b"100", 5), False))
        self.assertLess(low, high)
        with self.assertRaises(tool.Halt):
            tool.NameRig(self.image).m.memory.bytes_at(0x10, 4)

    def test_generated_builder_and_drop_cases_agree(self):
        brig = tool.NameRig(self.image)
        for case in list(tool.idx_cases(120)):
            self.assertEqual(brig.run_idx(*case[:3], odd=case[3]), tool.idx_expect(case))
        for case in list(tool.name_cases(120)):
            self.assertEqual(brig.run_name(*case[:2], odd=case[2]), tool.name_expect(case))
        drig = tool.DropRig(self.image)
        for case in list(tool.drop_cases(120)):
            self.assertEqual(drig.run_drop(case), tool.model_drop(case))

    def test_committed_summary_is_consistent(self):
        if not WORK.exists():
            return
        summary = json.loads((WORK / "measure.json").read_text())
        self.assertGreaterEqual(summary["cases"], 10000)
        self.assertEqual(summary["negative_detected"] + summary["equivalent"], summary["negative_controls"])


if __name__ == "__main__":
    unittest.main()
