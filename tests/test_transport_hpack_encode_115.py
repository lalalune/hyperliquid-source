import hashlib
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import transport_hpack_encode_115 as hp  # noqa: E402


class HpackEncodeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = hp.load_image()
        cls.table = hp.read_table(cls.image)

    def emulate(self, case, patches=None, table_patch=None):
        harness = hp.Harness(self.image, patches, table_patch)
        return harness.run_case(case)

    # --- the Huffman table read from the image bytes ---

    def test_table_is_a_complete_prefix_code(self):
        rows = dict((name, (value, result)) for name, value, result in hp.table_checks(self.table))
        self.assertEqual(rows["kraft_sum"], ("1", "ok"))
        self.assertEqual(rows["prefix_free_adjacent_sorted"], ("True", "ok"))
        self.assertTrue(all(result == "ok" for _, result in rows.values()))
        self.assertEqual(len(self.table), 257)

    def test_corrupted_table_fails_checks(self):
        broken = list(self.table)
        broken[0x61] = (broken[0x61][0] + 1, broken[0x61][1])
        results = [result for _, _, result in hp.table_checks(broken)]
        self.assertIn("FAIL", results)

    def test_rfc7541_c4_huffman_vectors(self):
        vectors = {b"www.example.com": "f1e3c2e5f23a6ba0ab90f4ff", b"no-cache": "a8eb10649cbf",
                   b"custom-key": "25a849e95ba97d7f", b"custom-value": "25a849e95bb8e8b4bf"}
        for text, want in vectors.items():
            self.assertEqual(hp.huffman_ref(self.table, text).hex(), want)
            got, kept, _ = self.emulate(hp.make_case("huffman-single", text))
            self.assertEqual(got.hex(), want)
            self.assertEqual(kept, b"")

    # --- model details ---

    def test_varint_reference(self):
        self.assertEqual(hp.varint_ref(0), b"\x00")
        self.assertEqual(hp.varint_ref(127), b"\x7f")
        self.assertEqual(hp.varint_ref(128), b"\x80\x01")
        self.assertEqual(hp.varint_ref(16384), b"\x80\x80\x01")

    def test_string_reference_prefix_forms(self):
        self.assertEqual(hp.string_ref(self.table, b""), b"\x00")
        short = hp.string_ref(self.table, b"0" * 300)
        self.assertEqual(short[0], 0xFF)
        self.assertEqual(short[1], len(hp.huffman_ref(self.table, b"0" * 300)) - 127)

    def test_literal_reference_index_forms(self):
        self.assertEqual(hp.literal_ref(self.table, 14, b"", False), b"\x0e\x00")
        self.assertEqual(hp.literal_ref(self.table, 15, b"", False), b"\x0f\x00\x00")
        self.assertEqual(hp.literal_ref(self.table, 16, b"", True), b"\x1f\x01\x00")
        self.assertEqual(hp.literal_ref(self.table, 143, b"", False), b"\x0f\x80\x01\x00")

    # --- emulated function bodies against the model ---

    def test_huffman_every_symbol(self):
        harness = hp.Harness(self.image)
        for symbol in range(256):
            case = hp.make_case("huffman-single", bytes([symbol]), spare=symbol % 3)
            got, kept, steps = harness.run_case(case)
            self.assertEqual(got, hp.huffman_ref(self.table, bytes([symbol])), symbol)
            self.assertGreater(steps, 0)

    def test_string_length_boundaries(self):
        harness = hp.Harness(self.image)
        for count in (0, 1, 24, 25, 200, 201, 202, 410, 411, 412, 413):
            case = hp.make_case("string-sweep", b"0" * count)
            got, _, _ = harness.run_case(case)
            self.assertEqual(got, hp.string_ref(self.table, case["data"]), count)

    def test_literal_index_boundaries(self):
        harness = hp.Harness(self.image)
        for index in (0, 14, 15, 16, 142, 143, 144, 16398, 16399, 16400, 2097166, 2097167, 1 << 28, (1 << 49) + 15):
            for sensitive in (False, True):
                case = hp.make_case("literal-boundary", b"no-cache", index=index, sensitive=sensitive, spare=0)
                got, _, _ = harness.run_case(case)
                self.assertEqual(got, hp.literal_ref(self.table, index, b"no-cache", sensitive), (index, sensitive))

    def test_existing_destination_bytes_are_kept(self):
        case = hp.make_case("literal-random", b"abc", index=3, prefix=b"\x01\x02\x03", spare=0)
        got, kept, _ = self.emulate(case)
        self.assertEqual(kept, b"\x01\x02\x03")
        self.assertEqual(got, hp.literal_ref(self.table, 3, b"abc", False))

    def test_forced_reserve_path_is_exercised(self):
        harness = hp.Harness(self.image)
        harness.run_case(hp.make_case("huffman-single", b"a" * 3, spare=0))
        self.assertGreater(harness.reserve_calls, 0)
        self.assertGreater(harness.put_calls, 0)

    def test_three_byte_varint_prefix(self):
        table = self.table
        count = 0
        while -(-(table[0x61][0] + 5 * count) // 8) < 16511:
            count += 1
        case = hp.make_case("string-huge", b"a" + b"0" * count, spare=0)
        got, _, _ = self.emulate(case)
        self.assertEqual(got[:4], b"\xff\x80\x80\x01"[:1] + hp.varint_ref(16384))
        self.assertEqual(got, hp.string_ref(table, case["data"]))

    def test_case_generation_is_deterministic_and_sized(self):
        first = [(case["kind"], case["data"], case["index"]) for case in hp.cases(self.table)]
        second = [(case["kind"], case["data"], case["index"]) for case in hp.cases(self.table)]
        self.assertEqual(first, second)
        self.assertGreaterEqual(len(first), 10000)

    # --- negative controls ---

    def test_unmodelled_reserve_argument_is_rejected(self):
        # 0x179d81a is `mov edx,0x1` before the reserve slot; flipping it to 0 must stop the stub contract
        at = 0x179D81B
        patches = {at: self.image.blob[self.image.offset(at)] ^ 1}
        case = hp.make_case("huffman-single", b"a" * 3, spare=0)
        with self.assertRaises(hp.Halt):
            self.emulate(case, patches)

    def test_inverted_branch_changes_output(self):
        # invert `jae` at the first compare of encode_str's short-length path (0x17acff2 cmp r13,0x7f; jae)
        at = 0x17ACFF6
        self.assertIn(self.image.blob[self.image.offset(at)], range(0x70, 0x80))
        patches = {at: self.image.blob[self.image.offset(at)] ^ 1}
        case = hp.make_case("string-sweep", b"0" * 3)
        try:
            got, _, _ = self.emulate(case, patches)
        except (hp.Halt, hp.Panic):
            return
        self.assertNotEqual(got, hp.string_ref(self.table, case["data"]))

    def test_table_mutant_changes_output(self):
        bits, code = self.table[0x61]
        got, _, _ = self.emulate(hp.make_case("huffman-single", b"aaaa"), table_patch={hp.TABLE_VA + 16 * 0x61 + 8: code ^ 1})
        self.assertNotEqual(got, hp.huffman_ref(self.table, b"aaaa"))

    def test_probe_selection_detects_branch_mutants(self):
        seen = hp.evaluate(self.image, self.table, selection=lambda number, case: number % 400 == 0)["seen"]
        mutants = [item for item in hp.mutant_list(self.image, seen) if item[1] == "jcc-invert"][:12]
        self.assertGreaterEqual(len(mutants), 12)
        detected = 0
        for _, _, _, patches, table_patch in mutants:
            result = hp.evaluate(self.image, self.table, patches, table_patch, hp.probe_selection, stop_on_mismatch=True)
            detected += bool(result["mismatch"])
        self.assertGreaterEqual(detected, 9)

    def test_tampered_image_is_rejected(self):
        blob = bytearray(self.image.blob)
        blob[hp.TABLE_VA] ^= 1
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "node"
            path.write_bytes(bytes(blob))
            with self.assertRaises(hp.EvidenceError):
                hp.load_image(path)

    def test_out_of_range_address_is_rejected(self):
        with self.assertRaises(hp.EvidenceError):
            self.image.offset(0x7FFFFFFFFFFF)
        with self.assertRaises(KeyError):
            self.image.fde_ends[0x179D761]

    def test_functions_cover_whole_fde_extents(self):
        rows = hp.function_rows(self.image)
        for name, entry, _ in hp.FUNCTIONS:
            self.assertEqual(rows[name][0].va, entry)
            self.assertEqual(rows[name][-1].next, self.image.fde_ends[entry])
            body = self.image.blob[self.image.offset(entry):self.image.offset(entry) + self.image.fde_ends[entry] - entry]
            self.assertEqual(len(hashlib.sha256(body).hexdigest()), 64)


if __name__ == "__main__":
    unittest.main()
